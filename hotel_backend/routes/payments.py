from flask import Blueprint, jsonify, request
from database import get_db
from security.encryption import decrypt, encrypt
from security.jwt_handler import get_current_user
from security.rbac import jwt_required_fp, require_role

payments_bp = Blueprint("payments", __name__)


@payments_bp.route("/payments", methods=["POST"])
@jwt_required_fp()
def create_payment():
    user_id, role = get_current_user()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    booking_id = data.get("booking_id")
    amount = data.get("amount")
    card_number = str(data.get("card_number", "")).replace(" ", "")

    if not isinstance(booking_id, int) or booking_id <= 0:
        return jsonify({"error": "Invalid input"}), 400
    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({"error": "Invalid input"}), 400
    if not card_number.isdigit() or not (13 <= len(card_number) <= 19):
        return jsonify({"error": "Invalid input"}), 400

    try:
        conn = get_db()

        booking = conn.execute(
            "SELECT id, user_id, status FROM bookings WHERE id = ?", (booking_id,)
        ).fetchone()

        if not booking:
            conn.close()
            return jsonify({"error": "Not found"}), 404

        if role not in ("staff", "admin") and str(booking["user_id"]) != str(user_id):
            conn.close()
            return jsonify({"error": "Insufficient permissions"}), 403

        if booking["status"] != "confirmed":
            conn.close()
            return jsonify({"error": "Booking is not active"}), 400

        existing = conn.execute(
            "SELECT id FROM payments WHERE booking_id = ? AND status = 'completed'",
            (booking_id,),
        ).fetchone()

        if existing:
            conn.close()
            return jsonify({"error": "Payment already processed"}), 409

        encrypted_card = encrypt(card_number)

        conn.execute(
            "INSERT INTO payments (booking_id, amount, card_number_encrypted, status) VALUES (?, ?, ?, ?)",
            (booking_id, amount, encrypted_card, "completed"),
        )
        conn.commit()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    return jsonify({"message": "Payment processed"}), 201


@payments_bp.route("/payments", methods=["GET"])
@require_role("admin")
def get_all_payments():
    try:
        conn = get_db()
        payments = conn.execute(
            "SELECT id, booking_id, amount, card_number_encrypted, status, created_at FROM payments"
        ).fetchall()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    results = []
    for payment in payments:
        p = dict(payment)
        try:
            card = decrypt(p.pop("card_number_encrypted"))
            p["card_number_masked"] = "*" * (len(card) - 4) + card[-4:]
        except Exception:
            p.pop("card_number_encrypted", None)
            p["card_number_masked"] = "****"
        results.append(p)

    return jsonify(results), 200


@payments_bp.route("/payments/<int:booking_id>", methods=["GET"])
@require_role("admin")
def get_payment(booking_id):
    try:
        conn = get_db()
        payment = conn.execute(
            "SELECT id, booking_id, amount, card_number_encrypted, status, created_at FROM payments WHERE booking_id = ?",
            (booking_id,),
        ).fetchone()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    if not payment:
        return jsonify({"error": "Not found"}), 404

    result = dict(payment)
    try:
        card = decrypt(result.pop("card_number_encrypted"))
        result["card_number_masked"] = "*" * (len(card) - 4) + card[-4:]
    except Exception:
        result.pop("card_number_encrypted", None)
        result["card_number_masked"] = "****"

    return jsonify(result), 200
