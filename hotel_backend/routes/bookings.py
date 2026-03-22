from datetime import datetime

from flask import Blueprint, jsonify, request
from database import get_db
from security.jwt_handler import get_current_user
from security.rbac import jwt_required_fp

bookings_bp = Blueprint("bookings", __name__)


def _parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


@bookings_bp.route("/bookings", methods=["POST"])
@jwt_required_fp()
def create_booking():
    user_id, role = get_current_user()
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    room_id = data.get("room_id")
    check_in = _parse_date(data.get("check_in", ""))
    check_out = _parse_date(data.get("check_out", ""))

    if not isinstance(room_id, int) or room_id <= 0:
        return jsonify({"error": "Invalid input"}), 400
    if not check_in or not check_out:
        return jsonify({"error": "Invalid input"}), 400
    if check_out <= check_in:
        return jsonify({"error": "Invalid input"}), 400
    if check_in < datetime.today().date():
        return jsonify({"error": "Invalid input"}), 400

    try:
        conn = get_db()

        room = conn.execute(
            "SELECT id, is_available FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()

        if not room or not room["is_available"]:
            conn.close()
            return jsonify({"error": "Room not available"}), 400

        overlap = conn.execute(
            """SELECT id FROM bookings
               WHERE room_id = ? AND status = 'confirmed'
               AND NOT (check_out <= ? OR check_in >= ?)""",
            (room_id, str(check_in), str(check_out)),
        ).fetchone()

        if overlap:
            conn.close()
            return jsonify({"error": "Room not available for selected dates"}), 409

        conn.execute(
            "INSERT INTO bookings (user_id, room_id, check_in, check_out, status) VALUES (?, ?, ?, ?, ?)",
            (user_id, room_id, str(check_in), str(check_out), "confirmed"),
        )
        conn.execute("UPDATE rooms SET is_available = 0 WHERE id = ?", (room_id,))
        conn.commit()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    return jsonify({"message": "Booking created"}), 201


@bookings_bp.route("/bookings", methods=["GET"])
@jwt_required_fp()
def get_bookings():
    user_id, role = get_current_user()

    try:
        conn = get_db()
        if role in ("staff", "admin"):
            bookings = conn.execute(
                "SELECT id, user_id, room_id, check_in, check_out, status, created_at FROM bookings"
            ).fetchall()
        else:
            bookings = conn.execute(
                "SELECT id, user_id, room_id, check_in, check_out, status, created_at FROM bookings WHERE user_id = ?",
                (user_id,),
            ).fetchall()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    return jsonify([dict(b) for b in bookings]), 200


@bookings_bp.route("/bookings/<int:id>/cancel", methods=["PUT"])
@jwt_required_fp()
def cancel_booking(id):
    user_id, role = get_current_user()

    try:
        conn = get_db()
        booking = conn.execute(
            "SELECT id, user_id, room_id, status FROM bookings WHERE id = ?", (id,)
        ).fetchone()

        if not booking:
            conn.close()
            return jsonify({"error": "Not found"}), 404

        if role not in ("staff", "admin") and str(booking["user_id"]) != str(user_id):
            conn.close()
            return jsonify({"error": "Insufficient permissions"}), 403

        if booking["status"] != "confirmed":
            conn.close()
            return jsonify({"error": "Booking cannot be cancelled"}), 400

        conn.execute("UPDATE bookings SET status = 'cancelled' WHERE id = ?", (id,))
        conn.execute("UPDATE rooms SET is_available = 1 WHERE id = ?", (booking["room_id"],))
        conn.commit()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    return jsonify({"message": "Booking cancelled"}), 200
