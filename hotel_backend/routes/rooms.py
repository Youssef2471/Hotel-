from flask import Blueprint, jsonify, request

from database import get_db
from security.rbac import require_role

rooms_bp = Blueprint("rooms", __name__)


@rooms_bp.route("/rooms", methods=["GET"])
def get_rooms():
    try:
        conn = get_db()
        rooms = conn.execute(
            "SELECT id, room_number, type, price_per_night, is_available FROM rooms WHERE is_available = 1"
        ).fetchall()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    return jsonify([dict(r) for r in rooms]), 200


@rooms_bp.route("/rooms/<int:id>", methods=["GET"])
def get_room(id):
    try:
        conn = get_db()
        room = conn.execute(
            "SELECT id, room_number, type, price_per_night, is_available FROM rooms WHERE id = ?",
            (id,),
        ).fetchone()
        conn.close()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    if not room:
        return jsonify({"error": "Not found"}), 404

    return jsonify(dict(room)), 200


@rooms_bp.route("/rooms", methods=["POST"])
@require_role("staff", "admin")
def create_room():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    room_number = data.get("room_number", "").strip()
    room_type = data.get("type", "").strip()
    price = data.get("price_per_night")

    if not room_number or not room_type:
        return jsonify({"error": "Invalid input"}), 400
    if not isinstance(price, (int, float)) or price <= 0:
        return jsonify({"error": "Invalid input"}), 400

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO rooms (room_number, type, price_per_night, is_available) VALUES (?, ?, ?, ?)",
            (room_number, room_type, price, 1),
        )
        conn.commit()
        conn.close()
    except Exception:
        return jsonify({"error": "Could not create room"}), 400

    return jsonify({"message": "Room created"}), 201


@rooms_bp.route("/rooms/<int:id>", methods=["PUT"])
@require_role("staff", "admin")
def update_room(id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    room_type = data.get("type", "").strip()
    price = data.get("price_per_night")
    is_available = data.get("is_available")

    if not room_type:
        return jsonify({"error": "Invalid input"}), 400
    if not isinstance(price, (int, float)) or price <= 0:
        return jsonify({"error": "Invalid input"}), 400
    if is_available not in (0, 1, True, False):
        return jsonify({"error": "Invalid input"}), 400

    try:
        conn = get_db()
        result = conn.execute(
            "UPDATE rooms SET type = ?, price_per_night = ?, is_available = ? WHERE id = ?",
            (room_type, price, int(is_available), id),
        )
        conn.commit()
        conn.close()
        if result.rowcount == 0:
            return jsonify({"error": "Not found"}), 404
    except Exception:
        return jsonify({"error": "Could not update room"}), 400

    return jsonify({"message": "Room updated"}), 200


@rooms_bp.route("/rooms/<int:id>", methods=["DELETE"])
@require_role("admin")
def delete_room(id):
    try:
        conn = get_db()
        result = conn.execute("DELETE FROM rooms WHERE id = ?", (id,))
        conn.commit()
        conn.close()
        if result.rowcount == 0:
            return jsonify({"error": "Not found"}), 404
    except Exception:
        return jsonify({"error": "Could not delete room"}), 400

    return jsonify({"message": "Room deleted"}), 200
