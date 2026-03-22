import logging
import re
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from database import get_db
from security.hashing import hash_password, verify_password
from security.jwt_handler import create_token, token_blocklist
from security.rbac import jwt_required_fp

logger = logging.getLogger(__name__)

MAX_FAILED_ATTEMPTS = 3
LOCKOUT_MINUTES = 15
ADMIN_HOUR_START = 9
ADMIN_HOUR_END = 18

auth_bp = Blueprint("auth", __name__)

_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')


def _valid_username(value) -> bool:
    return isinstance(value, str) and 3 <= len(value) <= 50 and re.match(r'^[a-zA-Z0-9_\-]+$', value) is not None


def _valid_email(value) -> bool:
    return isinstance(value, str) and bool(_EMAIL_RE.match(value))


def _valid_password(value) -> bool:
    return isinstance(value, str) and len(value) >= 8


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    role = data.get("role", "guest")

    if not _valid_username(username) or not _valid_email(email) or not _valid_password(password):
        return jsonify({"error": "Invalid input"}), 400
    if role not in ("guest", "staff", "admin"):
        return jsonify({"error": "Invalid input"}), 400

    password_hash = hash_password(password)

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role),
        )
        conn.commit()
        conn.close()
    except Exception:
        return jsonify({"error": "Registration failed"}), 400

    return jsonify({"message": "Registration successful"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Invalid credentials"}), 401

    try:
        conn = get_db()
        user = conn.execute(
            "SELECT id, password_hash, role, failed_attempts, locked_until FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    except Exception:
        return jsonify({"error": "An error occurred"}), 500

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if account is locked
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if datetime.now() < locked_until:
            conn.close()
            return jsonify({"error": "Account temporarily locked. Try again later"}), 403

    if not verify_password(user["password_hash"], password):
        new_attempts = user["failed_attempts"] + 1
        if new_attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = (datetime.now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (new_attempts, locked_until, user["id"]),
            )
            logger.warning("Account locked: user_id=%s after %d failed attempts", user["id"], new_attempts)
        else:
            conn.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (new_attempts, user["id"]),
            )
        conn.commit()
        conn.close()
        return jsonify({"error": "Invalid credentials"}), 401

    # Successful login — reset failed attempts
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user["id"],),
    )
    conn.commit()
    conn.close()

    # Admin login timing warning (9AM–6PM)
    if user["role"] == "admin":
        current_hour = datetime.now().hour
        if not (ADMIN_HOUR_START <= current_hour < ADMIN_HOUR_END):
            logger.warning(
                "Admin login outside working hours: user_id=%s hour=%d",
                user["id"], current_hour,
            )

    token = create_token(user["id"], user["role"])
    return jsonify({"access_token": token}), 200


@auth_bp.route("/logout", methods=["POST"])
@jwt_required_fp()
def logout():
    jti = get_jwt()["jti"]
    token_blocklist.add(jti)
    return jsonify({"message": "Logged out successfully"}), 200
