import logging
from functools import wraps

from flask import jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt

logger = logging.getLogger(__name__)


def _check_device_fingerprint(claims) -> bool:
    token_fingerprint = claims.get("device_fingerprint", "")
    current_fingerprint = request.headers.get("User-Agent", "")
    if token_fingerprint and token_fingerprint != current_fingerprint:
        logger.warning("Device fingerprint mismatch — possible token theft detected")
        return False
    return True


def jwt_required_fp():
    """Decorator that enforces JWT authentication and device fingerprint check."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception:
                return jsonify({"error": "Authentication required"}), 401

            claims = get_jwt()
            if not _check_device_fingerprint(claims):
                return jsonify({"error": "Authentication required"}), 401

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_role(*roles):
    """Decorator that enforces JWT authentication, device fingerprint, and role-based access.

    Returns 401 if no valid token or fingerprint mismatch.
    Returns 403 if the token's role is not in the allowed roles.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
            except Exception:
                return jsonify({"error": "Authentication required"}), 401

            claims = get_jwt()

            if not _check_device_fingerprint(claims):
                return jsonify({"error": "Authentication required"}), 401

            role = claims.get("role")
            if role not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator
