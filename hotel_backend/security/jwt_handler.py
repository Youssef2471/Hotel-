import logging

from flask import request
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity

import config

logger = logging.getLogger(__name__)

# In-memory token blocklist. Use Redis in production — this resets on restart.
token_blocklist: set = set()


def create_token(user_id: int, role: str) -> str:
    ip_address = request.remote_addr
    device_fingerprint = request.headers.get("User-Agent", "")
    logger.info("Token issued: user_id=%s role=%s ip=%s", user_id, role, ip_address)
    return create_access_token(
        identity=str(user_id),
        additional_claims={
            "role": role,
            "ip": ip_address,
            "device_fingerprint": device_fingerprint,
        },
    )


def get_current_user() -> tuple:
    """Returns (user_id: str, role: str) from the current JWT."""
    claims = get_jwt()
    user_id = get_jwt_identity()
    role = claims.get("role")
    return user_id, role
