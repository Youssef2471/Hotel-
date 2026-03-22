import os
from datetime import timedelta

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-this-secret-in-production")  # nosec B105
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

DATABASE_PATH = os.environ.get("DATABASE_PATH", "database.db")

# Must be exactly 32 bytes when encoded. Set via environment variable in production.
AES_KEY = os.environ.get("AES_KEY", "change-this-aes-key-32-bytes!!!!")  # nosec B105

DEBUG = True
