import os
import tempfile

_fd, _TEST_DB = tempfile.mkstemp(suffix=".db")
os.close(_fd)

os.environ["JWT_SECRET_KEY"] = "test_jwt_secret_key_for_automated_pytest_only_!"
os.environ["AES_KEY"] = "01234567890123456789012345678901"
os.environ["DATABASE_PATH"] = _TEST_DB

import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


def pytest_sessionfinish(session, exitstatus):
    try:
        os.unlink(_TEST_DB)
    except OSError:
        pass
