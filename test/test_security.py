import sqlite3
import uuid

import config


def _headers(token=None):
    h = {"Content-Type": "application/json", "User-Agent": "pytest-client/1.0"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def test_register_rejects_weak_password(client):
    r = client.post(
        "/register",
        json={
            "username": f"u_{uuid.uuid4().hex[:8]}",
            "email": f"{uuid.uuid4().hex[:8]}@example.com",
            "password": "short",
            "role": "guest",
        },
        headers=_headers(),
    )
    assert r.status_code == 400


def test_login_returns_jwt_on_success(client):
    user = f"guest_{uuid.uuid4().hex[:8]}"
    email = f"{user}@example.com"
    password = "strongpass1"
    assert (
        client.post(
            "/register",
            json={"username": user, "email": email, "password": password, "role": "guest"},
            headers=_headers(),
        ).status_code
        == 201
    )
    r = client.post(
        "/login",
        json={"username": user, "password": password},
        headers=_headers(),
    )
    assert r.status_code == 200
    data = r.get_json()
    assert "access_token" in data
    assert len(data["access_token"]) > 20


def test_login_fails_on_wrong_password(client):
    user = f"u_{uuid.uuid4().hex[:8]}"
    email = f"{user}@example.com"
    password = "correctpass1"
    assert (
        client.post(
            "/register",
            json={"username": user, "email": email, "password": password, "role": "guest"},
            headers=_headers(),
        ).status_code
        == 201
    )
    r = client.post(
        "/login",
        json={"username": user, "password": "wrongpassword1"},
        headers=_headers(),
    )
    assert r.status_code == 401


def test_protected_route_rejects_missing_jwt(client):
    r = client.post(
        "/bookings",
        json={
            "room_id": 1,
            "check_in": "2099-01-01",
            "check_out": "2099-01-05",
        },
        headers=_headers(),
    )
    assert r.status_code == 401


def test_guest_cannot_access_admin_routes(client):
    user = f"g_{uuid.uuid4().hex[:8]}"
    email = f"{user}@example.com"
    password = "guestpass1"
    client.post(
        "/register",
        json={"username": user, "email": email, "password": password, "role": "guest"},
        headers=_headers(),
    )
    login = client.post("/login", json={"username": user, "password": password}, headers=_headers())
    token = login.get_json()["access_token"]
    r = client.get("/payments", headers=_headers(token))
    assert r.status_code == 403


def test_staff_cannot_access_admin_only_routes(client):
    user = f"s_{uuid.uuid4().hex[:8]}"
    email = f"{user}@example.com"
    password = "staffpass1"
    client.post(
        "/register",
        json={"username": user, "email": email, "password": password, "role": "staff"},
        headers=_headers(),
    )
    login = client.post("/login", json={"username": user, "password": password}, headers=_headers())
    token = login.get_json()["access_token"]
    r = client.delete("/rooms/1", headers=_headers(token))
    assert r.status_code == 403


def test_sql_injection_login_attempt_blocked(client):
    r = client.post(
        "/login",
        json={"username": "x' OR '1'='1", "password": "anything"},
        headers=_headers(),
    )
    assert r.status_code == 401


def test_password_hash_stored_not_plaintext(client):
    user = f"h_{uuid.uuid4().hex[:8]}"
    email = f"{user}@example.com"
    plain = "mypassword1"
    client.post(
        "/register",
        json={"username": user, "email": email, "password": plain, "role": "guest"},
        headers=_headers(),
    )
    conn = sqlite3.connect(config.DATABASE_PATH)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (user,),
    ).fetchone()
    conn.close()
    assert row is not None
    stored = row[0]
    assert stored != plain
    assert stored.startswith("$argon2")


def test_metrics_endpoint_exposed(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert len(r.get_data()) > 0
