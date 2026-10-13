from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import AuditEvent

def test_register_success(client: TestClient):
    r = client.post("/auth/register", json={
        "email": "alice@example.com",
        "password": "correct-horse-battery",
    })
    assert r.status_code == 201
    body = r.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


def test_register_weak_password_rejected(client: TestClient):
    r = client.post("/auth/register", json={
        "email": "weak@example.com",
        "password": "123",
    })
    assert r.status_code == 400
    assert "минимум" in r.json()["detail"].lower()


def test_register_duplicate_email(client: TestClient):
    payload = {"email": "dup@example.com", "password": "correct-horse-battery"}
    r1 = client.post("/auth/register", json=payload)
    assert r1.status_code == 201

    r2 = client.post("/auth/register", json=payload)
    assert r2.status_code == 409


def test_login_success(client: TestClient):
    client.post("/auth/register", json={
        "email": "login@example.com",
        "password": "correct-horse-battery",
    })
    r = client.post("/auth/login", json={
        "email": "login@example.com",
        "password": "correct-horse-battery",
    })
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_wrong_password_returns_401_neutral(client: TestClient):
    client.post("/auth/register", json={
        "email": "wrong@example.com",
        "password": "correct-horse-battery",
    })
    r = client.post("/auth/login", json={
        "email": "wrong@example.com",
        "password": "totally-wrong-password",
    })
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid credentials"


def test_login_unknown_email_same_message(client: TestClient):
    r = client.post("/auth/login", json={
        "email": "ghost@example.com",
        "password": "whatever-12345",
    })
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid credentials"


def test_me_without_token_returns_401(client: TestClient):
    r = client.get("/auth/me")
    assert r.status_code == 401


def test_me_with_garbage_token_returns_401(client: TestClient):
    r = client.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401


def test_me_with_valid_token(client: TestClient):
    reg = client.post("/auth/register", json={
        "email": "me@example.com",
        "password": "correct-horse-battery",
    }).json()
    token = reg["access_token"]

    r = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "me@example.com"
    assert body["is_admin"] is False


def test_audit_event_written_on_login_success(
    client: TestClient, db_session: Session
):
    """После успешного логина в audit_events появляется user.login.success."""
    client.post("/auth/register", json={
        "email": "audit@example.com",
        "password": "correct-horse-battery",
    })
    client.post("/auth/login", json={
        "email": "audit@example.com",
        "password": "correct-horse-battery",
    })

    events = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "user.login.success")
        .all()
    )
    assert len(events) == 1
    assert events[0].actor_id is not None
    # Секреты в metadata не попадают
    meta = events[0].metadata_json or {}
    assert "password" not in meta
    assert "hashed_password" not in meta