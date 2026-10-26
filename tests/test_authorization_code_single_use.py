"""Тест: auth code одноразовый."""

from datetime import datetime, timedelta, timezone

from app.core.security.pkce import compute_challenge
from app.core.security.tokens import generate_opaque_token, hash_token
from app.db import SessionLocal
from app.models import AuditEvent, AuthCode


def _create_auth_code(client_id, user_id, verifier="a" * 64) -> str:
    code = generate_opaque_token(48)
    challenge = compute_challenge(verifier, "S256")
    with SessionLocal() as db:
        ac = AuthCode(
            code_hash=hash_token(code),
            client_id=client_id,
            user_id=user_id,
            redirect_uri="http://localhost/callback",
            scope="openid",
            code_challenge=challenge,
            code_challenge_method="S256",
            nonce=None,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        )
        db.add(ac)
        db.commit()
    return code


def test_auth_code_single_use(client, public_client, test_user):
    verifier = "a" * 64
    code = _create_auth_code(public_client.client_id, test_user.id, verifier)

    # Первый обмен — успех
    r1 = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost/callback",
        "client_id": public_client.client_id,
        "code_verifier": verifier,
    })
    assert r1.status_code == 200
    assert "access_token" in r1.json()

    # Второй обмен — атака
    r2 = client.post("/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost/callback",
        "client_id": public_client.client_id,
        "code_verifier": verifier,
    })
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_grant"

    # Аудит зафиксировал атаку
    with SessionLocal() as db:
        event = (
            db.query(AuditEvent)
            .filter(AuditEvent.event_type == "auth_code.reuse_detected")
            .first()
        )
        assert event is not None