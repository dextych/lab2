"""Тесты refresh token rotation."""

import secrets

from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditEvent, RefreshToken


def _get_password_tokens(client, conf_client_and_secret):
    c, secret = conf_client_and_secret
    r = client.post("/oauth/token", data={
        "grant_type": "password",
        "username": "test@example.com",
        "password": "correct-horse-battery",
        "scope": "openid",
        "client_id": c.client_id,
        "client_secret": secret,
    })
    assert r.status_code == 200
    return r.json()


def test_refresh_rotation_success(client, confidential_client):
    tokens = _get_password_tokens(client, confidential_client)
    old_refresh = tokens["refresh_token"]

    r = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": old_refresh,
        "client_id": confidential_client[0].client_id,
        "client_secret": confidential_client[1],
    })
    assert r.status_code == 200
    new_refresh = r.json()["refresh_token"]

    # Новый токен отличается
    assert new_refresh != old_refresh


def test_refresh_reuse_revokes_family(client, confidential_client):
    c, secret = confidential_client
    tokens = _get_password_tokens(client, confidential_client)
    old_refresh = tokens["refresh_token"]

    # 1. Первый refresh — успех
    r = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": old_refresh,
        "client_id": c.client_id,
        "client_secret": secret,
    })
    assert r.status_code == 200

    # 2. Повторное использование старого — атака
    r2 = client.post("/oauth/token", data={
        "grant_type": "refresh_token",
        "refresh_token": old_refresh,
        "client_id": c.client_id,
        "client_secret": secret,
    })
    assert r2.status_code == 400
    assert r2.json()["error"] == "invalid_grant"

    # 3. Вся семья отозвана
    with SessionLocal() as db:
        # Находим family_id по старому токену
        old_hash = __import__("app.core.security.tokens", fromlist=["hash_token"]).hash_token(old_refresh)
        old_token = db.query(RefreshToken).filter(RefreshToken.token_hash == old_hash).first()
        family_id = old_token.family_id

        # Все токены семьи отозваны
        family = db.query(RefreshToken).filter(RefreshToken.family_id == family_id).all()
        assert all(rt.revoked_at is not None for rt in family)

        # Аудит зафиксировал
        event = (
            db.query(AuditEvent)
            .filter(AuditEvent.event_type == "token.reuse_detected")
            .first()
        )
        assert event is not None
        assert event.metadata_json["family_id"] == family_id