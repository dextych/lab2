"""Общие фикстуры для тестов."""

from __future__ import annotations

import secrets
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.passwords import hash_password
from app.db import SessionLocal, get_db
from app.main import app
from app.models import AuditEvent, OAuthClient, User  # noqa: F401


@pytest.fixture()
def db_session() -> Generator:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(autouse=True)
def clean_db() -> Generator[None, None, None]:
    with SessionLocal() as session:
        session.execute(text("SET lock_timeout = '3s'"))
        session.execute(text(
            "TRUNCATE audit_events, auth_codes, refresh_tokens, user_sessions, "
            "oauth_clients, users RESTART IDENTITY CASCADE"
        ))
        session.commit()
    yield


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client


# ============ OAuth-фикстуры ============

@pytest.fixture()
def public_client(db_session) -> OAuthClient:
    """Публичный клиент (без секрета, с PKCE)."""
    c = OAuthClient(
        client_id="test-public-client",
        name="Test Public",
        is_confidential=False,
        redirect_uris=["http://localhost/callback"],
        scopes=["openid", "email", "profile"],
        grant_types=["authorization_code", "refresh_token"],
        hashed_secret=None,
        is_active=True,
    )
    db_session.add(c)
    db_session.commit()
    db_session.refresh(c)
    return c


@pytest.fixture()
def confidential_client(db_session) -> tuple[OAuthClient, str]:
    """Конфиденциальный клиент. Возвращает (client, plain_secret)."""
    plain_secret = secrets.token_urlsafe(48)
    c = OAuthClient(
        client_id="test-conf-client",
        name="Test Confidential",
        is_confidential=True,
        redirect_uris=["http://localhost/callback"],
        scopes=["openid", "email", "profile"],
        grant_types=["authorization_code", "refresh_token", "client_credentials", "password"],
        hashed_secret=hash_password(plain_secret),
        is_active=True,
    )
    db_session.add(c)
    db_session.commit()
    db_session.refresh(c)
    return c, plain_secret


@pytest.fixture()
def test_user(db_session) -> User:
    """Пользователь с паролем `correct-horse-battery`."""
    u = User(
        email="test@example.com",
        hashed_password=hash_password("correct-horse-battery"),
        is_active=True,
        is_admin=False,
    )
    db_session.add(u)
    db_session.commit()
    db_session.refresh(u)
    return u