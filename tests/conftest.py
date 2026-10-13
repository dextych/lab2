from __future__ import annotations

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import SessionLocal, get_db
from app.main import app
from app.models import AuditEvent, OAuthClient, User

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
            "TRUNCATE audit_events, oauth_clients, users RESTART IDENTITY CASCADE"
        ))
        session.commit()
    yield


@pytest.fixture()
def client() -> Generator[TestClient, None, None]:
    with TestClient(app) as test_client:
        yield test_client