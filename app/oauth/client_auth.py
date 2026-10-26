"""Аутентификация OAuth-клиента по client_secret (Basic или body)."""

from __future__ import annotations

import base64
import binascii

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.passwords import verify_password
from app.models import OAuthClient
from app.oauth.errors import invalid_client


def authenticate_client(
    request: Request,
    db: Session,
    client_id: str | None,
    client_secret: str | None,
) -> OAuthClient:

    # 1. Basic auth переопределяет body-параметры
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("basic "):
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
            basic_id, _, basic_secret = decoded.partition(":")
            client_id = basic_id or client_id
            client_secret = basic_secret or client_secret
        except (binascii.Error, UnicodeDecodeError):
            raise invalid_client("Некорректный Basic auth header")

    if not client_id:
        raise invalid_client("client_id обязателен")

    # 2. Ищем клиента
    client = (
        db.query(OAuthClient)
        .filter(OAuthClient.client_id == client_id)
        .first()
    )
    if client is None:
        raise invalid_client("Клиент не найден")
    if not client.is_active:
        raise invalid_client("Клиент деактивирован")

    # 3. Публичный клиент — без секрета
    if client.is_confidential is False and client.hashed_secret is None:
        return client

    # 4. Конфиденциальный — секрет обязателен
    if not client_secret:
        raise invalid_client("client_secret обязателен для конфиденциального клиента")

    if not client.hashed_secret or not verify_password(client_secret, client.hashed_secret):
        raise invalid_client("Неверный client_secret")

    return client