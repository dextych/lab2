"""Формирование ответа /oauth/token."""

from __future__ import annotations

from app.config.config import settings
from app.core.security.jwt_rsa import sign_access_token, sign_id_token
from app.models import User


def build_token_response(
    *,
    sub: str,
    client_id: str,
    scope: list[str],
    refresh_token: str | None = None,
    user: User | None = None,
    nonce: str | None = None,
    include_id_token: bool = False,
) -> dict:
    """Возвращает JSON для /oauth/token."""
    access_token = sign_access_token(
        sub=sub,
        client_id=client_id,
        scopes=scope,
        ttl_sec=settings.access_token_ttl_sec,
    )

    body: dict = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_sec,
        "scope": " ".join(scope),
    }

    if refresh_token is not None:
        body["refresh_token"] = refresh_token

    if include_id_token and user is not None and "openid" in scope:
        body["id_token"] = sign_id_token(
            sub=sub,
            client_id=client_id,
            nonce=nonce,
            user=user,
            scopes=scope,
            ttl_sec=settings.access_token_ttl_sec,
        )

    return body