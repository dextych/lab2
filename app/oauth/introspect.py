"""POST /oauth/introspect — проверка активности токена (RFC 7662)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from app.core.security.jwt_rsa import verify_token
from app.core.security.tokens import hash_token
from app.db import get_db
from app.models import RefreshToken
from app.oauth.blacklist import is_blacklisted
from app.oauth.client_auth import authenticate_client

router = APIRouter(tags=["oauth"])


@router.post("/oauth/introspect")
async def introspect_endpoint(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    # 1. Аутентификация: только конфиденциальные клиенты
    client = authenticate_client(request, db, client_id, client_secret)
    if not client.is_confidential or client.hashed_secret is None:
        from app.oauth.errors import unauthorized_client
        raise unauthorized_client("introspect только для конфиденциальных клиентов")

    # 2. Пробуем access
    if token_type_hint in (None, "access_token"):
        result = await _introspect_access(token)
        if result is not None:
            return result

    # 3. Пробуем refresh
    if token_type_hint in (None, "refresh_token"):
        result = _introspect_refresh(db, token)
        if result is not None:
            return result

    # 4. Неизвестный токен
    return {"active": False}


async def _introspect_access(token: str) -> dict | None:
    try:
        payload = verify_token(token)
    except ValueError:
        return None

    jti = payload.get("jti")
    if jti and await is_blacklisted(jti):
        return {"active": False}

    return {
        "active": True,
        "sub": payload.get("sub"),
        "scope": payload.get("scope"),
        "client_id": payload.get("aud"),
        "exp": payload.get("exp"),
        "iat": payload.get("iat"),
        "iss": payload.get("iss"),
        "jti": jti,
        "token_type": "access_token",
    }


def _introspect_refresh(db: Session, token: str) -> dict | None:
    token_hash = hash_token(token)
    rt = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )
    if rt is None:
        return None

    now = datetime.now(timezone.utc)
    active = (
        rt.revoked_at is None
        and rt.used_at is None
        and rt.expires_at > now
    )

    if not active:
        return {"active": False}

    return {
        "active": True,
        "sub": str(rt.user_id),
        "scope": rt.scope,
        "client_id": rt.client_id,
        "exp": int(rt.expires_at.timestamp()),
        "token_type": "refresh_token",
    }