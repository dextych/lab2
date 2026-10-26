"""POST /oauth/revoke — отзыв access- или refresh-токена (RFC 7009)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from app.audit.service import extract_request_info, write_event
from app.core.security.jwt_rsa import verify_token
from app.core.security.tokens import hash_token
from app.db import get_db
from app.models import RefreshToken, UserSession
from app.oauth.blacklist import blacklist_jti
from app.oauth.client_auth import authenticate_client

router = APIRouter(tags=["oauth"])


@router.post("/oauth/revoke")
async def revoke_endpoint(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),  # access_token | refresh_token
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    # 1. Аутентифицируем клиента
    client = authenticate_client(request, db, client_id, client_secret)

    # 2. Пробуем как access-токен (JWT)
    if token_type_hint in (None, "access_token"):
        if await _try_revoke_access_token(db, request, token, client.client_id):
            return {}   # 200 OK

    # 3. Пробуем как refresh-токен (opaque)
    if token_type_hint in (None, "refresh_token"):
        if _try_revoke_refresh_token(db, request, token, client.client_id):
            return {}   # 200 OK

    # 4. RFC 7009: всегда 200 OK, даже если токен не найден
    return {}


async def _try_revoke_access_token(
    db: Session, request: Request, token: str, client_id: str,
) -> bool:
    """Пытается отозвать access-токен. True, если получилось."""
    try:
        payload = verify_token(token)
    except ValueError:
        return False

    # Проверяем, что токен принадлежит этому клиенту
    if payload.get("aud") != client_id and payload.get("azp") != client_id:
        return False

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return False

    # Вызываем асинхронную функцию через await
    await blacklist_jti(jti, exp)

    ip, ua = extract_request_info(request)
    write_event(
        db, "token.revoked",
        client_id=client_id, ip=ip, user_agent=ua,
        metadata={"token_type": "access", "jti": jti},
    )
    return True


def _try_revoke_refresh_token(
    db: Session, request: Request, token: str, client_id: str,
) -> bool:
    """Пытается отозвать refresh-токен. True, если получилось."""
    token_hash = hash_token(token)
    rt = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == token_hash)
        .first()
    )
    if rt is None or rt.client_id != client_id:
        return False

    now = datetime.now(timezone.utc)
    rt.revoked_at = now

    # Отзываем сессию этого семейства
    db.query(UserSession).filter(
        UserSession.family_id == rt.family_id,
        UserSession.revoked_at.is_(None),
    ).update({"revoked_at": now})

    db.commit()

    ip, ua = extract_request_info(request)
    write_event(
        db, "token.revoked",
        actor_id=rt.user_id, client_id=client_id, ip=ip, user_agent=ua,
        metadata={"token_type": "refresh", "family_id": rt.family_id},
    )
    return True