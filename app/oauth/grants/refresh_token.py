"""grant_type=refresh_token с ротацией и reuse detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Request
from sqlalchemy.orm import Session

from app.audit.service import extract_request_info, write_event
from app.config.config import settings
from app.core.security.tokens import generate_opaque_token, hash_token
from app.models import OAuthClient, RefreshToken, User, UserSession
from app.oauth.errors import invalid_grant, invalid_request, invalid_scope, unauthorized_client
from app.oauth.responses import build_token_response


def handle(
    *, db: Session, request: Request, client: OAuthClient,
    refresh_token: str | None, scope: str | None,
) -> dict:
    if not refresh_token:
        raise invalid_request("refresh_token обязателен")

    if "refresh_token" not in (client.grant_types or []):
        raise unauthorized_client("Клиент не поддерживает grant_type=refresh_token")

    # 1. Находим токен
    token = (
        db.query(RefreshToken)
        .filter(RefreshToken.token_hash == hash_token(refresh_token))
        .first()
    )
    if token is None:
        raise invalid_grant("Refresh-токен не найден")

    # 2. АТАКА: токен уже использован — отзываем всё семейство
    if token.used_at is not None:
        _revoke_family(db, token, request)
        raise invalid_grant("Refresh-токен уже был использован (reuse detected)")

    # 3. Отозван?
    if token.revoked_at is not None:
        raise invalid_grant("Refresh-токен отозван")

    # 4. Истёк?
    if token.expires_at < datetime.now(timezone.utc):
        raise invalid_grant("Refresh-токен истёк")

    # 5. client_id совпадает
    if token.client_id != client.client_id:
        raise invalid_grant("Токен выдан другому клиенту")

    # 6. Пользователь
    user = db.query(User).filter(User.id == token.user_id).first()
    if user is None or not user.is_active:
        raise invalid_grant("Пользователь не найден или деактивирован")

    # 7. Scope (можно только сузить)
    old_scope = token.scope.split()
    if scope:
        new_scope = scope.split()
        if not set(new_scope).issubset(set(old_scope)):
            raise invalid_scope("Нельзя расширить scope при refresh")
        final_scope = new_scope
    else:
        final_scope = old_scope

    # 8. Rotation: старый помечаем used, генерим новый в том же family
    now = datetime.now(timezone.utc)
    new_refresh_str = generate_opaque_token(48)
    new_hash = hash_token(new_refresh_str)

    token.used_at = now
    token.replaced_by_hash = new_hash

    new_token = RefreshToken(
        jti=uuid4().hex,
        family_id=token.family_id,
        token_hash=new_hash,
        user_id=user.id,
        client_id=client.client_id,
        scope=" ".join(final_scope),
        expires_at=now + timedelta(days=settings.refresh_token_ttl_days),
    )
    db.add(new_token)

    # 9. Обновляем last_seen_at у сессии
    session = (
        db.query(UserSession)
        .filter(UserSession.family_id == token.family_id)
        .first()
    )
    if session is not None and session.revoked_at is None:
        session.last_seen_at = now

    db.commit()

    ip, ua = extract_request_info(request)
    write_event(
        db, "token.refreshed",
        actor_id=user.id, client_id=client.client_id,
        ip=ip, user_agent=ua,
        metadata={
            "grant_type": "refresh_token",
            "family_id": token.family_id,
            "old_jti": token.jti,
        },
    )

    return build_token_response(
        sub=user.email,
        client_id=client.client_id,
        scope=final_scope,
        refresh_token=new_refresh_str,
        user=user,
        include_id_token=True,
    )


def _revoke_family(db: Session, token: RefreshToken, request: Request) -> None:
    """Отзывает всё семейство токенов и сессию."""
    now = datetime.now(timezone.utc)

    # Все refresh-токены семейства
    db.query(RefreshToken).filter(
        RefreshToken.family_id == token.family_id,
        RefreshToken.revoked_at.is_(None),
    ).update({"revoked_at": now})

    # Сессию
    db.query(UserSession).filter(
        UserSession.family_id == token.family_id,
        UserSession.revoked_at.is_(None),
    ).update({"revoked_at": now})

    db.commit()

    ip, ua = extract_request_info(request)
    write_event(
        db, "token.reuse_detected",
        actor_id=token.user_id, client_id=token.client_id,
        ip=ip, user_agent=ua,
        metadata={
            "family_id": token.family_id,
            "jti": token.jti,
            "reason": "refresh_token_reuse",
        },
    )