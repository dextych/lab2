from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid
from typing import Any
import secrets

from ariadne import MutationType, QueryType
from sqlalchemy import desc, or_
from app.audit.service import extract_request_info, write_event
from app.config.config import settings
from app.core.jwt import create_access_token
from app.core.passwords import (
    WeakPasswordError,
    hash_password,
    validate_policy,
)
from app.models import AuditEvent, OAuthClient, User, UserSession, RefreshToken

query = QueryType()
mutation = MutationType()


# Сериализация

def _serialize_user(user: User) -> dict[str, Any]:
    return {
        "id": str(user.id),
        "email": user.email,
        "isActive": user.is_active,
        "isAdmin": user.is_admin,
        "createdAt": user.created_at.isoformat(),
    }


def _serialize_client(client: OAuthClient) -> dict[str, Any]:
    return {
        "id": str(client.id),
        "clientId": client.client_id,
        "name": client.name,
        "isConfidential": client.is_confidential,
        "redirectUris": client.redirect_uris,
        "scopes": client.scopes,
        "grantTypes": client.grant_types,
        "isActive": client.is_active,
        "createdAt": client.created_at.isoformat(),
        "updatedAt": client.updated_at.isoformat(),
    }


def _serialize_event(event: AuditEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "eventType": event.event_type,
        "actorId": event.actor_id,
        "ip": event.ip,
        "userAgent": event.user_agent,
        "metadata": json.dumps(event.metadata_json, ensure_ascii=False) if event.metadata_json else None,
        "createdAt": event.created_at.isoformat(),
    }

def _serialize_session(s: UserSession) -> dict:
    return {
        "id": str(s.id),
        "clientId": s.client_id,
        "familyId": s.family_id,
        "ip": s.ip,
        "userAgent": s.user_agent,
        "createdAt": s.created_at.isoformat(),
        "lastSeenAt": s.last_seen_at.isoformat(),
        "revokedAt": s.revoked_at.isoformat() if s.revoked_at else None,
    }

def _serialize_refresh_token(rt: RefreshToken) -> dict:
    return {
        "id": str(rt.id),
        "jti": rt.jti,
        "familyId": rt.family_id,
        "clientId": rt.client_id,
        "scope": rt.scope,
        "expiresAt": rt.expires_at.isoformat(),
        "usedAt": rt.used_at.isoformat() if rt.used_at else None,
        "revokedAt": rt.revoked_at.isoformat() if rt.revoked_at else None,
        "createdAt": rt.created_at.isoformat(),
    }


# Query 

@query.field("me")
def resolve_me(_: Any, info: Any) -> dict[str, Any]:
    return _serialize_user(info.context["user"])


@query.field("users")
def resolve_users(
    _: Any,
    info: Any,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    db = info.context["db"]
    q = db.query(User)
    if search:
        q = q.filter(or_(User.email.ilike(f"%{search}%")))
    q = q.order_by(User.id).offset(offset).limit(limit)
    return [_serialize_user(u) for u in q.all()]


@query.field("clients")
def resolve_clients(_: Any, info: Any) -> list[dict[str, Any]]:
    db = info.context["db"]
    return [_serialize_client(c) for c in db.query(OAuthClient).all()]


@query.field("auditEvents")
def resolve_audit_events(
    _: Any,
    info: Any,
    event_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    db = info.context["db"]
    q = db.query(AuditEvent)
    if event_type:
        q = q.filter(AuditEvent.event_type == event_type)
    q = q.order_by(desc(AuditEvent.created_at)).offset(offset).limit(limit)
    return [_serialize_event(e) for e in q.all()]


# Mutation

@mutation.field("registerUser")
def resolve_register_user(
    _: Any,
    info: Any,
    email: str,
    password: str,
) -> dict[str, Any]:
    db = info.context["db"]
    request = info.context["request"]

    # 1. Email занят?
    if db.query(User).filter(User.email == email).first():
        raise Exception("Email уже зарегистрирован")

    # 2. Политика пароля
    try:
        validate_policy(password, user_inputs=[email])
    except WeakPasswordError as exc:
        raise Exception(str(exc)) from exc

    # 3. Создаём пользователя
    user = User(
        email=email,
        hashed_password=hash_password(password),
        is_active=True,
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # 4. Аудит
    ip, ua = extract_request_info(request)
    write_event(
        db,
        "user.created",
        actor_id=user.id,
        ip=ip,
        user_agent=ua,
        metadata={"email": user.email},
    )

    # 5. Токен
    token = create_access_token(
        sub=user.email,
        ttl_min=settings.jwt_access_token_expire_minutes,
    )
    return {"accessToken": token, "tokenType": "bearer"}


@mutation.field("createClient")
def resolve_create_client(
    _,
    info,
    name: str,
    isConfidential: bool = True,
    scopes: list[str] | None = None,
    grantTypes: list[str] | None = None,
    redirectUris: list[str] | None = None,
) -> dict:
    db = info.context["db"]
    request = info.context["request"]
    admin = info.context["user"]

    from app.core.passwords import hash_password

    client_secret = None
    hashed_secret = None

    if isConfidential:
        # Секрет генерируется один раз и возвращается пользователю
        client_secret = secrets.token_urlsafe(48)
        hashed_secret = hash_password(client_secret)

    client = OAuthClient(
        client_id=secrets.token_urlsafe(24),
        name=name,
        is_confidential=isConfidential,
        redirect_uris=redirectUris or [],
        scopes=scopes or ["openid"],
        grant_types=grantTypes or ["authorization_code", "refresh_token"],
        hashed_secret=hashed_secret,
        is_active=True,
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    ip, ua = extract_request_info(request)
    write_event(
        db,
        "client.created",
        actor_id=admin.id,
        client_id=client.client_id,
        ip=ip,
        user_agent=ua,
        metadata={"name": client.name, "is_confidential": isConfidential},
    )

    return {
        "clientId": client.client_id,
        "clientSecret": client_secret,   # показывается ОДИН раз
    }


@mutation.field("disableUser")
def resolve_disable_user(
    _: Any,
    info: Any,
    userId: int,
) -> dict[str, Any]:
    db = info.context["db"]
    request = info.context["request"]
    admin = info.context["user"]

    target = db.query(User).filter(User.id == userId).first()
    if target is None:
        raise Exception("Пользователь не найден")

    target.is_active = False
    db.commit()
    db.refresh(target)

    ip, ua = extract_request_info(request)
    write_event(
        db,
        "user.disabled",
        actor_id=admin.id,
        ip=ip,
        user_agent=ua,
        metadata={"target_user_id": target.id, "target_email": target.email},
    )

    return _serialize_user(target)

@query.field("sessions")
def resolve_sessions(_, info, userId: str | None = None) -> list[dict]:
    db = info.context["db"]
    q = db.query(UserSession)
    if userId is not None:
        q = q.filter(UserSession.user_id == int(userId))
    q = q.order_by(UserSession.created_at.desc())
    return [_serialize_session(s) for s in q.all()]

@query.field("refreshTokens")
def resolve_refresh_tokens(_, info, userId: str | None = None) -> list[dict]:
    db = info.context["db"]
    q = db.query(RefreshToken)
    if userId is not None:
        q = q.filter(RefreshToken.user_id == int(userId))
    q = q.order_by(RefreshToken.created_at.desc())
    return [_serialize_refresh_token(rt) for rt in q.all()]

@mutation.field("revokeUserSessions")
def resolve_revoke_user_sessions(_, info, userId: str) -> int:
    db = info.context["db"]
    request = info.context["request"]
    admin = info.context["user"]

    uid = int(userId)
    now = datetime.now(timezone.utc)

    # 1. Отзываем все активные refresh-токены пользователя
    refresh_count = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.user_id == uid,
            RefreshToken.revoked_at.is_(None),
        )
        .update({"revoked_at": now}, synchronize_session=False)
    )

    # 2. Отзываем все активные сессии пользователя
    session_count = (
        db.query(UserSession)
        .filter(
            UserSession.user_id == uid,
            UserSession.revoked_at.is_(None),
        )
        .update({"revoked_at": now}, synchronize_session=False)
    )

    db.commit()

    # 3. Аудит
    ip, ua = extract_request_info(request)
    write_event(
        db, "session.revoked",
        actor_id=admin.id, ip=ip, user_agent=ua,
        metadata={
            "target_user_id": uid,
            "refresh_tokens_revoked": refresh_count,
            "sessions_revoked": session_count,
        },
    )

    return session_count

@mutation.field("rotateClientSecret")
def resolve_rotate_client_secret(_, info, clientId: str) -> dict:
    db = info.context["db"]
    request = info.context["request"]
    admin = info.context["user"]

    client = (
        db.query(OAuthClient)
        .filter(OAuthClient.client_id == clientId)
        .first()
    )
    if client is None:
        raise Exception("Клиент не найден")

    if not client.is_confidential:
        raise Exception("Ротация секрета доступна только для конфиденциальных клиентов")

    # 1. Генерируем новый секрет
    new_secret = secrets.token_urlsafe(48)

    # 2. Хэшируем и сохраняем
    client.hashed_secret = hash_password(new_secret)
    db.commit()

    # 3. Аудит
    ip, ua = extract_request_info(request)
    write_event(
        db, "client.secret_rotated",
        actor_id=admin.id, client_id=client.client_id,
        ip=ip, user_agent=ua,
        metadata={"name": client.name},
    )

    # 4. Возвращаем секрет ОДИН раз
    return {
        "clientId": client.client_id,
        "clientSecret": new_secret,
    }


@mutation.field("enableClient")
def resolve_enable_client(_, info, clientId: str) -> dict:
    return _set_client_active(info, clientId, True)


@mutation.field("disableClient")
def resolve_disable_client(_, info, clientId: str) -> dict:
    return _set_client_active(info, clientId, False)


def _set_client_active(info, clientId: str, active: bool) -> dict:
    db = info.context["db"]
    request = info.context["request"]
    admin = info.context["user"]

    client = (
        db.query(OAuthClient)
        .filter(OAuthClient.client_id == clientId)
        .first()
    )
    if client is None:
        raise Exception("Клиент не найден")

    client.is_active = active
    db.commit()
    db.refresh(client)

    ip, ua = extract_request_info(request)
    write_event(
        db,
        "client.enabled" if active else "client.disabled",
        actor_id=admin.id, client_id=client.client_id,
        ip=ip, user_agent=ua,
        metadata={"name": client.name},
    )

    return _serialize_client(client)