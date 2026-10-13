from __future__ import annotations

import json
import uuid
from typing import Any

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
from app.models import AuditEvent, OAuthClient, User

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
        "createdAt": client.created_at.isoformat(),
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
    _: Any,
    info: Any,
    name: str,
    isConfidential: bool = True,
) -> dict[str, Any]:
    db = info.context["db"]
    request = info.context["request"]
    admin = info.context["user"]

    client = OAuthClient(
        client_id=uuid.uuid4().hex,
        name=name,
        is_confidential=isConfidential,
        redirect_uris=[],
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
        metadata={"name": client.name},
    )

    return _serialize_client(client)


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