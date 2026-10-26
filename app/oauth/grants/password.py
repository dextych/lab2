"""grant_type=password."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse  # <--- ДОБАВЛЕНО
from sqlalchemy.orm import Session

from app.audit.service import extract_request_info, write_event
from app.config.config import settings
from app.core.passwords import verify_password
from app.core.security.tokens import generate_opaque_token, hash_token
from app.models import OAuthClient, RefreshToken, User, UserSession
from app.oauth.errors import invalid_grant, invalid_request, invalid_scope, unauthorized_client
from app.oauth.responses import build_token_response


def handle(
    *, db: Session, request: Request, client: OAuthClient,
    username: str | None, password: str | None, scope: str | None,
) -> dict:
    if not username or not password:
        raise invalid_request("username и password обязательны")

    # 1. Клиент имеет право на grant password?
    if "password" not in (client.grant_types or []):
        raise unauthorized_client("Клиент не поддерживает grant_type=password")

    # 2. Проверяем пользователя
    user = db.query(User).filter(User.email == username).first()
    if user is None or not verify_password(password, user.hashed_password):
        ip, ua = extract_request_info(request)
        write_event(
            db, "user.login.failure",
            actor_id=user.id if user else None,
            client_id=client.client_id,
            ip=ip, user_agent=ua,
            metadata={"email": username, "grant_type": "password"},
        )
        raise invalid_grant("Неверный email или пароль")

    if not user.is_active:
        raise invalid_grant("Пользователь деактивирован")

    # 3. Определяем scope (сужение разрешено)
    requested = (scope or "openid").split()
    allowed = set(client.scopes or [])
    if not set(requested).issubset(allowed):
        raise invalid_scope(f"Разрешённые scopes: {sorted(allowed)}")
    final_scope = requested

    # 4. Выдаём refresh-токен
    family_id = uuid4().hex
    refresh_str = generate_opaque_token(48)
    refresh = RefreshToken(
        jti=uuid4().hex,
        family_id=family_id,
        token_hash=hash_token(refresh_str),
        user_id=user.id,
        client_id=client.client_id,
        scope=" ".join(final_scope),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_ttl_days),
    )
    db.add(refresh)

    # 5. Создаём UserSession
    ip, ua = extract_request_info(request)
    session = UserSession(
        user_id=user.id,
        client_id=client.client_id,
        family_id=family_id,
        ip=ip, user_agent=ua,
    )
    db.add(session)
    db.commit()

    # 6. Аудит
    write_event(
        db, "token.issued",
        actor_id=user.id, client_id=client.client_id,
        ip=ip, user_agent=ua,
        metadata={"grant_type": "password", "scope": " ".join(final_scope)},
    )

    # 7. Получаем данные ответа
    response_data = build_token_response(
        sub=user.email,
        client_id=client.client_id,
        scope=final_scope,
        refresh_token=refresh_str,
        user=user,
        include_id_token=True,
    )

    # 8. Записываем access_token в куку для работы Demo-RP
    response = JSONResponse(content=response_data)
    response.set_cookie(
        key="access_token", 
        value=response_data["access_token"], 
        httponly=True, 
        max_age=settings.access_token_ttl_sec,
        samesite="lax"
    )
    return response