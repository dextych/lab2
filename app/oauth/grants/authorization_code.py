"""grant_type=authorization_code с проверкой PKCE."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Request
from sqlalchemy.orm import Session

from app.audit.service import extract_request_info, write_event
from app.config.config import settings
from app.core.security.pkce import PKCEError, verify_pkce
from app.core.security.tokens import generate_opaque_token, hash_token
from app.models import AuthCode, OAuthClient, RefreshToken, User, UserSession
from app.oauth.errors import invalid_grant, invalid_request, invalid_scope, unauthorized_client
from app.oauth.responses import build_token_response


def handle(
    *, db: Session, request: Request, client: OAuthClient,
    code: str | None, redirect_uri: str | None,
    code_verifier: str | None, scope: str | None,
) -> dict:
    if not code:
        raise invalid_request("code обязателен")
    if not redirect_uri:
        raise invalid_request("redirect_uri обязателен")

    # 1. Право на grant
    if "authorization_code" not in (client.grant_types or []):
        raise unauthorized_client("Клиент не поддерживает grant_type=authorization_code")

    # 2. Находим код по хэшу
    auth_code = (
        db.query(AuthCode)
        .filter(AuthCode.code_hash == hash_token(code))
        .first()
    )
    if auth_code is None:
        raise invalid_grant("Код не найден")

    # 3. Повторное использование?
    if auth_code.used_at is not None:
        write_event(
            db, "auth_code.reuse_detected",
            client_id=auth_code.client_id,
            metadata={"auth_code_id": auth_code.id},
        )
        raise invalid_grant("Код уже был использован")

    # 4. Срок
    if auth_code.expires_at < datetime.now(timezone.utc):
        raise invalid_grant("Код истёк")

    # 5. client_id совпадает
    if auth_code.client_id != client.client_id:
        raise invalid_grant("Код выдан другому клиенту")

    # 6. redirect_uri совпадает
    if auth_code.redirect_uri != redirect_uri:
        raise invalid_grant("redirect_uri не совпадает")

    # 7. PKCE
    if auth_code.code_challenge:
        if not code_verifier:
            raise invalid_grant("code_verifier обязателен")
        try:
            verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method or "S256")
        except PKCEError as e:
            raise invalid_grant(str(e))

    # 8. Пользователь
    user = db.query(User).filter(User.id == auth_code.user_id).first()
    if user is None or not user.is_active:
        raise invalid_grant("Пользователь не найден или деактивирован")

    # 9. Scope (сужение)
    final_scope = auth_code.scope.split() if not scope else scope.split()
    allowed = set(client.scopes or [])
    if not set(final_scope).issubset(allowed):
        raise invalid_scope(f"Разрешённые scopes: {sorted(allowed)}")

    # 10. Помечаем код использованным
    auth_code.used_at = datetime.now(timezone.utc)

    # 11. Выдаём refresh-токен
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

    # 12. UserSession
    ip, ua = extract_request_info(request)
    session = UserSession(
        user_id=user.id,
        client_id=client.client_id,
        family_id=family_id,
        ip=ip, user_agent=ua,
    )
    db.add(session)
    db.commit()

    # 13. Аудит
    write_event(
        db, "token.issued",
        actor_id=user.id, client_id=client.client_id,
        ip=ip, user_agent=ua,
        metadata={"grant_type": "authorization_code", "scope": " ".join(final_scope)},
    )

    # 14. ID token содержит nonce из auth_code
    return build_token_response(
        sub=user.email,
        client_id=client.client_id,
        scope=final_scope,
        refresh_token=refresh_str,
        user=user,
        nonce=auth_code.nonce,
        include_id_token=True,
    )