"""GET /oauth/authorize — authorization code flow, первая половина."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit.service import extract_request_info, write_event
from app.config.config import settings
from app.core.security.tokens import generate_opaque_token, hash_token
from app.db import get_db
from app.models import AuthCode, OAuthClient, User

router = APIRouter(tags=["oauth"])


@router.get("/oauth/authorize")
def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="openid"),
    state: str = Query(...),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
    nonce: str | None = Query(default=None),
    access_token_cookie: str | None = Cookie(default=None, alias="access_token"), # <--- ДОБАВЛЕНО
    db: Session = Depends(get_db),
):
    ip, ua = extract_request_info(request)
    requested_scopes = scope.split()

    if response_type != "code":
        return _redirect_error(redirect_uri, state, "unsupported_response_type", "response_type не поддерживается")

    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if client is None or not client.is_active:
        write_event(db, "oauth.authorize.failure", client_id=client_id, ip=ip, user_agent=ua, metadata={"reason": "invalid_client"})
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Клиент не найден или неактивен"})

    if redirect_uri not in client.redirect_uris:
        write_event(db, "oauth.authorize.failure", client_id=client_id, ip=ip, user_agent=ua, metadata={"reason": "invalid_redirect_uri"})
        raise HTTPException(400, {"error": "invalid_request", "error_description": "redirect_uri не разрешён"})

    if not client.is_confidential and settings.pkce_required_for_public:
        if not code_challenge or code_challenge_method != "S256":
            return _redirect_error(redirect_uri, state, "invalid_request", "PKCE обязателен (S256)")

    allowed_scopes = set(client.scopes or [])
    if not set(requested_scopes).issubset(allowed_scopes):
        return _redirect_error(redirect_uri, state, "invalid_scope", f"Разрешённые scopes: {sorted(allowed_scopes)}")

    # <--- ИЗМЕНЕНО ЗДЕСЬ --->
    user = _get_current_user(request, db, access_token_cookie)
    if user is None:
        raise HTTPException(401, "Требуется авторизация: передайте Bearer access-токен или cookie")

    code = generate_opaque_token(48)
    auth_code = AuthCode(
        code_hash=hash_token(code),
        client_id=client.client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=" ".join(requested_scopes),
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.auth_code_ttl_sec),
    )
    db.add(auth_code)
    db.commit()

    write_event(
        db, "oauth.authorize.success", actor_id=user.id, client_id=client.client_id,
        ip=ip, user_agent=ua, metadata={"scope": " ".join(requested_scopes)},
    )

    params = {"code": code, "state": state}
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


def _redirect_error(redirect_uri: str, state: str, error: str, description: str) -> RedirectResponse:
    params = {"error": error, "error_description": description, "state": state}
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


def _get_current_user(request: Request, db: Session, cookie_token: str | None = None) -> User | None:
    # <--- ИЗМЕНЕНО ЗДЕСЬ: проверяем сначала заголовок, потом куку --->
    token = cookie_token
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        
    if not token:
        return None

    from app.core.security.jwt_rsa import verify_token
    try:
        payload = verify_token(token)
    except ValueError:
        return None

    if payload.get("typ") != "access":
        return None

    sub = payload.get("sub")
    if not sub:
        return None

    user = db.query(User).filter(User.email == sub).first()
    if user and user.is_active:
        return user
    return None