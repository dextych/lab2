"""GET /oauth/authorize — authorization code flow с экраном согласия."""

from __future__ import annotations

from urllib.parse import urlencode
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import json
import secrets
import redis.asyncio as redis
from urllib.parse import urlencode, quote
from app.config.config import settings
from app.db import get_db
from app.models import OAuthClient, User, WebSession
from app.web.deps import get_current_web_user

router = APIRouter(tags=["oauth"])
redis_client = redis.from_url(settings.redis_url, decode_responses=True)

@router.get("/oauth/authorize")
async def authorize(
    request: Request,
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query(default="openid"),
    state: str = Query(...),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
    nonce: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    if response_type != "code":
        raise HTTPException(400, "response_type должен быть 'code'")

    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if not client or not client.is_active:
        raise HTTPException(400, {"error": "invalid_client", "error_description": "Клиент не найден"})

    if redirect_uri not in client.redirect_uris:
        raise HTTPException(400, {"error": "invalid_request", "error_description": "redirect_uri не разрешён"})

    # Проверяем, залогинен ли юзер через ВЕБ-СЕССИЮ (Куку)
    session_id = request.session.get("session_id")
    user = None
    if session_id:
        ws = db.query(WebSession).filter(WebSession.session_id == session_id, WebSession.revoked_at.is_(None)).first()
        if ws:
            user = ws.user

    # Если НЕ залогинен — отправляем на страницу логина и запоминаем, куда вернуться
    if not user:
        # Сохраняем текущий URL (со всеми параметрами), чтобы вернуться после логина
        current_url = str(request.url)
        login_url = f"/web/login?next={quote(current_url)}"
        return RedirectResponse(url=login_url, status_code=303)

    # Если залогинен — сохраняем параметры в Redis (TTL 5 минут)
    pending_id = secrets.token_urlsafe(32)
    pending_data = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "nonce": nonce,
        "user_id": user.id
    }
    
    await redis_client.setex(f"consent:{pending_id}", 300, json.dumps(pending_data))

    # Перекидываем на экран согласия
    return RedirectResponse(url=f"/web/consent?request_id={pending_id}", status_code=303)