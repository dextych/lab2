from fastapi import APIRouter, Request, Form, Depends, HTTPException
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode
from sqlalchemy.orm import Session
import json, secrets
import redis.asyncio as redis
from datetime import datetime, timezone, timedelta

from app.config.config import settings
from app.db import get_db
from app.models import User, AuthCode, OAuthClient
from app.web.templates import templates
from app.web.csrf import get_csrf_token, verify_csrf
from app.core.security.tokens import generate_opaque_token, hash_token
from app.audit.service import extract_request_info, write_event
from app.web.deps import get_current_web_user

router = APIRouter(prefix="/web", tags=["web"])
redis_client = redis.from_url(settings.redis_url, decode_responses=True)

@router.get("/consent")
async def consent_page(request: Request, request_id: str, user: User | None = Depends(get_current_web_user)):
    if not user:
        return RedirectResponse("/web/login", status_code=303)

    data_str = await redis_client.get(f"consent:{request_id}")
    if not data_str:
        raise HTTPException(400, "Запрос на авторизацию истёк или не существует")
    
    data = json.loads(data_str)
    
    return templates.TemplateResponse("consent.html", {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "current_user": user,
        "request_id": request_id,
        "client_name": "Demo-RP", # В идеале взять из БД
        "scopes": data["scope"].split(),
    })

@router.post("/consent")
async def consent_action(
    request: Request,
    request_id: str = Form(...),
    decision: str = Form(...),
    csrf_token: str = Form(...),
    user: User | None = Depends(get_current_web_user),
    db: Session = Depends(get_db)
):
    if not user:
        return RedirectResponse("/web/login", status_code=303)
        
    verify_csrf(request, csrf_token)

    data_str = await redis_client.get(f"consent:{request_id}")
    if not data_str:
        raise HTTPException(400, "Запрос истёк")
    
    data = json.loads(data_str)
    await redis_client.delete(f"consent:{request_id}") # Удаляем, чтобы не использовали дважды

    redirect_uri = data["redirect_uri"]
    state = data["state"]

    # Если пользователь нажал "Отклонить"
    if decision == "deny":
        params = {"error": "access_denied", "state": state}
        return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=303)

    # Если "Разрешить" — генерируем AuthCode
    code = generate_opaque_token(48)
    auth_code = AuthCode(
        code_hash=hash_token(code),
        client_id=data["client_id"],
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=data["scope"],
        code_challenge=data["code_challenge"],
        code_challenge_method=data["code_challenge_method"],
        nonce=data["nonce"],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.auth_code_ttl_sec),
    )
    db.add(auth_code)
    db.commit()

    ip, ua = extract_request_info(request)
    write_event(db, "oauth.consent.granted", actor_id=user.id, client_id=data["client_id"], ip=ip, user_agent=ua, metadata={"scope": data["scope"]})

    params = {"code": code, "state": state}
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=303)