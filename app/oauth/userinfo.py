"""GET /oauth/userinfo — OIDC-профиль пользователя."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.security.jwt_rsa import verify_token
from app.db import get_db
from app.models import User
from app.oauth.blacklist import is_blacklisted

router = APIRouter(tags=["oauth"])
bearer_scheme = HTTPBearer(auto_error=False)


@router.get("/oauth/userinfo")
async def userinfo_endpoint(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
):
    if credentials is None:
        raise HTTPException(401, "Требуется Authorization: Bearer <access_token>")
    
    token = credentials.credentials

    # 2. Проверяем подпись и срок
    try:
        payload = verify_token(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=401,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    if payload.get("typ") != "access":
        raise HTTPException(
            status_code=401,
            detail="Неверный тип токена",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Проверяем blacklist
    jti = payload.get("jti")
    if jti and await is_blacklisted(jti):
        raise HTTPException(
            status_code=401,
            detail="Токен отозван",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Находим пользователя
    sub = payload.get("sub")
    if not sub:
        raise HTTPException(401, "В токене отсутствует sub")

    user = db.query(User).filter(User.email == sub).first()
    if user is None or not user.is_active:
        raise HTTPException(401, "Пользователь не найден или деактивирован")

    # 5. Формируем ответ по scope
    scopes = (payload.get("scope") or "").split()
    result: dict = {"sub": str(user.id)}

    if "email" in scopes:
        result["email"] = user.email
        result["email_verified"] = True
    if "profile" in scopes:
        result["preferred_username"] = user.email
        # Если у тебя есть поле name в модели User — добавь:
        # result["name"] = user.name
        result["updated_at"] = int(user.created_at.timestamp())

    return result