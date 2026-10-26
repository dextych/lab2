from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.oauth.blacklist import is_blacklisted
from app.core.security.jwt_rsa import verify_token
from app.db.db import get_db
from app.models import User
from app.redis_client import redis_client

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(401, "Требуется Authorization: Bearer <token>")

    token = credentials.credentials

    try:
        payload = verify_token(token)
    except ValueError as exc:
        raise HTTPException(401, str(exc))

    # Проверка типа
    if payload.get("typ") != "access":
        raise HTTPException(401, "Неверный тип токена")

    # Проверка blacklist
    jti = payload.get("jti")
    if jti:
        revoked = await redis_client.get(f"revoked:jti:{jti}")
        if revoked:
            raise HTTPException(401, "Токен отозван")
    if jti and await is_blacklisted(jti):
        raise HTTPException(401, "Токен отозван")

    sub = payload.get("sub")
    if not sub:
        raise HTTPException(401, "В токене отсутствует sub")

    user = db.query(User).filter(User.email == sub).first()
    if user is None:
        raise HTTPException(401, "Пользователь не найден")

    if not user.is_active:
        raise HTTPException(403, "Пользователь деактивирован")

    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(403, "Требуются права администратора")
    return user