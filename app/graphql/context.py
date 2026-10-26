from __future__ import annotations

from typing import Any
import asyncio
from starlette.requests import Request
from app.oauth.blacklist import is_blacklisted
from app.core.security.jwt_rsa import verify_token
from app.db import SessionLocal
from app.models import User


async def get_context_value(request, data):
    db = request.scope["db"]
    user = None

    # Извлекаем токен из заголовка (или из куки, если хочешь)
    auth = request.headers.get("authorization")
    token = None
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()

    if token:
        try:
            payload = verify_token(token)
            
            # Проверяем blacklist через await (так как мы в async def)
            jti = payload.get("jti")
            if jti and await is_blacklisted(jti):
                raise ValueError("Токен отозван")
                
            sub = payload.get("sub")
            if sub and payload.get("typ") == "access":
                candidate = db.query(User).filter(User.email == sub).first()
                if candidate and candidate.is_active:
                    user = candidate
        except ValueError:
            pass  # Токен битый или отозван — user остается None

    return {"request": request, "db": db, "user": user}