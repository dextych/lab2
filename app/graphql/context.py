from __future__ import annotations

from typing import Any

from starlette.requests import Request

from app.core.jwt import decode_token
from app.db import SessionLocal
from app.models import User


def get_context_value(request: Request, _data: dict[str, Any]) -> dict[str, Any]:
    """
    Создаёт контекст для резолверов:
      - db: сессия SQLAlchemy
      - request: starlette Request
      - user: текущий пользователь или None
    """
    db = request.scope["db"]
    user: User | None = None

    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        try:
            payload = decode_token(token)
            sub = payload.get("sub")
            if sub and payload.get("typ") == "access":
                candidate = db.query(User).filter(User.email == sub).first()
                if candidate is not None and candidate.is_active:
                    user = candidate
        except ValueError:
            # Битый / просроченный токен — просто user=None, директивы сами решат
            pass

    return {"request": request, "db": db, "user": user}