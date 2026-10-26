from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.schemas import Credentials, MeResponse, TokenResponse
from app.config.config import settings
from app.audit.service import write_event, extract_request_info
from app.core.deps import get_current_user
from app.core.security.jwt_rsa import sign_access_token
from app.core.passwords import (
    WeakPasswordError,
    hash_password,
    validate_policy,
    verify_password,
)
from app.db import get_db
from app.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=201)
def register(
    payload: Credentials,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    # email уже занят?
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email уже зарегистрирован.",
        )

    # политика пароля (передаём email как user_input)
    try:
        validate_policy(payload.password, user_inputs=[payload.email])
    except WeakPasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # создаём пользователя
    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        is_active=True,
        is_admin=False,
    )
    db.add(user)
    db.flush()  # получим user.id до commit

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

    # один коммит на всё
    db.commit()
    db.refresh(user)

    # токен
    token = sign_access_token(
        sub=user.email,
        client_id=None,
        scopes=["openid", "email", "profile"],
        ttl_sec=settings.access_token_ttl_sec,
    )
    return TokenResponse(access_token=token)


@router.post("/login", response_model=TokenResponse)
def login(
    payload: Credentials,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = db.query(User).filter(User.email == payload.email).first()
    ip, ua = extract_request_info(request)

    # 1. Неверный email или пароль
    if user is None or not verify_password(payload.password, user.hashed_password):
        write_event(
            db,
            "user.login.failure",
            actor_id=user.id if user else None,
            ip=ip,
            user_agent=ua,
            metadata={"email": payload.email},
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Деактивирован
    if not user.is_active:
        write_event(
            db,
            "user.login.failure",
            actor_id=user.id,
            ip=ip,
            user_agent=ua,
            metadata={"email": user.email, "reason": "inactive"},
        )
        raise HTTPException(status_code=403, detail="Аккаунт деактивирован.")

    # 3. Успех
    write_event(
        db,
        "user.login.success",
        actor_id=user.id,
        ip=ip,
        user_agent=ua,
        metadata={"email": user.email},
    )

    token = sign_access_token(
        sub=user.email,
        client_id=None,
        scopes=["openid", "email", "profile"],
        ttl_sec=settings.access_token_ttl_sec,
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=MeResponse)
def me(user: User = Depends(get_current_user)) -> MeResponse:
    return MeResponse(id=user.id, email=user.email, is_admin=user.is_admin)