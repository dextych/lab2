"""POST /oauth/token — единый эндпоинт для всех grant-типов."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.oauth.client_auth import authenticate_client
from app.oauth.errors import invalid_request, unsupported_grant_type
from app.oauth.grants import (
    authorization_code as grant_auth_code,
    client_credentials as grant_client_creds,
    password as grant_password,
    refresh_token as grant_refresh,
)

router = APIRouter(tags=["oauth"])


@router.post("/oauth/token")
def token_endpoint(
    request: Request,
    grant_type: str = Form(...),
    client_id: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
    # authorization_code
    code: str | None = Form(default=None),
    redirect_uri: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    # password
    username: str | None = Form(default=None),
    password: str | None = Form(default=None),
    # refresh_token
    refresh_token: str | None = Form(default=None),
    # общее
    scope: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    # 1. Аутентифицируем клиента
    client = authenticate_client(request, db, client_id, client_secret)

    # 2. Ветвимся по grant_type
    if grant_type == "password":
        return grant_password.handle(
            db=db, request=request, client=client,
            username=username, password=password, scope=scope,
        )
    if grant_type == "authorization_code":
        return grant_auth_code.handle(
            db=db, request=request, client=client,
            code=code, redirect_uri=redirect_uri,
            code_verifier=code_verifier, scope=scope,
        )
    if grant_type == "refresh_token":
        return grant_refresh.handle(
            db=db, request=request, client=client,
            refresh_token=refresh_token, scope=scope,
        )
    if grant_type == "client_credentials":
        return grant_client_creds.handle(
            db=db, request=request, client=client, scope=scope,
        )

    raise unsupported_grant_type(f"grant_type={grant_type!r}")