"""Demo-RP: минимальное OIDC-приложение, логинящееся через Vault"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from demo_rp.config import rp_settings

app = FastAPI(title="Demo RP")
templates = Jinja2Templates(directory="demo_rp/templates")


# Утилиты PKCE

def generate_pkce() -> tuple[str, str]:
    """Возвращает (code_verifier, code_challenge)."""
    verifier = secrets.token_urlsafe(64)   # 64 байта ≈ 86 символов base64url
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


# Главная страница

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    access_token = request.cookies.get("access_token")
    email = request.cookies.get("email")

    if access_token and email:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "logged_in": True, "email": email},
        )
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "logged_in": False},
    )


# login

@app.get("/login")
async def login():
    # 1. Генерируем PKCE и state
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(32)

    # 2. Формируем URL /oauth/authorize
    params = {
        "response_type": "code",
        "client_id": rp_settings.client_id,
        "redirect_uri": f"{rp_settings.base_url}/callback",
        "scope": "openid email profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        # nonce для OIDC
        "nonce": secrets.token_urlsafe(16),
    }
    authorize_url = f"{rp_settings.issuer}/oauth/authorize?{urlencode(params)}"

    # 3. Сохраняем verifier и state в cookie, редиректим на Vault
    response = RedirectResponse(url=authorize_url, status_code=302)
    response.set_cookie("pkce_verifier", verifier, httponly=True, max_age=300)
    response.set_cookie("oauth_state", state, httponly=True, max_age=300)
    return response


# callback — обмен кода на токены

@app.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    # 1. Ошибка от Vault?
    if error:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": error, "description": request.query_params.get("error_description", "")},
        )

    # 2. Проверка state (CSRF)
    saved_state = request.cookies.get("oauth_state")
    if not state or state != saved_state:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "invalid_state", "description": "State не совпадает (CSRF?)"},
        )

    # 3. Проверка code
    if not code:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "no_code", "description": "Vault не вернул code"},
        )

    verifier = request.cookies.get("pkce_verifier")
    if not verifier:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "no_verifier", "description": "PKCE verifier не найден в cookie"},
        )

    # 4. Обмен кода на токены
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{rp_settings.base_url}/callback",
        "client_id": rp_settings.client_id,
        "code_verifier": verifier,
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{rp_settings.issuer}/oauth/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code != 200:
        error_body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"error": "unknown"}
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": error_body.get("error"), "description": error_body.get("error_description", "")},
        )

    tokens = resp.json()
    access_token = tokens["access_token"]
    id_token = tokens.get("id_token")

    # 5. Проверяем id_token (или получаем userinfo)
    # В учебном проекте — просто запрашиваем /oauth/userinfo
    async with httpx.AsyncClient() as client:
        userinfo_resp = await client.get(
            f"{rp_settings.issuer}/oauth/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if userinfo_resp.status_code != 200:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "error": "userinfo_failed", "description": userinfo_resp.text},
        )

    userinfo = userinfo_resp.json()
    email = userinfo.get("email") or userinfo.get("sub")

    # 6. Сохраняем в cookie и редиректим на главную
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie("access_token", access_token, httponly=True, max_age=900)
    response.set_cookie("email", email, httponly=True, max_age=900)
    response.delete_cookie("pkce_verifier")
    response.delete_cookie("oauth_state")
    return response


#logout

@app.post("/logout")
async def logout(request: Request):
    access_token = request.cookies.get("access_token")
    if access_token:
        # Отзываем токен
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{rp_settings.issuer}/oauth/revoke",
                data={"token": access_token, "client_id": rp_settings.client_id},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("access_token")
    response.delete_cookie("email")
    return response