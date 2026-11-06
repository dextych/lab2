from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from app.oauth.errors import OAuthError
from app.auth.router import router as auth_router
from app.config.config import settings
from app.graphql.schema import graphql_app
from app.oauth.router import router as oauth_router
from app.oauth.discovery import router as discovery_router
from app.oauth.jwks import router as jwks_router
from starlette.middleware.sessions import SessionMiddleware
from fastapi.templating import Jinja2Templates
from app.web.csrf import get_csrf_token
from app.web.deps import get_current_web_user
from app.web.router import router as web_router
from app.web.consent import router as consent_router
from app.web.admin_router import router as admin_web_router;

app = FastAPI(title=settings.app_name, debug=settings.debug)

@app.exception_handler(OAuthError)
async def oauth_error_handler(request, exc: OAuthError):
    return JSONResponse(status_code=exc.status_code, content=exc.detail)

app.include_router(oauth_router)
app.include_router(auth_router)
app.mount("/graphql", graphql_app)

# Статика админки
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/admin", StaticFiles(directory=STATIC_DIR, html=True), name="admin")

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_ttl_min * 60,
    https_only=False, # в проде поставить True
    same_site="lax"
)

app.include_router(web_router)
app.include_router(consent_router)
app.include_router(admin_web_router)

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}