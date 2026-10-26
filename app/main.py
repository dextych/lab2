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


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}