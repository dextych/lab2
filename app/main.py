from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.auth.router import router as auth_router
from app.config.config import settings
from app.graphql.schema import graphql_app

app = FastAPI(title=settings.app_name, debug=settings.debug)

app.include_router(auth_router)
app.mount("/graphql", graphql_app)

# Статика админки
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/admin", StaticFiles(directory=STATIC_DIR, html=True), name="admin")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}