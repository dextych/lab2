from pathlib import Path

from ariadne import make_executable_schema, load_schema_from_path
from ariadne.asgi import GraphQL

from app.graphql.context import get_context_value
from app.graphql.directives import IsAdminDirective, IsAuthenticatedDirective
from app.graphql.resolvers import mutation, query
from starlette.types import ASGIApp, Receive, Scope, Send
from app.db import SessionLocal

# Загружаем SDL из файла
type_defs = load_schema_from_path(str(Path(__file__).parent / "schema.graphql"))

schema = make_executable_schema(
    type_defs,
    query,
    mutation,
    directives={
        "isAuthenticated": IsAuthenticatedDirective,
        "isAdmin": IsAdminDirective,
    },
)

class DBSessionMiddleware:
    """Создаёт одну сессию БД на HTTP-запрос и закрывает её после ответа."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        with SessionLocal() as db:
            scope["db"] = db
            await self.app(scope, receive, send)


graphql_app = DBSessionMiddleware(
    GraphQL(schema, context_value=get_context_value, debug=True)
)