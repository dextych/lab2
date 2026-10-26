"""grant_type=client_credentials — только для конфиденциальных."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from app.audit.service import extract_request_info, write_event
from app.models import OAuthClient
from app.oauth.errors import invalid_scope, unauthorized_client
from app.oauth.responses import build_token_response


def handle(
    *, db: Session, request: Request, client: OAuthClient, scope: str | None,
) -> dict:
    # 1. Только конфиденциальные
    if not client.is_confidential or client.hashed_secret is None:
        raise unauthorized_client("client_credentials только для конфиденциальных клиентов")

    if "client_credentials" not in (client.grant_types or []):
        raise unauthorized_client("Клиент не поддерживает grant_type=client_credentials")

    # 2. Scope
    requested = (scope or "openid").split()
    allowed = set(client.scopes or [])
    if not set(requested).issubset(allowed):
        raise invalid_scope(f"Разрешённые scopes: {sorted(allowed)}")

    ip, ua = extract_request_info(request)
    write_event(
        db, "token.issued",
        client_id=client.client_id,
        ip=ip, user_agent=ua,
        metadata={"grant_type": "client_credentials", "scope": " ".join(requested)},
    )

    # 3. Только access_token, без refresh и id_token
    return build_token_response(
        sub=client.client_id,          # sub = client_id
        client_id=client.client_id,
        scope=requested,
        refresh_token=None,            # НЕ выдаём
        include_id_token=False,        # НЕ выдаём
    )