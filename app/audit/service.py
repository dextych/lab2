from __future__ import annotations
from typing import Any
from sqlalchemy.orm import Session
from app.models import AuditEvent
from fastapi import Request


def write_event(
    db: Session,
    event_type: str,
    *,
    actor_id: int | None = None,
    client_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:

    event = AuditEvent(
        event_type=event_type,
        actor_id=actor_id,
        client_id=client_id,
        ip=ip,
        user_agent=user_agent,
        metadata_json=metadata,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

def extract_request_info(request: Request) -> tuple[str | None, str | None]:
    """Достаёт IP и User-Agent из FastAPI Request. Возвращает (ip, user_agent)."""
    ip: str | None = None
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    elif request.client is not None:
        ip = request.client.host

    user_agent = request.headers.get("user-agent")
    return ip, user_agent