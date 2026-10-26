"""Blacklist отозванных access-токенов в Redis."""

from __future__ import annotations

from datetime import datetime, timezone

from app.redis_client import redis_client


async def blacklist_jti(jti: str, exp: int) -> None:
    now = int(datetime.now(timezone.utc).timestamp())
    ttl = exp - now
    if ttl <= 0:
        # токен уже истёк — в blacklist не нужен
        return
    await redis_client.setex(f"revoked:jti:{jti}", ttl, "1")


async def is_blacklisted(jti: str) -> bool:
    """Проверяет, есть ли jti в blacklist."""
    return await redis_client.exists(f"revoked:jti:{jti}") > 0