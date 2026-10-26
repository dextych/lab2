import redis.asyncio as redis

from app.config.config import settings

redis_client = redis.from_url(
    settings.redis_url,
    encoding="utf-8",
    decode_responses=True,
)