#Утилиты для opaque-токенов: генерация, хэширование

from __future__ import annotations

import hashlib
import secrets


def generate_opaque_token(nbytes: int = 48) -> str:
    """Генерирует криптостойкую случайную строку (base64url)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 от opaque-токена. Используется для хранения в БД."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()