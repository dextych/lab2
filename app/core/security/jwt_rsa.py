# RS256 JWT: подпись приватным ключом, проверка публичным

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt

from app.config.config import settings


# Ключи

_private_key: rsa.RSAPrivateKey | None = None
_public_key: rsa.RSAPublicKey | None = None


def _get_private_key() -> rsa.RSAPrivateKey:
    global _private_key
    if _private_key is None:
        path = Path(settings.rsa_key_path)
        if not path.exists():
            raise RuntimeError(
                f"Приватный ключ не найден: {path}. "
            )
        pem = path.read_bytes()
        _private_key = serialization.load_pem_private_key(pem, password=None)
    return _private_key


def _get_public_key() -> rsa.RSAPublicKey:
    global _public_key
    if _public_key is None:
        # публичная часть всегда извлекается из приватного ключа
        _public_key = _get_private_key().public_key()
    return _public_key


def load_private_key() -> str:
    #Возвращает приватный ключ в PEM-строке (для python-jose)
    return _get_private_key().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def load_public_key() -> str:
    #Возвращает публичный ключ в PEM-строке (для python-jose)
    return _get_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def get_public_key_object() -> rsa.RSAPublicKey:
    #Для JWKS-эндпоинта: возвращает объект ключа, а не PEM
    return _get_public_key()


# Токены

def sign_access_token(
    sub: str,
    client_id: str | None,
    scopes: list[str],
    ttl_sec: int,
) -> str:
    #Подписывает access-токен RS256
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": sub,
        "aud": client_id or "vault",
        "scope": " ".join(scopes),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_sec)).timestamp()),
        "jti": uuid.uuid4().hex,
        "typ": "access",
    }
    headers = {
        "alg": "RS256",
        "kid": settings.rsa_key_id,
        "typ": "JWT",
    }
    return jwt.encode(payload, load_private_key(), algorithm="RS256", headers=headers)


def sign_id_token(
    sub: str,
    client_id: str,
    nonce: str | None,
    user: Any,
    scopes: list[str],
    ttl_sec: int,
) -> str:
    #Подписывает OIDC ID Token
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": sub,
        "aud": client_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_sec)).timestamp()),
    }

    if nonce:
        payload["nonce"] = nonce

    # Стандартные OIDC-claim'ы по scope
    if "email" in scopes:
        payload["email"] = user.email
        payload["email_verified"] = True
    if "profile" in scopes:
        payload["preferred_username"] = user.email
        # name — если есть поле name в модели; если нет, можно пропустить

    headers = {
        "alg": "RS256",
        "kid": settings.rsa_key_id,
        "typ": "JWT",
    }
    return jwt.encode(payload, load_private_key(), algorithm="RS256", headers=headers)


def verify_token(token: str) -> dict[str, Any]:
    #Проверяет подпись RS256 по публичному ключу и возвращает payload
    try:
        return jwt.decode(
            token,
            load_public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False},  # audience проверяем вручную при необходимости
        )
    except JWTError as exc:
        raise ValueError(f"Невалидный токен: {exc}") from exc