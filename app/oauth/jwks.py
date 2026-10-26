from __future__ import annotations

from fastapi import APIRouter
from jose import jwk

from app.config.config import settings
from app.core.security.jwt_rsa import get_public_key_object

router = APIRouter(tags=["oauth"])


def build_jwks() -> dict:
    """Превращает публичный RSA-ключ в JWKS-документ."""
    public_key = get_public_key_object()

    # python-jose умеет извлекать n и e из объекта ключа
    from cryptography.hazmat.primitives import serialization

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    jwk_dict = jwk.construct(public_pem, algorithm="RS256").to_dict()
    jwk_dict["kid"] = settings.rsa_key_id
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"

    return {"keys": [jwk_dict]}


@router.get("/.well-known/jwks.json")
def jwks_endpoint() -> dict:
    return build_jwks()