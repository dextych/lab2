from fastapi import APIRouter

from app.config.config import settings

router = APIRouter(tags=["oauth"])


@router.get("/.well-known/openid-configuration")
def discovery_endpoint() -> dict:
    issuer = settings.issuer.rstrip("/")
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth/authorize",
        "token_endpoint": f"{issuer}/oauth/token",
        "userinfo_endpoint": f"{issuer}/oauth/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "revocation_endpoint": f"{issuer}/oauth/revoke",
        "introspection_endpoint": f"{issuer}/oauth/introspect",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "password",
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "code_challenge_methods_supported": ["S256"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "subject_types_supported": ["public"],
    }