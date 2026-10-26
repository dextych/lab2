"""OAuth2 errors по RFC 6749."""

from __future__ import annotations

from fastapi import HTTPException


class OAuthError(HTTPException):
    """Ошибка OAuth2 с корректным JSON-телом."""

    def __init__(self, error: str, description: str | None = None, status_code: int = 400):
        body = {"error": error}
        if description:
            body["error_description"] = description
        super().__init__(status_code=status_code, detail=body)


# Сокращения для частых случаев
def invalid_request(msg: str) -> OAuthError:
    return OAuthError("invalid_request", msg, 400)


def invalid_client(msg: str = "Client authentication failed") -> OAuthError:
    return OAuthError("invalid_client", msg, 401)


def invalid_grant(msg: str) -> OAuthError:
    return OAuthError("invalid_grant", msg, 400)


def unauthorized_client(msg: str = "Client not authorized for this grant type") -> OAuthError:
    return OAuthError("unauthorized_client", msg, 400)


def unsupported_grant_type(msg: str) -> OAuthError:
    return OAuthError("unsupported_grant_type", msg, 400)


def invalid_scope(msg: str) -> OAuthError:
    return OAuthError("invalid_scope", msg, 400)


def server_error(msg: str = "Server error") -> OAuthError:
    return OAuthError("server_error", msg, 500)