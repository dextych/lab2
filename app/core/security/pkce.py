#PKCE: проверка S256-челленджа по RFC 7636

from __future__ import annotations

import base64
import hashlib
import hmac


MIN_VERIFIER_LENGTH = 43
MAX_VERIFIER_LENGTH = 128


class PKCEError(ValueError):
    """Ошибка валидации PKCE."""
    pass


def compute_challenge(code_verifier: str, method: str = "S256") -> str:
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if method == "plain":
        return code_verifier
    raise PKCEError(f"Unsupported code_challenge_method: {method}")


def verify_pkce(
    code_verifier: str,
    code_challenge: str,
    method: str,
) -> bool:

    if not code_verifier:
        raise PKCEError("code_verifier обязателен")
    if not (MIN_VERIFIER_LENGTH <= len(code_verifier) <= MAX_VERIFIER_LENGTH):
        raise PKCEError(
            f"code_verifier должен быть {MIN_VERIFIER_LENGTH}–{MAX_VERIFIER_LENGTH} символов, "
            f"получено {len(code_verifier)}"
        )

    if method == "S256":
        expected = compute_challenge(code_verifier, "S256")
    elif method == "plain":
        expected = code_verifier
    else:
        raise PKCEError(f"Unsupported code_challenge_method: {method}")

    # constant-time comparison: защита от timing-атак
    if not hmac.compare_digest(expected, code_challenge):
        raise PKCEError("code_verifier не соответствует code_challenge")

    return True