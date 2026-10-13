from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from zxcvbn import zxcvbn

from app.config.config import settings


class WeakPasswordError(Exception):

    def __init__(self, message: str, score: int | None = None) -> None:
        super().__init__(message)
        self.score = score


_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    peppered = password + settings.argon2_pepper
    return _hasher.hash(peppered)


def verify_password(password: str, hashed: str) -> bool:
    #проверяем соответствие хэшированному паролю
    peppered = password + settings.argon2_pepper
    try:
        return _hasher.verify(hashed, peppered)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_policy(password: str, user_inputs: list[str] | None = None) -> None:
    user_inputs = user_inputs or []

    if len(password) < settings.password_min_length:
        raise WeakPasswordError(
            f"Пароль должен содержать минимум {settings.password_min_length} символов."
        )

    result = zxcvbn(password, user_inputs=user_inputs)
    score: int = result["score"]

    if score < 3:
        feedback = result.get("feedback", {})
        warning = feedback.get("warning", "")
        suggestions = feedback.get("suggestions", [])
        parts = [warning, *suggestions]
        message = " ".join(p for p in parts if p).strip()
        if not message:
            message = "Пароль слишком слабый. Используйте более длинную фразу."
        raise WeakPasswordError(message, score=score)