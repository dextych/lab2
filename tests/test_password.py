import pytest

from app.core.passwords import (
    WeakPasswordError,
    hash_password,
    validate_policy,
    verify_password,
)


class TestHashAndVerify:
    def test_hash_is_not_plaintext(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert "correct-horse-battery-staple" not in hashed

    def test_hash_has_argon2id_marker(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert hashed.startswith("$argon2id$")

    def test_verify_correct_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("wrong-password", hashed) is False

    def test_verify_broken_hash(self):
        assert verify_password("anything", "not-a-valid-argon2-hash") is False

    def test_same_password_gives_different_hashes(self):
        """Соль разная — значит и хэши разные."""
        h1 = hash_password("correct-horse-battery-staple")
        h2 = hash_password("correct-horse-battery-staple")
        assert h1 != h2
        assert verify_password("correct-horse-battery-staple", h1)
        assert verify_password("correct-horse-battery-staple", h2)


class TestValidatePolicy:
    def test_accepts_strong_password(self):
        validate_policy("Tr0ub4dor&3-correct-horse", user_inputs=["alice@example.com"])

    def test_rejects_short_password(self):
        with pytest.raises(WeakPasswordError) as exc_info:
            validate_policy("Short1!", user_inputs=[])
        assert "минимум" in str(exc_info.value).lower()

    def test_rejects_weak_password(self):
        with pytest.raises(WeakPasswordError) as exc_info:
            validate_policy("password1234", user_inputs=[])
        assert exc_info.value.score is not None
        assert exc_info.value.score < 3

    def test_rejects_password_matching_email(self):
        with pytest.raises(WeakPasswordError):
            validate_policy("alice@example.com", user_inputs=["alice@example.com"])