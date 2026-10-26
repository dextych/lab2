"""Тесты PKCE: S256, plain, ошибочные случаи."""

import pytest

from app.core.security.pkce import (
    PKCEError,
    compute_challenge,
    verify_pkce,
)

# Пример из RFC 7636, Appendix B
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class TestComputeChallenge:
    def test_s256_rfc_example(self):
        assert compute_challenge(RFC_VERIFIER, "S256") == RFC_CHALLENGE

    def test_plain_returns_verifier(self):
        assert compute_challenge("abc123", "plain") == "abc123"

    def test_unknown_method_raises(self):
        with pytest.raises(PKCEError, match="Unsupported"):
            compute_challenge("abc", "MD5")


class TestVerifyPKCE:
    def test_s256_correct(self):
        assert verify_pkce(RFC_VERIFIER, RFC_CHALLENGE, "S256") is True

    def test_s256_wrong_verifier(self):
        wrong = "x" * 43
        with pytest.raises(PKCEError, match="не соответствует"):
            verify_pkce(wrong, RFC_CHALLENGE, "S256")

    def test_plain_correct(self):
        verif = "a" * 44;
        assert verify_pkce(verif, verif, "plain") is True

    def test_plain_wrong(self):
        verifier = "a" * 43
        challenge = "b" * 43   # не совпадает
        with pytest.raises(PKCEError, match="не соответствует"):
            verify_pkce(verifier, challenge, "plain")

    def test_empty_verifier(self):
        with pytest.raises(PKCEError, match="обязателен"):
            verify_pkce("", RFC_CHALLENGE, "S256")

    def test_verifier_too_short(self):
        short = "a" * 42
        with pytest.raises(PKCEError, match="43"):
            verify_pkce(short, RFC_CHALLENGE, "S256")

    def test_verifier_too_long(self):
        long = "a" * 129
        with pytest.raises(PKCEError, match="128"):
            verify_pkce(long, RFC_CHALLENGE, "S256")

    def test_unknown_method(self):
        with pytest.raises(PKCEError, match="Unsupported"):
            verify_pkce(RFC_VERIFIER, RFC_CHALLENGE, "MD5")