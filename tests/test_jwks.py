"""Тесты JWKS и discovery."""


def test_jwks_returns_key(client):
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    body = r.json()
    assert "keys" in body
    assert len(body["keys"]) >= 1

    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


def test_discovery_document(client):
    r = client.get("/.well-known/openid-configuration")
    assert r.status_code == 200
    body = r.json()
    assert "issuer" in body
    assert body["jwks_uri"].endswith("/.well-known/jwks.json")
    assert body["token_endpoint"].endswith("/oauth/token")
    assert "S256" in body["code_challenge_methods_supported"]
    assert "RS256" in body["id_token_signing_alg_values_supported"]
    assert "openid" in body["scopes_supported"]


def test_access_token_verifiable_with_jwks_key(client, public_client):
    """Токен, подписанный Vault, проверяется ключом из JWKS."""
    from jose import jwt as jose_jwt

    # 1. Получаем токен через password grant (нужен конфиденциальный клиент)
    #    Но проще — подписать напрямую
    from app.core.security.jwt_rsa import sign_access_token

    token = sign_access_token(
        sub="alice@example.com",
        client_id=public_client.client_id,
        scopes=["openid"],
        ttl_sec=60,
    )

    # 2. Достаём JWKS
    r = client.get("/.well-known/jwks.json")
    jwk_key = r.json()["keys"][0]

    # 3. Проверяем подпись
    from jose import jwk as jose_jwk
    public_key = jose_jwk.construct(jwk_key, algorithm="RS256")
    payload = jose_jwt.decode(token, public_key, algorithms=["RS256"])

    assert payload["sub"] == "alice@example.com"