"""Тесты /oauth/userinfo."""


def _login(client, confidential_client, scope):
    c, secret = confidential_client
    r = client.post("/oauth/token", data={
        "grant_type": "password",
        "username": "test@example.com",
        "password": "correct-horse-battery",
        "scope": scope,
        "client_id": c.client_id,
        "client_secret": secret,
    })
    return r.json()["access_token"]


def test_userinfo_returns_email_with_email_scope(client, confidential_client):
    access = _login(client, confidential_client, "openid email")
    r = client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == "test@example.com"
    assert body["email_verified"] is True


def test_userinfo_without_email_scope_hides_email(client, confidential_client):
    access = _login(client, confidential_client, "openid")
    r = client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200
    body = r.json()
    assert "email" not in body
    assert "sub" in body


def test_userinfo_requires_token(client):
    r = client.get("/oauth/userinfo")
    assert r.status_code == 401