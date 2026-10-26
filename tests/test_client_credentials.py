"""Тесты grant_type=client_credentials."""


def test_client_credentials_confidential_success(client, confidential_client):
    c, secret = confidential_client
    r = client.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": c.client_id,
        "client_secret": secret,
        "scope": "openid",
    })
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    assert "refresh_token" not in body
    assert "id_token" not in body


def test_client_credentials_public_rejected(client, public_client):
    r = client.post("/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": public_client.client_id,
        "scope": "openid",
    })
    assert r.status_code == 400
    assert r.json()["error"] == "unauthorized_client"