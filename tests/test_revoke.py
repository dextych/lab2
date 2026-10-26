"""Тесты /oauth/revoke и /oauth/introspect."""


def test_revoke_access_token_blocks_it(client, confidential_client):
    c, secret = confidential_client
    # Получаем токен
    r = client.post("/oauth/token", data={
        "grant_type": "password",
        "username": "test@example.com",
        "password": "correct-horse-battery",
        "scope": "openid",
        "client_id": c.client_id,
        "client_secret": secret,
    })
    access = r.json()["access_token"]

    # Проверяем, что работает
    r = client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200

    # Отзываем
    r = client.post("/oauth/revoke", data={
        "token": access,
        "client_id": c.client_id,
        "client_secret": secret,
    })
    assert r.status_code == 200

    # Больше не работает
    r = client.get("/oauth/userinfo", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401


def test_introspect_revoked_token(client, confidential_client):
    c, secret = confidential_client
    # Получаем и отзываем
    r = client.post("/oauth/token", data={
        "grant_type": "password",
        "username": "test@example.com",
        "password": "correct-horse-battery",
        "scope": "openid",
        "client_id": c.client_id,
        "client_secret": secret,
    })
    access = r.json()["access_token"]

    client.post("/oauth/revoke", data={
        "token": access,
        "client_id": c.client_id,
        "client_secret": secret,
    })

    # Introspect → не активен
    r = client.post("/oauth/introspect", data={
        "token": access,
        "client_id": c.client_id,
        "client_secret": secret,
    })
    assert r.status_code == 200
    assert r.json() == {"active": False}