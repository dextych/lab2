from app.core.security.jwt_rsa import sign_access_token, verify_token


def main() -> None:
    token = sign_access_token(
        sub="alice@example.com",
        client_id="demo-client",
        scopes=["openid", "email"],
        ttl_sec=300,
    )
    print(f"Токен: {token[:80]}...")
    print()

    payload = verify_token(token)
    print("Payload:")
    for k, v in payload.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()