from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Password hashing
    argon2_pepper: str
    password_min_length: int = 12

    # App
    app_name: str = "GraphQL Auth Service"
    debug: bool = False

    redis_url: str = "redis://localhost:6379/0"

     # OAuth2 / OIDC
    issuer: str = "http://127.0.0.1:8000"
    rsa_key_path: str = "./keys/rsa_private.pem"
    rsa_key_id: str = "vault-key-1"
    access_token_ttl_sec: int = 900
    refresh_token_ttl_days: int = 30
    auth_code_ttl_sec: int = 60
    pkce_required_for_public: bool = True


settings = Settings()