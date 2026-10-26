from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class RPSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Vault (OIDC provider)
    issuer: str = "http://127.0.0.1:8080"
    client_id: str = Field(default="", validation_alias="DEMO_RP_CLIENT_ID")
    client_secret: str = ""   # пустой для публичного клиента

    # Demo-RP
    base_url: str = "http://127.0.0.1:8001"
    session_secret: str = "demo-rp-session-secret-change-me"


rp_settings = RPSettings()