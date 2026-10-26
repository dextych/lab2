from datetime import datetime
from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_confidential: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False, server_default="[]")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # НОВЫЕ ПОЛЯ лр3
    hashed_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False, server_default='["openid"]')
    grant_types: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False, server_default='["authorization_code","refresh_token"]')
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<OAuthClient id={self.id} client_id={self.client_id!r}>"