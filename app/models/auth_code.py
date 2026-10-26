"""Модель одноразового authorization code."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuthCode(Base):
    __tablename__ = "auth_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # SHA-256 от opaque-кода
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    client_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # redirect_uri сверяется при обмене кода на токен
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)

    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # PKCE
    code_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    code_challenge_method: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # OIDC
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)

    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<AuthCode id={self.id} client={self.client_id!r} used={self.used_at is not None}>"