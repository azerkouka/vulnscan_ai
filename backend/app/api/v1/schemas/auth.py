from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.application.dto.auth import RegisteredUser, TokenPair
from app.domain.entities.user import User


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    @classmethod
    def from_dto(cls, dto: TokenPair) -> TokenResponse:
        return cls(
            access_token=dto.access_token,
            refresh_token=dto.refresh_token,
            token_type=dto.token_type,
        )


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: str
    full_name: str | None
    is_active: bool
    is_superuser: bool
    created_at: datetime

    @classmethod
    def from_dto(cls, dto: RegisteredUser) -> UserResponse:
        return cls(
            id=dto.id,
            email=dto.email,
            full_name=dto.full_name,
            is_active=dto.is_active,
            is_superuser=dto.is_superuser,
            created_at=dto.created_at,
        )

    @classmethod
    def from_user(cls, user: User) -> UserResponse:
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_superuser=user.is_superuser,
            created_at=user.created_at,
        )
