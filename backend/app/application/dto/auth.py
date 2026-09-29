"""Data transfer objects for the auth use cases.

Plain dataclasses, not Pydantic - the application layer stays framework-free,
same as the domain. The API layer converts its Pydantic request/response
schemas to/from these at the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegisterUserInput:
    email: str
    password: str
    full_name: str | None = None


@dataclass(frozen=True, slots=True)
class RegisteredUser:
    id: UUID
    email: str
    full_name: str | None
    is_active: bool
    is_superuser: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class LoginUserInput:
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
