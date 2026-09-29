"""The User entity.

A plain, framework-free dataclass - no ORM, no Pydantic. Infrastructure maps
this to/from its own representations (SQLAlchemy models, API schemas).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class User:
    id: UUID
    email: str
    hashed_password: str
    full_name: str | None
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime
