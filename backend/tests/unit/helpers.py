"""Small builders for domain entities, so use-case tests don't repeat
boilerplate field lists.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.domain.entities.user import User


def make_user(
    *,
    user_id: UUID | None = None,
    email: str = "user@example.com",
    hashed_password: str = "hashed:password123",  # noqa: S107 - fixture data, not a real secret
    full_name: str | None = None,
    is_active: bool = True,
    is_superuser: bool = False,
) -> User:
    now = datetime.now(UTC)
    return User(
        id=user_id or uuid4(),
        email=email,
        hashed_password=hashed_password,
        full_name=full_name,
        is_active=is_active,
        is_superuser=is_superuser,
        created_at=now,
        updated_at=now,
    )
