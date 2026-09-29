"""The RefreshToken entity.

Stores only the *hash* of the opaque refresh token value - the raw value is
handed to the client once and never persisted, so a stolen database dump
cannot be replayed as a valid refresh token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RefreshToken:
    id: UUID
    user_id: UUID
    token_hash: str
    expires_at: datetime
    revoked_at: datetime | None
    replaced_by_id: UUID | None
    created_at: datetime

    @property
    def is_active(self) -> bool:
        """True if this token has neither been revoked nor expired."""
        return self.revoked_at is None and self.expires_at > datetime.now(UTC)
