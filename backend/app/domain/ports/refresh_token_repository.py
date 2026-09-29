from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.entities.refresh_token import RefreshToken


class RefreshTokenRepository(ABC):
    @abstractmethod
    async def add(self, token: RefreshToken) -> None: ...

    @abstractmethod
    async def get_by_token_hash(self, token_hash: str) -> RefreshToken | None: ...

    @abstractmethod
    async def revoke(self, token_id: UUID, *, replaced_by_id: UUID | None = None) -> None:
        """Mark a single token as revoked (used on rotation and on logout)."""

    @abstractmethod
    async def revoke_all_for_user(self, user_id: UUID) -> None:
        """Revoke every active token for a user - used when reuse of an
        already-rotated token is detected, as a likely-theft response."""
