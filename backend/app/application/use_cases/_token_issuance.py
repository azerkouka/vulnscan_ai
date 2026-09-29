"""Shared helper for issuing a fresh access/refresh token pair.

Used by both `LoginUserUseCase` and `RefreshTokenUseCase` so the two stay in
sync on exactly how a token pair is minted and persisted.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.application.dto.auth import TokenPair
from app.domain.entities.refresh_token import RefreshToken
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork


async def issue_token_pair(
    uow: UnitOfWork, token_service: TokenService, user_id: UUID, refresh_ttl: timedelta
) -> tuple[TokenPair, UUID]:
    """Returns the token pair and the new refresh token's id (the latter is
    only needed by `RefreshTokenUseCase`, to link the rotation chain)."""
    access_token = token_service.create_access_token(user_id)
    refresh_value = token_service.generate_refresh_token()
    new_token_id = uuid4()

    now = datetime.now(UTC)
    await uow.refresh_tokens.add(
        RefreshToken(
            id=new_token_id,
            user_id=user_id,
            token_hash=token_service.hash_refresh_token(refresh_value),
            expires_at=now + refresh_ttl,
            revoked_at=None,
            replaced_by_id=None,
            created_at=now,
        )
    )
    return TokenPair(access_token=access_token, refresh_token=refresh_value), new_token_id
