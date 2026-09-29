from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.refresh_token import RefreshToken
from app.domain.ports.refresh_token_repository import RefreshTokenRepository
from app.infrastructure.persistence.models import RefreshTokenModel


def _to_domain(model: RefreshTokenModel) -> RefreshToken:
    return RefreshToken(
        id=model.id,
        user_id=model.user_id,
        token_hash=model.token_hash,
        expires_at=model.expires_at,
        revoked_at=model.revoked_at,
        replaced_by_id=model.replaced_by_id,
        created_at=model.created_at,
    )


def _to_model(token: RefreshToken) -> RefreshTokenModel:
    return RefreshTokenModel(
        id=token.id,
        user_id=token.user_id,
        token_hash=token.token_hash,
        expires_at=token.expires_at,
        revoked_at=token.revoked_at,
        replaced_by_id=token.replaced_by_id,
    )


class SqlAlchemyRefreshTokenRepository(RefreshTokenRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, token: RefreshToken) -> None:
        self._session.add(_to_model(token))

    async def get_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        stmt = select(RefreshTokenModel).where(RefreshTokenModel.token_hash == token_hash)
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_domain(model) if model else None

    async def revoke(self, token_id: UUID, *, replaced_by_id: UUID | None = None) -> None:
        stmt = (
            update(RefreshTokenModel)
            .where(RefreshTokenModel.id == token_id)
            .values(revoked_at=datetime.now(UTC), replaced_by_id=replaced_by_id)
        )
        await self._session.execute(stmt)

    async def revoke_all_for_user(self, user_id: UUID) -> None:
        stmt = (
            update(RefreshTokenModel)
            .where(
                RefreshTokenModel.user_id == user_id,
                RefreshTokenModel.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
        await self._session.execute(stmt)
