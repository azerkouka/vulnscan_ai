from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.user import User
from app.domain.ports.user_repository import UserRepository
from app.infrastructure.persistence.models import UserModel


def _to_domain(model: UserModel) -> User:
    return User(
        id=model.id,
        email=model.email,
        hashed_password=model.hashed_password,
        full_name=model.full_name,
        is_active=model.is_active,
        is_superuser=model.is_superuser,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _to_model(user: User) -> UserModel:
    return UserModel(
        id=user.id,
        email=user.email,
        hashed_password=user.hashed_password,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
    )


class SqlAlchemyUserRepository(UserRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, user_id: UUID) -> User | None:
        model = await self._session.get(UserModel, user_id)
        return _to_domain(model) if model else None

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(UserModel).where(UserModel.email == email)
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_domain(model) if model else None

    async def add(self, user: User) -> None:
        self._session.add(_to_model(user))
