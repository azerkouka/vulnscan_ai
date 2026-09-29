from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.refresh_token import RefreshToken
from app.infrastructure.persistence.repositories.refresh_token_repository import (
    SqlAlchemyRefreshTokenRepository,
)
from app.infrastructure.persistence.repositories.user_repository import SqlAlchemyUserRepository
from tests.unit.helpers import make_user


@pytest.mark.integration
async def test_user_repository_add_and_get_by_email(db_session: AsyncSession) -> None:
    repo = SqlAlchemyUserRepository(db_session)
    user = make_user(email="integration@example.com")

    await repo.add(user)
    await db_session.flush()

    found = await repo.get_by_email("integration@example.com")
    assert found is not None
    assert found.id == user.id


@pytest.mark.integration
async def test_user_repository_get_by_id_returns_none_when_missing(
    db_session: AsyncSession,
) -> None:
    repo = SqlAlchemyUserRepository(db_session)

    assert await repo.get_by_id(uuid4()) is None


@pytest.mark.integration
async def test_user_repository_enforces_unique_email(db_session: AsyncSession) -> None:
    repo = SqlAlchemyUserRepository(db_session)
    await repo.add(make_user(email="dup@example.com"))
    await db_session.flush()

    await repo.add(make_user(email="dup@example.com"))
    with pytest.raises(IntegrityError):
        await db_session.flush()


@pytest.mark.integration
async def test_refresh_token_repository_round_trip_and_revoke(db_session: AsyncSession) -> None:
    users = SqlAlchemyUserRepository(db_session)
    tokens = SqlAlchemyRefreshTokenRepository(db_session)
    user = make_user(email="rt@example.com")
    await users.add(user)
    await db_session.flush()

    token = RefreshToken(
        id=uuid4(),
        user_id=user.id,
        token_hash="hash-abc",
        expires_at=datetime.now(UTC) + timedelta(days=1),
        revoked_at=None,
        replaced_by_id=None,
        created_at=datetime.now(UTC),
    )
    await tokens.add(token)
    await db_session.flush()

    found = await tokens.get_by_token_hash("hash-abc")
    assert found is not None
    assert found.user_id == user.id
    assert found.revoked_at is None

    await tokens.revoke(token.id)
    await db_session.flush()

    revoked = await tokens.get_by_token_hash("hash-abc")
    assert revoked is not None
    assert revoked.revoked_at is not None


@pytest.mark.integration
async def test_revoke_all_for_user_only_touches_that_users_active_tokens(
    db_session: AsyncSession,
) -> None:
    users = SqlAlchemyUserRepository(db_session)
    tokens = SqlAlchemyRefreshTokenRepository(db_session)
    user_a = make_user(email="a@example.com")
    user_b = make_user(email="b@example.com")
    await users.add(user_a)
    await users.add(user_b)
    await db_session.flush()

    def _new_token(user_id, hash_value):  # type: ignore[no-untyped-def]
        return RefreshToken(
            id=uuid4(),
            user_id=user_id,
            token_hash=hash_value,
            expires_at=datetime.now(UTC) + timedelta(days=1),
            revoked_at=None,
            replaced_by_id=None,
            created_at=datetime.now(UTC),
        )

    await tokens.add(_new_token(user_a.id, "a-active"))
    await tokens.add(_new_token(user_b.id, "b-active"))
    await db_session.flush()

    await tokens.revoke_all_for_user(user_a.id)
    await db_session.flush()

    a_token = await tokens.get_by_token_hash("a-active")
    b_token = await tokens.get_by_token_hash("b-active")
    assert a_token is not None and a_token.revoked_at is not None
    assert b_token is not None and b_token.revoked_at is None
