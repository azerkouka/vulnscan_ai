from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.refresh_token import RefreshTokenUseCase
from app.domain.entities.refresh_token import RefreshToken
from app.domain.exceptions import InactiveUserError, InvalidRefreshTokenError
from tests.unit.fakes import FakeTokenService, FakeUnitOfWork
from tests.unit.helpers import make_user


async def _seed_active_token(
    uow: FakeUnitOfWork, tokens: FakeTokenService, *, user_id: UUID, ttl_days: int = 7
) -> tuple[RefreshToken, str]:
    raw_value = f"refresh:{uuid4()}"
    tokens.next_refresh_value = raw_value
    token = RefreshToken(
        id=uuid4(),
        user_id=user_id,
        token_hash=tokens.hash_refresh_token(raw_value),
        expires_at=datetime.now(UTC) + timedelta(days=ttl_days),
        revoked_at=None,
        replaced_by_id=None,
        created_at=datetime.now(UTC),
    )
    await uow.refresh_tokens.add(token)
    tokens.next_refresh_value = None
    return token, raw_value


@pytest.mark.unit
async def test_refresh_rotates_token_and_revokes_old_one() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    user = make_user()
    await uow.users.add(user)
    old_token, raw_value = await _seed_active_token(uow, tokens, user_id=user.id)
    use_case = RefreshTokenUseCase(uow, tokens, timedelta(days=7))

    result = await use_case.execute(raw_value)

    assert result.refresh_token != raw_value
    old_after = uow.refresh_tokens.by_id[old_token.id]
    assert old_after.revoked_at is not None
    new_token = await uow.refresh_tokens.get_by_token_hash(
        tokens.hash_refresh_token(result.refresh_token)
    )
    assert new_token is not None
    assert old_after.replaced_by_id == new_token.id


@pytest.mark.unit
async def test_refresh_rejects_unknown_token() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    use_case = RefreshTokenUseCase(uow, tokens, timedelta(days=7))

    with pytest.raises(InvalidRefreshTokenError):
        await use_case.execute("never-issued")


@pytest.mark.unit
async def test_reusing_a_revoked_token_revokes_the_whole_family() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    user = make_user()
    await uow.users.add(user)
    old_token, raw_value = await _seed_active_token(uow, tokens, user_id=user.id)
    use_case = RefreshTokenUseCase(uow, tokens, timedelta(days=7))

    # Legitimate rotation.
    first_result = await use_case.execute(raw_value)

    # Attacker (or a buggy client) replays the now-rotated-away token.
    with pytest.raises(InvalidRefreshTokenError):
        await use_case.execute(raw_value)

    # The entire family - including the token issued by the first, legitimate
    # rotation - must now be dead.
    new_token = await uow.refresh_tokens.get_by_token_hash(
        tokens.hash_refresh_token(first_result.refresh_token)
    )
    assert new_token is not None
    assert new_token.revoked_at is not None


@pytest.mark.unit
async def test_refresh_rejects_expired_token() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    user = make_user()
    await uow.users.add(user)
    _, raw_value = await _seed_active_token(uow, tokens, user_id=user.id, ttl_days=-1)
    use_case = RefreshTokenUseCase(uow, tokens, timedelta(days=7))

    with pytest.raises(InvalidRefreshTokenError):
        await use_case.execute(raw_value)


@pytest.mark.unit
async def test_refresh_rejects_inactive_user() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    user = make_user(is_active=False)
    await uow.users.add(user)
    _, raw_value = await _seed_active_token(uow, tokens, user_id=user.id)
    use_case = RefreshTokenUseCase(uow, tokens, timedelta(days=7))

    with pytest.raises(InactiveUserError):
        await use_case.execute(raw_value)
