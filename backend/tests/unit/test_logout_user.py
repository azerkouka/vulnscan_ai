from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.application.use_cases.logout_user import LogoutUserUseCase
from app.domain.entities.refresh_token import RefreshToken
from tests.unit.fakes import FakeTokenService, FakeUnitOfWork


@pytest.mark.unit
async def test_logout_revokes_an_active_token() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    raw_value = "refresh:abc"
    token = RefreshToken(
        id=uuid4(),
        user_id=uuid4(),
        token_hash=tokens.hash_refresh_token(raw_value),
        expires_at=datetime.now(UTC) + timedelta(days=7),
        revoked_at=None,
        replaced_by_id=None,
        created_at=datetime.now(UTC),
    )
    await uow.refresh_tokens.add(token)
    use_case = LogoutUserUseCase(uow, tokens)

    await use_case.execute(raw_value)

    assert uow.refresh_tokens.by_id[token.id].revoked_at is not None


@pytest.mark.unit
async def test_logout_with_unknown_token_is_a_no_op() -> None:
    uow = FakeUnitOfWork()
    use_case = LogoutUserUseCase(uow, FakeTokenService())

    # Should not raise.
    await use_case.execute("never-issued")
