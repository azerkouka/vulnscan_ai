import pytest

from app.application.use_cases.get_current_user import GetCurrentUserUseCase
from app.domain.exceptions import InvalidCredentialsError
from tests.unit.fakes import FakeTokenService, FakeUnitOfWork
from tests.unit.helpers import make_user


@pytest.mark.unit
async def test_valid_token_resolves_to_its_user() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    user = make_user()
    await uow.users.add(user)
    token = tokens.create_access_token(user.id)
    use_case = GetCurrentUserUseCase(uow, tokens)

    resolved = await use_case.execute(token)

    assert resolved.id == user.id


@pytest.mark.unit
async def test_unknown_token_is_rejected() -> None:
    use_case = GetCurrentUserUseCase(FakeUnitOfWork(), FakeTokenService())

    with pytest.raises(InvalidCredentialsError):
        await use_case.execute("not-a-real-token")


@pytest.mark.unit
async def test_inactive_user_is_rejected() -> None:
    uow = FakeUnitOfWork()
    tokens = FakeTokenService()
    user = make_user(is_active=False)
    await uow.users.add(user)
    token = tokens.create_access_token(user.id)
    use_case = GetCurrentUserUseCase(uow, tokens)

    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(token)
