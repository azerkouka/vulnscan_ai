from datetime import timedelta

import pytest

from app.application.dto.auth import LoginUserInput
from app.application.use_cases.login_user import LoginUserUseCase
from app.domain.exceptions import InactiveUserError, InvalidCredentialsError
from tests.unit.fakes import FakePasswordHasher, FakeTokenService, FakeUnitOfWork
from tests.unit.helpers import make_user


@pytest.mark.unit
async def test_login_succeeds_with_correct_credentials() -> None:
    uow = FakeUnitOfWork()
    hasher = FakePasswordHasher()
    user = make_user(email="carol@example.com", hashed_password=hasher.hash("correct-horse"))
    await uow.users.add(user)
    tokens = FakeTokenService()
    use_case = LoginUserUseCase(uow, hasher, tokens, timedelta(days=7))

    result = await use_case.execute(
        LoginUserInput(email="carol@example.com", password="correct-horse")
    )

    assert result.access_token
    assert result.refresh_token
    stored_token = await uow.refresh_tokens.get_by_token_hash(
        tokens.hash_refresh_token(result.refresh_token)
    )
    assert stored_token is not None
    assert stored_token.user_id == user.id


@pytest.mark.unit
async def test_login_rejects_wrong_password() -> None:
    uow = FakeUnitOfWork()
    hasher = FakePasswordHasher()
    user = make_user(email="dave@example.com", hashed_password=hasher.hash("right-password"))
    await uow.users.add(user)
    use_case = LoginUserUseCase(uow, hasher, FakeTokenService(), timedelta(days=7))

    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(LoginUserInput(email="dave@example.com", password="wrong-password"))


@pytest.mark.unit
async def test_login_rejects_unknown_email() -> None:
    uow = FakeUnitOfWork()
    use_case = LoginUserUseCase(uow, FakePasswordHasher(), FakeTokenService(), timedelta(days=7))

    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(LoginUserInput(email="ghost@example.com", password="whatever123"))


@pytest.mark.unit
async def test_login_rejects_inactive_user() -> None:
    uow = FakeUnitOfWork()
    hasher = FakePasswordHasher()
    user = make_user(
        email="erin@example.com", hashed_password=hasher.hash("password123"), is_active=False
    )
    await uow.users.add(user)
    use_case = LoginUserUseCase(uow, hasher, FakeTokenService(), timedelta(days=7))

    with pytest.raises(InactiveUserError):
        await use_case.execute(LoginUserInput(email="erin@example.com", password="password123"))
