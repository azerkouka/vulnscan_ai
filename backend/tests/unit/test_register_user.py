import pytest

from app.application.dto.auth import RegisterUserInput
from app.application.use_cases.register_user import RegisterUserUseCase
from app.domain.exceptions import EmailAlreadyRegisteredError
from tests.unit.fakes import FakePasswordHasher, FakeUnitOfWork


@pytest.mark.unit
async def test_register_user_succeeds_and_hashes_password() -> None:
    uow = FakeUnitOfWork()
    use_case = RegisterUserUseCase(uow, FakePasswordHasher())

    result = await use_case.execute(
        RegisterUserInput(email="Alice@Example.com", password="s3cret-pass", full_name="Alice")
    )

    assert result.email == "alice@example.com"  # normalized to lowercase
    stored = await uow.users.get_by_email("alice@example.com")
    assert stored is not None
    assert stored.hashed_password != "s3cret-pass"
    assert uow.committed is True


@pytest.mark.unit
async def test_register_user_rejects_duplicate_email() -> None:
    uow = FakeUnitOfWork()
    use_case = RegisterUserUseCase(uow, FakePasswordHasher())
    await use_case.execute(RegisterUserInput(email="bob@example.com", password="password123"))

    with pytest.raises(EmailAlreadyRegisteredError):
        await use_case.execute(RegisterUserInput(email="bob@example.com", password="different-pw"))
