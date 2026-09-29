from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.application.dto.auth import RegisteredUser, RegisterUserInput
from app.domain.entities.user import User
from app.domain.exceptions import EmailAlreadyRegisteredError
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.unit_of_work import UnitOfWork


class RegisterUserUseCase:
    def __init__(self, uow: UnitOfWork, password_hasher: PasswordHasher) -> None:
        self._uow = uow
        self._hasher = password_hasher

    async def execute(self, data: RegisterUserInput) -> RegisteredUser:
        email = data.email.strip().lower()

        async with self._uow:
            if await self._uow.users.get_by_email(email) is not None:
                raise EmailAlreadyRegisteredError(f"Email already registered: {email}")

            now = datetime.now(UTC)
            user = User(
                id=uuid4(),
                email=email,
                hashed_password=self._hasher.hash(data.password),
                full_name=data.full_name,
                is_active=True,
                is_superuser=False,
                created_at=now,
                updated_at=now,
            )
            await self._uow.users.add(user)
            await self._uow.commit()

        return RegisteredUser(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_superuser=user.is_superuser,
            created_at=user.created_at,
        )
