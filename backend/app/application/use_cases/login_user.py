from __future__ import annotations

from datetime import timedelta

from app.application.dto.auth import LoginUserInput, TokenPair
from app.application.use_cases._token_issuance import issue_token_pair
from app.domain.exceptions import InactiveUserError, InvalidCredentialsError
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork


class LoginUserUseCase:
    def __init__(
        self,
        uow: UnitOfWork,
        password_hasher: PasswordHasher,
        token_service: TokenService,
        refresh_token_ttl: timedelta,
    ) -> None:
        self._uow = uow
        self._hasher = password_hasher
        self._tokens = token_service
        self._refresh_ttl = refresh_token_ttl

    async def execute(self, data: LoginUserInput) -> TokenPair:
        email = data.email.strip().lower()

        async with self._uow:
            user = await self._uow.users.get_by_email(email)
            if user is None or not self._hasher.verify(data.password, user.hashed_password):
                raise InvalidCredentialsError("Invalid email or password.")
            if not user.is_active:
                raise InactiveUserError("This account has been deactivated.")

            token_pair, _ = await issue_token_pair(
                self._uow, self._tokens, user.id, self._refresh_ttl
            )
            await self._uow.commit()

        return token_pair
