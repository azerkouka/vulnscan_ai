from __future__ import annotations

from datetime import timedelta

from app.application.dto.auth import LoginUserInput, TokenPair
from app.application.use_cases._token_issuance import issue_token_pair
from app.domain.exceptions import InactiveUserError, InvalidCredentialsError
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork

# Verified against when no account matches the email, so that a login attempt
# costs the same password-hash computation whether or not the account exists.
# Without it, "unknown email" answers measurably faster than "wrong password",
# which lets anyone test which emails are registered.
_DECOY_PASSWORD = "decoy-password-for-constant-time-login"  # noqa: S105 - not a credential
_decoy_hashes: dict[type[PasswordHasher], str] = {}


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
            hashed_password = user.hashed_password if user else self._decoy_hash()
            password_matches = self._hasher.verify(data.password, hashed_password)
            if user is None or not password_matches:
                raise InvalidCredentialsError("Invalid email or password.")
            if not user.is_active:
                raise InactiveUserError("This account has been deactivated.")

            token_pair, _ = await issue_token_pair(
                self._uow, self._tokens, user.id, self._refresh_ttl
            )
            await self._uow.commit()

        return token_pair

    def _decoy_hash(self) -> str:
        """A real hash from this hasher (so verifying against it does the
        full work), computed once per hasher type."""
        hasher_type = type(self._hasher)
        if hasher_type not in _decoy_hashes:
            _decoy_hashes[hasher_type] = self._hasher.hash(_DECOY_PASSWORD)
        return _decoy_hashes[hasher_type]
