from __future__ import annotations

from datetime import timedelta

from app.application.dto.auth import TokenPair
from app.application.use_cases._token_issuance import issue_token_pair
from app.domain.exceptions import InactiveUserError, InvalidRefreshTokenError
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork


class RefreshTokenUseCase:
    """Rotates a refresh token: the presented token is revoked and replaced
    by a new one in the same transaction as issuing new tokens.

    If a token that was *already* revoked is presented again, that is a
    strong signal of theft (a stolen refresh token being replayed after the
    legitimate client already rotated past it) - the entire token family for
    that user is revoked, forcing a fresh login everywhere.
    """

    def __init__(
        self, uow: UnitOfWork, token_service: TokenService, refresh_token_ttl: timedelta
    ) -> None:
        self._uow = uow
        self._tokens = token_service
        self._refresh_ttl = refresh_token_ttl

    async def execute(self, refresh_token_value: str) -> TokenPair:
        token_hash = self._tokens.hash_refresh_token(refresh_token_value)

        async with self._uow:
            stored = await self._uow.refresh_tokens.get_by_token_hash(token_hash)
            if stored is None:
                raise InvalidRefreshTokenError("Refresh token not recognized.")

            if stored.revoked_at is not None:
                await self._uow.refresh_tokens.revoke_all_for_user(stored.user_id)
                await self._uow.commit()
                raise InvalidRefreshTokenError("Refresh token has already been used.")

            if not stored.is_active:
                raise InvalidRefreshTokenError("Refresh token has expired.")

            user = await self._uow.users.get_by_id(stored.user_id)
            if user is None or not user.is_active:
                raise InactiveUserError("This account has been deactivated.")

            token_pair, new_token_id = await issue_token_pair(
                self._uow, self._tokens, user.id, self._refresh_ttl
            )
            await self._uow.refresh_tokens.revoke(stored.id, replaced_by_id=new_token_id)
            await self._uow.commit()

        return token_pair
