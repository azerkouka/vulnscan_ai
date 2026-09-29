from __future__ import annotations

from app.domain.entities.user import User
from app.domain.exceptions import InvalidCredentialsError
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork


class GetCurrentUserUseCase:
    """Resolves an access token to its owning, active `User`. Used by the
    `get_current_user` API dependency that guards protected endpoints.
    """

    def __init__(self, uow: UnitOfWork, token_service: TokenService) -> None:
        self._uow = uow
        self._tokens = token_service

    async def execute(self, access_token: str) -> User:
        claims = self._tokens.decode_access_token(access_token)

        async with self._uow:
            user = await self._uow.users.get_by_id(claims.user_id)

        if user is None or not user.is_active:
            raise InvalidCredentialsError("Invalid or expired access token.")
        return user
