from __future__ import annotations

from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork


class LogoutUserUseCase:
    """Revokes the presented refresh token. Idempotent: logging out with an
    already-invalid or unknown token is not an error - the end state (that
    token cannot be used again) is already true.
    """

    def __init__(self, uow: UnitOfWork, token_service: TokenService) -> None:
        self._uow = uow
        self._tokens = token_service

    async def execute(self, refresh_token_value: str) -> None:
        token_hash = self._tokens.hash_refresh_token(refresh_token_value)

        async with self._uow:
            stored = await self._uow.refresh_tokens.get_by_token_hash(token_hash)
            if stored is not None and stored.revoked_at is None:
                await self._uow.refresh_tokens.revoke(stored.id)
                await self._uow.commit()
