"""Unit-of-work port: groups the repositories that must be written
atomically within one use case (e.g. rotating a refresh token both inserts
the new one and revokes the old one).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from types import TracebackType

from app.domain.ports.refresh_token_repository import RefreshTokenRepository
from app.domain.ports.user_repository import UserRepository


class UnitOfWork(ABC):
    users: UserRepository
    refresh_tokens: RefreshTokenRepository

    @abstractmethod
    async def __aenter__(self) -> UnitOfWork: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...
