from __future__ import annotations

from types import TracebackType

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.ports.unit_of_work import UnitOfWork
from app.infrastructure.persistence.repositories.finding_repository import (
    SqlAlchemyFindingRepository,
)
from app.infrastructure.persistence.repositories.knowledge_document_repository import (
    SqlAlchemyKnowledgeDocumentRepository,
)
from app.infrastructure.persistence.repositories.refresh_token_repository import (
    SqlAlchemyRefreshTokenRepository,
)
from app.infrastructure.persistence.repositories.scan_repository import SqlAlchemyScanRepository
from app.infrastructure.persistence.repositories.user_repository import SqlAlchemyUserRepository


class SqlAlchemyUnitOfWork(UnitOfWork):
    """Wraps a request-scoped `AsyncSession` (owned and closed by the
    `get_db_session` API dependency) with commit/rollback and exposes the
    repositories that share it.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self.users = SqlAlchemyUserRepository(session)
        self.refresh_tokens = SqlAlchemyRefreshTokenRepository(session)
        self.knowledge_documents = SqlAlchemyKnowledgeDocumentRepository(session)
        self.scans = SqlAlchemyScanRepository(session)
        self.findings = SqlAlchemyFindingRepository(session)

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()
