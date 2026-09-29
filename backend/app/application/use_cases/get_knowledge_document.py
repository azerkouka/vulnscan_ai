from __future__ import annotations

from app.application.dto.knowledge import KnowledgeDocumentSummary
from app.domain.exceptions import KnowledgeDocumentNotFoundError
from app.domain.ports.unit_of_work import UnitOfWork


class GetKnowledgeDocumentUseCase:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, external_id: str) -> KnowledgeDocumentSummary:
        async with self._uow:
            record = await self._uow.knowledge_documents.get_by_external_id(external_id)

        if record is None:
            raise KnowledgeDocumentNotFoundError(f"No knowledge document with id {external_id!r}.")

        return KnowledgeDocumentSummary(
            external_id=record.external_id,
            source=record.source,
            name=record.name,
            category=record.category,
            url=record.url,
            ingested_at=record.ingested_at,
        )
