from __future__ import annotations

from dataclasses import dataclass

from app.application.dto.knowledge import KnowledgeDocumentSummary
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.knowledge_source import KnowledgeSource


@dataclass(frozen=True, slots=True)
class ListKnowledgeDocumentsInput:
    source: KnowledgeSource | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True, slots=True)
class ListKnowledgeDocumentsResult:
    documents: list[KnowledgeDocumentSummary]
    total: int


class ListKnowledgeDocumentsUseCase:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, data: ListKnowledgeDocumentsInput) -> ListKnowledgeDocumentsResult:
        async with self._uow:
            records = await self._uow.knowledge_documents.list(
                source=data.source, limit=data.limit, offset=data.offset
            )
            total = await self._uow.knowledge_documents.count(source=data.source)

        return ListKnowledgeDocumentsResult(
            documents=[
                KnowledgeDocumentSummary(
                    external_id=r.external_id,
                    source=r.source,
                    name=r.name,
                    category=r.category,
                    url=r.url,
                    ingested_at=r.ingested_at,
                )
                for r in records
            ],
            total=total,
        )
