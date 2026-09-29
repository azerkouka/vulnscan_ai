from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource


class KnowledgeIndexer(ABC):
    """Write-side of the knowledge base vector store - used only by the
    ingestion use case, never by request-serving code."""

    @abstractmethod
    async def upsert(self, documents: Sequence[KnowledgeDocument]) -> None: ...

    @abstractmethod
    async def delete(self, external_ids: Sequence[str]) -> None: ...

    @abstractmethod
    async def count(self, source: KnowledgeSource | None = None) -> int: ...
