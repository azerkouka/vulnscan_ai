from __future__ import annotations

from abc import ABC, abstractmethod

from app.domain.entities.knowledge_document import KnowledgeDocumentRecord
from app.domain.value_objects.knowledge_source import KnowledgeSource


class KnowledgeDocumentRepository(ABC):
    """Postgres mirror of what's in the vector store - the source of truth
    for the admin listing endpoints and for the ingestion use case's
    idempotency check (comparing content hashes to skip unchanged docs)."""

    @abstractmethod
    async def upsert(self, record: KnowledgeDocumentRecord) -> None: ...

    @abstractmethod
    async def get_by_external_id(self, external_id: str) -> KnowledgeDocumentRecord | None: ...

    @abstractmethod
    async def list(
        self, *, source: KnowledgeSource | None = None, limit: int = 50, offset: int = 0
    ) -> list[KnowledgeDocumentRecord]: ...

    @abstractmethod
    async def count(self, *, source: KnowledgeSource | None = None) -> int: ...

    @abstractmethod
    async def get_content_hashes(self, source: KnowledgeSource | None = None) -> dict[str, str]:
        """Map of external_id -> content_hash for every stored document
        (optionally scoped to one source), used to diff against freshly
        loaded documents without re-reading full content."""

    @abstractmethod
    async def delete(self, external_id: str) -> None: ...
