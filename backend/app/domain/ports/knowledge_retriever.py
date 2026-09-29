from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.domain.value_objects.knowledge_source import KnowledgeSource


@dataclass(frozen=True, slots=True)
class RetrievedKnowledge:
    """One vector-search hit, backend-agnostic (no Chroma types leak out)."""

    external_id: str
    source: KnowledgeSource
    name: str
    url: str | None
    content: str
    distance: float
    """Lower is more similar. Exact meaning depends on the backend's
    configured distance metric (Chroma's default is squared L2)."""


class KnowledgeRetriever(ABC):
    """Read-side of the knowledge base - used by the Phase 4 RAG pipeline to
    ground LLM answers, and to validate that a CWE id the LLM cites actually
    exists (anti-hallucination)."""

    @abstractmethod
    async def query(
        self, query_text: str, *, top_k: int = 5, source: KnowledgeSource | None = None
    ) -> list[RetrievedKnowledge]: ...

    @abstractmethod
    async def exists(self, external_id: str) -> bool:
        """True if `external_id` (e.g. "CWE-89") is a real entry in the
        knowledge base."""
