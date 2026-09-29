"""The KnowledgeDocument entity.

One entry from the security knowledge base (an OWASP category, a CWE
weakness, or an ATT&CK technique), normalized into a single shape regardless
of source. `external_id` is the natural, human-meaningful key (e.g.
"CWE-89") shared by the vector store, the Postgres mirror table, and
anti-hallucination checks in Phase 4 - it is what a `Finding` cites.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime

from app.domain.value_objects.knowledge_source import KnowledgeSource


@dataclass(frozen=True, slots=True)
class KnowledgeDocument:
    external_id: str
    source: KnowledgeSource
    name: str
    category: str | None
    url: str | None
    content: str
    """Full text used for embedding - title + description, kept human-readable."""

    @property
    def content_hash(self) -> str:
        """Stable hash of everything that would change the embedding, used
        by the ingestion use case to skip re-embedding unchanged documents."""
        payload = f"{self.name}\0{self.category}\0{self.url}\0{self.content}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class KnowledgeDocumentRecord:
    """A `KnowledgeDocument` as persisted (Postgres mirror table row) -
    adds the bookkeeping fields the domain document itself doesn't need."""

    external_id: str
    source: KnowledgeSource
    name: str
    category: str | None
    url: str | None
    content_hash: str
    ingested_at: datetime
