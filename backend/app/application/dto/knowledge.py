from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from app.domain.value_objects.knowledge_source import KnowledgeSource


@dataclass(frozen=True, slots=True)
class SourceIngestCounts:
    created: int
    updated: int
    unchanged: int

    @property
    def total(self) -> int:
        return self.created + self.updated + self.unchanged


@dataclass(frozen=True, slots=True)
class IngestKnowledgeResult:
    per_source: dict[KnowledgeSource, SourceIngestCounts] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class KnowledgeDocumentSummary:
    external_id: str
    source: KnowledgeSource
    name: str
    category: str | None
    url: str | None
    ingested_at: datetime
