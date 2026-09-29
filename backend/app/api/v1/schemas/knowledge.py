from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.application.dto.knowledge import (
    IngestKnowledgeResult,
    KnowledgeDocumentSummary,
)
from app.application.use_cases.get_knowledge_health import KnowledgeHealthResult
from app.application.use_cases.list_knowledge_documents import ListKnowledgeDocumentsResult
from app.domain.value_objects.knowledge_source import KnowledgeSource


class IngestRequest(BaseModel):
    sources: list[KnowledgeSource] | None = Field(
        default=None, description="Sources to (re-)ingest; omit to ingest all of them."
    )


class SourceIngestCountsResponse(BaseModel):
    created: int
    updated: int
    unchanged: int
    total: int


class IngestResponse(BaseModel):
    per_source: dict[KnowledgeSource, SourceIngestCountsResponse]

    @classmethod
    def from_dto(cls, dto: IngestKnowledgeResult) -> IngestResponse:
        return cls(
            per_source={
                source: SourceIngestCountsResponse(
                    created=counts.created,
                    updated=counts.updated,
                    unchanged=counts.unchanged,
                    total=counts.total,
                )
                for source, counts in dto.per_source.items()
            }
        )


class KnowledgeDocumentResponse(BaseModel):
    external_id: str
    source: KnowledgeSource
    name: str
    category: str | None
    url: str | None
    ingested_at: datetime

    @classmethod
    def from_dto(cls, dto: KnowledgeDocumentSummary) -> KnowledgeDocumentResponse:
        return cls(
            external_id=dto.external_id,
            source=dto.source,
            name=dto.name,
            category=dto.category,
            url=dto.url,
            ingested_at=dto.ingested_at,
        )


class KnowledgeDocumentListResponse(BaseModel):
    documents: list[KnowledgeDocumentResponse]
    total: int
    limit: int
    offset: int

    @classmethod
    def from_dto(
        cls, dto: ListKnowledgeDocumentsResult, *, limit: int, offset: int
    ) -> KnowledgeDocumentListResponse:
        return cls(
            documents=[KnowledgeDocumentResponse.from_dto(d) for d in dto.documents],
            total=dto.total,
            limit=limit,
            offset=offset,
        )


class KnowledgeHealthResponse(BaseModel):
    counts_by_source: dict[KnowledgeSource, int]
    total: int

    @classmethod
    def from_dto(cls, dto: KnowledgeHealthResult) -> KnowledgeHealthResponse:
        return cls(counts_by_source=dto.counts_by_source, total=dto.total)
