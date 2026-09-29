"""Idempotently indexes a batch of already-loaded knowledge documents.

Deliberately takes pre-loaded `KnowledgeDocument`s rather than reading files
itself: parsing OWASP markdown / CWE XML / ATT&CK STIX is an infrastructure
concern (`app.infrastructure.ingestion`), and the application layer must not
import infrastructure. The API router and the CLI script - both composition
roots, allowed to know about infra - call the loaders and hand the result to
this use case.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from app.application.dto.knowledge import IngestKnowledgeResult, SourceIngestCounts
from app.domain.entities.knowledge_document import KnowledgeDocument, KnowledgeDocumentRecord
from app.domain.ports.knowledge_indexer import KnowledgeIndexer
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.knowledge_source import KnowledgeSource


class IngestKnowledgeUseCase:
    def __init__(self, uow: UnitOfWork, indexer: KnowledgeIndexer) -> None:
        self._uow = uow
        self._indexer = indexer

    async def execute(self, documents: Sequence[KnowledgeDocument]) -> IngestKnowledgeResult:
        by_source: dict[KnowledgeSource, list[KnowledgeDocument]] = {}
        for doc in documents:
            by_source.setdefault(doc.source, []).append(doc)

        per_source: dict[KnowledgeSource, SourceIngestCounts] = {}

        async with self._uow:
            for source, source_documents in by_source.items():
                existing_hashes = await self._uow.knowledge_documents.get_content_hashes(source)

                to_upsert: list[KnowledgeDocument] = []
                created = updated = unchanged = 0
                for doc in source_documents:
                    existing_hash = existing_hashes.get(doc.external_id)
                    if existing_hash is None:
                        created += 1
                        to_upsert.append(doc)
                    elif existing_hash != doc.content_hash:
                        updated += 1
                        to_upsert.append(doc)
                    else:
                        unchanged += 1

                if to_upsert:
                    await self._indexer.upsert(to_upsert)
                    now = datetime.now(UTC)
                    for doc in to_upsert:
                        await self._uow.knowledge_documents.upsert(
                            KnowledgeDocumentRecord(
                                external_id=doc.external_id,
                                source=doc.source,
                                name=doc.name,
                                category=doc.category,
                                url=doc.url,
                                content_hash=doc.content_hash,
                                ingested_at=now,
                            )
                        )

                per_source[source] = SourceIngestCounts(
                    created=created, updated=updated, unchanged=unchanged
                )

            await self._uow.commit()

        return IngestKnowledgeResult(per_source=per_source)
