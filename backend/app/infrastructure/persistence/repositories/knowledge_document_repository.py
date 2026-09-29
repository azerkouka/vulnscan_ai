from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.knowledge_document import KnowledgeDocumentRecord
from app.domain.ports.knowledge_document_repository import KnowledgeDocumentRepository
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.persistence.models import KnowledgeDocumentModel


def _to_domain(model: KnowledgeDocumentModel) -> KnowledgeDocumentRecord:
    return KnowledgeDocumentRecord(
        external_id=model.external_id,
        source=KnowledgeSource(model.source),
        name=model.name,
        category=model.category,
        url=model.url,
        content_hash=model.content_hash,
        ingested_at=model.ingested_at,
    )


class SqlAlchemyKnowledgeDocumentRepository(KnowledgeDocumentRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(self, record: KnowledgeDocumentRecord) -> None:
        stmt = pg_insert(KnowledgeDocumentModel).values(
            external_id=record.external_id,
            source=record.source.value,
            name=record.name,
            category=record.category,
            url=record.url,
            content_hash=record.content_hash,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[KnowledgeDocumentModel.external_id],
            set_={
                "source": stmt.excluded.source,
                "name": stmt.excluded.name,
                "category": stmt.excluded.category,
                "url": stmt.excluded.url,
                "content_hash": stmt.excluded.content_hash,
                "ingested_at": func.now(),
            },
        )
        await self._session.execute(stmt)

    async def get_by_external_id(self, external_id: str) -> KnowledgeDocumentRecord | None:
        stmt = select(KnowledgeDocumentModel).where(
            KnowledgeDocumentModel.external_id == external_id
        )
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_domain(model) if model else None

    async def list(
        self, *, source: KnowledgeSource | None = None, limit: int = 50, offset: int = 0
    ) -> list[KnowledgeDocumentRecord]:
        stmt = select(KnowledgeDocumentModel).order_by(KnowledgeDocumentModel.external_id)
        if source is not None:
            stmt = stmt.where(KnowledgeDocumentModel.source == source.value)
        stmt = stmt.limit(limit).offset(offset)
        models = (await self._session.execute(stmt)).scalars().all()
        return [_to_domain(model) for model in models]

    async def count(self, *, source: KnowledgeSource | None = None) -> int:
        stmt = select(func.count()).select_from(KnowledgeDocumentModel)
        if source is not None:
            stmt = stmt.where(KnowledgeDocumentModel.source == source.value)
        return (await self._session.execute(stmt)).scalar_one()

    async def get_content_hashes(self, source: KnowledgeSource | None = None) -> dict[str, str]:
        stmt = select(KnowledgeDocumentModel.external_id, KnowledgeDocumentModel.content_hash)
        if source is not None:
            stmt = stmt.where(KnowledgeDocumentModel.source == source.value)
        rows = (await self._session.execute(stmt)).all()
        return dict(rows)

    async def delete(self, external_id: str) -> None:
        stmt = delete(KnowledgeDocumentModel).where(
            KnowledgeDocumentModel.external_id == external_id
        )
        await self._session.execute(stmt)
