from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.knowledge_document import KnowledgeDocumentRecord
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.persistence.repositories.knowledge_document_repository import (
    SqlAlchemyKnowledgeDocumentRepository,
)


def _record(
    external_id: str, source: KnowledgeSource, content_hash: str = "hash-1"
) -> KnowledgeDocumentRecord:
    return KnowledgeDocumentRecord(
        external_id=external_id,
        source=source,
        name=external_id,
        category=None,
        url=None,
        content_hash=content_hash,
        ingested_at=datetime.now(UTC),
    )


@pytest.mark.integration
async def test_upsert_then_get_by_external_id(db_session: AsyncSession) -> None:
    repo = SqlAlchemyKnowledgeDocumentRepository(db_session)

    await repo.upsert(_record("CWE-89", KnowledgeSource.CWE))
    await db_session.flush()

    found = await repo.get_by_external_id("CWE-89")
    assert found is not None
    assert found.source == KnowledgeSource.CWE
    assert found.content_hash == "hash-1"


@pytest.mark.integration
async def test_upsert_on_existing_external_id_updates_in_place(db_session: AsyncSession) -> None:
    repo = SqlAlchemyKnowledgeDocumentRepository(db_session)
    await repo.upsert(_record("CWE-89", KnowledgeSource.CWE, content_hash="hash-1"))
    await db_session.flush()

    await repo.upsert(_record("CWE-89", KnowledgeSource.CWE, content_hash="hash-2"))
    await db_session.flush()

    found = await repo.get_by_external_id("CWE-89")
    assert found is not None
    assert found.content_hash == "hash-2"
    assert await repo.count() == 1  # still one row, not two


@pytest.mark.integration
async def test_list_and_count_filter_by_source(db_session: AsyncSession) -> None:
    repo = SqlAlchemyKnowledgeDocumentRepository(db_session)
    await repo.upsert(_record("CWE-89", KnowledgeSource.CWE))
    await repo.upsert(_record("A03:2021", KnowledgeSource.OWASP))
    await db_session.flush()

    cwe_only = await repo.list(source=KnowledgeSource.CWE)
    assert [r.external_id for r in cwe_only] == ["CWE-89"]
    assert await repo.count(source=KnowledgeSource.CWE) == 1
    assert await repo.count() == 2


@pytest.mark.integration
async def test_get_content_hashes_scoped_to_source(db_session: AsyncSession) -> None:
    repo = SqlAlchemyKnowledgeDocumentRepository(db_session)
    await repo.upsert(_record("CWE-89", KnowledgeSource.CWE, content_hash="h1"))
    await repo.upsert(_record("A03:2021", KnowledgeSource.OWASP, content_hash="h2"))
    await db_session.flush()

    hashes = await repo.get_content_hashes(KnowledgeSource.CWE)

    assert hashes == {"CWE-89": "h1"}


@pytest.mark.integration
async def test_delete_removes_the_document(db_session: AsyncSession) -> None:
    repo = SqlAlchemyKnowledgeDocumentRepository(db_session)
    await repo.upsert(_record("CWE-89", KnowledgeSource.CWE))
    await db_session.flush()

    await repo.delete("CWE-89")
    await db_session.flush()

    assert await repo.get_by_external_id("CWE-89") is None
