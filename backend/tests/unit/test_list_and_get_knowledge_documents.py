from datetime import UTC, datetime

import pytest

from app.application.use_cases.get_knowledge_document import GetKnowledgeDocumentUseCase
from app.application.use_cases.list_knowledge_documents import (
    ListKnowledgeDocumentsInput,
    ListKnowledgeDocumentsUseCase,
)
from app.domain.entities.knowledge_document import KnowledgeDocumentRecord
from app.domain.exceptions import KnowledgeDocumentNotFoundError
from app.domain.value_objects.knowledge_source import KnowledgeSource
from tests.unit.fakes import FakeUnitOfWork


def _record(external_id: str, source: KnowledgeSource) -> KnowledgeDocumentRecord:
    return KnowledgeDocumentRecord(
        external_id=external_id,
        source=source,
        name=external_id,
        category=None,
        url=None,
        content_hash="hash",
        ingested_at=datetime.now(UTC),
    )


@pytest.mark.unit
async def test_list_filters_by_source() -> None:
    uow = FakeUnitOfWork()
    await uow.knowledge_documents.upsert(_record("CWE-89", KnowledgeSource.CWE))
    await uow.knowledge_documents.upsert(_record("A03:2021", KnowledgeSource.OWASP))
    use_case = ListKnowledgeDocumentsUseCase(uow)

    result = await use_case.execute(ListKnowledgeDocumentsInput(source=KnowledgeSource.CWE))

    assert result.total == 1
    assert [d.external_id for d in result.documents] == ["CWE-89"]


@pytest.mark.unit
async def test_list_paginates() -> None:
    uow = FakeUnitOfWork()
    for i in range(5):
        await uow.knowledge_documents.upsert(_record(f"CWE-{i}", KnowledgeSource.CWE))
    use_case = ListKnowledgeDocumentsUseCase(uow)

    page = await use_case.execute(ListKnowledgeDocumentsInput(limit=2, offset=2))

    assert page.total == 5
    assert len(page.documents) == 2


@pytest.mark.unit
async def test_get_returns_the_matching_document() -> None:
    uow = FakeUnitOfWork()
    await uow.knowledge_documents.upsert(_record("CWE-89", KnowledgeSource.CWE))
    use_case = GetKnowledgeDocumentUseCase(uow)

    result = await use_case.execute("CWE-89")

    assert result.external_id == "CWE-89"


@pytest.mark.unit
async def test_get_raises_when_missing() -> None:
    use_case = GetKnowledgeDocumentUseCase(FakeUnitOfWork())

    with pytest.raises(KnowledgeDocumentNotFoundError):
        await use_case.execute("CWE-999")
