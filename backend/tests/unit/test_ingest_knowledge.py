import pytest

from app.application.use_cases.ingest_knowledge import IngestKnowledgeUseCase
from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource
from tests.unit.fakes import FakeKnowledgeIndexer, FakeUnitOfWork


def _doc(
    external_id: str, content: str, source: KnowledgeSource = KnowledgeSource.CWE
) -> KnowledgeDocument:
    return KnowledgeDocument(
        external_id=external_id,
        source=source,
        name=external_id,
        category=None,
        url=None,
        content=content,
    )


@pytest.mark.unit
async def test_first_ingestion_creates_every_document() -> None:
    uow = FakeUnitOfWork()
    indexer = FakeKnowledgeIndexer()
    use_case = IngestKnowledgeUseCase(uow, indexer)
    docs = [_doc("CWE-89", "sql injection"), _doc("CWE-79", "xss")]

    result = await use_case.execute(docs)

    counts = result.per_source[KnowledgeSource.CWE]
    assert (counts.created, counts.updated, counts.unchanged) == (2, 0, 0)
    assert indexer.upsert_calls == [["CWE-89", "CWE-79"]]
    assert await uow.knowledge_documents.get_by_external_id("CWE-89") is not None


@pytest.mark.unit
async def test_reingesting_unchanged_documents_skips_the_indexer() -> None:
    uow = FakeUnitOfWork()
    indexer = FakeKnowledgeIndexer()
    use_case = IngestKnowledgeUseCase(uow, indexer)
    docs = [_doc("CWE-89", "sql injection")]
    await use_case.execute(docs)

    result = await use_case.execute(docs)

    counts = result.per_source[KnowledgeSource.CWE]
    assert (counts.created, counts.updated, counts.unchanged) == (0, 0, 1)
    # Only the first call actually touched the indexer.
    assert indexer.upsert_calls == [["CWE-89"]]


@pytest.mark.unit
async def test_changed_content_is_reported_as_updated_and_re_indexed() -> None:
    uow = FakeUnitOfWork()
    indexer = FakeKnowledgeIndexer()
    use_case = IngestKnowledgeUseCase(uow, indexer)
    await use_case.execute([_doc("CWE-89", "sql injection v1")])

    result = await use_case.execute([_doc("CWE-89", "sql injection v2, more detail")])

    counts = result.per_source[KnowledgeSource.CWE]
    assert (counts.created, counts.updated, counts.unchanged) == (0, 1, 0)
    assert indexer.upsert_calls == [["CWE-89"], ["CWE-89"]]
    stored = await uow.knowledge_documents.get_by_external_id("CWE-89")
    assert stored is not None
    assert stored.content_hash == _doc("CWE-89", "sql injection v2, more detail").content_hash


@pytest.mark.unit
async def test_counts_are_tracked_independently_per_source() -> None:
    uow = FakeUnitOfWork()
    indexer = FakeKnowledgeIndexer()
    use_case = IngestKnowledgeUseCase(uow, indexer)
    docs = [
        _doc("CWE-89", "sql injection", source=KnowledgeSource.CWE),
        _doc("A03:2021", "injection", source=KnowledgeSource.OWASP),
        _doc("T1190", "exploit public facing app", source=KnowledgeSource.ATTACK),
    ]

    result = await use_case.execute(docs)

    assert set(result.per_source) == {
        KnowledgeSource.CWE,
        KnowledgeSource.OWASP,
        KnowledgeSource.ATTACK,
    }
    assert all(counts.created == 1 for counts in result.per_source.values())


@pytest.mark.unit
async def test_empty_input_commits_with_no_work() -> None:
    uow = FakeUnitOfWork()
    indexer = FakeKnowledgeIndexer()
    use_case = IngestKnowledgeUseCase(uow, indexer)

    result = await use_case.execute([])

    assert result.per_source == {}
    assert indexer.upsert_calls == []
    assert uow.committed is True
