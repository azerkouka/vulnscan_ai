import pytest

from app.application.use_cases.get_knowledge_health import GetKnowledgeHealthUseCase
from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource
from tests.unit.fakes import FakeKnowledgeIndexer


@pytest.mark.unit
async def test_reports_counts_per_source_including_empty_ones() -> None:
    indexer = FakeKnowledgeIndexer()
    await indexer.upsert(
        [
            KnowledgeDocument(
                external_id="CWE-89",
                source=KnowledgeSource.CWE,
                name="SQLi",
                category=None,
                url=None,
                content="...",
            )
        ]
    )
    use_case = GetKnowledgeHealthUseCase(indexer)

    result = await use_case.execute()

    assert result.counts_by_source[KnowledgeSource.CWE] == 1
    assert result.counts_by_source[KnowledgeSource.OWASP] == 0
    assert result.counts_by_source[KnowledgeSource.ATTACK] == 0
    assert result.total == 1
