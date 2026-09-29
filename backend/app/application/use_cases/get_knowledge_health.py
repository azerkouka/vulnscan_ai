from __future__ import annotations

from dataclasses import dataclass

from app.domain.ports.knowledge_indexer import KnowledgeIndexer
from app.domain.value_objects.knowledge_source import KnowledgeSource


@dataclass(frozen=True, slots=True)
class KnowledgeHealthResult:
    counts_by_source: dict[KnowledgeSource, int]

    @property
    def total(self) -> int:
        return sum(self.counts_by_source.values())


class GetKnowledgeHealthUseCase:
    def __init__(self, indexer: KnowledgeIndexer) -> None:
        self._indexer = indexer

    async def execute(self) -> KnowledgeHealthResult:
        counts = {source: await self._indexer.count(source) for source in KnowledgeSource}
        return KnowledgeHealthResult(counts_by_source=counts)
