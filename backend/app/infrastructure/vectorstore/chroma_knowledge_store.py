"""ChromaDB adapter for the knowledge base: implements both the write side
(`KnowledgeIndexer`, used only by ingestion) and the read side
(`KnowledgeRetriever`, used by the RAG pipeline and anti-hallucination
checks).

The official `chromadb` client is synchronous. Every call here runs on a
worker thread via `asyncio.to_thread` so it never blocks the event loop -
the same reasoning as running blocking DB drivers off the main loop.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.ports.knowledge_indexer import KnowledgeIndexer
from app.domain.ports.knowledge_retriever import KnowledgeRetriever, RetrievedKnowledge
from app.domain.value_objects.knowledge_source import KnowledgeSource

_EMPTY = ""  # Chroma metadata values can't be None


class ChromaKnowledgeStore(KnowledgeIndexer, KnowledgeRetriever):
    def __init__(self, host: str, port: int, collection_name: str) -> None:
        self._client = chromadb.HttpClient(host=host, port=port)
        self._collection_name = collection_name
        # Any: chromadb's own annotations for embedding functions don't line
        # up between this factory and `get_or_create_collection`.
        self._embedding_function: Any = DefaultEmbeddingFunction()

    def _collection(self) -> chromadb.Collection:
        return self._client.get_or_create_collection(
            name=self._collection_name, embedding_function=self._embedding_function
        )

    async def upsert(self, documents: Sequence[KnowledgeDocument]) -> None:
        if not documents:
            return

        def _do_upsert() -> None:
            collection = self._collection()
            collection.upsert(
                ids=[doc.external_id for doc in documents],
                documents=[doc.content for doc in documents],
                metadatas=[
                    {
                        "source": doc.source.value,
                        "name": doc.name,
                        "category": doc.category or _EMPTY,
                        "url": doc.url or _EMPTY,
                    }
                    for doc in documents
                ],
            )

        await asyncio.to_thread(_do_upsert)

    async def delete(self, external_ids: Sequence[str]) -> None:
        if not external_ids:
            return
        await asyncio.to_thread(lambda: self._collection().delete(ids=list(external_ids)))

    async def count(self, source: KnowledgeSource | None = None) -> int:
        def _do_count() -> int:
            collection = self._collection()
            if source is None:
                return int(collection.count())
            result = collection.get(where={"source": source.value}, include=[])
            return len(result["ids"])

        return await asyncio.to_thread(_do_count)

    async def query(
        self, query_text: str, *, top_k: int = 5, source: KnowledgeSource | None = None
    ) -> list[RetrievedKnowledge]:
        def _do_query() -> Any:
            collection = self._collection()
            return collection.query(
                query_texts=[query_text],
                n_results=top_k,
                where={"source": source.value} if source else None,
            )

        result = await asyncio.to_thread(_do_query)

        ids = result["ids"][0]
        documents = result["documents"][0]
        metadatas = result["metadatas"][0]
        distances = result["distances"][0]

        return [
            RetrievedKnowledge(
                external_id=doc_id,
                source=KnowledgeSource(metadata["source"]),
                name=metadata["name"],
                url=metadata["url"] or None,
                content=content,
                distance=distance,
            )
            for doc_id, content, metadata, distance in zip(
                ids, documents, metadatas, distances, strict=True
            )
        ]

    async def exists(self, external_id: str) -> bool:
        def _do_exists() -> bool:
            result = self._collection().get(ids=[external_id], include=[])
            return len(result["ids"]) > 0

        return await asyncio.to_thread(_do_exists)
