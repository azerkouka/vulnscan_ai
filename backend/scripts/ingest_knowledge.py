#!/usr/bin/env python
"""Idempotent CLI to build/refresh the ChromaDB knowledge base.

Loads OWASP Top 10 (markdown), CWE (XML) and MITRE ATT&CK (STIX JSON) sources
from `data/knowledge/`, and upserts them into Chroma + the Postgres mirror
table - stable ids and content hashing (see
`app.domain.entities.knowledge_document.KnowledgeDocument.content_hash`)
make re-running this script any number of times safe: unchanged documents
are skipped, not re-embedded.

Usage:
    python -m scripts.ingest_knowledge
    python -m scripts.ingest_knowledge --source owasp,cwe
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.application.dto.knowledge import IngestKnowledgeResult
from app.application.use_cases.ingest_knowledge import IngestKnowledgeUseCase
from app.core.config import get_settings
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.ingestion import load_documents
from app.infrastructure.persistence.database import create_engine, create_session_factory
from app.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from app.infrastructure.vectorstore.chroma_knowledge_store import ChromaKnowledgeStore

_SOURCE_NAMES = {
    "owasp": KnowledgeSource.OWASP,
    "cwe": KnowledgeSource.CWE,
    "attack": KnowledgeSource.ATTACK,
}


def _parse_sources(raw: str) -> list[KnowledgeSource]:
    try:
        return [_SOURCE_NAMES[name.strip().lower()] for name in raw.split(",") if name.strip()]
    except KeyError as exc:
        valid = ", ".join(_SOURCE_NAMES)
        raise SystemExit(f"Unknown source {exc.args[0]!r}; valid sources: {valid}") from exc


def _print_result(result: IngestKnowledgeResult) -> None:
    if not result.per_source:
        print("Nothing to ingest.")
        return

    for source, counts in result.per_source.items():
        print(
            f"{source.value:<8} created={counts.created:<4} "
            f"updated={counts.updated:<4} unchanged={counts.unchanged:<4} "
            f"total={counts.total}"
        )


async def _run(sources: list[KnowledgeSource]) -> None:
    settings = get_settings()

    documents = load_documents(sources, Path(settings.knowledge_data_dir))
    if not documents:
        print("No documents found for the requested sources.", file=sys.stderr)
        raise SystemExit(1)

    engine = create_engine(settings.database_url, echo=False)
    session_factory = create_session_factory(engine)
    indexer = ChromaKnowledgeStore(
        host=settings.chroma_host,
        port=settings.chroma_port,
        collection_name=f"{settings.chroma_collection_prefix}_knowledge",
    )

    try:
        async with session_factory() as session:
            uow = SqlAlchemyUnitOfWork(session)
            use_case = IngestKnowledgeUseCase(uow, indexer)
            result = await use_case.execute(documents)
    finally:
        await engine.dispose()

    _print_result(result)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--source",
        default="owasp,cwe,attack",
        help="Comma-separated list of sources to ingest (owasp, cwe, attack).",
    )
    args = parser.parse_args()

    asyncio.run(_run(_parse_sources(args.source)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
