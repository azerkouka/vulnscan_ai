"""Loads OWASP Top 10 category documents from local markdown files.

Each file is expected in the shape produced by `data/knowledge/owasp/*.md`:

    # A03:2021 - Injection

    **Category:** Injection
    **URL:** https://owasp.org/...

    <free-form markdown body>

Sourced from local files rather than fetched live, per the project's
ingestion design: `scripts/ingest_knowledge.py` re-runs against whatever is
checked into `data/knowledge/`, which keeps ingestion offline-reproducible.
"""

from __future__ import annotations

import re
from pathlib import Path

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource

_HEADING_RE = re.compile(
    r"^#\s*(?P<id>[A-Z0-9:]+)\s*[-–]\s*(?P<name>.+?)\s*$",  # noqa: RUF001 - en dash is intentional, matches real OWASP headings
    re.MULTILINE,
)
_CATEGORY_RE = re.compile(r"^\*\*Category:\*\*\s*(?P<value>.+?)\s*$", re.MULTILINE)
_URL_RE = re.compile(r"^\*\*URL:\*\*\s*(?P<value>.+?)\s*$", re.MULTILINE)


def load_owasp_documents(data_dir: Path) -> list[KnowledgeDocument]:
    documents: list[KnowledgeDocument] = []

    for path in sorted(data_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")

        heading = _HEADING_RE.search(text)
        if heading is None:
            raise ValueError(f"{path}: missing a top-level '# <ID> - <Name>' heading")

        category_match = _CATEGORY_RE.search(text)
        url_match = _URL_RE.search(text)

        documents.append(
            KnowledgeDocument(
                external_id=heading.group("id"),
                source=KnowledgeSource.OWASP,
                name=heading.group("name"),
                category=category_match.group("value") if category_match else None,
                url=url_match.group("value") if url_match else None,
                content=text.strip(),
            )
        )

    return documents
