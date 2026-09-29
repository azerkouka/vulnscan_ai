from collections.abc import Sequence
from pathlib import Path

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.ingestion.attack_loader import load_attack_documents
from app.infrastructure.ingestion.cwe_loader import load_cwe_documents
from app.infrastructure.ingestion.owasp_loader import load_owasp_documents

__all__ = ["load_attack_documents", "load_cwe_documents", "load_documents", "load_owasp_documents"]


def load_documents(sources: Sequence[KnowledgeSource], data_dir: Path) -> list[KnowledgeDocument]:
    """Dispatches to the right loader per requested source and concatenates
    the results. The composition root (API router, CLI script) calls this -
    the application layer only ever sees the plain `KnowledgeDocument`s it
    returns, never the loaders themselves."""
    documents: list[KnowledgeDocument] = []
    if KnowledgeSource.OWASP in sources:
        documents += load_owasp_documents(data_dir / "owasp")
    if KnowledgeSource.CWE in sources:
        documents += load_cwe_documents(data_dir / "cwe" / "cwe_catalog.xml")
    if KnowledgeSource.ATTACK in sources:
        documents += load_attack_documents(data_dir / "attack" / "attack_bundle.json")
    return documents
