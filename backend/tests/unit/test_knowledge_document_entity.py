import pytest

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource


def _doc(**overrides: object) -> KnowledgeDocument:
    fields: dict[str, object] = {
        "external_id": "CWE-89",
        "source": KnowledgeSource.CWE,
        "name": "SQL Injection",
        "category": "Weakness",
        "url": "https://cwe.mitre.org/data/definitions/89.html",
        "content": "SQL injection allows...",
    }
    fields.update(overrides)
    return KnowledgeDocument(**fields)  # type: ignore[arg-type]


@pytest.mark.unit
def test_content_hash_is_deterministic() -> None:
    assert _doc().content_hash == _doc().content_hash


@pytest.mark.unit
def test_content_hash_changes_when_content_changes() -> None:
    assert _doc().content_hash != _doc(content="different content").content_hash


@pytest.mark.unit
def test_content_hash_is_unaffected_by_external_id() -> None:
    """external_id is the document's identity, not part of its content -
    renaming an id (which the loaders never do) shouldn't look like an
    edit to the ingestion use case's diff logic."""
    assert _doc().content_hash == _doc(external_id="CWE-90").content_hash
