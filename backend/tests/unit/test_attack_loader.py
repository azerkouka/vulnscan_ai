from pathlib import Path

import pytest

from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.ingestion.attack_loader import load_attack_documents

_BUNDLE = (
    Path(__file__).resolve().parents[2] / "data" / "knowledge" / "attack" / "attack_bundle.json"
)


@pytest.mark.unit
def test_loads_every_technique_in_the_bundle() -> None:
    documents = load_attack_documents(_BUNDLE)

    assert len(documents) >= 10
    assert all(doc.external_id.startswith("T") for doc in documents)
    assert all(doc.source == KnowledgeSource.ATTACK for doc in documents)


@pytest.mark.unit
def test_exploit_public_facing_application_entry_is_well_formed() -> None:
    documents = load_attack_documents(_BUNDLE)
    technique = next(doc for doc in documents if doc.external_id == "T1190")

    assert technique.name == "Exploit Public-Facing Application"
    assert technique.category == "initial-access"
    assert technique.url is not None and "attack.mitre.org" in technique.url


@pytest.mark.unit
def test_objects_without_a_mitre_attack_reference_are_skipped(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text(
        '{"objects": [{"type": "attack-pattern", "name": "Untraceable", '
        '"description": "no external_references at all"}]}',
        encoding="utf-8",
    )

    assert load_attack_documents(bundle) == []


@pytest.mark.unit
def test_missing_name_raises(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle.json"
    bundle.write_text(
        '{"objects": [{"type": "attack-pattern", "description": "x", '
        '"external_references": [{"source_name": "mitre-attack", "external_id": "T0000"}]}]}',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="name"):
        load_attack_documents(bundle)
