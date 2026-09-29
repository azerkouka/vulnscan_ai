from pathlib import Path

import pytest

from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.ingestion.cwe_loader import load_cwe_documents

_CATALOG = Path(__file__).resolve().parents[2] / "data" / "knowledge" / "cwe" / "cwe_catalog.xml"


@pytest.mark.unit
def test_loads_every_weakness_in_the_catalog() -> None:
    documents = load_cwe_documents(_CATALOG)

    assert len(documents) >= 15
    assert all(doc.external_id.startswith("CWE-") for doc in documents)
    assert all(doc.source == KnowledgeSource.CWE for doc in documents)


@pytest.mark.unit
def test_sql_injection_entry_is_well_formed() -> None:
    documents = load_cwe_documents(_CATALOG)
    sqli = next(doc for doc in documents if doc.external_id == "CWE-89")

    assert "SQL" in sqli.name
    assert "SQL" in sqli.content
    assert sqli.url == "https://cwe.mitre.org/data/definitions/89.html"


@pytest.mark.unit
def test_missing_id_or_name_raises(tmp_path: Path) -> None:
    bad_catalog = tmp_path / "bad.xml"
    bad_catalog.write_text(
        '<Weakness_Catalog><Weaknesses><Weakness Name="No ID Here">'
        "<Description>x</Description></Weakness></Weaknesses></Weakness_Catalog>",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="ID or Name"):
        load_cwe_documents(bad_catalog)
