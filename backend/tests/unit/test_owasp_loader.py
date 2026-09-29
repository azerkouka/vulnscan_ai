from pathlib import Path

import pytest

from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.ingestion.owasp_loader import load_owasp_documents

_DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "knowledge" / "owasp"


@pytest.mark.unit
def test_loads_all_ten_owasp_categories() -> None:
    documents = load_owasp_documents(_DATA_DIR)

    assert len(documents) == 10
    ids = {doc.external_id for doc in documents}
    assert ids == {f"A{i:02d}:2021" for i in range(1, 11)}


@pytest.mark.unit
def test_parses_id_name_category_and_url() -> None:
    documents = load_owasp_documents(_DATA_DIR)
    injection = next(doc for doc in documents if doc.external_id == "A03:2021")

    assert injection.name == "Injection"
    assert injection.source == KnowledgeSource.OWASP
    assert injection.category == "Injection"
    assert injection.url is not None and injection.url.startswith("https://owasp.org")
    assert "SQL" in injection.content


@pytest.mark.unit
def test_missing_heading_raises(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.md"
    bad_file.write_text("No heading here, just text.", encoding="utf-8")

    with pytest.raises(ValueError, match="heading"):
        load_owasp_documents(tmp_path)
