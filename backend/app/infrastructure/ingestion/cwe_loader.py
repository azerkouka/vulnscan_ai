"""Loads CWE weakness documents from a local XML catalog.

Parses the simplified `Weakness_Catalog` XML in
`data/knowledge/cwe/cwe_catalog.xml` (a curated subset in the shape of
MITRE's official CWE List schema - a real full dump uses the same element
names, so swapping in the official file needs no code change beyond
skipping unrecognized attributes/elements this loader doesn't read).
"""

from __future__ import annotations

from pathlib import Path
from xml.etree import ElementTree as ET

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource

_CATEGORY = "Weakness"


def load_cwe_documents(catalog_path: Path) -> list[KnowledgeDocument]:
    tree = ET.parse(catalog_path)  # noqa: S314 - local, trusted, checked-in file
    root = tree.getroot()

    documents: list[KnowledgeDocument] = []
    for weakness in root.iter("Weakness"):
        cwe_id = weakness.get("ID")
        name = weakness.get("Name")
        if not cwe_id or not name:
            raise ValueError(f"{catalog_path}: a <Weakness> element is missing ID or Name")

        description = _text_of(weakness, "Description")
        extended_description = _text_of(weakness, "Extended_Description")
        url = _text_of(weakness, "URL")

        content_parts = [f"CWE-{cwe_id}: {name}", description]
        if extended_description:
            content_parts.append(extended_description)

        documents.append(
            KnowledgeDocument(
                external_id=f"CWE-{cwe_id}",
                source=KnowledgeSource.CWE,
                name=name,
                category=_CATEGORY,
                url=url,
                content="\n\n".join(part for part in content_parts if part),
            )
        )

    return documents


def _text_of(element: ET.Element, tag: str) -> str | None:
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None
