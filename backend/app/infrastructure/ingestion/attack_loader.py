"""Loads MITRE ATT&CK technique documents from a local STIX 2.1 bundle.

Parses `data/knowledge/attack/attack_bundle.json` (a curated subset of
`attack-pattern` objects, in real STIX shape) - only the fields this loader
reads (`type`, `name`, `description`, `external_references`) are required,
so a genuine ATT&CK Enterprise STIX export can be dropped in unchanged; this
loader simply ignores every other STIX object type and field.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource

_ATTACK_PATTERN = "attack-pattern"
_MITRE_SOURCE = "mitre-attack"


def load_attack_documents(bundle_path: Path) -> list[KnowledgeDocument]:
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    documents: list[KnowledgeDocument] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != _ATTACK_PATTERN:
            continue

        technique_id = _technique_id(obj)
        if technique_id is None:
            continue  # a STIX object without a mitre-attack external_id isn't a technique we can cite

        name = obj.get("name")
        description = obj.get("description", "")
        if not name:
            raise ValueError(f"{bundle_path}: an attack-pattern object is missing a name")

        phases = obj.get("kill_chain_phases", [])
        category = phases[0]["phase_name"] if phases else None
        url = next(
            (
                ref.get("url")
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == _MITRE_SOURCE
            ),
            None,
        )

        documents.append(
            KnowledgeDocument(
                external_id=technique_id,
                source=KnowledgeSource.ATTACK,
                name=name,
                category=category,
                url=url,
                content=f"{technique_id}: {name}\n\n{description}".strip(),
            )
        )

    return documents


def _technique_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == _MITRE_SOURCE and ref.get("external_id"):
            return str(ref["external_id"])
    return None
