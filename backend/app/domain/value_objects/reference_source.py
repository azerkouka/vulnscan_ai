from __future__ import annotations

from enum import StrEnum


class ReferenceSource(StrEnum):
    """Where a Finding's reference came from. A superset of `KnowledgeSource`
    (adds OTHER) since a finding could, in principle, cite something outside
    our three ingested knowledge bases."""

    OWASP = "OWASP"
    CWE = "CWE"
    ATTACK = "ATTACK"
    OTHER = "OTHER"
