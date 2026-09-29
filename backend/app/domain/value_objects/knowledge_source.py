from __future__ import annotations

from enum import StrEnum


class KnowledgeSource(StrEnum):
    """Which knowledge base a document came from."""

    OWASP = "OWASP"
    CWE = "CWE"
    ATTACK = "ATTACK"
