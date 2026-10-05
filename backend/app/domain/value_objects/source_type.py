from __future__ import annotations

from enum import StrEnum


class SourceType(StrEnum):
    SNIPPET = "SNIPPET"
    FILE = "FILE"
    ZIP = "ZIP"
