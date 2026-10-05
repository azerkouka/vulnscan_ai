from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from app.domain.value_objects.code_location import CodeLocation


class ChunkKind(StrEnum):
    """MODULE is the whole-file fallback, used when a language has no
    chunker grammar available or the file couldn't be parsed."""

    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"


@dataclass(frozen=True, slots=True)
class CodeChunk:
    content: str
    language: str
    location: CodeLocation
    kind: ChunkKind
