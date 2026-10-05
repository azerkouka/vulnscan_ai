from __future__ import annotations

from abc import ABC, abstractmethod

from app.domain.value_objects.code_chunk import CodeChunk


class CodeChunker(ABC):
    @abstractmethod
    def supports(self, language: str) -> bool: ...

    @abstractmethod
    def chunk(self, content: str, *, file_path: str, language: str) -> list[CodeChunk]:
        """Splits a file into function/class-sized chunks that together
        cover every non-blank line. Implementations must fall back to
        whole-file `ChunkKind.MODULE` chunks (windowed, if the file is long)
        rather than raising, if `language` isn't `supports()`-ed or parsing
        fails - a scan should never fail outright just because one file
        couldn't be split finely."""
