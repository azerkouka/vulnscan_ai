from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExtractedFile:
    relative_path: str
    """Normalized, forward-slash, guaranteed relative with no `..` part."""
    content: str


class ArchiveExtractor(ABC):
    @abstractmethod
    def extract(self, archive: bytes) -> list[ExtractedFile]:
        """Returns the analyzable source files of an uploaded archive,
        in memory - nothing is written to disk.

        Raises `app.domain.exceptions.InvalidArchiveError` if the archive is
        corrupt or trips a safety limit (path traversal, entry count,
        uncompressed size, compression ratio). Entries that are merely
        irrelevant (unsupported extension, binary, dependency folders) are
        skipped silently."""
