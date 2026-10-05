from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID


class SourceStorage(ABC):
    """Holds submitted source text between scan creation and its (later,
    asynchronous) analysis. Keyed only by ids we generate - a name or path
    supplied by the user never reaches the storage backend."""

    @abstractmethod
    async def save(self, scan_id: UUID, file_id: UUID, content: str) -> None: ...

    @abstractmethod
    async def read(self, scan_id: UUID, file_id: UUID) -> str: ...

    @abstractmethod
    async def delete_scan(self, scan_id: UUID) -> None:
        """Removes everything stored for a scan; a no-op if nothing is."""
