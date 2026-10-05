from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from uuid import UUID

from app.domain.entities.scan import Scan, ScanFile
from app.domain.value_objects.scan_status import ScanStatus


class ScanRepository(ABC):
    @abstractmethod
    async def add(self, scan: Scan, files: Sequence[ScanFile]) -> None: ...

    @abstractmethod
    async def get_by_id(self, scan_id: UUID) -> Scan | None: ...

    @abstractmethod
    async def list_for_user(self, user_id: UUID, *, limit: int = 20, offset: int = 0) -> list[Scan]:
        """Most recent first."""

    @abstractmethod
    async def count_for_user(self, user_id: UUID) -> int: ...

    @abstractmethod
    async def count_by_status_for_user(self, user_id: UUID) -> dict[ScanStatus, int]:
        """Only statuses the user has at least one scan in are present."""

    @abstractmethod
    async def list_files(self, scan_id: UUID) -> list[ScanFile]:
        """Ordered by `relative_path`, so progress and reports are stable."""

    @abstractmethod
    async def update(self, scan: Scan) -> None:
        """Persists the mutable lifecycle fields (status, progress, error,
        counters, started/completed timestamps) of an existing scan."""

    @abstractmethod
    async def delete(self, scan_id: UUID) -> None:
        """Removes the scan along with its files and findings."""

    @abstractmethod
    async def fail_unfinished(self, error_message: str) -> int:
        """Marks every PENDING/RUNNING scan as FAILED and returns how many
        were affected. Called once at startup: jobs run in-process, so a scan
        still unfinished when the process starts can never complete."""
