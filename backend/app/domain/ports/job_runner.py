from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID


class JobRunner(ABC):
    @abstractmethod
    async def enqueue_scan(self, scan_id: UUID) -> None:
        """Schedules the analysis of an already-persisted PENDING scan and
        returns without waiting for it. The scan row itself is the job's
        state: callers follow progress by reading the scan, not the runner."""
