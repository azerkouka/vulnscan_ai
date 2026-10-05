from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from uuid import UUID

from app.domain.entities.finding import Finding
from app.domain.value_objects.severity import Severity


class FindingRepository(ABC):
    @abstractmethod
    async def add_many(self, findings: Sequence[Finding]) -> None: ...

    @abstractmethod
    async def list_for_scan(self, scan_id: UUID) -> list[Finding]: ...

    @abstractmethod
    async def count_by_severity_for_user(self, user_id: UUID) -> dict[Severity, int]:
        """Across all of the user's scans; only severities with at least one
        finding are present."""

    @abstractmethod
    async def top_cwes_for_user(self, user_id: UUID, *, limit: int = 5) -> list[tuple[str, int]]:
        """The CWE ids most often found across the user's scans, with their
        counts, most frequent first. Findings without a CWE are not counted."""
