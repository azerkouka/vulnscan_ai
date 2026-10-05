"""Marking scans FAILED from outside the analysis itself - for the cases
where `RunScanAnalysisUseCase` never got to run, so couldn't record its own
failure.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.scan_status import ScanStatus

_INTERRUPTED_MESSAGE = "The analysis was interrupted by a server restart; run the scan again."


class FailScanUseCase:
    """For a job that couldn't even be assembled (e.g. the LLM or vector
    store adapter failed to initialize)."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, scan_id: UUID, error_message: str) -> None:
        async with self._uow:
            scan = await self._uow.scans.get_by_id(scan_id)
            if scan is None or scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
                return
            await self._uow.scans.update(
                replace(
                    scan,
                    status=ScanStatus.FAILED,
                    error_message=error_message,
                    completed_at=datetime.now(UTC),
                )
            )
            await self._uow.commit()


class FailInterruptedScansUseCase:
    """Run once at startup - see `ScanRepository.fail_unfinished`."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self) -> int:
        async with self._uow:
            count = await self._uow.scans.fail_unfinished(_INTERRUPTED_MESSAGE)
            await self._uow.commit()
        return count
