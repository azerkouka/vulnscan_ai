from __future__ import annotations

from uuid import UUID

from app.application.dto.scan import ScanSummary
from app.application.use_cases._scan_access import get_owned_scan
from app.domain.ports.unit_of_work import UnitOfWork


class GetScanUseCase:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, user_id: UUID, scan_id: UUID) -> ScanSummary:
        async with self._uow:
            scan = await get_owned_scan(self._uow, user_id, scan_id)
        return ScanSummary.from_scan(scan)
