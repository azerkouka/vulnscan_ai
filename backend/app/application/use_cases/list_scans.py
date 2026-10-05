from __future__ import annotations

from uuid import UUID

from app.application.dto.scan import ScanList, ScanSummary
from app.domain.ports.unit_of_work import UnitOfWork


class ListScansUseCase:
    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, user_id: UUID, *, limit: int = 20, offset: int = 0) -> ScanList:
        async with self._uow:
            scans = await self._uow.scans.list_for_user(user_id, limit=limit, offset=offset)
            total = await self._uow.scans.count_for_user(user_id)
        return ScanList(scans=[ScanSummary.from_scan(scan) for scan in scans], total=total)
