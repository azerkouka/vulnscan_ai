from __future__ import annotations

from uuid import UUID

from app.application.use_cases._scan_access import get_owned_scan
from app.domain.exceptions import ScanInProgressError
from app.domain.ports.source_storage import SourceStorage
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.scan_status import ScanStatus


class DeleteScanUseCase:
    def __init__(self, uow: UnitOfWork, storage: SourceStorage) -> None:
        self._uow = uow
        self._storage = storage

    async def execute(self, user_id: UUID, scan_id: UUID) -> None:
        async with self._uow:
            scan = await get_owned_scan(self._uow, user_id, scan_id)
            if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                # Its job is still reading the stored source and writing findings.
                raise ScanInProgressError("This scan is still in progress; delete it once it ends.")
            await self._uow.scans.delete(scan_id)
            await self._uow.commit()

        await self._storage.delete_scan(scan_id)
