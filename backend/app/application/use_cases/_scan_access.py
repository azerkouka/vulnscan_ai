"""Shared ownership check for every use case that reads or deletes a scan."""

from __future__ import annotations

from uuid import UUID

from app.domain.entities.scan import Scan
from app.domain.exceptions import ScanNotFoundError
from app.domain.ports.unit_of_work import UnitOfWork


async def get_owned_scan(uow: UnitOfWork, user_id: UUID, scan_id: UUID) -> Scan:
    """Another user's scan raises the same error as a missing one, so scan
    ids can't be probed for existence."""
    scan = await uow.scans.get_by_id(scan_id)
    if scan is None or scan.user_id != user_id:
        raise ScanNotFoundError(f"No scan with id {scan_id}.")
    return scan
