from __future__ import annotations

from uuid import UUID

from app.application.dto.scan import ScanReport, ScanSummary
from app.application.use_cases._report_builder import count_by_severity, sort_findings
from app.application.use_cases._scan_access import get_owned_scan
from app.domain.ports.unit_of_work import UnitOfWork


class GetScanReportUseCase:
    """Available at any scan status: while a scan is still running, the
    report simply holds the findings recorded so far."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, user_id: UUID, scan_id: UUID) -> ScanReport:
        async with self._uow:
            scan = await get_owned_scan(self._uow, user_id, scan_id)
            files = await self._uow.scans.list_files(scan_id)
            findings = await self._uow.findings.list_for_scan(scan_id)

        return ScanReport(
            scan=ScanSummary.from_scan(scan),
            files=files,
            findings=sort_findings(findings),
            severity_counts=count_by_severity(findings),
        )
