from __future__ import annotations

from uuid import UUID

from app.application.dto.scan import CweCount, DashboardSummary, ScanSummary
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity

_RECENT_SCANS = 5
_TOP_CWES = 5


class GetDashboardSummaryUseCase:
    """Everything the dashboard shows about one user's scans, in one call -
    aggregated in SQL rather than by the client paging through every scan."""

    def __init__(self, uow: UnitOfWork) -> None:
        self._uow = uow

    async def execute(self, user_id: UUID) -> DashboardSummary:
        async with self._uow:
            by_status = await self._uow.scans.count_by_status_for_user(user_id)
            by_severity = await self._uow.findings.count_by_severity_for_user(user_id)
            top_cwes = await self._uow.findings.top_cwes_for_user(user_id, limit=_TOP_CWES)
            recent = await self._uow.scans.list_for_user(user_id, limit=_RECENT_SCANS)

        # Every status and severity is present, with 0 when it has no row:
        # the client can render a full breakdown without special cases.
        scans_by_status = {status: by_status.get(status, 0) for status in ScanStatus}
        findings_by_severity = {severity: by_severity.get(severity, 0) for severity in Severity}

        return DashboardSummary(
            total_scans=sum(scans_by_status.values()),
            scans_by_status=scans_by_status,
            total_findings=sum(findings_by_severity.values()),
            findings_by_severity=findings_by_severity,
            top_cwes=[CweCount(cwe_id=cwe_id, count=count) for cwe_id, count in top_cwes],
            recent_scans=[ScanSummary.from_scan(scan) for scan in recent],
        )
