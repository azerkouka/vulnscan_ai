from __future__ import annotations

from pydantic import BaseModel

from app.api.v1.schemas.scan import ScanResponse
from app.application.dto.scan import DashboardSummary
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity


class CweCountResponse(BaseModel):
    cwe_id: str
    count: int


class DashboardSummaryResponse(BaseModel):
    total_scans: int
    scans_by_status: dict[ScanStatus, int]
    total_findings: int
    findings_by_severity: dict[Severity, int]
    top_cwes: list[CweCountResponse]
    recent_scans: list[ScanResponse]

    @classmethod
    def from_dto(cls, dto: DashboardSummary) -> DashboardSummaryResponse:
        return cls(
            total_scans=dto.total_scans,
            scans_by_status=dto.scans_by_status,
            total_findings=dto.total_findings,
            findings_by_severity=dto.findings_by_severity,
            top_cwes=[
                CweCountResponse(cwe_id=item.cwe_id, count=item.count) for item in dto.top_cwes
            ],
            recent_scans=[ScanResponse.from_dto(scan) for scan in dto.recent_scans],
        )
