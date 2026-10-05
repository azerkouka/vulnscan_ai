from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.entities.finding import Finding
from app.domain.entities.scan import Scan, ScanFile
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from app.domain.value_objects.source_type import SourceType


@dataclass(frozen=True, slots=True)
class CreateScanInput:
    user_id: UUID
    content: bytes
    filename: str | None = None
    """None means a pasted snippet; otherwise the uploaded file's name."""
    language: str | None = None
    """Optional hint, only meaningful for a snippet (which has no extension
    to detect the language from)."""


@dataclass(frozen=True, slots=True)
class ScanSummary:
    id: UUID
    source_type: SourceType
    status: ScanStatus
    progress_percent: int
    error_message: str | None
    total_files: int
    total_findings: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    @classmethod
    def from_scan(cls, scan: Scan) -> ScanSummary:
        return cls(
            id=scan.id,
            source_type=scan.source_type,
            status=scan.status,
            progress_percent=scan.progress_percent,
            error_message=scan.error_message,
            total_files=scan.total_files,
            total_findings=scan.total_findings,
            created_at=scan.created_at,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
        )


@dataclass(frozen=True, slots=True)
class ScanList:
    scans: list[ScanSummary]
    total: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    scan: ScanSummary
    files: list[ScanFile]
    findings: list[Finding]
    """Most severe first, then by file and line."""
    severity_counts: dict[Severity, int]
    """Every severity is present as a key, with 0 when it has no finding."""


@dataclass(frozen=True, slots=True)
class CweCount:
    cwe_id: str
    count: int


@dataclass(frozen=True, slots=True)
class DashboardSummary:
    total_scans: int
    scans_by_status: dict[ScanStatus, int]
    total_findings: int
    findings_by_severity: dict[Severity, int]
    top_cwes: list[CweCount]
    recent_scans: list[ScanSummary]


@dataclass(frozen=True, slots=True)
class ExportedReport:
    content: bytes
    media_type: str
    filename: str
