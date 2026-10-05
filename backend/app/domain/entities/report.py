from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.domain.entities.finding import Finding
from app.domain.entities.scan import Scan, ScanFile
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True, slots=True)
class ScanReportData:
    """Everything a report says about one scan, ready to be rendered -
    what a `ReportExporter` turns into a file."""

    scan: Scan
    files: list[ScanFile]
    findings: list[Finding]
    """Most severe first, then by file and line."""
    severity_counts: dict[Severity, int]
    """Every severity is present as a key, with 0 when it has no finding."""
    generated_at: datetime
