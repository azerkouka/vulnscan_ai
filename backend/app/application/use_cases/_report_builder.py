"""How a scan's findings are ordered and counted in a report - shared by the
on-screen report and the exported one, so the two can never disagree."""

from __future__ import annotations

from app.domain.entities.finding import Finding
from app.domain.value_objects.severity import Severity


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by file and line."""
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, f.location.file_path, f.location.line_start, f.title),
    )


def count_by_severity(findings: list[Finding]) -> dict[Severity, int]:
    """Every severity is present as a key, with 0 when it has no finding."""
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    return counts
