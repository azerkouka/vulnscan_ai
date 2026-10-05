"""JSON export: the report as structured data, for scripts and other tools.

`schema_version` is bumped whenever a field is renamed or removed, so a
consumer can tell which shape it is reading.
"""

from __future__ import annotations

import json
from typing import Any

from app.domain.entities.finding import Finding
from app.domain.entities.report import ScanReportData
from app.domain.ports.report_exporter import ReportExporter

SCHEMA_VERSION = 1


class JsonReportExporter(ReportExporter):
    @property
    def media_type(self) -> str:
        return "application/json"

    @property
    def file_extension(self) -> str:
        return "json"

    def export(self, report: ScanReportData) -> bytes:
        scan = report.scan
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "generator": "VulnScan AI",
            "generated_at": report.generated_at.isoformat(),
            "scan": {
                "id": str(scan.id),
                "source_type": scan.source_type.value,
                "status": scan.status.value,
                "error_message": scan.error_message,
                "created_at": scan.created_at.isoformat(),
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "summary": {
                "total_files": len(report.files),
                "total_lines": sum(file.loc for file in report.files),
                "total_findings": len(report.findings),
                "findings_by_severity": {
                    severity.value: count for severity, count in report.severity_counts.items()
                },
            },
            "files": [
                {
                    "path": file.relative_path,
                    "language": file.language,
                    "lines": file.loc,
                    "size_bytes": file.size_bytes,
                    "sha256": file.content_hash,
                }
                for file in report.files
            ],
            "findings": [_finding(finding) for finding in report.findings],
        }
        # ensure_ascii=False: source code and explanations keep their
        # non-ASCII characters readable instead of becoming \\uXXXX escapes.
        return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8")


def _finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence,
        "cwe_id": finding.cwe_id,
        "owasp_category": finding.owasp_category,
        "attack_technique_id": finding.attack_technique_id,
        "location": {
            "file": finding.location.file_path,
            "line_start": finding.location.line_start,
            "line_end": finding.location.line_end,
        },
        "vulnerable_snippet": finding.vulnerable_snippet,
        "explanation": finding.explanation,
        "recommendation": finding.recommendation,
        "fixed_code": finding.fixed_code,
        "references": [
            {
                "source": reference.source.value,
                "id": reference.ref_id,
                "title": reference.title,
                "url": reference.url,
            }
            for reference in finding.references
        ],
    }
