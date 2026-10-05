from __future__ import annotations

import asyncio
from collections.abc import Mapping
from datetime import UTC, datetime
from uuid import UUID

from app.application.dto.scan import ExportedReport
from app.application.use_cases._report_builder import count_by_severity, sort_findings
from app.application.use_cases._scan_access import get_owned_scan
from app.domain.entities.report import ScanReportData
from app.domain.exceptions import ReportFormatUnavailableError, ScanInProgressError
from app.domain.ports.report_exporter import ReportExporter
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.report_format import ReportFormat
from app.domain.value_objects.scan_status import ScanStatus


class ExportScanReportUseCase:
    def __init__(self, uow: UnitOfWork, exporters: Mapping[ReportFormat, ReportExporter]) -> None:
        self._uow = uow
        self._exporters = exporters

    async def execute(
        self, user_id: UUID, scan_id: UUID, report_format: ReportFormat
    ) -> ExportedReport:
        exporter = self._exporters.get(report_format)
        if exporter is None:
            raise ReportFormatUnavailableError(
                f"Export to {report_format.value} is not available on this installation."
            )

        async with self._uow:
            scan = await get_owned_scan(self._uow, user_id, scan_id)
            if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                # A file is a snapshot people keep and forward: don't hand out
                # one that would silently be missing findings still to come.
                raise ScanInProgressError(
                    "This scan is still in progress; export its report once it ends."
                )
            files = await self._uow.scans.list_files(scan_id)
            findings = await self._uow.findings.list_for_scan(scan_id)

        report = ScanReportData(
            scan=scan,
            files=files,
            findings=sort_findings(findings),
            severity_counts=count_by_severity(findings),
            generated_at=datetime.now(UTC),
        )
        # Rendering (PDF layout in particular) is CPU-bound - keep it off the event loop.
        content = await asyncio.to_thread(exporter.export, report)

        return ExportedReport(
            content=content,
            media_type=exporter.media_type,
            filename=f"vulnscan-report-{scan.id}.{exporter.file_extension}",
        )
