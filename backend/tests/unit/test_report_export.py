import json
import sys
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.export_scan_report import ExportScanReportUseCase
from app.domain.entities.finding import Finding, FindingReference
from app.domain.entities.report import ScanReportData
from app.domain.exceptions import (
    ReportFormatUnavailableError,
    ScanInProgressError,
    ScanNotFoundError,
)
from app.domain.ports.report_exporter import ReportExporter
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.report_format import ReportFormat
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from app.infrastructure.export.json_exporter import JsonReportExporter
from app.infrastructure.export.pdf_exporter import PdfReportExporter, _refuse_every_url
from tests.unit.fakes import FakeUnitOfWork
from tests.unit.helpers import make_scan, make_scan_file

_HOSTILE_TITLE = '<img src="http://127.0.0.1:9/steal.png" onerror="alert(1)">'


def _finding(scan_id: UUID, **overrides: object) -> Finding:
    values: dict[str, object] = {
        "id": uuid4(),
        "scan_id": scan_id,
        "scan_file_id": None,
        "title": "SQL injection",
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021",
        "attack_technique_id": None,
        "severity": Severity.HIGH,
        "confidence": 0.87,
        "location": CodeLocation("src/app.py", 12, 13),
        "vulnerable_snippet": "    query = 'SELECT ' + name\n    return run(query)",
        "explanation": "User input is concatenated into the query.",
        "recommendation": "Use a parameterized query.",
        "fixed_code": "run('SELECT ?', (name,))",
        "references": [
            FindingReference(
                ReferenceSource.CWE,
                "CWE-89",
                "SQL Injection",
                "https://cwe.mitre.org/data/definitions/89.html",
            )
        ],
        "created_at": datetime.now(UTC),
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def _report(findings: list[Finding] | None = None, **scan_overrides: object) -> ScanReportData:
    scan = replace(make_scan(status=ScanStatus.COMPLETED), **scan_overrides)  # type: ignore[arg-type]
    findings = findings if findings is not None else [_finding(scan.id)]
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    return ScanReportData(
        scan=scan,
        files=[make_scan_file(scan.id, relative_path="src/app.py", content="a\nb\nc\n")],
        findings=findings,
        severity_counts=counts,
        generated_at=datetime(2026, 10, 5, 12, 30, tzinfo=UTC),
    )


# --- JSON ----------------------------------------------------------------------


@pytest.mark.unit
def test_json_export_is_a_complete_structured_document() -> None:
    report = _report()

    exporter = JsonReportExporter()
    document = json.loads(exporter.export(report))

    assert (exporter.media_type, exporter.file_extension) == ("application/json", "json")
    assert document["schema_version"] == 1
    assert document["generated_at"] == "2026-10-05T12:30:00+00:00"
    assert document["scan"]["id"] == str(report.scan.id)
    assert document["scan"]["status"] == "COMPLETED"
    assert document["summary"] == {
        "total_files": 1,
        "total_lines": 3,
        "total_findings": 1,
        "findings_by_severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 0},
    }
    assert document["files"][0]["path"] == "src/app.py"
    [finding] = document["findings"]
    assert finding["title"] == "SQL injection"
    assert finding["severity"] == "HIGH"
    assert finding["location"] == {"file": "src/app.py", "line_start": 12, "line_end": 13}
    assert finding["vulnerable_snippet"] == "    query = 'SELECT ' + name\n    return run(query)"
    assert finding["references"] == [
        {
            "source": "CWE",
            "id": "CWE-89",
            "title": "SQL Injection",
            "url": "https://cwe.mitre.org/data/definitions/89.html",
        }
    ]


@pytest.mark.unit
def test_json_export_keeps_text_verbatim_including_markup_and_non_ascii() -> None:
    scan_id = uuid4()
    report = _report([_finding(scan_id, title=_HOSTILE_TITLE, explanation="Entrée non validée ✓")])

    raw = JsonReportExporter().export(report)
    [finding] = json.loads(raw)["findings"]

    # JSON has no markup to inject into: the text is data, returned as it is.
    assert finding["title"] == _HOSTILE_TITLE
    assert finding["explanation"] == "Entrée non validée ✓"
    assert "Entrée non validée ✓".encode() in raw


# --- HTML (the intermediate form of the PDF) -------------------------------------


@pytest.fixture
def render_html():  # type: ignore[no-untyped-def]
    pytest.importorskip("jinja2", reason="install the 'export' extra to run this")
    from app.infrastructure.export.report_html import render_report_html

    return render_report_html


@pytest.mark.unit
def test_html_report_shows_the_scan_and_its_findings(render_html) -> None:  # type: ignore[no-untyped-def]
    html = render_html(_report())

    assert "Security scan report" in html
    assert "2026-10-05 12:30 UTC" in html
    assert "SQL injection" in html
    assert "src/app.py, lines 12-13" in html
    assert "confidence 87%" in html
    assert "CWE-89 - SQL Injection" in html
    assert '<span class="ln">12</span>      query = &#39;SELECT &#39; + name' in html
    assert "proof that the code is secure" in " ".join(html.split())


@pytest.mark.unit
def test_html_report_escapes_everything_that_comes_from_the_scan(render_html) -> None:  # type: ignore[no-untyped-def]
    scan_id = uuid4()
    hostile = _finding(
        scan_id,
        title=_HOSTILE_TITLE,
        explanation='<script src="http://127.0.0.1:9/x.js"></script>',
        recommendation='<link rel="stylesheet" href="http://127.0.0.1:9/x.css">',
        vulnerable_snippet='</pre><iframe src="file:///etc/passwd"></iframe>',
        fixed_code="<style>@import url(http://127.0.0.1:9/x.css)</style>",
        location=CodeLocation('"><img src=x>.py', 1, 1),
        references=[
            FindingReference(ReferenceSource.OTHER, "<b>id</b>", "<i>title</i>", "javascript:x")
        ],
    )
    report = _report([hostile], error_message="<u>partial</u>")

    html = render_html(report)

    for tag in ("<img", "<script", "<iframe", "<link", "<b>", "<i>", "<u>"):
        assert tag not in html, f"{tag} from report content reached the HTML unescaped"
    # The document's own <style> block is the only one.
    assert html.count("<style") == 1
    assert "&lt;img src=&#34;http://127.0.0.1:9/steal.png&#34;" in html


@pytest.mark.unit
def test_html_report_of_a_failed_or_empty_scan(render_html) -> None:  # type: ignore[no-untyped-def]
    failed = render_html(
        ScanReportData(
            scan=make_scan(status=ScanStatus.FAILED),
            files=[],
            findings=[],
            severity_counts={severity: 0 for severity in Severity},
            generated_at=datetime(2026, 10, 5, 12, 30, tzinfo=UTC),
        )
    )

    assert "This scan failed." in failed
    assert "No finding was recorded for this scan." in failed
    assert "0 files, 0 lines" in " ".join(failed.split())


# --- PDF -------------------------------------------------------------------------


@pytest.fixture
def pdf_exporter() -> PdfReportExporter:
    exporter = PdfReportExporter()
    try:
        exporter.export(_report([]))
    except ReportFormatUnavailableError:
        pytest.skip("WeasyPrint is not installed (install the 'export' extra to run this)")
    return exporter


@pytest.mark.unit
def test_pdf_export_produces_a_pdf(pdf_exporter: PdfReportExporter) -> None:
    pdf = pdf_exporter.export(_report())

    assert (pdf_exporter.media_type, pdf_exporter.file_extension) == ("application/pdf", "pdf")
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 2000


@pytest.mark.unit
def test_pdf_export_never_fetches_what_report_content_points_to(
    pdf_exporter: PdfReportExporter,
) -> None:
    scan_id = uuid4()
    hostile = _finding(
        scan_id,
        title=_HOSTILE_TITLE,
        explanation='<img src="http://127.0.0.1:9/a.png"><link rel=stylesheet href="file:///etc/passwd">',
        fixed_code="<style>@import url(http://127.0.0.1:9/x.css)</style>",
    )

    # If any of this were interpreted as markup, the renderer would call the
    # URL fetcher, which refuses every URL - and WeasyPrint logs, not raises,
    # so the proof is in the fetcher never being reached (see the next test)
    # together with the HTML-escaping test above. Here: the export succeeds.
    pdf = pdf_exporter.export(_report([hostile]))

    assert pdf.startswith(b"%PDF-")


@pytest.mark.unit
def test_pdf_url_fetcher_refuses_every_url() -> None:
    for url in ("http://127.0.0.1/admin", "https://example.com/x.css", "file:///etc/passwd"):
        with pytest.raises(ValueError, match="not allowed"):
            _refuse_every_url(url)


@pytest.mark.unit
def test_pdf_export_reports_itself_unavailable_without_its_library(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "weasyprint", None)  # makes `import weasyprint` fail

    with pytest.raises(ReportFormatUnavailableError, match="PDF export is not available"):
        PdfReportExporter().export(_report([]))


# --- Use case ----------------------------------------------------------------------


class _RecordingExporter(ReportExporter):
    def __init__(self) -> None:
        self.reports: list[ScanReportData] = []

    @property
    def media_type(self) -> str:
        return "text/plain"

    @property
    def file_extension(self) -> str:
        return "txt"

    def export(self, report: ScanReportData) -> bytes:
        self.reports.append(report)
        return b"exported"


async def _finished_scan(uow: FakeUnitOfWork, status: ScanStatus = ScanStatus.COMPLETED):  # type: ignore[no-untyped-def]
    scan = make_scan(status=status)
    await uow.scans.add(scan, [make_scan_file(scan.id)])
    return scan


@pytest.mark.unit
async def test_export_hands_the_sorted_report_to_the_exporter_of_that_format() -> None:
    uow = FakeUnitOfWork()
    scan = await _finished_scan(uow)
    await uow.findings.add_many(
        [
            _finding(scan.id, title="Low one", severity=Severity.LOW),
            _finding(scan.id, title="Critical one", severity=Severity.CRITICAL),
        ]
    )
    exporter = _RecordingExporter()

    result = await ExportScanReportUseCase(uow, {ReportFormat.JSON: exporter}).execute(
        scan.user_id, scan.id, ReportFormat.JSON
    )

    assert result.content == b"exported"
    assert result.media_type == "text/plain"
    assert result.filename == f"vulnscan-report-{scan.id}.txt"
    [report] = exporter.reports
    assert [f.title for f in report.findings] == ["Critical one", "Low one"]
    assert report.severity_counts[Severity.CRITICAL] == 1
    assert len(report.files) == 1


@pytest.mark.unit
async def test_export_of_a_failed_scan_is_allowed() -> None:
    uow = FakeUnitOfWork()
    scan = await _finished_scan(uow, ScanStatus.FAILED)

    result = await ExportScanReportUseCase(uow, {ReportFormat.JSON: _RecordingExporter()}).execute(
        scan.user_id, scan.id, ReportFormat.JSON
    )

    assert result.content == b"exported"


@pytest.mark.unit
@pytest.mark.parametrize("status", [ScanStatus.PENDING, ScanStatus.RUNNING])
async def test_export_refuses_a_scan_still_in_progress(status: ScanStatus) -> None:
    uow = FakeUnitOfWork()
    scan = await _finished_scan(uow, status)
    exporter = _RecordingExporter()

    with pytest.raises(ScanInProgressError):
        await ExportScanReportUseCase(uow, {ReportFormat.JSON: exporter}).execute(
            scan.user_id, scan.id, ReportFormat.JSON
        )

    assert exporter.reports == []


@pytest.mark.unit
async def test_export_of_another_users_scan_is_not_found() -> None:
    uow = FakeUnitOfWork()
    scan = await _finished_scan(uow)
    exporter = _RecordingExporter()

    with pytest.raises(ScanNotFoundError):
        await ExportScanReportUseCase(uow, {ReportFormat.JSON: exporter}).execute(
            uuid4(), scan.id, ReportFormat.JSON
        )

    assert exporter.reports == []


@pytest.mark.unit
async def test_export_to_a_format_without_an_exporter_is_unavailable() -> None:
    uow = FakeUnitOfWork()
    scan = await _finished_scan(uow)

    with pytest.raises(ReportFormatUnavailableError, match="pdf"):
        await ExportScanReportUseCase(uow, {ReportFormat.JSON: _RecordingExporter()}).execute(
            scan.user_id, scan.id, ReportFormat.PDF
        )
