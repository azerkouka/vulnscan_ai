"""PDF export, laid out by WeasyPrint from the HTML of `report_html`.

WeasyPrint (optional `export` extra, plus system libraries the Docker image
installs) is imported only when a PDF is actually requested, so the rest of
the app runs without it.

A PDF renderer is also an HTTP client: it will download whatever an
`<img>`, `<link>` or CSS `url()` in its input points to, from inside the
server's network. The HTML is escaped so report content can't add such a
reference, and as a second, independent barrier the renderer is given a
fetcher that refuses every URL - so even a mistake in the template could
not be turned into a request to an internal service.
"""

from __future__ import annotations

from typing import Any

from app.domain.entities.report import ScanReportData
from app.domain.exceptions import ReportFormatUnavailableError
from app.domain.ports.report_exporter import ReportExporter


def _refuse_every_url(url: str, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise ValueError(f"External resources are not allowed in reports (requested: {url!r}).")


class PdfReportExporter(ReportExporter):
    @property
    def media_type(self) -> str:
        return "application/pdf"

    @property
    def file_extension(self) -> str:
        return "pdf"

    def export(self, report: ScanReportData) -> bytes:
        try:
            import weasyprint

            from app.infrastructure.export.report_html import render_report_html
        except (ImportError, OSError) as exc:
            # OSError: the package is there but its system libraries (Pango) are not.
            raise ReportFormatUnavailableError(
                "PDF export is not available on this installation."
            ) from exc

        document = weasyprint.HTML(string=render_report_html(report), url_fetcher=_refuse_every_url)
        pdf: bytes = document.write_pdf()
        return pdf
