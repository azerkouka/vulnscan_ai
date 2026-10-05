from __future__ import annotations

from abc import ABC, abstractmethod

from app.domain.entities.report import ScanReportData


class ReportExporter(ABC):
    """Renders a scan report into one downloadable file format."""

    @property
    @abstractmethod
    def media_type(self) -> str: ...

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Without the dot, e.g. "pdf"."""

    @abstractmethod
    def export(self, report: ScanReportData) -> bytes:
        """Synchronous and possibly CPU-heavy (PDF layout): callers run it
        off the event loop.

        Report content is untrusted - it is text an LLM wrote about code a
        user submitted - so an implementation must encode it for its output
        format and never interpret it (as markup, as a URL to fetch, ...).

        Raises `app.domain.exceptions.ReportFormatUnavailableError` if the
        format can't be produced on this installation."""
