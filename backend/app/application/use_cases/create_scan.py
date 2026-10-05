"""Validates submitted source, stores it, records a PENDING scan and hands
it to the job runner - the analysis itself happens later, in
`RunScanAnalysisUseCase`.

Submitted code is only ever treated as text: it is decoded, hashed, counted
and stored, never imported or executed.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from uuid import uuid4

from app.application.dto.scan import CreateScanInput, ScanSummary
from app.domain.entities.scan import Scan, ScanFile
from app.domain.exceptions import InvalidSourceError, SourceTooLargeError
from app.domain.ports.archive_extractor import ArchiveExtractor, ExtractedFile
from app.domain.ports.job_runner import JobRunner
from app.domain.ports.source_storage import SourceStorage
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.source_text import normalize_newlines, split_lines
from app.domain.value_objects.language import (
    SUPPORTED_LANGUAGES,
    detect_language,
    extension_for_language,
)
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.source_type import SourceType

_ARCHIVE_EXTENSION = ".zip"
_MAX_FILENAME_LENGTH = 255


@dataclass(frozen=True, slots=True)
class ScanSourceLimits:
    max_upload_bytes: int
    allowed_extensions: frozenset[str]
    """Lower-case, dot-prefixed (".py"); includes ".zip" if archives are accepted."""


class CreateScanUseCase:
    def __init__(
        self,
        uow: UnitOfWork,
        storage: SourceStorage,
        extractor: ArchiveExtractor,
        job_runner: JobRunner,
        limits: ScanSourceLimits,
    ) -> None:
        self._uow = uow
        self._storage = storage
        self._extractor = extractor
        self._job_runner = job_runner
        self._limits = limits

    async def execute(self, data: CreateScanInput) -> ScanSummary:
        if len(data.content) > self._limits.max_upload_bytes:
            limit_mb = self._limits.max_upload_bytes / (1024 * 1024)
            raise SourceTooLargeError(f"Submitted source exceeds the {limit_mb:g} MB limit.")

        source_type, resolved = await self._resolve_sources(data)
        sources = [
            ExtractedFile(source.relative_path, normalize_newlines(source.content))
            for source in resolved
        ]

        scan_id = uuid4()
        files = [
            ScanFile(
                id=uuid4(),
                scan_id=scan_id,
                filename=PurePosixPath(source.relative_path).name,
                relative_path=source.relative_path,
                language=detect_language(source.relative_path),
                size_bytes=len(source.content.encode("utf-8")),
                content_hash=hashlib.sha256(source.content.encode("utf-8")).hexdigest(),
                loc=len(split_lines(source.content)),
            )
            for source in sources
        ]
        scan = Scan(
            id=scan_id,
            user_id=data.user_id,
            source_type=source_type,
            status=ScanStatus.PENDING,
            progress_percent=0,
            error_message=None,
            total_files=len(files),
            total_findings=0,
            created_at=datetime.now(UTC),
            started_at=None,
            completed_at=None,
        )

        try:
            for file, source in zip(files, sources, strict=True):
                await self._storage.save(scan_id, file.id, source.content)
            async with self._uow:
                await self._uow.scans.add(scan, files)
                await self._uow.commit()
        except Exception:
            # Don't leave stored source behind for a scan that was never recorded.
            await self._storage.delete_scan(scan_id)
            raise

        await self._job_runner.enqueue_scan(scan_id)
        return ScanSummary.from_scan(scan)

    async def _resolve_sources(
        self, data: CreateScanInput
    ) -> tuple[SourceType, list[ExtractedFile]]:
        if data.filename is None:
            return SourceType.SNIPPET, [self._snippet(data)]

        filename = _safe_filename(data.filename)
        extension = PurePosixPath(filename).suffix.lower()
        if extension not in self._limits.allowed_extensions:
            allowed = ", ".join(sorted(self._limits.allowed_extensions))
            raise InvalidSourceError(
                f"Unsupported file type {extension or filename!r}; allowed: {allowed}."
            )

        if extension == _ARCHIVE_EXTENSION:
            # Decompression is CPU-bound and can be sizeable - keep it off the event loop.
            extracted = await asyncio.to_thread(self._extractor.extract, data.content)
            return SourceType.ZIP, extracted

        return SourceType.FILE, [ExtractedFile(filename, _decode_source(data.content))]

    def _snippet(self, data: CreateScanInput) -> ExtractedFile:
        extension = ".txt"
        if data.language:
            language = data.language.strip().lower()
            if language not in SUPPORTED_LANGUAGES:
                supported = ", ".join(sorted(SUPPORTED_LANGUAGES))
                raise InvalidSourceError(
                    f"Unsupported language {data.language!r}; supported: {supported}."
                )
            extension = extension_for_language(language) or extension
        return ExtractedFile(f"snippet{extension}", _decode_source(data.content))


def _safe_filename(raw: str) -> str:
    """The bare, printable file name of whatever the client sent as a name -
    it is only ever displayed and used for its extension, never as a path."""
    name = PurePosixPath(raw.replace("\\", "/")).name
    name = "".join(char for char in name if char.isprintable()).strip()
    if not name:
        raise InvalidSourceError("The uploaded file has no usable name.")
    return name[-_MAX_FILENAME_LENGTH:]


def _decode_source(content: bytes) -> str:
    if b"\0" in content:
        raise InvalidSourceError("The submitted source looks like a binary file, not source code.")
    text = content.decode("utf-8-sig", errors="replace")
    if not text.strip():
        raise InvalidSourceError("The submitted source is empty.")
    return text
