from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.source_type import SourceType


@dataclass(frozen=True, slots=True)
class ScanFile:
    id: UUID
    scan_id: UUID
    filename: str
    relative_path: str
    language: str | None
    size_bytes: int
    content_hash: str
    loc: int


@dataclass(frozen=True, slots=True)
class Scan:
    id: UUID
    user_id: UUID
    source_type: SourceType
    status: ScanStatus
    progress_percent: int
    error_message: str | None
    total_files: int
    total_findings: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
