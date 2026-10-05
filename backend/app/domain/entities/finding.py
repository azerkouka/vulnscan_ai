from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.severity import Severity


@dataclass(frozen=True, slots=True)
class FindingReference:
    source: ReferenceSource
    ref_id: str
    title: str
    url: str | None


@dataclass(frozen=True, slots=True)
class Finding:
    id: UUID
    scan_id: UUID
    scan_file_id: UUID | None
    title: str
    cwe_id: str | None
    owasp_category: str | None
    attack_technique_id: str | None
    severity: Severity
    confidence: float
    location: CodeLocation
    vulnerable_snippet: str
    explanation: str
    recommendation: str
    fixed_code: str | None
    references: list[FindingReference]
    created_at: datetime
