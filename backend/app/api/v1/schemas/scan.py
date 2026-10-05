from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.application.dto.scan import ScanList, ScanReport, ScanSummary
from app.domain.entities.finding import Finding, FindingReference
from app.domain.entities.scan import ScanFile
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from app.domain.value_objects.source_type import SourceType


class ScanResponse(BaseModel):
    id: UUID
    source_type: SourceType
    status: ScanStatus
    progress_percent: int
    error_message: str | None
    total_files: int
    total_findings: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    @classmethod
    def from_dto(cls, dto: ScanSummary) -> ScanResponse:
        return cls(
            id=dto.id,
            source_type=dto.source_type,
            status=dto.status,
            progress_percent=dto.progress_percent,
            error_message=dto.error_message,
            total_files=dto.total_files,
            total_findings=dto.total_findings,
            created_at=dto.created_at,
            started_at=dto.started_at,
            completed_at=dto.completed_at,
        )


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int
    limit: int
    offset: int

    @classmethod
    def from_dto(cls, dto: ScanList, *, limit: int, offset: int) -> ScanListResponse:
        return cls(
            scans=[ScanResponse.from_dto(scan) for scan in dto.scans],
            total=dto.total,
            limit=limit,
            offset=offset,
        )


class ScanFileResponse(BaseModel):
    id: UUID
    filename: str
    relative_path: str
    language: str | None
    size_bytes: int
    loc: int

    @classmethod
    def from_entity(cls, file: ScanFile) -> ScanFileResponse:
        return cls(
            id=file.id,
            filename=file.filename,
            relative_path=file.relative_path,
            language=file.language,
            size_bytes=file.size_bytes,
            loc=file.loc,
        )


class FindingReferenceResponse(BaseModel):
    source: ReferenceSource
    ref_id: str
    title: str
    url: str | None

    @classmethod
    def from_entity(cls, reference: FindingReference) -> FindingReferenceResponse:
        return cls(
            source=reference.source,
            ref_id=reference.ref_id,
            title=reference.title,
            url=reference.url,
        )


class FindingResponse(BaseModel):
    id: UUID
    scan_file_id: UUID | None
    title: str
    severity: Severity
    confidence: float
    cwe_id: str | None
    owasp_category: str | None
    attack_technique_id: str | None
    file_path: str
    line_start: int
    line_end: int
    vulnerable_snippet: str
    explanation: str
    recommendation: str
    fixed_code: str | None
    references: list[FindingReferenceResponse]

    @classmethod
    def from_entity(cls, finding: Finding) -> FindingResponse:
        return cls(
            id=finding.id,
            scan_file_id=finding.scan_file_id,
            title=finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
            cwe_id=finding.cwe_id,
            owasp_category=finding.owasp_category,
            attack_technique_id=finding.attack_technique_id,
            file_path=finding.location.file_path,
            line_start=finding.location.line_start,
            line_end=finding.location.line_end,
            vulnerable_snippet=finding.vulnerable_snippet,
            explanation=finding.explanation,
            recommendation=finding.recommendation,
            fixed_code=finding.fixed_code,
            references=[
                FindingReferenceResponse.from_entity(reference) for reference in finding.references
            ],
        )


class ScanReportResponse(BaseModel):
    scan: ScanResponse
    severity_counts: dict[Severity, int]
    files: list[ScanFileResponse]
    findings: list[FindingResponse]

    @classmethod
    def from_dto(cls, dto: ScanReport) -> ScanReportResponse:
        return cls(
            scan=ScanResponse.from_dto(dto.scan),
            severity_counts=dto.severity_counts,
            files=[ScanFileResponse.from_entity(file) for file in dto.files],
            findings=[FindingResponse.from_entity(finding) for finding in dto.findings],
        )
