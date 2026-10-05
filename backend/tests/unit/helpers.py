"""Small builders for domain entities, so use-case tests don't repeat
boilerplate field lists.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.domain.entities.knowledge_document import KnowledgeDocumentRecord
from app.domain.entities.scan import Scan, ScanFile
from app.domain.entities.user import User
from app.domain.ports.llm_analyzer import AnalyzedFinding
from app.domain.source_text import split_lines
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from app.domain.value_objects.source_type import SourceType


def make_user(
    *,
    user_id: UUID | None = None,
    email: str = "user@example.com",
    hashed_password: str = "hashed:password123",  # noqa: S107 - fixture data, not a real secret
    full_name: str | None = None,
    is_active: bool = True,
    is_superuser: bool = False,
) -> User:
    now = datetime.now(UTC)
    return User(
        id=user_id or uuid4(),
        email=email,
        hashed_password=hashed_password,
        full_name=full_name,
        is_active=is_active,
        is_superuser=is_superuser,
        created_at=now,
        updated_at=now,
    )


def make_scan(
    *,
    scan_id: UUID | None = None,
    user_id: UUID | None = None,
    source_type: SourceType = SourceType.SNIPPET,
    status: ScanStatus = ScanStatus.PENDING,
    total_files: int = 1,
    total_findings: int = 0,
    created_at: datetime | None = None,
) -> Scan:
    return Scan(
        id=scan_id or uuid4(),
        user_id=user_id or uuid4(),
        source_type=source_type,
        status=status,
        progress_percent=0,
        error_message=None,
        total_files=total_files,
        total_findings=total_findings,
        created_at=created_at or datetime.now(UTC),
        started_at=None,
        completed_at=None,
    )


def make_scan_file(
    scan_id: UUID, *, relative_path: str = "app.py", content: str = "print('hi')\n"
) -> ScanFile:
    return ScanFile(
        id=uuid4(),
        scan_id=scan_id,
        filename=relative_path.rsplit("/", 1)[-1],
        relative_path=relative_path,
        language="python" if relative_path.endswith(".py") else None,
        size_bytes=len(content.encode("utf-8")),
        content_hash="0" * 64,
        loc=len(split_lines(content)),
    )


def make_analyzed_finding(
    *,
    title: str = "SQL injection",
    cwe_id: str | None = "CWE-89",
    owasp_category: str | None = None,
    attack_technique_id: str | None = None,
    severity: Severity = Severity.HIGH,
    confidence: float = 0.9,
    line_start: int = 1,
    line_end: int = 1,
    fixed_code: str | None = None,
) -> AnalyzedFinding:
    return AnalyzedFinding(
        title=title,
        cwe_id=cwe_id,
        owasp_category=owasp_category,
        attack_technique_id=attack_technique_id,
        severity=severity,
        confidence=confidence,
        line_start=line_start,
        line_end=line_end,
        explanation="User input reaches the query unescaped.",
        recommendation="Use a parameterized query.",
        fixed_code=fixed_code,
    )


def make_knowledge_record(
    external_id: str = "CWE-89",
    source: KnowledgeSource = KnowledgeSource.CWE,
    name: str = "SQL Injection",
    url: str | None = "https://cwe.mitre.org/data/definitions/89.html",
) -> KnowledgeDocumentRecord:
    return KnowledgeDocumentRecord(
        external_id=external_id,
        source=source,
        name=name,
        category=None,
        url=url,
        content_hash="0" * 64,
        ingested_at=datetime.now(UTC),
    )
