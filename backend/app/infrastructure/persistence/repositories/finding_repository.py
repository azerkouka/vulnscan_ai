from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.finding import Finding, FindingReference
from app.domain.ports.finding_repository import FindingRepository
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.severity import Severity
from app.infrastructure.persistence.models import (
    FindingModel,
    FindingReferenceModel,
    ScanModel,
)


def _to_domain(model: FindingModel) -> Finding:
    return Finding(
        id=model.id,
        scan_id=model.scan_id,
        scan_file_id=model.scan_file_id,
        title=model.title,
        cwe_id=model.cwe_id,
        owasp_category=model.owasp_category,
        attack_technique_id=model.attack_technique_id,
        severity=Severity(model.severity),
        confidence=model.confidence,
        location=CodeLocation(model.file_path, model.line_start, model.line_end),
        vulnerable_snippet=model.vulnerable_snippet,
        explanation=model.explanation,
        recommendation=model.recommendation,
        fixed_code=model.fixed_code,
        references=[
            FindingReference(
                source=ReferenceSource(reference.source),
                ref_id=reference.ref_id,
                title=reference.title,
                url=reference.url,
            )
            for reference in model.references
        ],
        created_at=model.created_at,
    )


def _to_model(finding: Finding) -> FindingModel:
    return FindingModel(
        id=finding.id,
        scan_id=finding.scan_id,
        scan_file_id=finding.scan_file_id,
        title=finding.title,
        cwe_id=finding.cwe_id,
        owasp_category=finding.owasp_category,
        attack_technique_id=finding.attack_technique_id,
        severity=finding.severity.value,
        confidence=finding.confidence,
        file_path=finding.location.file_path,
        line_start=finding.location.line_start,
        line_end=finding.location.line_end,
        vulnerable_snippet=finding.vulnerable_snippet,
        explanation=finding.explanation,
        recommendation=finding.recommendation,
        fixed_code=finding.fixed_code,
        created_at=finding.created_at,
        references=[
            FindingReferenceModel(
                position=position,
                source=reference.source.value,
                ref_id=reference.ref_id,
                title=reference.title,
                url=reference.url,
            )
            for position, reference in enumerate(finding.references)
        ],
    )


class SqlAlchemyFindingRepository(FindingRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_many(self, findings: Sequence[Finding]) -> None:
        self._session.add_all([_to_model(finding) for finding in findings])

    async def list_for_scan(self, scan_id: UUID) -> list[Finding]:
        stmt = (
            select(FindingModel)
            .where(FindingModel.scan_id == scan_id)
            .order_by(FindingModel.created_at, FindingModel.id)
        )
        models = (await self._session.execute(stmt)).scalars().all()
        return [_to_domain(model) for model in models]

    async def count_by_severity_for_user(self, user_id: UUID) -> dict[Severity, int]:
        stmt = (
            select(FindingModel.severity, func.count())
            .join(ScanModel, ScanModel.id == FindingModel.scan_id)
            .where(ScanModel.user_id == user_id)
            .group_by(FindingModel.severity)
        )
        rows = (await self._session.execute(stmt)).all()
        return {Severity(severity): count for severity, count in rows}

    async def top_cwes_for_user(self, user_id: UUID, *, limit: int = 5) -> list[tuple[str, int]]:
        occurrences = func.count().label("occurrences")
        stmt = (
            select(FindingModel.cwe_id, occurrences)
            .join(ScanModel, ScanModel.id == FindingModel.scan_id)
            .where(ScanModel.user_id == user_id, FindingModel.cwe_id.is_not(None))
            .group_by(FindingModel.cwe_id)
            # Ties broken by id, so the ranking is stable from one call to the next.
            .order_by(occurrences.desc(), FindingModel.cwe_id)
            .limit(limit)
        )
        rows = (await self._session.execute(stmt)).all()
        # The column is nullable; the WHERE clause above already excludes NULLs.
        return [(cwe_id, count) for cwe_id, count in rows if cwe_id is not None]
