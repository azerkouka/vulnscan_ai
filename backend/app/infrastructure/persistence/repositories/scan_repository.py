from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.scan import Scan, ScanFile
from app.domain.ports.scan_repository import ScanRepository
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.source_type import SourceType
from app.infrastructure.persistence.models import ScanFileModel, ScanModel


def _to_domain(model: ScanModel) -> Scan:
    return Scan(
        id=model.id,
        user_id=model.user_id,
        source_type=SourceType(model.source_type),
        status=ScanStatus(model.status),
        progress_percent=model.progress_percent,
        error_message=model.error_message,
        total_files=model.total_files,
        total_findings=model.total_findings,
        created_at=model.created_at,
        started_at=model.started_at,
        completed_at=model.completed_at,
    )


def _to_model(scan: Scan) -> ScanModel:
    return ScanModel(
        id=scan.id,
        user_id=scan.user_id,
        source_type=scan.source_type.value,
        status=scan.status.value,
        progress_percent=scan.progress_percent,
        error_message=scan.error_message,
        total_files=scan.total_files,
        total_findings=scan.total_findings,
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


def _file_to_domain(model: ScanFileModel) -> ScanFile:
    return ScanFile(
        id=model.id,
        scan_id=model.scan_id,
        filename=model.filename,
        relative_path=model.relative_path,
        language=model.language,
        size_bytes=model.size_bytes,
        content_hash=model.content_hash,
        loc=model.loc,
    )


def _file_to_model(file: ScanFile) -> ScanFileModel:
    return ScanFileModel(
        id=file.id,
        scan_id=file.scan_id,
        filename=file.filename,
        relative_path=file.relative_path,
        language=file.language,
        size_bytes=file.size_bytes,
        content_hash=file.content_hash,
        loc=file.loc,
    )


class SqlAlchemyScanRepository(ScanRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, scan: Scan, files: Sequence[ScanFile]) -> None:
        # Flushed step by step: the models declare foreign keys but no
        # relationship(), and the ORM only orders INSERTs along relationships.
        # Left to one flush, scan_files could be written before their scan -
        # and findings added right after, before the files they point to.
        self._session.add(_to_model(scan))
        await self._session.flush()
        self._session.add_all([_file_to_model(file) for file in files])
        await self._session.flush()

    async def get_by_id(self, scan_id: UUID) -> Scan | None:
        # A column select, not `session.get`: the analysis job re-reads a scan
        # it has itself bulk-UPDATEd, and must not get a stale identity-map copy.
        stmt = select(ScanModel).where(ScanModel.id == scan_id)
        stmt = stmt.execution_options(populate_existing=True)
        model = (await self._session.execute(stmt)).scalar_one_or_none()
        return _to_domain(model) if model else None

    async def list_for_user(self, user_id: UUID, *, limit: int = 20, offset: int = 0) -> list[Scan]:
        stmt = (
            select(ScanModel)
            .where(ScanModel.user_id == user_id)
            .order_by(ScanModel.created_at.desc(), ScanModel.id)
            .limit(limit)
            .offset(offset)
            .execution_options(populate_existing=True)
        )
        models = (await self._session.execute(stmt)).scalars().all()
        return [_to_domain(model) for model in models]

    async def count_for_user(self, user_id: UUID) -> int:
        stmt = select(func.count()).select_from(ScanModel).where(ScanModel.user_id == user_id)
        return (await self._session.execute(stmt)).scalar_one()

    async def count_by_status_for_user(self, user_id: UUID) -> dict[ScanStatus, int]:
        stmt = (
            select(ScanModel.status, func.count())
            .where(ScanModel.user_id == user_id)
            .group_by(ScanModel.status)
        )
        rows = (await self._session.execute(stmt)).all()
        return {ScanStatus(status): count for status, count in rows}

    async def list_files(self, scan_id: UUID) -> list[ScanFile]:
        stmt = (
            select(ScanFileModel)
            .where(ScanFileModel.scan_id == scan_id)
            .order_by(ScanFileModel.relative_path, ScanFileModel.id)
        )
        models = (await self._session.execute(stmt)).scalars().all()
        return [_file_to_domain(model) for model in models]

    async def update(self, scan: Scan) -> None:
        stmt = (
            update(ScanModel)
            .where(ScanModel.id == scan.id)
            .values(
                status=scan.status.value,
                progress_percent=scan.progress_percent,
                error_message=scan.error_message,
                total_files=scan.total_files,
                total_findings=scan.total_findings,
                started_at=scan.started_at,
                completed_at=scan.completed_at,
            )
        )
        await self._session.execute(stmt)

    async def delete(self, scan_id: UUID) -> None:
        # Files, findings and their references go with it (ON DELETE CASCADE).
        await self._session.execute(delete(ScanModel).where(ScanModel.id == scan_id))

    async def fail_unfinished(self, error_message: str) -> int:
        stmt = (
            update(ScanModel)
            .where(ScanModel.status.in_([ScanStatus.PENDING.value, ScanStatus.RUNNING.value]))
            .values(
                status=ScanStatus.FAILED.value,
                error_message=error_message,
                completed_at=datetime.now(UTC),
            )
        )
        result = await self._session.execute(stmt)
        return result.rowcount  # type: ignore[attr-defined,no-any-return]
