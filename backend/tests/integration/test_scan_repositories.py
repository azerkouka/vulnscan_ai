from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.finding import Finding, FindingReference
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from app.domain.value_objects.source_type import SourceType
from app.infrastructure.persistence.models import (
    FindingModel,
    FindingReferenceModel,
    ScanFileModel,
)
from app.infrastructure.persistence.repositories.finding_repository import (
    SqlAlchemyFindingRepository,
)
from app.infrastructure.persistence.repositories.scan_repository import SqlAlchemyScanRepository
from app.infrastructure.persistence.repositories.user_repository import SqlAlchemyUserRepository
from tests.unit.helpers import make_scan, make_scan_file, make_user


async def _persisted_user_id(session: AsyncSession, email: str = "scanner@example.com") -> UUID:
    user = make_user(email=email)
    await SqlAlchemyUserRepository(session).add(user)
    await session.flush()
    return user.id


def _finding(scan_id: UUID, scan_file_id: UUID | None, **overrides: object) -> Finding:
    finding = Finding(
        id=uuid4(),
        scan_id=scan_id,
        scan_file_id=scan_file_id,
        title="SQL injection",
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        attack_technique_id=None,
        severity=Severity.HIGH,
        confidence=0.85,
        location=CodeLocation("src/app.py", 12, 14),
        vulnerable_snippet="query = 'SELECT ...' + name",
        explanation="Unescaped input reaches the query.",
        recommendation="Use bound parameters.",
        fixed_code="cursor.execute(sql, (name,))",
        references=[
            FindingReference(ReferenceSource.CWE, "CWE-89", "SQL Injection", "https://cwe/89"),
            FindingReference(ReferenceSource.OWASP, "A03:2021", "Injection", None),
        ],
        created_at=datetime.now(UTC),
    )
    return replace(finding, **overrides)  # type: ignore[arg-type]


async def _count(session: AsyncSession, model: type) -> int:
    return (await session.execute(select(func.count()).select_from(model))).scalar_one()


@pytest.mark.integration
async def test_scan_round_trips_with_its_files(db_session: AsyncSession) -> None:
    repo = SqlAlchemyScanRepository(db_session)
    scan = make_scan(
        user_id=await _persisted_user_id(db_session), source_type=SourceType.ZIP, total_files=2
    )
    files = [
        make_scan_file(scan.id, relative_path="src/zeta.py"),
        make_scan_file(scan.id, relative_path="src/alpha.py"),
    ]

    await repo.add(scan, files)
    await db_session.flush()

    assert await repo.get_by_id(scan.id) == scan
    stored_files = await repo.list_files(scan.id)
    assert [f.relative_path for f in stored_files] == ["src/alpha.py", "src/zeta.py"]
    assert stored_files[0] == files[1]


@pytest.mark.integration
async def test_get_by_id_returns_none_when_missing(db_session: AsyncSession) -> None:
    assert await SqlAlchemyScanRepository(db_session).get_by_id(uuid4()) is None


@pytest.mark.integration
async def test_list_for_user_is_scoped_paginated_and_newest_first(
    db_session: AsyncSession,
) -> None:
    repo = SqlAlchemyScanRepository(db_session)
    user_id = await _persisted_user_id(db_session)
    other_user_id = await _persisted_user_id(db_session, "other@example.com")
    now = datetime.now(UTC)
    scans = [make_scan(user_id=user_id, created_at=now - timedelta(minutes=i)) for i in range(3)]
    for scan in scans:
        await repo.add(scan, [])
    await repo.add(make_scan(user_id=other_user_id), [])
    await db_session.flush()

    first_page = await repo.list_for_user(user_id, limit=2, offset=0)
    second_page = await repo.list_for_user(user_id, limit=2, offset=2)

    assert [s.id for s in first_page] == [scans[0].id, scans[1].id]
    assert [s.id for s in second_page] == [scans[2].id]
    assert await repo.count_for_user(user_id) == 3
    assert await repo.count_for_user(other_user_id) == 1


@pytest.mark.integration
async def test_update_persists_lifecycle_fields_and_is_visible_to_a_re_read(
    db_session: AsyncSession,
) -> None:
    repo = SqlAlchemyScanRepository(db_session)
    scan = make_scan(user_id=await _persisted_user_id(db_session))
    await repo.add(scan, [])
    await db_session.flush()
    assert await repo.get_by_id(scan.id) == scan  # now cached in the session

    finished = replace(
        scan,
        status=ScanStatus.FAILED,
        progress_percent=40,
        error_message="LLM unavailable",
        total_findings=3,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
    )
    await repo.update(finished)

    assert await repo.get_by_id(scan.id) == finished
    [listed] = await repo.list_for_user(scan.user_id)
    assert listed == finished


@pytest.mark.integration
async def test_fail_unfinished_only_touches_pending_and_running_scans(
    db_session: AsyncSession,
) -> None:
    repo = SqlAlchemyScanRepository(db_session)
    user_id = await _persisted_user_id(db_session)
    by_status = {status: make_scan(user_id=user_id, status=status) for status in ScanStatus}
    for scan in by_status.values():
        await repo.add(scan, [])
    await db_session.flush()

    count = await repo.fail_unfinished("interrupted")

    assert count == 2
    for original_status, scan in by_status.items():
        stored = await repo.get_by_id(scan.id)
        assert stored is not None
        if original_status in (ScanStatus.PENDING, ScanStatus.RUNNING):
            assert (stored.status, stored.error_message) == (ScanStatus.FAILED, "interrupted")
            assert stored.completed_at is not None
        else:
            assert stored == scan


@pytest.mark.integration
async def test_findings_round_trip_with_their_references_in_order(
    db_session: AsyncSession,
) -> None:
    scans = SqlAlchemyScanRepository(db_session)
    findings = SqlAlchemyFindingRepository(db_session)
    scan = make_scan(user_id=await _persisted_user_id(db_session))
    file = make_scan_file(scan.id, relative_path="src/app.py")
    await scans.add(scan, [file])
    first = _finding(scan.id, file.id)
    second = _finding(
        scan.id,
        None,
        title="Hardcoded secret",
        cwe_id=None,
        owasp_category=None,
        fixed_code=None,
        references=[],
        created_at=first.created_at + timedelta(seconds=1),
    )

    await findings.add_many([first, second])
    await db_session.flush()

    assert await findings.list_for_scan(scan.id) == [first, second]
    assert await findings.list_for_scan(uuid4()) == []


@pytest.mark.integration
async def test_deleting_a_scan_cascades_to_files_findings_and_references(
    db_session: AsyncSession,
) -> None:
    scans = SqlAlchemyScanRepository(db_session)
    findings = SqlAlchemyFindingRepository(db_session)
    user_id = await _persisted_user_id(db_session)
    deleted = make_scan(user_id=user_id)
    kept = make_scan(user_id=user_id)
    for scan in (deleted, kept):
        file = make_scan_file(scan.id)
        await scans.add(scan, [file])
        await findings.add_many([_finding(scan.id, file.id)])
    await db_session.flush()

    await scans.delete(deleted.id)
    await db_session.flush()
    db_session.expire_all()

    assert await scans.get_by_id(deleted.id) is None
    assert await scans.get_by_id(kept.id) is not None
    # Exactly the other scan's rows are left: one file, one finding, two references.
    assert await _count(db_session, ScanFileModel) == 1
    assert await _count(db_session, FindingModel) == 1
    assert await _count(db_session, FindingReferenceModel) == 2
    assert len(await findings.list_for_scan(kept.id)) == 1


@pytest.mark.integration
async def test_per_user_aggregates_count_only_that_users_rows(db_session: AsyncSession) -> None:
    scans = SqlAlchemyScanRepository(db_session)
    findings = SqlAlchemyFindingRepository(db_session)
    user_id = await _persisted_user_id(db_session)
    other_user_id = await _persisted_user_id(db_session, "other@example.com")

    completed = make_scan(user_id=user_id, status=ScanStatus.COMPLETED)
    also_completed = make_scan(user_id=user_id, status=ScanStatus.COMPLETED)
    failed = make_scan(user_id=user_id, status=ScanStatus.FAILED)
    theirs = make_scan(user_id=other_user_id, status=ScanStatus.RUNNING)
    for scan in (completed, also_completed, failed, theirs):
        await scans.add(scan, [])
    await findings.add_many(
        [
            _finding(completed.id, None, severity=Severity.CRITICAL, cwe_id="CWE-89"),
            _finding(completed.id, None, severity=Severity.HIGH, cwe_id="CWE-79"),
            _finding(also_completed.id, None, severity=Severity.HIGH, cwe_id="CWE-89"),
            _finding(also_completed.id, None, severity=Severity.LOW, cwe_id=None),
            _finding(theirs.id, None, severity=Severity.CRITICAL, cwe_id="CWE-22"),
            _finding(theirs.id, None, severity=Severity.CRITICAL, cwe_id="CWE-22"),
            _finding(theirs.id, None, severity=Severity.CRITICAL, cwe_id="CWE-22"),
        ]
    )
    await db_session.flush()

    assert await scans.count_by_status_for_user(user_id) == {
        ScanStatus.COMPLETED: 2,
        ScanStatus.FAILED: 1,
    }
    assert await findings.count_by_severity_for_user(user_id) == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 2,
        Severity.LOW: 1,
    }
    assert await findings.top_cwes_for_user(user_id) == [("CWE-89", 2), ("CWE-79", 1)]
    assert await findings.top_cwes_for_user(user_id, limit=1) == [("CWE-89", 2)]

    assert await scans.count_by_status_for_user(other_user_id) == {ScanStatus.RUNNING: 1}
    assert await findings.top_cwes_for_user(other_user_id) == [("CWE-22", 3)]
    assert await findings.count_by_severity_for_user(uuid4()) == {}
