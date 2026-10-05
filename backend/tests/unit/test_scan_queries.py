from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.delete_scan import DeleteScanUseCase
from app.application.use_cases.fail_scans import FailInterruptedScansUseCase, FailScanUseCase
from app.application.use_cases.get_scan import GetScanUseCase
from app.application.use_cases.get_scan_report import GetScanReportUseCase
from app.application.use_cases.list_scans import ListScansUseCase
from app.domain.entities.finding import Finding
from app.domain.exceptions import ScanInProgressError, ScanNotFoundError
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from tests.unit.fakes import FakeSourceStorage, FakeUnitOfWork
from tests.unit.helpers import make_scan, make_scan_file


def _finding(
    scan_id: UUID, severity: Severity, *, file_path: str = "app.py", line: int = 1
) -> Finding:
    return Finding(
        id=uuid4(),
        scan_id=scan_id,
        scan_file_id=None,
        title=f"{severity.value} issue",
        cwe_id=None,
        owasp_category=None,
        attack_technique_id=None,
        severity=severity,
        confidence=0.8,
        location=CodeLocation(file_path, line, line),
        vulnerable_snippet="x",
        explanation="because",
        recommendation="fix it",
        fixed_code=None,
        references=[],
        created_at=datetime.now(UTC),
    )


@pytest.mark.unit
async def test_get_scan_returns_the_owners_scan() -> None:
    uow = FakeUnitOfWork()
    scan = make_scan(status=ScanStatus.RUNNING)
    await uow.scans.add(scan, [])

    result = await GetScanUseCase(uow).execute(scan.user_id, scan.id)

    assert (result.id, result.status) == (scan.id, ScanStatus.RUNNING)


@pytest.mark.unit
async def test_get_scan_hides_other_users_scans_as_not_found() -> None:
    uow = FakeUnitOfWork()
    scan = make_scan()
    await uow.scans.add(scan, [])

    with pytest.raises(ScanNotFoundError):
        await GetScanUseCase(uow).execute(uuid4(), scan.id)

    with pytest.raises(ScanNotFoundError):
        await GetScanUseCase(uow).execute(scan.user_id, uuid4())


@pytest.mark.unit
async def test_list_scans_is_scoped_to_the_user_paginated_and_newest_first() -> None:
    uow = FakeUnitOfWork()
    user_id = uuid4()
    now = datetime.now(UTC)
    scans = [make_scan(user_id=user_id, created_at=now - timedelta(minutes=i)) for i in range(3)]
    for scan in scans:
        await uow.scans.add(scan, [])
    await uow.scans.add(make_scan(), [])  # somebody else's

    first_page = await ListScansUseCase(uow).execute(user_id, limit=2, offset=0)
    second_page = await ListScansUseCase(uow).execute(user_id, limit=2, offset=2)

    assert first_page.total == 3
    assert [s.id for s in first_page.scans] == [scans[0].id, scans[1].id]
    assert [s.id for s in second_page.scans] == [scans[2].id]


@pytest.mark.unit
async def test_report_orders_findings_by_severity_then_location_and_counts_them() -> None:
    uow = FakeUnitOfWork()
    scan = make_scan(status=ScanStatus.COMPLETED)
    file = make_scan_file(scan.id)
    await uow.scans.add(scan, [file])
    await uow.findings.add_many(
        [
            _finding(scan.id, Severity.LOW),
            _finding(scan.id, Severity.HIGH, file_path="b.py", line=3),
            _finding(scan.id, Severity.CRITICAL),
            _finding(scan.id, Severity.HIGH, file_path="a.py", line=40),
            _finding(scan.id, Severity.HIGH, file_path="a.py", line=2),
            _finding(uuid4(), Severity.CRITICAL),  # another scan's
        ]
    )

    report = await GetScanReportUseCase(uow).execute(scan.user_id, scan.id)

    assert [(f.severity, f.location.file_path, f.location.line_start) for f in report.findings] == [
        (Severity.CRITICAL, "app.py", 1),
        (Severity.HIGH, "a.py", 2),
        (Severity.HIGH, "a.py", 40),
        (Severity.HIGH, "b.py", 3),
        (Severity.LOW, "app.py", 1),
    ]
    assert report.severity_counts == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 3,
        Severity.MEDIUM: 0,
        Severity.LOW: 1,
        Severity.INFO: 0,
    }
    assert report.files == [file]
    assert report.scan.id == scan.id


@pytest.mark.unit
async def test_report_of_another_users_scan_is_not_found() -> None:
    uow = FakeUnitOfWork()
    scan = make_scan(status=ScanStatus.COMPLETED)
    await uow.scans.add(scan, [])

    with pytest.raises(ScanNotFoundError):
        await GetScanReportUseCase(uow).execute(uuid4(), scan.id)


@pytest.mark.unit
@pytest.mark.parametrize("status", [ScanStatus.COMPLETED, ScanStatus.FAILED])
async def test_delete_removes_a_finished_scan_and_its_stored_source(status: ScanStatus) -> None:
    uow = FakeUnitOfWork()
    storage = FakeSourceStorage()
    scan = make_scan(status=status)
    file = make_scan_file(scan.id)
    await uow.scans.add(scan, [file])
    await storage.save(scan.id, file.id, "x = 1")

    await DeleteScanUseCase(uow, storage).execute(scan.user_id, scan.id)

    assert await uow.scans.get_by_id(scan.id) is None
    assert storage.contents == {}
    assert uow.committed is True


@pytest.mark.unit
@pytest.mark.parametrize("status", [ScanStatus.PENDING, ScanStatus.RUNNING])
async def test_delete_refuses_a_scan_still_in_progress(status: ScanStatus) -> None:
    uow = FakeUnitOfWork()
    storage = FakeSourceStorage()
    scan = make_scan(status=status)
    await uow.scans.add(scan, [])

    with pytest.raises(ScanInProgressError):
        await DeleteScanUseCase(uow, storage).execute(scan.user_id, scan.id)

    assert await uow.scans.get_by_id(scan.id) is not None
    assert storage.deleted_scan_ids == []


@pytest.mark.unit
async def test_delete_of_another_users_scan_is_not_found_and_deletes_nothing() -> None:
    uow = FakeUnitOfWork()
    storage = FakeSourceStorage()
    scan = make_scan(status=ScanStatus.COMPLETED)
    await uow.scans.add(scan, [])

    with pytest.raises(ScanNotFoundError):
        await DeleteScanUseCase(uow, storage).execute(uuid4(), scan.id)

    assert await uow.scans.get_by_id(scan.id) is not None


@pytest.mark.unit
async def test_fail_scan_marks_an_unfinished_scan_failed() -> None:
    uow = FakeUnitOfWork()
    scan = make_scan(status=ScanStatus.PENDING)
    await uow.scans.add(scan, [])

    await FailScanUseCase(uow).execute(scan.id, "pipeline unavailable")

    stored = await uow.scans.get_by_id(scan.id)
    assert stored is not None
    assert (stored.status, stored.error_message) == (ScanStatus.FAILED, "pipeline unavailable")
    assert stored.completed_at is not None


@pytest.mark.unit
async def test_fail_scan_leaves_a_finished_scan_alone() -> None:
    uow = FakeUnitOfWork()
    scan = make_scan(status=ScanStatus.COMPLETED)
    await uow.scans.add(scan, [])

    await FailScanUseCase(uow).execute(scan.id, "too late")
    await FailScanUseCase(uow).execute(uuid4(), "unknown scan")

    stored = await uow.scans.get_by_id(scan.id)
    assert stored is not None
    assert stored.status is ScanStatus.COMPLETED


@pytest.mark.unit
async def test_startup_recovery_fails_only_unfinished_scans() -> None:
    uow = FakeUnitOfWork()
    pending = make_scan(status=ScanStatus.PENDING)
    running = make_scan(status=ScanStatus.RUNNING)
    completed = make_scan(status=ScanStatus.COMPLETED)
    for scan in (pending, running, completed):
        await uow.scans.add(scan, [])

    count = await FailInterruptedScansUseCase(uow).execute()

    assert count == 2
    statuses = {scan.id: scan.status for scan in uow.scans.by_id.values()}
    assert statuses == {
        pending.id: ScanStatus.FAILED,
        running.id: ScanStatus.FAILED,
        completed.id: ScanStatus.COMPLETED,
    }
    interrupted = uow.scans.by_id[running.id]
    assert interrupted.error_message is not None
    assert "restart" in interrupted.error_message
