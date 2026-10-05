from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.get_dashboard_summary import GetDashboardSummaryUseCase
from app.domain.entities.finding import Finding
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from tests.unit.fakes import FakeUnitOfWork
from tests.unit.helpers import make_scan


def _finding(scan_id: UUID, severity: Severity, cwe_id: str | None) -> Finding:
    return Finding(
        id=uuid4(),
        scan_id=scan_id,
        scan_file_id=None,
        title="issue",
        cwe_id=cwe_id,
        owasp_category=None,
        attack_technique_id=None,
        severity=severity,
        confidence=0.8,
        location=CodeLocation("app.py", 1, 1),
        vulnerable_snippet="x",
        explanation="because",
        recommendation="fix it",
        fixed_code=None,
        references=[],
        created_at=datetime.now(UTC),
    )


@pytest.mark.unit
async def test_new_user_gets_a_complete_all_zero_summary() -> None:
    summary = await GetDashboardSummaryUseCase(FakeUnitOfWork()).execute(uuid4())

    assert summary.total_scans == 0
    assert summary.total_findings == 0
    assert summary.scans_by_status == {status: 0 for status in ScanStatus}
    assert summary.findings_by_severity == {severity: 0 for severity in Severity}
    assert summary.top_cwes == []
    assert summary.recent_scans == []


@pytest.mark.unit
async def test_summary_aggregates_the_users_scans_and_findings() -> None:
    uow = FakeUnitOfWork()
    user_id = uuid4()
    completed = make_scan(user_id=user_id, status=ScanStatus.COMPLETED)
    also_completed = make_scan(user_id=user_id, status=ScanStatus.COMPLETED)
    failed = make_scan(user_id=user_id, status=ScanStatus.FAILED)
    running = make_scan(user_id=user_id, status=ScanStatus.RUNNING)
    for scan in (completed, also_completed, failed, running):
        await uow.scans.add(scan, [])
    await uow.findings.add_many(
        [
            _finding(completed.id, Severity.CRITICAL, "CWE-89"),
            _finding(completed.id, Severity.HIGH, "CWE-89"),
            _finding(completed.id, Severity.HIGH, "CWE-79"),
            _finding(also_completed.id, Severity.LOW, "CWE-89"),
            _finding(also_completed.id, Severity.LOW, None),
        ]
    )

    summary = await GetDashboardSummaryUseCase(uow).execute(user_id)

    assert summary.total_scans == 4
    assert summary.scans_by_status == {
        ScanStatus.PENDING: 0,
        ScanStatus.RUNNING: 1,
        ScanStatus.COMPLETED: 2,
        ScanStatus.FAILED: 1,
    }
    assert summary.total_findings == 5
    assert summary.findings_by_severity == {
        Severity.CRITICAL: 1,
        Severity.HIGH: 2,
        Severity.MEDIUM: 0,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }
    # Most frequent first; the finding without a CWE is not ranked.
    assert [(item.cwe_id, item.count) for item in summary.top_cwes] == [
        ("CWE-89", 3),
        ("CWE-79", 1),
    ]


@pytest.mark.unit
async def test_summary_never_includes_another_users_data() -> None:
    uow = FakeUnitOfWork()
    user_id = uuid4()
    mine = make_scan(user_id=user_id, status=ScanStatus.COMPLETED)
    theirs = make_scan(status=ScanStatus.COMPLETED)
    await uow.scans.add(mine, [])
    await uow.scans.add(theirs, [])
    await uow.findings.add_many(
        [
            _finding(mine.id, Severity.LOW, "CWE-79"),
            _finding(theirs.id, Severity.CRITICAL, "CWE-89"),
            _finding(theirs.id, Severity.CRITICAL, "CWE-89"),
        ]
    )

    summary = await GetDashboardSummaryUseCase(uow).execute(user_id)

    assert summary.total_scans == 1
    assert summary.total_findings == 1
    assert summary.findings_by_severity[Severity.CRITICAL] == 0
    assert [item.cwe_id for item in summary.top_cwes] == ["CWE-79"]
    assert [scan.id for scan in summary.recent_scans] == [mine.id]


@pytest.mark.unit
async def test_recent_scans_are_the_five_newest_and_top_cwes_are_capped() -> None:
    uow = FakeUnitOfWork()
    user_id = uuid4()
    now = datetime.now(UTC)
    scans = [
        make_scan(user_id=user_id, status=ScanStatus.COMPLETED, created_at=now - timedelta(hours=i))
        for i in range(7)
    ]
    for scan in scans:
        await uow.scans.add(scan, [])
    await uow.findings.add_many(
        [_finding(scans[0].id, Severity.MEDIUM, f"CWE-{number}") for number in range(1, 9)]
    )

    summary = await GetDashboardSummaryUseCase(uow).execute(user_id)

    assert [scan.id for scan in summary.recent_scans] == [scan.id for scan in scans[:5]]
    assert summary.total_scans == 7
    assert len(summary.top_cwes) == 5
