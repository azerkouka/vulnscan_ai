import pytest

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.exceptions import LLMAnalysisError
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.severity import Severity
from tests.conftest import ScanApiHarness
from tests.unit.helpers import make_analyzed_finding

_SUMMARY = "/api/v1/dashboard/summary"
_SCANS = "/api/v1/scans"


def _cwe(external_id: str) -> KnowledgeDocument:
    return KnowledgeDocument(
        external_id=external_id,
        source=KnowledgeSource.CWE,
        name=external_id,
        category=None,
        url=None,
        content=external_id,
    )


@pytest.mark.e2e
async def test_summary_requires_authentication(scan_api: ScanApiHarness) -> None:
    del scan_api.client.headers["Authorization"]

    assert (await scan_api.client.get(_SUMMARY)).status_code == 401


@pytest.mark.e2e
async def test_summary_of_a_new_account_is_all_zeros(scan_api: ScanApiHarness) -> None:
    response = await scan_api.client.get(_SUMMARY)

    assert response.status_code == 200
    assert response.json() == {
        "total_scans": 0,
        "scans_by_status": {"PENDING": 0, "RUNNING": 0, "COMPLETED": 0, "FAILED": 0},
        "total_findings": 0,
        "findings_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "top_cwes": [],
        "recent_scans": [],
    }


@pytest.mark.e2e
async def test_summary_reflects_scans_and_is_private_to_each_user(
    scan_api: ScanApiHarness,
) -> None:
    await scan_api.indexer.upsert([_cwe("CWE-89"), _cwe("CWE-78")])

    # Two completed scans with findings ...
    scan_api.analyzer.set_default(
        [
            make_analyzed_finding(title="SQL injection", cwe_id="CWE-89", severity=Severity.HIGH),
            make_analyzed_finding(
                title="Command injection", cwe_id="CWE-78", severity=Severity.CRITICAL
            ),
        ]
    )
    first = (await scan_api.client.post(_SCANS, data={"code": "a = 1"})).json()
    scan_api.analyzer.set_default(
        [make_analyzed_finding(title="SQL injection", cwe_id="CWE-89", severity=Severity.HIGH)]
    )
    second = (await scan_api.client.post(_SCANS, data={"code": "b = 2"})).json()
    # ... one that fails, and one still waiting.
    scan_api.analyzer.set_default_error(LLMAnalysisError("down"))
    await scan_api.client.post(_SCANS, data={"code": "c = 3"})
    scan_api.jobs.paused = True
    pending = (await scan_api.client.post(_SCANS, data={"code": "d = 4"})).json()

    summary = (await scan_api.client.get(_SUMMARY)).json()

    assert summary["total_scans"] == 4
    assert summary["scans_by_status"] == {"PENDING": 1, "RUNNING": 0, "COMPLETED": 2, "FAILED": 1}
    assert summary["total_findings"] == 3
    assert summary["findings_by_severity"] == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }
    assert summary["top_cwes"] == [
        {"cwe_id": "CWE-89", "count": 2},
        {"cwe_id": "CWE-78", "count": 1},
    ]
    recent_ids = [scan["id"] for scan in summary["recent_scans"]]
    assert len(recent_ids) == 4
    assert recent_ids[0] == pending["id"]  # newest first
    assert {first["id"], second["id"]} <= set(recent_ids)

    # Another user sees none of it.
    await scan_api.login_as("someone-else@example.com")
    other = (await scan_api.client.get(_SUMMARY)).json()
    assert other["total_scans"] == 0
    assert other["total_findings"] == 0
    assert other["top_cwes"] == []
    assert other["recent_scans"] == []
