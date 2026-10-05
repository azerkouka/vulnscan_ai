"""End-to-end tests of /api/v1/scans: real routing, auth, use cases, SQL
repositories, zip extraction and file storage - with only the LLM, the
vector store and the chunker replaced by fakes (see `scan_api` in conftest).
"""

import io
import zipfile

import pytest

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.exceptions import LLMAnalysisError
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.severity import Severity
from tests.conftest import ScanApiHarness
from tests.unit.helpers import make_analyzed_finding

_SCANS = "/api/v1/scans"

_VULNERABLE_PY = (
    "import sqlite3\n"
    "\n"
    "def find_user(conn, name):\n"
    '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    "    return conn.execute(query).fetchall()\n"
)

_CWE_89 = KnowledgeDocument(
    external_id="CWE-89",
    source=KnowledgeSource.CWE,
    name="SQL Injection",
    category=None,
    url="https://cwe.mitre.org/data/definitions/89.html",
    content="Improper neutralization of special elements used in an SQL command.",
)


def _zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


@pytest.mark.e2e
async def test_scan_endpoints_require_authentication(scan_api: ScanApiHarness) -> None:
    del scan_api.client.headers["Authorization"]

    assert (await scan_api.client.post(_SCANS, data={"code": "x = 1"})).status_code == 401
    assert (await scan_api.client.get(_SCANS)).status_code == 401
    assert (
        await scan_api.client.get(f"{_SCANS}/00000000-0000-0000-0000-000000000000")
    ).status_code == 401


@pytest.mark.e2e
async def test_snippet_scan_full_lifecycle(scan_api: ScanApiHarness) -> None:
    await scan_api.indexer.upsert([_CWE_89])
    scan_api.analyzer.set_default(
        [
            make_analyzed_finding(
                line_start=4, line_end=4, fixed_code="conn.execute(sql, (name,))"
            ),
            make_analyzed_finding(
                title="Made-up issue", cwe_id="CWE-99999", severity=Severity.LOW, line_start=1
            ),
        ]
    )

    # Submit: accepted immediately, analysis not done yet.
    scan_api.jobs.paused = True
    created = await scan_api.client.post(
        _SCANS, data={"code": _VULNERABLE_PY, "language": "python"}
    )
    assert created.status_code == 202
    scan = created.json()
    assert scan["status"] == "PENDING"
    assert scan["source_type"] == "SNIPPET"
    assert scan["total_files"] == 1
    scan_id = scan["id"]

    # Still in progress: can be polled, cannot be deleted.
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}")).json()["status"] == "PENDING"
    assert (await scan_api.client.delete(f"{_SCANS}/{scan_id}")).status_code == 409

    await scan_api.jobs.run_pending()

    polled = (await scan_api.client.get(f"{_SCANS}/{scan_id}")).json()
    assert polled["status"] == "COMPLETED"
    assert polled["progress_percent"] == 100
    assert polled["total_findings"] == 2
    assert polled["error_message"] is None
    assert polled["completed_at"] is not None

    report_response = await scan_api.client.get(f"{_SCANS}/{scan_id}/report")
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["scan"]["id"] == scan_id
    assert report["severity_counts"] == {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "INFO": 0}
    assert [f["relative_path"] for f in report["files"]] == ["snippet.py"]
    assert report["files"][0]["language"] == "python"

    high, low = report["findings"]  # most severe first
    assert high["title"] == "SQL injection"
    assert high["severity"] == "HIGH"
    assert high["cwe_id"] == "CWE-89"
    assert (high["file_path"], high["line_start"], high["line_end"]) == ("snippet.py", 4, 4)
    assert high["vulnerable_snippet"] == _VULNERABLE_PY.split("\n")[3]
    assert high["fixed_code"] == "conn.execute(sql, (name,))"
    assert high["references"] == [
        {
            "source": "CWE",
            "ref_id": "CWE-89",
            "title": "SQL Injection",
            "url": "https://cwe.mitre.org/data/definitions/89.html",
        }
    ]
    # The hallucinated CWE never reaches the client.
    assert low["title"] == "Made-up issue"
    assert low["cwe_id"] is None
    assert low["references"] == []

    listing = (await scan_api.client.get(_SCANS)).json()
    assert listing["total"] == 1
    assert listing["scans"][0]["id"] == scan_id

    assert scan_api.stored_files() != []
    assert (await scan_api.client.delete(f"{_SCANS}/{scan_id}")).status_code == 204
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}")).status_code == 404
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}/report")).status_code == 404
    assert (await scan_api.client.get(_SCANS)).json()["total"] == 0
    assert scan_api.stored_files() == []


@pytest.mark.e2e
async def test_single_file_upload_is_scanned(scan_api: ScanApiHarness) -> None:
    scan_api.analyzer.set_default([make_analyzed_finding(line_start=4)])

    created = await scan_api.client.post(
        _SCANS, files={"file": ("views.py", _VULNERABLE_PY.encode(), "text/x-python")}
    )

    assert created.status_code == 202
    assert created.json()["source_type"] == "FILE"
    report = (await scan_api.client.get(f"{_SCANS}/{created.json()['id']}/report")).json()
    assert report["scan"]["status"] == "COMPLETED"
    assert [f["filename"] for f in report["files"]] == ["views.py"]
    assert report["findings"][0]["file_path"] == "views.py"


@pytest.mark.e2e
async def test_zip_upload_scans_every_source_file_it_contains(scan_api: ScanApiHarness) -> None:
    scan_api.analyzer.set_default([make_analyzed_finding(line_start=1)])
    archive = _zip(
        {
            "project/app.py": _VULNERABLE_PY,
            "project/web/main.js": "eval(location.hash)\n",
            "project/README.md": "# not source",
            "project/node_modules/dep/index.js": "module.exports = 1\n",
        }
    )

    created = await scan_api.client.post(
        _SCANS, files={"file": ("project.zip", archive, "application/zip")}
    )

    assert created.status_code == 202
    body = created.json()
    assert (body["source_type"], body["total_files"]) == ("ZIP", 2)
    report = (await scan_api.client.get(f"{_SCANS}/{body['id']}/report")).json()
    assert report["scan"]["status"] == "COMPLETED"
    assert [f["relative_path"] for f in report["files"]] == [
        "project/app.py",
        "project/web/main.js",
    ]
    assert sorted(f["file_path"] for f in report["findings"]) == [
        "project/app.py",
        "project/web/main.js",
    ]
    assert len(scan_api.analyzer.calls) == 2


@pytest.mark.e2e
async def test_zip_slip_archive_is_rejected_and_nothing_is_created(
    scan_api: ScanApiHarness,
) -> None:
    archive = _zip({"app.py": "x = 1\n", "../../../etc/cron.d/evil.py": "import os\n"})

    response = await scan_api.client.post(
        _SCANS, files={"file": ("project.zip", archive, "application/zip")}
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "InvalidArchive"
    assert (await scan_api.client.get(_SCANS)).json()["total"] == 0
    assert scan_api.stored_files() == []
    assert scan_api.analyzer.calls == []


@pytest.mark.e2e
async def test_invalid_submissions_are_rejected(scan_api: ScanApiHarness) -> None:
    client = scan_api.client

    neither = await client.post(_SCANS, data={"language": "python"})
    assert neither.status_code == 422

    both = await client.post(
        _SCANS, data={"code": "x = 1"}, files={"file": ("a.py", b"x = 1", "text/plain")}
    )
    assert both.status_code == 422

    wrong_type = await client.post(
        _SCANS, files={"file": ("tool.exe", b"MZ", "application/octet-stream")}
    )
    assert wrong_type.status_code == 422
    assert wrong_type.json()["error"]["code"] == "InvalidSource"

    empty = await client.post(_SCANS, data={"code": "   "})
    assert empty.status_code == 422

    bad_language = await client.post(_SCANS, data={"code": "x = 1", "language": "cobol"})
    assert bad_language.status_code == 422

    not_a_zip = await client.post(
        _SCANS, files={"file": ("project.zip", b"not a zip", "application/zip")}
    )
    assert not_a_zip.status_code == 422

    assert (await client.get(_SCANS)).json()["total"] == 0


@pytest.mark.e2e
async def test_upload_over_the_size_limit_is_rejected(scan_api: ScanApiHarness) -> None:
    too_big = b"#" * (scan_api.max_upload_bytes + 1)

    response = await scan_api.client.post(
        _SCANS, files={"file": ("big.py", too_big, "text/x-python")}
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "SourceTooLarge"
    assert (await scan_api.client.get(_SCANS)).json()["total"] == 0


@pytest.mark.e2e
async def test_scans_are_private_to_their_owner(scan_api: ScanApiHarness) -> None:
    created = await scan_api.client.post(_SCANS, data={"code": "x = 1"})
    scan_id = created.json()["id"]

    await scan_api.login_as("intruder@example.com")

    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}")).status_code == 404
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}/report")).status_code == 404
    assert (await scan_api.client.delete(f"{_SCANS}/{scan_id}")).status_code == 404
    assert (await scan_api.client.get(_SCANS)).json()["total"] == 0


@pytest.mark.e2e
async def test_llm_failure_ends_as_a_failed_scan_with_a_message(scan_api: ScanApiHarness) -> None:
    scan_api.analyzer.set_default_error(LLMAnalysisError("no valid JSON"))

    created = await scan_api.client.post(_SCANS, data={"code": "x = 1"})

    assert created.status_code == 202
    scan = (await scan_api.client.get(f"{_SCANS}/{created.json()['id']}")).json()
    assert scan["status"] == "FAILED"
    assert scan["error_message"] == "The LLM could not analyze any of the submitted code."
    assert scan["completed_at"] is not None


@pytest.mark.e2e
async def test_unknown_or_malformed_scan_id(scan_api: ScanApiHarness) -> None:
    unknown = await scan_api.client.get(f"{_SCANS}/00000000-0000-0000-0000-000000000000")
    assert unknown.status_code == 404
    assert unknown.json()["error"]["code"] == "ScanNotFound"

    malformed = await scan_api.client.get(f"{_SCANS}/not-a-uuid")
    assert malformed.status_code == 422


@pytest.mark.e2e
async def test_list_is_paginated(scan_api: ScanApiHarness) -> None:
    for index in range(3):
        await scan_api.client.post(_SCANS, data={"code": f"x = {index}"})

    page = (await scan_api.client.get(f"{_SCANS}?limit=2&offset=0")).json()
    rest = (await scan_api.client.get(f"{_SCANS}?limit=2&offset=2")).json()

    assert (page["total"], len(page["scans"]), page["limit"], page["offset"]) == (3, 2, 2, 0)
    assert len(rest["scans"]) == 1
    assert (await scan_api.client.get(f"{_SCANS}?limit=0")).status_code == 422
