import json
from collections.abc import AsyncIterator

import pytest

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.severity import Severity
from tests.conftest import ScanApiHarness
from tests.unit.helpers import make_analyzed_finding

_SCANS = "/api/v1/scans"

_CODE = (
    "def find_user(conn, name):\n"
    '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    "    return conn.execute(query).fetchall()\n"
)


async def _completed_scan(scan_api: ScanApiHarness) -> str:
    await scan_api.indexer.upsert(
        [
            KnowledgeDocument(
                external_id="CWE-89",
                source=KnowledgeSource.CWE,
                name="SQL Injection",
                category=None,
                url="https://cwe.mitre.org/data/definitions/89.html",
                content="sql injection",
            )
        ]
    )
    scan_api.analyzer.set_default(
        [
            make_analyzed_finding(title="Verbose error", severity=Severity.LOW, cwe_id=None),
            make_analyzed_finding(title="SQL injection", line_start=2, line_end=2),
        ]
    )
    created = await scan_api.client.post(_SCANS, data={"code": _CODE, "language": "python"})
    assert created.status_code == 202
    return str(created.json()["id"])


@pytest.mark.e2e
async def test_json_export_downloads_the_report_as_a_file(scan_api: ScanApiHarness) -> None:
    scan_id = await _completed_scan(scan_api)

    response = await scan_api.client.get(f"{_SCANS}/{scan_id}/export?format=json")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="vulnscan-report-{scan_id}.json"'
    )
    assert response.headers["x-content-type-options"] == "nosniff"
    document = json.loads(response.content)
    assert document["scan"]["id"] == scan_id
    assert document["summary"]["total_findings"] == 2
    # Same order as the on-screen report: most severe first.
    assert [f["title"] for f in document["findings"]] == ["SQL injection", "Verbose error"]
    assert document["findings"][0]["vulnerable_snippet"] == _CODE.split("\n")[1]
    assert document["findings"][0]["references"][0]["id"] == "CWE-89"


@pytest.mark.e2e
async def test_export_defaults_to_json(scan_api: ScanApiHarness) -> None:
    scan_id = await _completed_scan(scan_api)

    response = await scan_api.client.get(f"{_SCANS}/{scan_id}/export")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"


@pytest.mark.e2e
async def test_pdf_export_downloads_a_pdf_where_the_pdf_library_is_installed(
    scan_api: ScanApiHarness,
) -> None:
    scan_id = await _completed_scan(scan_api)

    response = await scan_api.client.get(f"{_SCANS}/{scan_id}/export?format=pdf")

    if response.status_code == 503:
        # No WeasyPrint here (local Windows venv): the API must say so cleanly.
        assert response.json()["error"]["code"] == "ReportFormatUnavailable"
        pytest.skip("WeasyPrint is not installed (install the 'export' extra to run this)")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="vulnscan-report-{scan_id}.pdf"'
    )
    assert response.content.startswith(b"%PDF-")


@pytest.mark.e2e
async def test_export_is_refused_while_the_scan_is_in_progress(scan_api: ScanApiHarness) -> None:
    scan_api.jobs.paused = True
    created = await scan_api.client.post(_SCANS, data={"code": "x = 1"})

    response = await scan_api.client.get(f"{_SCANS}/{created.json()['id']}/export?format=json")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "ScanInProgress"


@pytest.mark.e2e
async def test_export_is_private_and_validates_its_format(scan_api: ScanApiHarness) -> None:
    scan_id = await _completed_scan(scan_api)

    bad_format = await scan_api.client.get(f"{_SCANS}/{scan_id}/export?format=docx")
    assert bad_format.status_code == 422
    assert bad_format.json()["error"]["code"] == "validation_error"

    await scan_api.login_as("intruder@example.com")
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}/export?format=json")).status_code == 404
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}/export?format=pdf")).status_code == 404

    del scan_api.client.headers["Authorization"]
    assert (await scan_api.client.get(f"{_SCANS}/{scan_id}/export")).status_code == 401


@pytest.mark.e2e
async def test_too_many_unfinished_scans_are_refused_until_one_finishes(
    scan_api: ScanApiHarness,
) -> None:
    scan_api.jobs.paused = True
    for index in range(3):  # MAX_ACTIVE_SCANS_PER_USER defaults to 3
        accepted = await scan_api.client.post(_SCANS, data={"code": f"x = {index}"})
        assert accepted.status_code == 202

    refused = await scan_api.client.post(_SCANS, data={"code": "x = 99"})

    assert refused.status_code == 429
    assert refused.json()["error"]["code"] == "TooManyActiveScans"
    assert "3 scans in progress" in refused.json()["error"]["message"]
    assert (await scan_api.client.get(_SCANS)).json()["total"] == 3

    await scan_api.jobs.run_pending()
    assert (await scan_api.client.post(_SCANS, data={"code": "x = 99"})).status_code == 202


@pytest.mark.e2e
async def test_oversized_request_is_refused_whatever_it_declares(scan_api: ScanApiHarness) -> None:
    # Over the request-size cap itself (upload limit + 1 MB of framing, i.e.
    # 11 MB by default), not merely over the upload limit: this is refused by
    # the middleware, before the endpoint or the multipart parser see it.
    oversized = b"#" * (12 * 1024 * 1024)

    declared = await scan_api.client.post(
        _SCANS, files={"file": ("big.py", oversized, "text/x-python")}
    )
    assert declared.status_code == 413
    assert "larger than the 11 MB allowed" in declared.json()["error"]["message"]

    async def chunks() -> AsyncIterator[bytes]:
        # A well-formed multipart upload that just never stops: a malformed
        # one would be turned away as a plain 400 by the parser, long before
        # reaching the size limit this test is about.
        yield (
            b'--x\r\nContent-Disposition: form-data; name="file"; filename="big.py"\r\n'
            b"Content-Type: text/x-python\r\n\r\n"
        )
        for start in range(0, len(oversized), 64 * 1024):
            yield oversized[start : start + 64 * 1024]

    streamed = await scan_api.client.post(
        _SCANS,
        content=chunks(),
        headers={"Content-Type": "multipart/form-data; boundary=x"},
    )
    assert streamed.status_code == 413
    assert "larger than the 11 MB allowed" in streamed.json()["error"]["message"]

    assert (await scan_api.client.get(_SCANS)).json()["total"] == 0
    assert scan_api.stored_files() == []


@pytest.mark.e2e
async def test_invalid_login_payload_gets_the_common_error_envelope(
    scan_api: ScanApiHarness,
) -> None:
    response = await scan_api.client.post(
        "/api/v1/auth/login", json={"email": "not-an-email", "password": "s3cret-value"}
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["field"] == "email"
    assert "s3cret-value" not in response.text
