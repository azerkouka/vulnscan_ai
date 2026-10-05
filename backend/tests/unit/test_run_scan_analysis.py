from uuid import UUID

import pytest

from app.application.use_cases.run_scan_analysis import AnalysisSettings, RunScanAnalysisUseCase
from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.entities.scan import Scan
from app.domain.exceptions import LLMAnalysisError
from app.domain.ports.llm_analyzer import AnalyzedFinding
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.scan_status import ScanStatus
from tests.unit.fakes import (
    FakeCodeChunker,
    FakeKnowledgeIndexer,
    FakeKnowledgeRetriever,
    FakeLLMAnalyzer,
    FakeSourceStorage,
    FakeUnitOfWork,
)
from tests.unit.helpers import (
    make_analyzed_finding,
    make_knowledge_record,
    make_scan,
    make_scan_file,
)

_VULNERABLE_CODE = (
    "import sqlite3\n"
    "\n"
    "def find_user(conn, name):\n"
    '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
    "    return conn.execute(query).fetchall()\n"
)


class _Harness:
    """A PENDING scan over in-memory fakes, ready to be analyzed."""

    def __init__(
        self,
        files: dict[str, str] | None = None,
        *,
        responses: list[list[AnalyzedFinding] | Exception] | None = None,
        default: list[AnalyzedFinding] | None = None,
        lines_per_chunk: int | None = None,
        settings: AnalysisSettings | None = None,
    ) -> None:
        self.uow = FakeUnitOfWork()
        self.storage = FakeSourceStorage()
        self.indexer = FakeKnowledgeIndexer()
        self.analyzer = FakeLLMAnalyzer(responses or [], default or [])
        self.scan_id: UUID = make_scan().id
        self._files = files if files is not None else {"app.py": _VULNERABLE_CODE}
        self.use_case = RunScanAnalysisUseCase(
            self.uow,
            self.storage,
            FakeCodeChunker(lines_per_chunk),
            FakeKnowledgeRetriever(self.indexer),
            self.analyzer,
            settings,
        )

    async def setup(self) -> "_Harness":
        scan = make_scan(scan_id=self.scan_id, total_files=len(self._files))
        scan_files = []
        for path, content in self._files.items():
            file = make_scan_file(scan.id, relative_path=path, content=content)
            scan_files.append(file)
            await self.storage.save(scan.id, file.id, content)
        await self.uow.scans.add(scan, scan_files)
        return self

    async def run(self) -> Scan:
        await self.use_case.execute(self.scan_id)
        scan = await self.uow.scans.get_by_id(self.scan_id)
        assert scan is not None
        return scan


async def _harness(**kwargs: object) -> _Harness:
    return await _Harness(**kwargs).setup()  # type: ignore[arg-type]


@pytest.mark.unit
async def test_successful_analysis_completes_the_scan_and_stores_findings() -> None:
    harness = await _harness(default=[make_analyzed_finding(line_start=4, line_end=4)])
    await harness.uow.knowledge_documents.upsert(make_knowledge_record("CWE-89"))

    scan = await harness.run()

    assert scan.status is ScanStatus.COMPLETED
    assert scan.progress_percent == 100
    assert scan.error_message is None
    assert scan.total_findings == 1
    assert scan.started_at is not None
    assert scan.completed_at is not None
    assert harness.uow.scans.status_history == [
        ScanStatus.PENDING,
        ScanStatus.RUNNING,
        ScanStatus.RUNNING,
        ScanStatus.COMPLETED,
    ]

    [finding] = await harness.uow.findings.list_for_scan(scan.id)
    assert finding.title == "SQL injection"
    assert finding.cwe_id == "CWE-89"
    assert (finding.location.file_path, finding.location.line_start) == ("app.py", 4)
    [file] = await harness.uow.scans.list_files(scan.id)
    assert finding.scan_file_id == file.id


@pytest.mark.unit
async def test_vulnerable_snippet_comes_from_the_source_not_from_the_llm() -> None:
    harness = await _harness(default=[make_analyzed_finding(line_start=4, line_end=5)])

    scan = await harness.run()

    [finding] = await harness.uow.findings.list_for_scan(scan.id)
    assert finding.vulnerable_snippet == (
        '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n'
        "    return conn.execute(query).fetchall()"
    )


@pytest.mark.unit
async def test_hallucinated_identifiers_are_stripped_but_the_finding_is_kept() -> None:
    harness = await _harness(
        default=[
            make_analyzed_finding(
                cwe_id="CWE-99999", owasp_category="A42:2021", attack_technique_id="T9999"
            )
        ]
    )
    await harness.uow.knowledge_documents.upsert(make_knowledge_record("CWE-89"))

    scan = await harness.run()

    [finding] = await harness.uow.findings.list_for_scan(scan.id)
    assert finding.cwe_id is None
    assert finding.owasp_category is None
    assert finding.attack_technique_id is None
    assert finding.references == []
    assert scan.total_findings == 1


@pytest.mark.unit
async def test_references_are_built_from_the_knowledge_base_not_from_llm_text() -> None:
    harness = await _harness(
        default=[
            make_analyzed_finding(
                cwe_id="cwe 89",
                owasp_category="A3 - Injection",
                attack_technique_id="t1190",
            )
        ]
    )
    # CWE-89 is found through retrieval (the vector store) ...
    await harness.indexer.upsert(
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
    # ... the two others only through the Postgres mirror table.
    await harness.uow.knowledge_documents.upsert(
        make_knowledge_record("A03:2021", KnowledgeSource.OWASP, "Injection", None)
    )
    await harness.uow.knowledge_documents.upsert(
        make_knowledge_record(
            "T1190", KnowledgeSource.ATTACK, "Exploit Public-Facing Application", None
        )
    )

    scan = await harness.run()

    [finding] = await harness.uow.findings.list_for_scan(scan.id)
    assert (finding.cwe_id, finding.owasp_category, finding.attack_technique_id) == (
        "CWE-89",
        "A03:2021",
        "T1190",
    )
    assert [(r.source, r.ref_id, r.title) for r in finding.references] == [
        (ReferenceSource.CWE, "CWE-89", "SQL Injection"),
        (ReferenceSource.OWASP, "A03:2021", "Injection"),
        (ReferenceSource.ATTACK, "T1190", "Exploit Public-Facing Application"),
    ]
    assert finding.references[0].url == "https://cwe.mitre.org/data/definitions/89.html"


@pytest.mark.unit
async def test_retrieved_knowledge_is_passed_to_the_llm_as_context() -> None:
    harness = await _harness()
    await harness.indexer.upsert(
        [
            KnowledgeDocument(
                external_id="CWE-89",
                source=KnowledgeSource.CWE,
                name="SQL Injection",
                category=None,
                url=None,
                content="sql injection",
            )
        ]
    )

    await harness.run()

    [(chunk, context)] = harness.analyzer.calls
    assert chunk.content == _VULNERABLE_CODE.rstrip("\n")
    assert [item.external_id for item in context] == ["CWE-89"]


@pytest.mark.unit
async def test_line_numbers_outside_the_chunk_are_pulled_back_inside() -> None:
    harness = await _harness(default=[make_analyzed_finding(line_start=400, line_end=900)])

    scan = await harness.run()

    [finding] = await harness.uow.findings.list_for_scan(scan.id)
    assert (finding.location.line_start, finding.location.line_end) == (1, 5)


@pytest.mark.unit
async def test_confidence_is_clamped_and_duplicate_findings_are_dropped() -> None:
    duplicate = make_analyzed_finding(confidence=7.5)
    harness = await _harness(default=[duplicate, duplicate])

    scan = await harness.run()

    [finding] = await harness.uow.findings.list_for_scan(scan.id)
    assert finding.confidence == 1.0
    assert scan.total_findings == 1


@pytest.mark.unit
async def test_clean_code_completes_with_no_findings() -> None:
    harness = await _harness()

    scan = await harness.run()

    assert scan.status is ScanStatus.COMPLETED
    assert scan.total_findings == 0
    assert await harness.uow.findings.list_for_scan(scan.id) == []


@pytest.mark.unit
async def test_progress_grows_chunk_by_chunk_and_only_reaches_100_on_completion() -> None:
    harness = await _harness(
        files={"a.py": "x = 1\ny = 2\n", "b.py": "z = 3\nw = 4\n"}, lines_per_chunk=1
    )

    scan = await harness.run()

    assert len(harness.analyzer.calls) == 4
    assert harness.uow.scans.progress_history == [0, 25, 50, 75, 99, 100]
    assert scan.status is ScanStatus.COMPLETED


@pytest.mark.unit
async def test_a_failed_chunk_does_not_fail_the_scan_but_is_reported() -> None:
    harness = await _harness(
        files={"a.py": "x = 1\ny = 2\n"},
        lines_per_chunk=1,
        responses=[LLMAnalysisError("invalid JSON"), [make_analyzed_finding(line_start=2)]],
    )

    scan = await harness.run()

    assert scan.status is ScanStatus.COMPLETED
    assert scan.total_findings == 1
    assert scan.error_message is not None
    assert "1 of 2 code chunks" in scan.error_message


@pytest.mark.unit
async def test_scan_fails_when_the_llm_keeps_failing() -> None:
    harness = await _harness(
        files={"a.py": "\n".join(f"line_{i} = {i}" for i in range(10))},
        lines_per_chunk=1,
        responses=[LLMAnalysisError("down")] * 10,
        settings=AnalysisSettings(max_consecutive_llm_failures=3),
    )

    scan = await harness.run()

    assert scan.status is ScanStatus.FAILED
    assert scan.error_message is not None
    assert "3 code chunks in a row" in scan.error_message
    assert scan.completed_at is not None
    # Gave up early instead of waiting out the remaining seven chunks.
    assert len(harness.analyzer.calls) == 3


@pytest.mark.unit
async def test_scan_fails_when_no_chunk_at_all_could_be_analyzed() -> None:
    harness = await _harness(responses=[LLMAnalysisError("invalid JSON")])

    scan = await harness.run()

    assert scan.status is ScanStatus.FAILED
    assert scan.error_message == "The LLM could not analyze any of the submitted code."


@pytest.mark.unit
async def test_unexpected_error_fails_the_scan_without_leaking_details() -> None:
    harness = await _harness(responses=[RuntimeError("secret internal hostname db-01")])

    scan = await harness.run()

    assert scan.status is ScanStatus.FAILED
    assert scan.error_message == "The analysis failed unexpectedly."


@pytest.mark.unit
async def test_findings_recorded_before_a_failure_are_kept() -> None:
    harness = await _harness(
        files={"a.py": "x = 1\ny = 2\n"},
        lines_per_chunk=1,
        responses=[[make_analyzed_finding()], RuntimeError("boom")],
    )

    scan = await harness.run()

    assert scan.status is ScanStatus.FAILED
    assert scan.total_findings == 1
    assert len(await harness.uow.findings.list_for_scan(scan.id)) == 1


@pytest.mark.unit
@pytest.mark.parametrize("status", [ScanStatus.RUNNING, ScanStatus.COMPLETED, ScanStatus.FAILED])
async def test_only_pending_scans_are_picked_up(status: ScanStatus) -> None:
    harness = await _harness(default=[make_analyzed_finding()])
    scan = await harness.uow.scans.get_by_id(harness.scan_id)
    assert scan is not None
    await harness.uow.scans.update(make_scan(scan_id=scan.id, status=status))

    result = await harness.run()

    assert result.status is status
    assert harness.analyzer.calls == []


@pytest.mark.unit
async def test_unknown_scan_id_is_a_no_op() -> None:
    harness = await _harness()

    await harness.use_case.execute(make_scan().id)

    assert harness.analyzer.calls == []


@pytest.mark.unit
async def test_scan_fails_with_a_clear_message_when_the_knowledge_base_is_down() -> None:
    harness = await _harness(
        files={"a.py": "x = 1\ny = 2\n"},
        lines_per_chunk=1,
        default=[make_analyzed_finding()],
    )

    async def _unreachable(*_args: object, **_kwargs: object) -> list[object]:
        raise ConnectionError("chromadb:8000 refused the connection")

    harness.use_case._retriever.query = _unreachable  # type: ignore[method-assign]

    scan = await harness.run()

    assert scan.status is ScanStatus.FAILED
    assert scan.error_message is not None
    assert "knowledge base could not be queried" in scan.error_message
    # Internal details stay in the logs, not in what the user is shown.
    assert "chromadb:8000" not in scan.error_message
    # No point asking the model anything, nor trying the second chunk.
    assert harness.analyzer.calls == []
