"""Small infrastructure adapters of the scan pipeline that need no external
service: source storage, the in-process job runner, and the line/language
helpers they all rely on."""

import asyncio
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from app.domain.source_text import normalize_newlines, split_lines
from app.domain.value_objects.language import (
    SUPPORTED_LANGUAGES,
    detect_language,
    extension_for_language,
)
from app.domain.value_objects.severity import Severity
from app.infrastructure.jobs.asyncio_job_runner import AsyncioJobRunner
from app.infrastructure.uploads.local_source_storage import LocalSourceStorage

# --- Source text ---------------------------------------------------------------


@pytest.mark.unit
def test_newlines_are_normalized_to_lf() -> None:
    assert normalize_newlines("a\r\nb\rc\nd") == "a\nb\nc\nd"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", []),
        ("a", ["a"]),
        ("a\n", ["a"]),
        ("a\n\nb\n", ["a", "", "b"]),
        ("a\n\n", ["a", ""]),
        # Form feeds and other separator characters are part of a line, not line breaks.
        ("a\x0cb\x1cc\n", ["a\x0cb\x1cc"]),
    ],
)
def test_lines_are_split_on_lf_only(text: str, expected: list[str]) -> None:
    assert split_lines(text) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("path", "language"),
    [
        ("app.py", "python"),
        ("src/Index.JS", "javascript"),
        ("ui/App.jsx", "javascript"),
        ("ui/App.tsx", "tsx"),
        ("api.ts", "typescript"),
        ("Main.java", "java"),
        ("main.go", "go"),
        ("index.php", "php"),
        ("Program.cs", "csharp"),
        ("app.rb", "ruby"),
        ("README.md", None),
        ("Makefile", None),
    ],
)
def test_language_is_detected_from_the_extension(path: str, language: str | None) -> None:
    assert detect_language(path) == language


@pytest.mark.unit
def test_every_supported_language_round_trips_through_its_extension() -> None:
    for language in SUPPORTED_LANGUAGES:
        extension = extension_for_language(language)
        assert extension is not None
        assert detect_language(f"file{extension}") == language


@pytest.mark.unit
def test_severity_rank_orders_most_severe_first() -> None:
    assert sorted(Severity, key=lambda s: s.rank) == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]


# --- Local source storage --------------------------------------------------------


@pytest.mark.unit
async def test_storage_round_trips_content_exactly(tmp_path: Path) -> None:
    storage = LocalSourceStorage(tmp_path)
    scan_id, file_id = uuid4(), uuid4()
    content = "def f():\n    return 'héllo ✓'\n"

    await storage.save(scan_id, file_id, content)

    assert await storage.read(scan_id, file_id) == content


@pytest.mark.unit
async def test_storage_paths_are_built_from_ids_only(tmp_path: Path) -> None:
    storage = LocalSourceStorage(tmp_path)
    scan_id, file_id = uuid4(), uuid4()

    await storage.save(scan_id, file_id, "x = 1")

    assert [p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file()] == [
        f"{scan_id}/{file_id}.src"
    ]


@pytest.mark.unit
async def test_deleting_a_scan_removes_only_that_scans_files(tmp_path: Path) -> None:
    storage = LocalSourceStorage(tmp_path)
    kept_scan, deleted_scan, file_id = uuid4(), uuid4(), uuid4()
    await storage.save(kept_scan, file_id, "keep")
    await storage.save(deleted_scan, file_id, "delete")

    await storage.delete_scan(deleted_scan)
    await storage.delete_scan(uuid4())  # nothing stored: a no-op, not an error

    assert await storage.read(kept_scan, file_id) == "keep"
    with pytest.raises(FileNotFoundError):
        await storage.read(deleted_scan, file_id)


# --- Asyncio job runner -----------------------------------------------------------


@pytest.mark.unit
async def test_enqueue_returns_before_the_job_has_run() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    finished: list[UUID] = []

    async def job(scan_id: UUID) -> None:
        started.set()
        await release.wait()
        finished.append(scan_id)

    runner = AsyncioJobRunner(job)
    scan_id = uuid4()

    await runner.enqueue_scan(scan_id)
    assert finished == []

    await started.wait()
    release.set()
    await runner.wait_idle()
    assert finished == [scan_id]


@pytest.mark.unit
async def test_jobs_run_one_at_a_time_by_default() -> None:
    running = 0
    max_running = 0

    async def job(_scan_id: UUID) -> None:
        nonlocal running, max_running
        running += 1
        max_running = max(max_running, running)
        await asyncio.sleep(0.01)
        running -= 1

    runner = AsyncioJobRunner(job)
    for _ in range(4):
        await runner.enqueue_scan(uuid4())
    await runner.wait_idle()

    assert max_running == 1


@pytest.mark.unit
async def test_concurrency_limit_is_configurable() -> None:
    running = 0
    max_running = 0

    async def job(_scan_id: UUID) -> None:
        nonlocal running, max_running
        running += 1
        max_running = max(max_running, running)
        await asyncio.sleep(0.01)
        running -= 1

    runner = AsyncioJobRunner(job, max_concurrent_jobs=3)
    for _ in range(6):
        await runner.enqueue_scan(uuid4())
    await runner.wait_idle()

    assert max_running == 3


@pytest.mark.unit
async def test_a_crashing_job_does_not_stop_later_jobs() -> None:
    done: list[UUID] = []
    crashing_id, healthy_id = uuid4(), uuid4()

    async def job(scan_id: UUID) -> None:
        if scan_id == crashing_id:
            raise RuntimeError("boom")
        done.append(scan_id)

    runner = AsyncioJobRunner(job)
    await runner.enqueue_scan(crashing_id)
    await runner.enqueue_scan(healthy_id)
    await runner.wait_idle()

    assert done == [healthy_id]


@pytest.mark.unit
async def test_shutdown_cancels_running_and_queued_jobs() -> None:
    cancelled: list[UUID] = []
    completed: list[UUID] = []

    async def job(scan_id: UUID) -> None:
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled.append(scan_id)
            raise
        completed.append(scan_id)

    runner = AsyncioJobRunner(job)
    running_id = uuid4()
    await runner.enqueue_scan(running_id)
    await runner.enqueue_scan(uuid4())  # queued behind the first, never starts
    await asyncio.sleep(0)  # let the first job start

    await asyncio.wait_for(runner.shutdown(), timeout=2)

    assert cancelled == [running_id]
    assert completed == []
