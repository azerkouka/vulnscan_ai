from uuid import uuid4

import pytest

from app.application.dto.scan import CreateScanInput
from app.application.use_cases.create_scan import CreateScanUseCase, ScanSourceLimits
from app.domain.exceptions import InvalidArchiveError, InvalidSourceError, SourceTooLargeError
from app.domain.ports.archive_extractor import ExtractedFile
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.source_type import SourceType
from tests.unit.fakes import FakeArchiveExtractor, FakeJobRunner, FakeSourceStorage, FakeUnitOfWork

_LIMITS = ScanSourceLimits(
    max_upload_bytes=1024, allowed_extensions=frozenset({".py", ".js", ".zip"})
)


class _Harness:
    def __init__(self, extractor: FakeArchiveExtractor | None = None) -> None:
        self.uow = FakeUnitOfWork()
        self.storage = FakeSourceStorage()
        self.extractor = extractor or FakeArchiveExtractor()
        self.jobs = FakeJobRunner()
        self.use_case = CreateScanUseCase(
            self.uow, self.storage, self.extractor, self.jobs, _LIMITS
        )


@pytest.mark.unit
async def test_snippet_creates_a_pending_scan_and_enqueues_it() -> None:
    harness = _Harness()
    user_id = uuid4()

    result = await harness.use_case.execute(
        CreateScanInput(user_id=user_id, content=b"import os\nos.system(cmd)\n", language="Python")
    )

    assert result.source_type is SourceType.SNIPPET
    assert result.status is ScanStatus.PENDING
    assert result.total_files == 1
    assert harness.uow.committed is True
    assert harness.jobs.enqueued_scan_ids == [result.id]

    stored_scan = await harness.uow.scans.get_by_id(result.id)
    assert stored_scan is not None
    assert stored_scan.user_id == user_id

    [file] = await harness.uow.scans.list_files(result.id)
    assert (file.relative_path, file.language, file.loc) == ("snippet.py", "python", 2)
    assert harness.storage.contents[(result.id, file.id)] == "import os\nos.system(cmd)\n"


@pytest.mark.unit
async def test_snippet_without_a_language_is_stored_as_plain_text() -> None:
    harness = _Harness()

    result = await harness.use_case.execute(
        CreateScanInput(user_id=uuid4(), content=b"SELECT * FROM users")
    )

    [file] = await harness.uow.scans.list_files(result.id)
    assert (file.relative_path, file.language) == ("snippet.txt", None)


@pytest.mark.unit
async def test_snippet_with_an_unsupported_language_is_rejected() -> None:
    harness = _Harness()

    with pytest.raises(InvalidSourceError, match="Unsupported language"):
        await harness.use_case.execute(
            CreateScanInput(user_id=uuid4(), content=b"code", language="cobol")
        )


@pytest.mark.unit
async def test_single_file_upload_detects_language_and_normalizes_newlines() -> None:
    harness = _Harness()

    result = await harness.use_case.execute(
        CreateScanInput(user_id=uuid4(), content=b"a = 1\r\nb = 2\r\n", filename="views.py")
    )

    assert result.source_type is SourceType.FILE
    [file] = await harness.uow.scans.list_files(result.id)
    assert (file.filename, file.language, file.loc) == ("views.py", "python", 2)
    assert harness.storage.contents[(result.id, file.id)] == "a = 1\nb = 2\n"


@pytest.mark.unit
async def test_client_supplied_path_is_reduced_to_its_file_name() -> None:
    harness = _Harness()

    result = await harness.use_case.execute(
        CreateScanInput(
            user_id=uuid4(), content=b"x = 1", filename="..\\..\\windows\\system32\\evil.py"
        )
    )

    [file] = await harness.uow.scans.list_files(result.id)
    assert file.relative_path == "evil.py"


@pytest.mark.unit
@pytest.mark.parametrize("filename", ["malware.exe", "notes", "archive.tar.gz"])
async def test_unsupported_extension_is_rejected(filename: str) -> None:
    harness = _Harness()

    with pytest.raises(InvalidSourceError, match="Unsupported file type"):
        await harness.use_case.execute(
            CreateScanInput(user_id=uuid4(), content=b"data", filename=filename)
        )

    assert harness.jobs.enqueued_scan_ids == []


@pytest.mark.unit
async def test_source_over_the_size_limit_is_rejected() -> None:
    harness = _Harness()

    with pytest.raises(SourceTooLargeError):
        await harness.use_case.execute(
            CreateScanInput(user_id=uuid4(), content=b"x" * 1025, filename="big.py")
        )


@pytest.mark.unit
@pytest.mark.parametrize("content", [b"", b"   \n\t\n"])
async def test_empty_source_is_rejected(content: bytes) -> None:
    harness = _Harness()

    with pytest.raises(InvalidSourceError, match="empty"):
        await harness.use_case.execute(CreateScanInput(user_id=uuid4(), content=content))


@pytest.mark.unit
async def test_binary_content_is_rejected() -> None:
    harness = _Harness()

    with pytest.raises(InvalidSourceError, match="binary"):
        await harness.use_case.execute(
            CreateScanInput(user_id=uuid4(), content=b"MZ\x00\x01\x02", filename="app.py")
        )


@pytest.mark.unit
async def test_zip_upload_creates_one_scan_file_per_extracted_file() -> None:
    harness = _Harness(
        FakeArchiveExtractor(
            [
                ExtractedFile("src/app.py", "print('a')\n"),
                ExtractedFile("src/static/main.js", "alert(1)\n"),
            ]
        )
    )

    result = await harness.use_case.execute(
        CreateScanInput(user_id=uuid4(), content=b"PK-fake-archive", filename="project.ZIP")
    )

    assert result.source_type is SourceType.ZIP
    assert result.total_files == 2
    assert harness.extractor.archives == [b"PK-fake-archive"]
    files = await harness.uow.scans.list_files(result.id)
    assert [(f.relative_path, f.filename, f.language) for f in files] == [
        ("src/app.py", "app.py", "python"),
        ("src/static/main.js", "main.js", "javascript"),
    ]


@pytest.mark.unit
async def test_rejected_archive_creates_nothing() -> None:
    harness = _Harness(FakeArchiveExtractor(error=InvalidArchiveError("path traversal")))

    with pytest.raises(InvalidArchiveError):
        await harness.use_case.execute(
            CreateScanInput(user_id=uuid4(), content=b"PK", filename="evil.zip")
        )

    assert harness.uow.scans.by_id == {}
    assert harness.storage.contents == {}
    assert harness.jobs.enqueued_scan_ids == []


@pytest.mark.unit
async def test_stored_source_is_cleaned_up_if_the_scan_cannot_be_recorded() -> None:
    harness = _Harness()

    async def _failing_add(*_args: object) -> None:
        raise RuntimeError("database is down")

    harness.uow.scans.add = _failing_add  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await harness.use_case.execute(CreateScanInput(user_id=uuid4(), content=b"x = 1"))

    assert harness.storage.contents == {}
    assert len(harness.storage.deleted_scan_ids) == 1
    assert harness.jobs.enqueued_scan_ids == []
