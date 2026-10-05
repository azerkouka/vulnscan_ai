import io
import stat
import zipfile

import pytest

from app.domain.exceptions import InvalidArchiveError
from app.infrastructure.uploads.safe_zip_extractor import SafeZipExtractor

_MEBIBYTE = 1024 * 1024


def _extractor(
    *,
    max_files: int = 100,
    max_uncompressed_bytes: int = 10 * _MEBIBYTE,
    max_compression_ratio: int = 100,
) -> SafeZipExtractor:
    return SafeZipExtractor(
        max_files=max_files,
        max_uncompressed_bytes=max_uncompressed_bytes,
        max_compression_ratio=max_compression_ratio,
        source_extensions=frozenset({".py", ".js"}),
    )


def _zip(entries: dict[str, bytes | str], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.unit
def test_extracts_source_files_with_normalized_paths() -> None:
    archive = _zip(
        {
            "project/app.py": "print('a')\n",
            "project\\web\\main.js": "alert(1)\n",
            "project/./lib/util.py": "x = 1\n",
        }
    )

    files = _extractor().extract(archive)

    assert [(f.relative_path, f.content) for f in files] == [
        ("project/app.py", "print('a')\n"),
        ("project/lib/util.py", "x = 1\n"),
        ("project/web/main.js", "alert(1)\n"),
    ]


@pytest.mark.unit
def test_skips_irrelevant_entries_without_rejecting_the_archive() -> None:
    archive = _zip(
        {
            "app.py": "print('kept')\n",
            "README.md": "# docs",
            "logo.png": b"\x89PNG\r\n",
            "node_modules/lib/index.js": "module.exports = 1\n",
            ".git/hooks/pre-commit.py": "print('hook')\n",
            "fake_source.py": b"\x00\x01\x02binary",
            "empty.py": "   \n",
            "nested.zip": _zip({"inner.py": "x = 1\n"}),
        }
    )

    files = _extractor().extract(archive)

    assert [f.relative_path for f in files] == ["app.py"]


@pytest.mark.unit
@pytest.mark.parametrize(
    "malicious_name",
    [
        "../../etc/passwd.py",
        "project/../../outside.py",
        "..\\..\\windows\\evil.py",
        "/etc/cron.d/job.py",
        "C:\\Windows\\evil.py",
        "C:/Windows/evil.py",
    ],
)
def test_zip_slip_entry_rejects_the_whole_archive(malicious_name: str) -> None:
    archive = _zip({"app.py": "print('innocent')\n", malicious_name: "print('evil')\n"})

    with pytest.raises(InvalidArchiveError, match="path traversal|absolute path"):
        _extractor().extract(archive)


@pytest.mark.unit
def test_traversal_is_rejected_even_on_an_entry_that_would_have_been_skipped() -> None:
    archive = _zip({"app.py": "x = 1\n", "../../notes.txt": "not source"})

    with pytest.raises(InvalidArchiveError, match="path traversal"):
        _extractor().extract(archive)


@pytest.mark.unit
def test_too_many_files_is_rejected() -> None:
    archive = _zip({f"file_{i}.py": "x = 1\n" for i in range(6)})

    with pytest.raises(InvalidArchiveError, match="more than the 5 files"):
        _extractor(max_files=5).extract(archive)


@pytest.mark.unit
def test_declared_size_over_the_limit_is_rejected_before_decompressing() -> None:
    archive = _zip({"big.py": "x" * (2 * _MEBIBYTE)}, compression=zipfile.ZIP_STORED)

    with pytest.raises(InvalidArchiveError, match="expands to more than"):
        _extractor(max_uncompressed_bytes=_MEBIBYTE).extract(archive)


@pytest.mark.unit
def test_zip_bomb_with_a_lying_header_is_stopped_while_decompressing() -> None:
    # 5 MiB of zeros deflates to a few kilobytes. The header's declared size
    # is then forged down to 10 bytes, so only the check on bytes actually
    # produced can catch it.
    payload = b"0" * (5 * _MEBIBYTE)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("bomb.py", payload)
    forged = _forge_declared_size(buffer.getvalue(), real_size=len(payload), fake_size=10)

    with pytest.raises(InvalidArchiveError):
        _extractor(max_uncompressed_bytes=_MEBIBYTE).extract(forged)


@pytest.mark.unit
def test_high_compression_ratio_is_rejected() -> None:
    archive = _zip({"bomb.py": "0" * (4 * _MEBIBYTE)})

    with pytest.raises(InvalidArchiveError, match="compression ratio"):
        _extractor(max_compression_ratio=100).extract(archive)


@pytest.mark.unit
def test_small_highly_repetitive_source_file_is_not_mistaken_for_a_bomb() -> None:
    archive = _zip({"constants.py": "ZERO = 0\n" * 20_000})  # ~180 KiB, ratio far above 100

    [file] = _extractor(max_compression_ratio=100).extract(archive)

    assert file.relative_path == "constants.py"


@pytest.mark.unit
def test_symlink_entries_are_skipped() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("app.py", "x = 1\n")
        link = zipfile.ZipInfo("link.py")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "/etc/passwd")

    files = _extractor().extract(buffer.getvalue())

    assert [f.relative_path for f in files] == ["app.py"]


@pytest.mark.unit
@pytest.mark.parametrize("data", [b"", b"this is not a zip archive", b"PK\x03\x04truncated"])
def test_corrupt_archive_is_rejected(data: bytes) -> None:
    with pytest.raises(InvalidArchiveError, match="not a readable ZIP"):
        _extractor().extract(data)


@pytest.mark.unit
def test_archive_without_any_source_file_is_rejected() -> None:
    archive = _zip({"README.md": "# docs", "data.csv": "a,b\n"})

    with pytest.raises(InvalidArchiveError, match="no analyzable source files"):
        _extractor().extract(archive)


def _forge_declared_size(archive: bytes, *, real_size: int, fake_size: int) -> bytes:
    """Rewrites every occurrence of the entry's uncompressed size (local
    header and central directory) to `fake_size`."""
    real = real_size.to_bytes(4, "little")
    assert archive.count(real) == 2, "expected the size in exactly two headers"
    return archive.replace(real, fake_size.to_bytes(4, "little"))
