"""In-memory ZIP extraction for uploaded projects, hardened against hostile
archives.

Nothing is ever written to disk from here, and no entry name is used as a
filesystem path (see `LocalSourceStorage`), but an uploaded archive is still
attacker-controlled input, so:

- zip slip: any entry with an absolute path, a drive letter or a `..`
  component rejects the whole archive - a legitimate project export never
  contains one, so its presence means the archive was crafted;
- zip bomb: the entry count, the total uncompressed size and the
  per-entry compression ratio are all capped. Sizes declared in the archive
  headers are checked first (cheap early exit) but never trusted: the caps
  are enforced again on the bytes actually produced while decompressing;
- symlinks are skipped, encrypted entries are refused.

Only files worth analyzing are decompressed at all: entries with a
non-source extension, inside dependency/build folders, or that turn out to
be binary are skipped.
"""

from __future__ import annotations

import io
import re
import stat
import zipfile
import zlib
from pathlib import PurePosixPath

from app.domain.exceptions import InvalidArchiveError
from app.domain.ports.archive_extractor import ArchiveExtractor, ExtractedFile

_READ_BLOCK_BYTES = 64 * 1024
# Below this size an entry can't be a meaningful bomb, however well it
# compresses - small, repetitive source files legitimately reach high ratios.
_RATIO_CHECK_FLOOR_BYTES = 1024 * 1024
_MAX_PATH_LENGTH = 1024
_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:")
_ENCRYPTED_FLAG = 0x1

_SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".venv",
        "venv",
        "__pycache__",
        "__MACOSX",
        "node_modules",
        "vendor",
        "dist",
        "build",
    }
)


class SafeZipExtractor(ArchiveExtractor):
    def __init__(
        self,
        *,
        max_files: int,
        max_uncompressed_bytes: int,
        max_compression_ratio: int,
        source_extensions: frozenset[str],
    ) -> None:
        self._max_files = max_files
        self._max_uncompressed_bytes = max_uncompressed_bytes
        self._max_compression_ratio = max_compression_ratio
        self._source_extensions = source_extensions

    def extract(self, archive: bytes) -> list[ExtractedFile]:
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as zip_file:
                return self._extract(zip_file)
        except InvalidArchiveError:
            raise
        except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError) as exc:
            # Corrupt data, an unsupported compression method, or a password prompt.
            raise InvalidArchiveError("The uploaded file is not a readable ZIP archive.") from exc

    def _extract(self, zip_file: zipfile.ZipFile) -> list[ExtractedFile]:
        entries = [info for info in zip_file.infolist() if not info.is_dir()]

        if len(entries) > self._max_files:
            raise InvalidArchiveError(
                f"The archive holds more than the {self._max_files} files allowed."
            )
        if sum(info.file_size for info in entries) > self._max_uncompressed_bytes:
            raise InvalidArchiveError(self._too_large_message())

        files: dict[str, str] = {}
        total_read = 0
        for info in entries:
            path = _safe_relative_path(info.filename)

            if info.flag_bits & _ENCRYPTED_FLAG:
                raise InvalidArchiveError("Encrypted archives are not supported.")
            if stat.S_ISLNK(info.external_attr >> 16) or not self._is_analyzable(path):
                continue

            data = self._read_entry(
                zip_file, info, budget=self._max_uncompressed_bytes - total_read
            )
            total_read += len(data)

            if b"\0" in data:
                continue  # binary content behind a source extension
            text = data.decode("utf-8-sig", errors="replace")
            if text.strip():
                files.setdefault(path, text)

        if not files:
            raise InvalidArchiveError("The archive contains no analyzable source files.")
        return [ExtractedFile(path, content) for path, content in sorted(files.items())]

    def _is_analyzable(self, path: str) -> bool:
        parts = PurePosixPath(path).parts
        if len(path) > _MAX_PATH_LENGTH or _SKIPPED_DIRECTORIES.intersection(parts[:-1]):
            return False
        return PurePosixPath(path).suffix.lower() in self._source_extensions

    def _read_entry(
        self, zip_file: zipfile.ZipFile, info: zipfile.ZipInfo, *, budget: int
    ) -> bytes:
        """Decompresses one entry block by block, stopping the moment it
        outgrows either the remaining size budget or the allowed ratio -
        whatever its header claimed."""
        ratio_limit = max(info.compress_size, 1) * self._max_compression_ratio
        blocks: list[bytes] = []
        read = 0
        with zip_file.open(info) as entry:
            while block := entry.read(_READ_BLOCK_BYTES):
                read += len(block)
                if read > budget:
                    raise InvalidArchiveError(self._too_large_message())
                if read > _RATIO_CHECK_FLOOR_BYTES and read > ratio_limit:
                    raise InvalidArchiveError(
                        "The archive has a suspiciously high compression ratio and was rejected."
                    )
                blocks.append(block)
        return b"".join(blocks)

    def _too_large_message(self) -> str:
        limit_mb = self._max_uncompressed_bytes / (1024 * 1024)
        return f"The archive expands to more than the {limit_mb:g} MB allowed."


def _safe_relative_path(name: str) -> str:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or _DRIVE_LETTER_RE.match(normalized):
        raise InvalidArchiveError("The archive contains an absolute path and was rejected.")

    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise InvalidArchiveError("The archive contains a path traversal entry and was rejected.")
    if not parts:
        raise InvalidArchiveError("The archive contains an entry with an empty name.")
    return "/".join(parts)
