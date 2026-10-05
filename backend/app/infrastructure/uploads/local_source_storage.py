"""Filesystem `SourceStorage`: one directory per scan, one file per source
file, both named after ids we generated.

No user-supplied name or archive path is ever part of a filesystem path
here, so there is nothing to traverse with - the original `relative_path`
of a file only exists as a database column, for display.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from uuid import UUID

from app.domain.ports.source_storage import SourceStorage


class LocalSourceStorage(SourceStorage):
    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir

    def _scan_dir(self, scan_id: UUID) -> Path:
        return self._base_dir / str(scan_id)

    def _file_path(self, scan_id: UUID, file_id: UUID) -> Path:
        return self._scan_dir(scan_id) / f"{file_id}.src"

    async def save(self, scan_id: UUID, file_id: UUID, content: str) -> None:
        def _do_save() -> None:
            path = self._file_path(scan_id, file_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            # newline="": store the text exactly as submitted, so line numbers
            # and content hashes computed from it stay true to what is on disk.
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(content)

        await asyncio.to_thread(_do_save)

    async def read(self, scan_id: UUID, file_id: UUID) -> str:
        def _do_read() -> str:
            with self._file_path(scan_id, file_id).open(encoding="utf-8", newline="") as handle:
                return handle.read()

        return await asyncio.to_thread(_do_read)

    async def delete_scan(self, scan_id: UUID) -> None:
        await asyncio.to_thread(shutil.rmtree, self._scan_dir(scan_id), ignore_errors=True)
