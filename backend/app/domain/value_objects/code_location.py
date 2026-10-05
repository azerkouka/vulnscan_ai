from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CodeLocation:
    file_path: str
    line_start: int
    line_end: int

    def __post_init__(self) -> None:
        if self.line_start < 1:
            raise ValueError("line_start must be >= 1")
        if self.line_end < self.line_start:
            raise ValueError("line_end must be >= line_start")
