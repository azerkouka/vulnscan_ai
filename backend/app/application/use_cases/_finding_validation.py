"""Normalization of what the LLM claims about a finding, before any of it
is trusted.

The LLM is free-text in, free-text out: it writes "CWE 89", "cwe-089",
"A3 - Injection", or line numbers relative to the excerpt it was shown.
These helpers reduce each of those to the one canonical form the knowledge
base is keyed by (so it can then be looked up - see
`RunScanAnalysisUseCase`), or to None when nothing usable is there.
"""

from __future__ import annotations

import re

from app.domain.value_objects.code_location import CodeLocation

_CWE_RE = re.compile(r"^\s*(?:CWE[\s_:-]*)?(\d{1,5})\b", re.IGNORECASE)
_OWASP_RE = re.compile(r"\bA(\d{1,2})(?:\s*:\s*(\d{4}))?", re.IGNORECASE)
_ATTACK_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?", re.IGNORECASE)

# The edition of the ingested OWASP Top 10 (`data/knowledge/owasp`), assumed
# when the LLM cites a category without its year.
_OWASP_DEFAULT_EDITION = "2021"


def normalize_cwe_id(raw: str | None) -> str | None:
    match = _CWE_RE.search(raw) if raw else None
    return f"CWE-{int(match.group(1))}" if match else None


def normalize_owasp_category(raw: str | None) -> str | None:
    match = _OWASP_RE.search(raw) if raw else None
    if match is None:
        return None
    return f"A{int(match.group(1)):02d}:{match.group(2) or _OWASP_DEFAULT_EDITION}"


def normalize_attack_technique_id(raw: str | None) -> str | None:
    match = _ATTACK_RE.search(raw) if raw else None
    if match is None:
        return None
    technique = f"T{match.group(1)}"
    return f"{technique}.{match.group(2)}" if match.group(2) else technique


def resolve_line_range(line_start: int, line_end: int, chunk: CodeLocation) -> tuple[int, int]:
    """Maps the line range an LLM reported onto real lines of the chunk it
    was shown, so a finding can never point outside the code it is about.

    A range lying entirely outside the chunk is first re-read as relative to
    the chunk's first line (a model that ignored the absolute numbering);
    if that doesn't land inside either, the whole chunk is used.
    """
    if line_end < line_start:
        line_start, line_end = line_end, line_start

    if line_end < chunk.line_start or line_start > chunk.line_end:
        offset = chunk.line_start - 1
        line_start, line_end = line_start + offset, line_end + offset
        if line_start < chunk.line_start or line_start > chunk.line_end:
            return chunk.line_start, chunk.line_end

    return max(line_start, chunk.line_start), min(line_end, chunk.line_end)
