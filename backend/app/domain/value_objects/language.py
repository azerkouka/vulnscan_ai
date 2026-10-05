"""Source-language detection from a file name.

The language id is what the rest of the pipeline keys on: the chunker picks
a grammar from it, and the LLM prompt names it. Purely extension-based - the
platform never executes or imports submitted code to find out what it is.
"""

from __future__ import annotations

from pathlib import PurePosixPath

UNKNOWN_LANGUAGE = "unknown"

_EXTENSION_BY_LANGUAGE: dict[str, str] = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "tsx": ".tsx",
    "java": ".java",
    "go": ".go",
    "php": ".php",
    "csharp": ".cs",
    "ruby": ".rb",
}

_LANGUAGE_BY_EXTENSION: dict[str, str] = {
    **{extension: language for language, extension in _EXTENSION_BY_LANGUAGE.items()},
    ".jsx": "javascript",
}

SUPPORTED_LANGUAGES: frozenset[str] = frozenset(_EXTENSION_BY_LANGUAGE)


def detect_language(file_path: str) -> str | None:
    """The language id for `file_path`, or None if its extension isn't one
    we analyze."""
    return _LANGUAGE_BY_EXTENSION.get(PurePosixPath(file_path).suffix.lower())


def extension_for_language(language: str) -> str | None:
    return _EXTENSION_BY_LANGUAGE.get(language)
