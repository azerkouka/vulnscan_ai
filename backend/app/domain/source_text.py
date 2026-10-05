"""How submitted source is split into lines - defined once, because line
numbers are the contract between every stage of the pipeline: the chunker
cuts on them, the LLM cites them, and findings are sliced back out by them.

Only "\n" separates lines (which is also how tree-sitter counts rows).
`str.splitlines()` must not be used on source text: it additionally splits
on form feeds and Unicode separators, which would shift every later line
number against the parser's.
"""

from __future__ import annotations


def normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # a trailing newline ends the last line, it doesn't start another
    return lines
