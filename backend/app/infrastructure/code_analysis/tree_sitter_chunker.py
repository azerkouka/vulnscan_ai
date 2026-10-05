"""tree-sitter `CodeChunker`: cuts a file at function/class boundaries so
each LLM call sees whole, self-contained units of code.

How a file is split:

1. Units. The syntax tree is walked for function- and class-like nodes. A
   unit longer than `max_chunk_lines` is opened up and its nested units
   (a big class's methods, a wrapper function's handlers) are used instead.
2. Coverage. Lines belonging to no unit - imports, constants, top-level
   statements - are kept as spans of their own: module-level code is where
   hardcoded secrets and insecure configuration live, so it must reach the
   LLM too. Every non-blank line of the file ends up in exactly one chunk.
3. Packing. Neighbouring spans are merged while they fit in
   `max_chunk_lines`, so a small file is reviewed in one call, with its
   imports in view, rather than one call per three-line function. A single
   span that is still too long is cut into consecutive line windows.

Parsing is purely syntactic - the code is never imported or executed. Any
failure (grammar package not installed, unknown language, parser error)
degrades to plain line windows over the whole file instead of raising.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

from app.core.logging import get_logger
from app.domain.ports.code_chunker import CodeChunker
from app.domain.source_text import split_lines
from app.domain.value_objects.code_chunk import ChunkKind, CodeChunk
from app.domain.value_objects.code_location import CodeLocation

logger = get_logger(__name__)

# An anonymous function only counts as a unit from this many lines up - a
# one-line lambda or callback is better read as part of its surroundings.
_MIN_INLINE_FUNCTION_LINES = 3


@dataclass(frozen=True, slots=True)
class _Grammar:
    name: str
    """Grammar id in tree-sitter-language-pack."""
    functions: frozenset[str]
    classes: frozenset[str]
    inline_functions: frozenset[str] = frozenset()
    wrappers: frozenset[str] = frozenset()
    """Nodes that only decorate a definition (Python decorators): classified
    by the definition they wrap, but spanning the decoration too."""


_JS_FUNCTIONS = frozenset(
    {"function_declaration", "generator_function_declaration", "method_definition"}
)
_JS_INLINE = frozenset({"arrow_function", "function_expression", "function"})
_JS_CLASSES = frozenset({"class_declaration"})

_GRAMMARS: dict[str, _Grammar] = {
    "python": _Grammar(
        "python",
        functions=frozenset({"function_definition"}),
        classes=frozenset({"class_definition"}),
        wrappers=frozenset({"decorated_definition"}),
    ),
    "javascript": _Grammar("javascript", _JS_FUNCTIONS, _JS_CLASSES, _JS_INLINE),
    "typescript": _Grammar("typescript", _JS_FUNCTIONS, _JS_CLASSES, _JS_INLINE),
    "tsx": _Grammar("tsx", _JS_FUNCTIONS, _JS_CLASSES, _JS_INLINE),
    "java": _Grammar(
        "java",
        functions=frozenset({"method_declaration", "constructor_declaration"}),
        classes=frozenset(
            {
                "class_declaration",
                "interface_declaration",
                "enum_declaration",
                "record_declaration",
            }
        ),
    ),
    "go": _Grammar(
        "go",
        functions=frozenset({"function_declaration", "method_declaration"}),
        classes=frozenset(),
        inline_functions=frozenset({"func_literal"}),
    ),
    "php": _Grammar(
        "php",
        functions=frozenset({"function_definition", "method_declaration"}),
        classes=frozenset({"class_declaration", "trait_declaration", "interface_declaration"}),
        inline_functions=frozenset(
            {"anonymous_function", "anonymous_function_creation_expression"}
        ),
    ),
    "csharp": _Grammar(
        "csharp",
        functions=frozenset(
            {"method_declaration", "constructor_declaration", "local_function_statement"}
        ),
        classes=frozenset(
            {
                "class_declaration",
                "struct_declaration",
                "interface_declaration",
                "record_declaration",
            }
        ),
    ),
    "ruby": _Grammar(
        "ruby",
        functions=frozenset({"method", "singleton_method"}),
        classes=frozenset({"class", "module"}),
    ),
}

_Span = tuple[int, int, ChunkKind]
"""(first line, last line, kind) - 1-based, inclusive."""


class TreeSitterChunker(CodeChunker):
    def __init__(self, max_chunk_lines: int = 120) -> None:
        if max_chunk_lines < 1:
            raise ValueError("max_chunk_lines must be >= 1")
        self._max_chunk_lines = max_chunk_lines
        self._parsers: dict[str, Any] = {}

    def supports(self, language: str) -> bool:
        return self._parser(language) is not None

    def chunk(self, content: str, *, file_path: str, language: str) -> list[CodeChunk]:
        lines = split_lines(content)
        if not content.strip():
            return []

        units = self._units(content, language)
        if units is None:
            spans: list[_Span] = [(1, len(lines), ChunkKind.MODULE)]
        else:
            spans = self._pack(_cover(units, lines))

        chunks: list[CodeChunk] = []
        for start, end, kind in spans:
            for window_start in range(start, end + 1, self._max_chunk_lines):
                window_end = min(end, window_start + self._max_chunk_lines - 1)
                text = "\n".join(lines[window_start - 1 : window_end])
                if text.strip():
                    chunks.append(
                        CodeChunk(
                            content=text,
                            language=language,
                            location=CodeLocation(file_path, window_start, window_end),
                            kind=kind,
                        )
                    )
        return chunks

    def _parser(self, language: str) -> Any | None:
        """The parser for `language`, or None if there is no usable grammar
        for it - cached either way, so a missing grammar is logged once."""
        if language in self._parsers:
            return self._parsers[language]

        parser: Any | None = None
        grammar = _GRAMMARS.get(language)
        if grammar is not None:
            try:
                # Imported by name: the package types `get_parser` with a
                # Literal of every grammar it ships, which a name looked up at
                # runtime can't satisfy - and it is an optional dependency.
                pack: Any = importlib.import_module("tree_sitter_language_pack")
                parser = pack.get_parser(grammar.name)
            except Exception as exc:
                # Not installed (optional `chunking` extra) or grammar unavailable.
                logger.warning("chunker_grammar_unavailable", language=language, error=repr(exc))

        self._parsers[language] = parser
        return parser

    def _units(self, content: str, language: str) -> list[_Span] | None:
        """Function/class spans found in `content`, or None if it couldn't
        be parsed at all (the caller then falls back to line windows)."""
        parser = self._parser(language)
        if parser is None:
            return None
        try:
            tree = parser.parse(content.encode("utf-8"))
            return self._collect(tree.root_node, _GRAMMARS[language])
        except Exception as exc:  # includes RecursionError, on pathologically deep trees
            logger.warning("chunker_parse_failed", language=language, error=repr(exc))
            return None

    def _collect(self, node: Any, grammar: _Grammar) -> list[_Span]:
        units: list[_Span] = []
        for child in node.children:
            start, end = _line_span(child)
            kind = _classify(child, grammar, line_count=end - start + 1)

            if kind is None:
                if end > start:  # a single-line node can't hold a unit worth cutting out
                    units += self._collect(child, grammar)
                continue

            if end - start + 1 > self._max_chunk_lines:
                nested = self._collect(child, grammar)
                if nested:
                    units += nested
                    continue
            units.append((start, end, kind))
        return units

    def _pack(self, spans: list[_Span]) -> list[_Span]:
        """Greedily merges consecutive spans while the result (including the
        blank lines between them) fits in one chunk. A span merged with a
        neighbour is no longer a single function or class, hence MODULE."""
        packed: list[_Span] = []
        for start, end, kind in spans:
            if packed and end - packed[-1][0] + 1 <= self._max_chunk_lines:
                packed[-1] = (packed[-1][0], end, ChunkKind.MODULE)
            else:
                packed.append((start, end, kind))
        return packed


def _line_span(node: Any) -> tuple[int, int]:
    start, end = node.start_point[0] + 1, node.end_point[0] + 1
    if node.end_point[1] == 0 and end > start:
        end -= 1  # the node ends on a newline: it doesn't reach into the next line
    return start, end


def _classify(node: Any, grammar: _Grammar, *, line_count: int) -> ChunkKind | None:
    node_type = node.type
    if node_type in grammar.wrappers:
        wrapped = [child.type for child in node.children]
        if any(child_type in grammar.classes for child_type in wrapped):
            return ChunkKind.CLASS
        if any(child_type in grammar.functions for child_type in wrapped):
            return ChunkKind.FUNCTION
        return None
    if node_type in grammar.functions:
        return ChunkKind.FUNCTION
    if node_type in grammar.classes:
        return ChunkKind.CLASS
    if node_type in grammar.inline_functions and line_count >= _MIN_INLINE_FUNCTION_LINES:
        return ChunkKind.FUNCTION
    return None


def _cover(units: list[_Span], lines: list[str]) -> list[_Span]:
    """Completes `units` into spans covering every non-blank line: the lines
    between units become MODULE spans, trimmed of surrounding blank lines."""
    spans: list[_Span] = []
    next_line = 1

    def add_gap(first: int, last: int) -> None:
        while first <= last and not lines[first - 1].strip():
            first += 1
        while last >= first and not lines[last - 1].strip():
            last -= 1
        if first <= last:
            spans.append((first, last, ChunkKind.MODULE))

    for start, end, kind in sorted(units):
        if start < next_line:
            # Shares its first line with the previous unit (two definitions on
            # one line): fold it in rather than emit overlapping chunks.
            if spans and end >= next_line:
                spans[-1] = (spans[-1][0], end, spans[-1][2])
                next_line = end + 1
            continue
        add_gap(next_line, start - 1)
        spans.append((start, end, kind))
        next_line = end + 1

    add_gap(next_line, len(lines))
    return spans
