import pytest

from app.domain.source_text import split_lines
from app.domain.value_objects.code_chunk import ChunkKind, CodeChunk
from app.infrastructure.code_analysis.tree_sitter_chunker import TreeSitterChunker


def _function(name: str, body_lines: int) -> str:
    body = "\n".join(f"    value_{i} = {i}" for i in range(body_lines - 2))
    return f"def {name}():\n{body}\n    return value_0\n"


def _covered_lines(chunks: list[CodeChunk]) -> list[int]:
    return [
        line
        for chunk in chunks
        for line in range(chunk.location.line_start, chunk.location.line_end + 1)
    ]


def _assert_covers_every_non_blank_line_once(content: str, chunks: list[CodeChunk]) -> None:
    lines = split_lines(content)
    covered = _covered_lines(chunks)
    assert len(covered) == len(set(covered)), "chunks overlap"
    non_blank = {number for number, line in enumerate(lines, start=1) if line.strip()}
    assert non_blank <= set(covered), f"lines never sent to the LLM: {non_blank - set(covered)}"
    for chunk in chunks:
        expected = "\n".join(lines[chunk.location.line_start - 1 : chunk.location.line_end])
        assert chunk.content == expected


# --- Fallback behaviour: needs no grammar, so it always runs -----------------


@pytest.mark.unit
def test_unknown_language_falls_back_to_one_module_chunk() -> None:
    content = "SELECT *\nFROM users\nWHERE id = 1\n"

    [chunk] = TreeSitterChunker().chunk(content, file_path="query.sql", language="unknown")

    assert chunk.kind is ChunkKind.MODULE
    assert chunk.language == "unknown"
    assert (chunk.location.file_path, chunk.location.line_start, chunk.location.line_end) == (
        "query.sql",
        1,
        3,
    )
    assert chunk.content == "SELECT *\nFROM users\nWHERE id = 1"


@pytest.mark.unit
def test_long_fallback_file_is_cut_into_line_windows() -> None:
    content = "\n".join(f"line {i}" for i in range(1, 26))

    chunks = TreeSitterChunker(max_chunk_lines=10).chunk(
        content, file_path="notes.txt", language="unknown"
    )

    assert [(c.location.line_start, c.location.line_end) for c in chunks] == [
        (1, 10),
        (11, 20),
        (21, 25),
    ]
    _assert_covers_every_non_blank_line_once(content, chunks)


@pytest.mark.unit
@pytest.mark.parametrize("content", ["", "\n\n   \n"])
def test_blank_file_yields_no_chunk(content: str) -> None:
    assert TreeSitterChunker().chunk(content, file_path="empty.py", language="python") == []


@pytest.mark.unit
def test_unsupported_language_is_reported_as_such() -> None:
    assert TreeSitterChunker().supports("cobol") is False


@pytest.mark.unit
def test_invalid_chunk_size_is_rejected() -> None:
    with pytest.raises(ValueError, match="max_chunk_lines"):
        TreeSitterChunker(max_chunk_lines=0)


# --- Grammar-based splitting: needs the optional `chunking` extra ------------


@pytest.fixture
def chunker() -> TreeSitterChunker:
    pytest.importorskip(
        "tree_sitter_language_pack", reason="install the 'chunking' extra to run this"
    )
    chunker = TreeSitterChunker(max_chunk_lines=20)
    if not chunker.supports("python"):
        pytest.skip("tree-sitter python grammar unavailable")
    return chunker


@pytest.mark.unit
def test_small_file_is_reviewed_as_a_single_chunk(chunker: TreeSitterChunker) -> None:
    content = "import os\n\n\ndef a():\n    return 1\n\n\ndef b():\n    return 2\n"

    [chunk] = chunker.chunk(content, file_path="small.py", language="python")

    assert chunk.kind is ChunkKind.MODULE
    assert (chunk.location.line_start, chunk.location.line_end) == (1, 9)


@pytest.mark.unit
def test_file_is_cut_at_function_boundaries(chunker: TreeSitterChunker) -> None:
    content = "import os\n\n\n" + _function("first", 15) + "\n\n" + _function("second", 15)

    chunks = chunker.chunk(content, file_path="views.py", language="python")

    functions = [c for c in chunks if c.kind is ChunkKind.FUNCTION]
    assert [c.content.split("\n")[0] for c in functions] == ["def second():"]
    # `import os` and first() fit together in one chunk; second() didn't fit with them.
    assert chunks[0].content.startswith("import os")
    assert "def first():" in chunks[0].content
    assert all(c.content.rstrip().endswith("return value_0") for c in chunks)
    _assert_covers_every_non_blank_line_once(content, chunks)


@pytest.mark.unit
def test_decorators_stay_attached_to_their_function(chunker: TreeSitterChunker) -> None:
    content = (
        _function("helper", 18)
        + "\n\n"
        + "@app.route('/login')\n@limiter\n"
        + _function("login", 15)
    )

    chunks = chunker.chunk(content, file_path="views.py", language="python")

    login = next(c for c in chunks if "def login" in c.content)
    assert login.content.startswith("@app.route('/login')\n@limiter\ndef login():")
    assert login.kind is ChunkKind.FUNCTION


@pytest.mark.unit
def test_large_class_is_split_into_its_methods(chunker: TreeSitterChunker) -> None:
    methods = "\n".join(
        f"    def method_{n}(self):\n"
        + "\n".join(f"        step_{i} = {i}" for i in range(13))
        + "\n        return step_0\n"
        for n in range(3)
    )
    content = "class Service:\n    name = 'svc'\n\n" + methods

    chunks = chunker.chunk(content, file_path="service.py", language="python")

    assert len(chunks) >= 3
    assert any(c.content.startswith("class Service:") for c in chunks)
    assert sum(1 for c in chunks if c.kind is ChunkKind.FUNCTION) >= 2
    assert all(c.location.line_end - c.location.line_start + 1 <= 20 for c in chunks)
    _assert_covers_every_non_blank_line_once(content, chunks)


@pytest.mark.unit
def test_function_longer_than_a_chunk_is_windowed_but_stays_a_function(
    chunker: TreeSitterChunker,
) -> None:
    content = _function("huge", 50)

    chunks = chunker.chunk(content, file_path="huge.py", language="python")

    assert [(c.location.line_start, c.location.line_end) for c in chunks] == [
        (1, 20),
        (21, 40),
        (41, 50),
    ]
    assert all(c.kind is ChunkKind.FUNCTION for c in chunks)


@pytest.mark.unit
def test_module_level_code_between_functions_is_not_lost(chunker: TreeSitterChunker) -> None:
    content = (
        _function("first", 18)
        + "\n\nAPI_KEY = 'sk-live-hardcoded'\napp.run(debug=True)\n\n\n"
        + _function("second", 18)
    )

    chunks = chunker.chunk(content, file_path="app.py", language="python")

    assert any("API_KEY = 'sk-live-hardcoded'" in c.content for c in chunks)
    _assert_covers_every_non_blank_line_once(content, chunks)


@pytest.mark.unit
def test_syntax_errors_do_not_prevent_chunking(chunker: TreeSitterChunker) -> None:
    content = "def broken(:\n    return (\n\n" + _function("fine", 15)

    chunks = chunker.chunk(content, file_path="broken.py", language="python")

    _assert_covers_every_non_blank_line_once(content, chunks)


@pytest.mark.unit
def test_javascript_route_handlers_are_units(chunker: TreeSitterChunker) -> None:
    if not chunker.supports("javascript"):
        pytest.skip("tree-sitter javascript grammar unavailable")
    handler_body = "\n".join(f"  const v{i} = {i};" for i in range(14))
    content = (
        "const express = require('express');\nconst app = express();\n\n"
        f"app.get('/users', (req, res) => {{\n{handler_body}\n  res.send(v0);\n}});\n\n"
        f"function helper() {{\n{handler_body}\n  return v0;\n}}\n"
    )

    chunks = chunker.chunk(content, file_path="server.js", language="javascript")

    assert any(
        c.kind is ChunkKind.FUNCTION and c.content.startswith("function helper()") for c in chunks
    )
    assert any(c.content.rstrip().endswith("});") for c in chunks)
    _assert_covers_every_non_blank_line_once(content, chunks)
