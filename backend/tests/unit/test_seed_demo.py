from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from scripts.seed_demo import (
    DEMO_FINDINGS,
    SAMPLE_FILES,
    build_demo_scan,
    load_sample_sources,
    locate,
)

from app.domain.source_text import split_lines
from app.domain.value_objects.scan_status import ScanStatus

_SAMPLE_DIR = Path(__file__).resolve().parents[2] / "data" / "samples" / "vulnerable-app"


@pytest.mark.unit
def test_every_demo_finding_points_at_exactly_one_line_of_the_sample() -> None:
    sources = load_sample_sources(_SAMPLE_DIR)

    assert set(sources) == set(SAMPLE_FILES)
    for demo in DEMO_FINDINGS:
        line = locate(sources[demo.path], demo.marker)
        # The line it resolves to really is the vulnerable statement.
        assert demo.marker in split_lines(sources[demo.path])[line - 1]


@pytest.mark.unit
def test_demo_scan_is_a_consistent_completed_scan() -> None:
    sources = load_sample_sources(_SAMPLE_DIR)
    user_id = uuid4()

    scan, files, located = build_demo_scan(user_id, sources, datetime.now(UTC))

    assert scan.user_id == user_id
    assert scan.status is ScanStatus.COMPLETED
    assert (scan.total_files, scan.total_findings) == (len(SAMPLE_FILES), len(DEMO_FINDINGS))
    assert scan.started_at is not None and scan.completed_at is not None
    assert scan.started_at <= scan.completed_at
    assert {file.relative_path for file in files} == set(SAMPLE_FILES)
    assert all(file.scan_id == scan.id and file.loc > 0 for file in files)
    assert {file.relative_path: file.language for file in files} == {
        "app.py": "python",
        "config.py": "python",
        "web/server.js": "javascript",
    }
    assert len(located) == len(DEMO_FINDINGS)


@pytest.mark.unit
def test_locate_refuses_a_marker_that_is_missing_or_ambiguous() -> None:
    content = "a = 1\nb = 2\na = 1\n"

    assert locate(content, "b = 2") == 2
    with pytest.raises(ValueError, match="found 0"):
        locate(content, "c = 3")
    with pytest.raises(ValueError, match="found 2"):
        locate(content, "a = 1")
