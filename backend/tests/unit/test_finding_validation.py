import pytest

from app.application.use_cases._finding_validation import (
    normalize_attack_technique_id,
    normalize_cwe_id,
    normalize_owasp_category,
    resolve_line_range,
)
from app.domain.value_objects.code_location import CodeLocation


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CWE-89", "CWE-89"),
        ("cwe-089", "CWE-89"),
        ("CWE 79", "CWE-79"),
        ("CWE:22", "CWE-22"),
        ("89", "CWE-89"),
        ("CWE-89: SQL Injection", "CWE-89"),
        ("SQL injection", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_cwe_id(raw: str | None, expected: str | None) -> None:
    assert normalize_cwe_id(raw) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("A03:2021", "A03:2021"),
        ("a3:2021", "A03:2021"),
        ("A03:2021 - Injection", "A03:2021"),
        ("A03", "A03:2021"),
        ("OWASP A01:2021", "A01:2021"),
        ("A10:2017", "A10:2017"),
        ("Injection", None),
        (None, None),
    ],
)
def test_normalize_owasp_category(raw: str | None, expected: str | None) -> None:
    assert normalize_owasp_category(raw) == expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("T1190", "T1190"),
        ("t1059.001", "T1059.001"),
        ("T1190 - Exploit Public-Facing Application", "T1190"),
        ("TA0001", None),
        ("Exploit", None),
        (None, None),
    ],
)
def test_normalize_attack_technique_id(raw: str | None, expected: str | None) -> None:
    assert normalize_attack_technique_id(raw) == expected


_CHUNK = CodeLocation("app.py", 50, 80)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ((60, 62), (60, 62)),  # already inside the chunk
        ((62, 60), (60, 62)),  # reversed
        ((45, 55), (50, 55)),  # overlaps the start: clamped
        ((75, 120), (75, 80)),  # overlaps the end: clamped
        ((3, 5), (52, 54)),  # outside, but valid as an offset into the chunk
        ((200, 210), (50, 80)),  # outside either way: the whole chunk
    ],
)
def test_resolve_line_range_never_leaves_the_chunk(
    reported: tuple[int, int], expected: tuple[int, int]
) -> None:
    assert resolve_line_range(*reported, _CHUNK) == expected
