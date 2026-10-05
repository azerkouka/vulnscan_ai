import json
from typing import Any

import pytest

from app.domain.value_objects.severity import Severity
from app.infrastructure.llm.response_parser import InvalidLLMOutputError, parse_analysis


def _finding(**overrides: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "title": "SQL injection",
        "severity": "HIGH",
        "confidence": 0.9,
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021",
        "attack_technique_id": "T1190",
        "line_start": 4,
        "line_end": 5,
        "explanation": "User input is concatenated into the query.",
        "recommendation": "Use a parameterized query.",
        "fixed_code": "conn.execute('SELECT * FROM users WHERE name = ?', (name,))",
    }
    finding.update(overrides)
    return finding


def _reply(*findings: dict[str, Any]) -> str:
    return json.dumps({"findings": list(findings)})


@pytest.mark.unit
def test_parses_a_well_formed_reply() -> None:
    [finding] = parse_analysis(_reply(_finding()))

    assert finding.title == "SQL injection"
    assert finding.severity is Severity.HIGH
    assert finding.confidence == 0.9
    assert (finding.cwe_id, finding.owasp_category, finding.attack_technique_id) == (
        "CWE-89",
        "A03:2021",
        "T1190",
    )
    assert (finding.line_start, finding.line_end) == (4, 5)
    assert finding.fixed_code is not None


@pytest.mark.unit
def test_empty_findings_list_is_a_valid_answer() -> None:
    assert parse_analysis('{"findings": []}') == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "raw",
    [
        '```json\n{"findings": []}\n```',
        'Here is my analysis:\n{"findings": []}\nLet me know if you need more.',
        "[]",
    ],
)
def test_tolerates_wrapping_around_the_json(raw: str) -> None:
    assert parse_analysis(raw) == []


@pytest.mark.unit
def test_tolerates_common_formatting_slips() -> None:
    [finding] = parse_analysis(
        _reply(
            _finding(
                severity=" critical ",
                confidence="85%",
                cwe_id=89,
                owasp_category="N/A",
                attack_technique_id="",
                fixed_code="null",
                unexpected_extra_field="ignored",
            )
        )
    )

    assert finding.severity is Severity.CRITICAL
    assert finding.confidence == 0.85
    assert finding.cwe_id == "89"
    assert finding.owasp_category is None
    assert finding.attack_technique_id is None
    assert finding.fixed_code is None


@pytest.mark.unit
def test_optional_fields_get_defaults() -> None:
    minimal = {
        "title": "Hardcoded secret",
        "severity": "MEDIUM",
        "line_start": 7,
        "explanation": "An API key is committed in source.",
    }

    [finding] = parse_analysis(_reply(minimal))

    assert finding.line_end == 7
    assert finding.confidence == 0.5
    assert finding.recommendation == ""
    assert finding.cwe_id is None


@pytest.mark.unit
@pytest.mark.parametrize("confidence", [-3, 250, 1.5])
def test_confidence_is_always_within_bounds(confidence: float) -> None:
    [finding] = parse_analysis(_reply(_finding(confidence=confidence)))

    assert 0.0 <= finding.confidence <= 1.0


@pytest.mark.unit
@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("I could not find any vulnerability.", "no JSON object"),
        ('{"findings": [', "no JSON object"),
        ('{"findings": [{"title": "x",}]}', "not valid JSON"),
        ('{"vulnerabilities": []}', "findings"),
        (_reply(_finding(severity="SUPER_BAD")), "severity"),
        (_reply(_finding(line_start="four")), "line_start"),
        (_reply(_finding(line_start=0)), "line_start"),
        (_reply(_finding(title="")), "title"),
        (_reply(_finding(confidence="very")), "confidence"),
        (_reply({"title": "No explanation", "severity": "LOW", "line_start": 1}), "explanation"),
        ('{"findings": "none"}', "findings"),
    ],
)
def test_rejects_malformed_replies_with_a_reason(raw: str, reason: str) -> None:
    with pytest.raises(InvalidLLMOutputError, match=reason):
        parse_analysis(raw)


@pytest.mark.unit
def test_one_invalid_finding_rejects_the_whole_reply() -> None:
    with pytest.raises(InvalidLLMOutputError):
        parse_analysis(_reply(_finding(), _finding(severity="???")))
