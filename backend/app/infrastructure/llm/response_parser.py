"""Strict validation of the LLM's raw reply into `AnalyzedFinding`s.

Tolerant about *form* a local model commonly gets slightly wrong (a markdown
fence around the JSON, "high" instead of "HIGH", a confidence given as a
percentage, "N/A" for a missing id) and strict about *substance*: a reply
missing a required field, or with a value of the wrong type, is rejected as
a whole - the caller retries rather than keeping half-understood output.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, ValidationError

from app.domain.ports.llm_analyzer import AnalyzedFinding
from app.domain.value_objects.severity import Severity

_NULL_WORDS = frozenset({"", "null", "none", "n/a", "na", "unknown", "-"})


class InvalidLLMOutputError(ValueError):
    """The reply isn't the JSON object we asked for. Its message is short
    and safe to feed back to the model in a retry prompt."""


def _optional_text(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str) and value.strip().lower() in _NULL_WORDS:
        return None
    return value


def _severity(value: Any) -> Any:
    return value.strip().upper() if isinstance(value, str) else value


def _confidence(value: Any) -> Any:
    if isinstance(value, str):
        value = value.strip().rstrip("%")
    try:
        number = float(value)
    except (TypeError, ValueError):
        return value  # left as-is for pydantic to reject with a clear message
    if 1.0 < number <= 100.0:
        number /= 100.0  # given as a percentage
    return min(1.0, max(0.0, number))


_OptionalText = Annotated[str | None, BeforeValidator(_optional_text)]


class _FindingPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    title: str = Field(min_length=1)
    severity: Annotated[Severity, BeforeValidator(_severity)]
    confidence: Annotated[float, BeforeValidator(_confidence)] = 0.5
    cwe_id: _OptionalText = None
    owasp_category: _OptionalText = None
    attack_technique_id: _OptionalText = None
    line_start: int = Field(ge=1)
    line_end: int | None = Field(default=None, ge=1)
    explanation: str = Field(min_length=1)
    recommendation: str = ""
    fixed_code: _OptionalText = None


class _AnalysisPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    findings: list[_FindingPayload]


def parse_analysis(raw: str) -> list[AnalyzedFinding]:
    data = _load_json(raw)
    if isinstance(data, list):
        data = {"findings": data}  # the bare list, without its wrapper object

    try:
        payload = _AnalysisPayload.model_validate(data)
    except ValidationError as exc:
        raise InvalidLLMOutputError(_summarize(exc)) from exc

    return [
        AnalyzedFinding(
            title=item.title,
            cwe_id=item.cwe_id,
            owasp_category=item.owasp_category,
            attack_technique_id=item.attack_technique_id,
            severity=item.severity,
            confidence=item.confidence,
            line_start=item.line_start,
            line_end=item.line_end if item.line_end is not None else item.line_start,
            explanation=item.explanation,
            recommendation=item.recommendation,
            fixed_code=item.fixed_code,
        )
        for item in payload.findings
    ]


def _load_json(raw: str) -> Any:
    text = raw.strip()
    # Drop anything around the outermost JSON value: a ```json fence, or a
    # sentence of preamble the model added despite the instructions.
    starts = [index for index in (text.find("{"), text.find("[")) if index != -1]
    end = max(text.rfind("}"), text.rfind("]"))
    if not starts or end < min(starts):
        raise InvalidLLMOutputError("the reply contains no JSON object.")
    try:
        return json.loads(text[min(starts) : end + 1])
    except json.JSONDecodeError as exc:
        raise InvalidLLMOutputError(f"the reply is not valid JSON ({exc.msg}).") from exc


def _summarize(error: ValidationError) -> str:
    problems = [
        f"{'.'.join(str(part) for part in issue['loc'])}: {issue['msg']}"
        for issue in error.errors()[:5]
    ]
    return "the JSON does not match the expected shape - " + "; ".join(problems)
