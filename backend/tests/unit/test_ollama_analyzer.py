"""The Ollama adapter, driven by a scripted chat model - no LLM involved."""

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Any

import pytest

from app.domain.exceptions import LLMAnalysisError
from app.domain.ports.knowledge_retriever import RetrievedKnowledge
from app.domain.value_objects.code_chunk import ChunkKind, CodeChunk
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.severity import Severity
from app.infrastructure.llm.ollama_analyzer import OllamaLLMAnalyzer
from app.infrastructure.llm.prompts import SYSTEM_PROMPT, build_user_prompt

_VALID_REPLY = json.dumps(
    {
        "findings": [
            {
                "title": "Command injection",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "cwe_id": "CWE-78",
                "line_start": 11,
                "line_end": 11,
                "explanation": "Shell command built from user input.",
                "recommendation": "Pass an argument list and no shell.",
            }
        ]
    }
)

_CHUNK = CodeChunk(
    content="def run(cmd):\n    os.system(cmd)",
    language="python",
    location=CodeLocation("tools/run.py", 10, 11),
    kind=ChunkKind.FUNCTION,
)

_CONTEXT = [
    RetrievedKnowledge(
        external_id="CWE-78",
        source=KnowledgeSource.CWE,
        name="OS Command Injection",
        url=None,
        content="The product constructs an OS command using externally-influenced input.",
        distance=0.1,
    )
]


@dataclass
class _Message:
    content: str


class _ScriptedChatModel:
    """Replies with the next scripted item on each call; an exception item
    is raised instead, and a float item is a delay before an empty reply."""

    def __init__(self, *script: str | Exception | float) -> None:
        self._script = list(script)
        self.calls: list[list[tuple[str, str]]] = []

    async def ainvoke(self, input: list[tuple[str, str]]) -> Any:
        self.calls.append(list(input))
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        if isinstance(item, float):
            await asyncio.sleep(item)
            return _Message('{"findings": []}')
        return _Message(item)


@pytest.mark.unit
async def test_returns_the_parsed_findings_of_a_valid_reply() -> None:
    model = _ScriptedChatModel(_VALID_REPLY)

    [finding] = await OllamaLLMAnalyzer(model).analyze(_CHUNK, _CONTEXT)

    assert finding.title == "Command injection"
    assert finding.severity is Severity.CRITICAL
    assert finding.cwe_id == "CWE-78"
    assert len(model.calls) == 1
    [(system_role, system_text), (human_role, _)] = model.calls[0]
    assert (system_role, human_role) == ("system", "human")
    assert system_text == SYSTEM_PROMPT


@pytest.mark.unit
async def test_invalid_reply_is_retried_with_the_rejection_reason() -> None:
    model = _ScriptedChatModel("Sure! The code looks risky.", _VALID_REPLY)

    findings = await OllamaLLMAnalyzer(model, max_retries=2).analyze(_CHUNK, _CONTEXT)

    assert len(findings) == 1
    assert len(model.calls) == 2
    retry = model.calls[1]
    assert [role for role, _ in retry] == ["system", "human", "ai", "human"]
    assert retry[:2] == model.calls[0]
    assert retry[2][1] == "Sure! The code looks risky."
    assert "no JSON object" in retry[3][1]


@pytest.mark.unit
async def test_reply_with_the_wrong_shape_is_retried() -> None:
    model = _ScriptedChatModel('{"findings": [{"title": "x", "severity": "BAD"}]}', _VALID_REPLY)

    findings = await OllamaLLMAnalyzer(model, max_retries=1).analyze(_CHUNK, _CONTEXT)

    assert len(findings) == 1
    assert "severity" in model.calls[1][3][1]


@pytest.mark.unit
async def test_gives_up_after_the_configured_number_of_attempts() -> None:
    model = _ScriptedChatModel("nope", "still nope", "nope again")

    with pytest.raises(LLMAnalysisError, match="after 3 attempts"):
        await OllamaLLMAnalyzer(model, max_retries=2).analyze(_CHUNK, _CONTEXT)

    assert len(model.calls) == 3


@pytest.mark.unit
async def test_transport_error_is_retried_with_the_original_prompt() -> None:
    model = _ScriptedChatModel(ConnectionError("ollama is down"), _VALID_REPLY)

    findings = await OllamaLLMAnalyzer(model, max_retries=1).analyze(_CHUNK, _CONTEXT)

    assert len(findings) == 1
    assert model.calls[1] == model.calls[0]


@pytest.mark.unit
async def test_unreachable_model_surfaces_as_a_domain_error() -> None:
    model = _ScriptedChatModel(ConnectionError("down"), ConnectionError("down"))

    with pytest.raises(LLMAnalysisError) as excinfo:
        await OllamaLLMAnalyzer(model, max_retries=1).analyze(_CHUNK, _CONTEXT)

    assert isinstance(excinfo.value.__cause__, ConnectionError)


@pytest.mark.unit
async def test_slow_call_times_out_and_counts_as_a_failed_attempt() -> None:
    model = _ScriptedChatModel(5.0, _VALID_REPLY)

    findings = await OllamaLLMAnalyzer(model, timeout_seconds=0.01, max_retries=1).analyze(
        _CHUNK, _CONTEXT
    )

    assert len(findings) == 1
    assert len(model.calls) == 2


@pytest.mark.unit
def test_user_prompt_shows_numbered_code_and_knowledge_excerpts() -> None:
    prompt = build_user_prompt(_CHUNK, _CONTEXT)

    assert "10 | def run(cmd):" in prompt
    assert "11 |     os.system(cmd)" in prompt
    assert "file: tools/run.py, language: python, lines 10-11" in prompt
    assert "[CWE-78] CWE - OS Command Injection" in prompt
    assert "externally-influenced input" in prompt


@pytest.mark.unit
def test_user_prompt_without_context_tells_the_model_to_use_null() -> None:
    prompt = build_user_prompt(_CHUNK, [])

    assert "none available" in prompt


@pytest.mark.unit
def test_long_knowledge_excerpts_are_truncated() -> None:
    long_entry = RetrievedKnowledge(
        external_id="CWE-1",
        source=KnowledgeSource.CWE,
        name="Long",
        url=None,
        content="word " * 2000,
        distance=0.0,
    )

    prompt = build_user_prompt(_CHUNK, [long_entry])

    assert len(prompt) < 2000
    assert "[...]" in prompt


@pytest.mark.unit
def test_code_cannot_forge_its_own_closing_boundary() -> None:
    first = build_user_prompt(_CHUNK, [])
    second = build_user_prompt(_CHUNK, [])

    [boundary_1] = set(re.findall(r"CODE-[0-9a-f]{16}", first))
    [boundary_2] = set(re.findall(r"CODE-[0-9a-f]{16}", second))
    # Unpredictable per call, so submitted code can't contain it in advance.
    assert boundary_1 != boundary_2
    assert first.count(boundary_1) == 3  # announced once, then opening and closing
