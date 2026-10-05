"""`LLMAnalyzer` backed by a local Ollama model, through LangChain.

The adapter only depends on the one method it calls on the chat model
(`ainvoke`), so tests drive it with a scripted fake and no LLM - and
`langchain_ollama` (optional `rag` extra) is only imported by
`create_ollama_analyzer`, when a real model is actually wanted.

Output handling: Ollama is asked for JSON (`format="json"`), but that only
guarantees *syntactically* valid JSON, not our shape. Every reply goes
through `parse_analysis`; on a rejected reply the model is shown its own
answer and the reason, and asked again, up to `max_retries` times. A call
that errors or times out is retried the same way. When every attempt is
spent, `LLMAnalysisError` is raised - never a partially valid result.
"""

from __future__ import annotations

import asyncio
from typing import Any, Protocol

from app.core.logging import get_logger
from app.domain.exceptions import LLMAnalysisError
from app.domain.ports.knowledge_retriever import RetrievedKnowledge
from app.domain.ports.llm_analyzer import AnalyzedFinding, LLMAnalyzer
from app.domain.value_objects.code_chunk import CodeChunk
from app.infrastructure.llm.prompts import RETRY_PROMPT, SYSTEM_PROMPT, build_user_prompt
from app.infrastructure.llm.response_parser import InvalidLLMOutputError, parse_analysis

logger = get_logger(__name__)

# How much of a rejected reply is replayed to the model on retry.
_MAX_REPLAYED_REPLY_CHARS = 4000

_Messages = list[tuple[str, str]]
"""(role, text) pairs - a message format LangChain chat models accept as-is."""


class ChatModel(Protocol):
    async def ainvoke(self, input: _Messages) -> Any: ...


class OllamaLLMAnalyzer(LLMAnalyzer):
    def __init__(
        self, chat_model: ChatModel, *, timeout_seconds: float = 120, max_retries: int = 2
    ) -> None:
        self._chat_model = chat_model
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries

    async def analyze(
        self, chunk: CodeChunk, context: list[RetrievedKnowledge]
    ) -> list[AnalyzedFinding]:
        base_messages: _Messages = [
            ("system", SYSTEM_PROMPT),
            ("human", build_user_prompt(chunk, context)),
        ]
        messages = base_messages
        attempts = 1 + self._max_retries
        last_error: Exception | None = None

        for attempt in range(1, attempts + 1):
            try:
                response = await asyncio.wait_for(
                    self._chat_model.ainvoke(messages), timeout=self._timeout_seconds
                )
            except Exception as exc:
                # Model unreachable, not pulled, or too slow: nothing to correct, just ask again.
                last_error = exc
                logger.warning("llm_call_failed", attempt=attempt, error=repr(exc))
                continue

            reply = _reply_text(response)
            try:
                return parse_analysis(reply)
            except InvalidLLMOutputError as exc:
                last_error = exc
                logger.warning("llm_output_rejected", attempt=attempt, reason=str(exc))
                messages = [
                    *base_messages,
                    ("ai", reply[:_MAX_REPLAYED_REPLY_CHARS]),
                    ("human", RETRY_PROMPT.format(error=exc)),
                ]

        raise LLMAnalysisError(
            f"The LLM produced no valid analysis after {attempts} attempts."
        ) from last_error


def _reply_text(response: Any) -> str:
    content = getattr(response, "content", response)
    return content if isinstance(content, str) else str(content)


def create_ollama_analyzer(
    *, base_url: str, model: str, timeout_seconds: float, num_ctx: int, max_retries: int
) -> OllamaLLMAnalyzer:
    from langchain_ollama import ChatOllama

    chat_model = ChatOllama(
        base_url=base_url,
        model=model,
        format="json",
        # Deterministic: the same code should get the same review twice.
        temperature=0,
        # Ollama's default context window is far smaller than the model's and
        # silently truncates the prompt - cutting off the code under review.
        num_ctx=num_ctx,
        client_kwargs={"timeout": timeout_seconds},
    )
    return OllamaLLMAnalyzer(chat_model, timeout_seconds=timeout_seconds, max_retries=max_retries)
