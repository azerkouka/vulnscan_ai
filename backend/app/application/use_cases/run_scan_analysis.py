"""The analysis pipeline for one scan: chunk each file, retrieve grounding
knowledge for each chunk, ask the LLM, then validate what it said before
persisting any of it.

Runs outside any HTTP request (see `JobRunner`), so it never raises to its
caller: every outcome, including an unexpected crash, ends up recorded on
the scan row, which is what clients poll.

What the LLM returns is treated as untrusted:
- a CWE / OWASP / ATT&CK id is kept only if it resolves to a real entry of
  the ingested knowledge base (anti-hallucination) - the finding's
  references are then built from that entry, never from LLM text;
- line numbers are forced inside the chunk the LLM was actually shown;
- the vulnerable snippet is sliced from the stored source, not echoed back
  from the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

from app.application.use_cases._finding_validation import (
    normalize_attack_technique_id,
    normalize_cwe_id,
    normalize_owasp_category,
    resolve_line_range,
)
from app.domain.entities.finding import Finding, FindingReference
from app.domain.entities.scan import Scan, ScanFile
from app.domain.exceptions import LLMAnalysisError
from app.domain.ports.code_chunker import CodeChunker
from app.domain.ports.knowledge_retriever import KnowledgeRetriever, RetrievedKnowledge
from app.domain.ports.llm_analyzer import AnalyzedFinding, LLMAnalyzer
from app.domain.ports.source_storage import SourceStorage
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.source_text import split_lines
from app.domain.value_objects.code_chunk import CodeChunk
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.language import UNKNOWN_LANGUAGE
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.scan_status import ScanStatus

logger = logging.getLogger(__name__)

_MAX_TITLE_LENGTH = 255
_UNEXPECTED_FAILURE_MESSAGE = "The analysis failed unexpectedly."


@dataclass(frozen=True, slots=True)
class AnalysisSettings:
    retrieval_top_k: int = 5
    retrieval_query_max_chars: int = 2000
    """Only the head of a chunk is embedded as the retrieval query - enough
    to characterize it, without paying to embed a whole long function."""
    max_consecutive_llm_failures: int = 3
    """Give up on the scan after this many chunks in a row fail: the model
    is down or misconfigured, and every further chunk would just wait out
    its timeout too."""


class _AnalysisAbortedError(Exception):
    """An expected failure whose message is safe to show the scan's owner."""


class RunScanAnalysisUseCase:
    def __init__(
        self,
        uow: UnitOfWork,
        storage: SourceStorage,
        chunker: CodeChunker,
        retriever: KnowledgeRetriever,
        analyzer: LLMAnalyzer,
        settings: AnalysisSettings | None = None,
    ) -> None:
        self._uow = uow
        self._storage = storage
        self._chunker = chunker
        self._retriever = retriever
        self._analyzer = analyzer
        self._settings = settings or AnalysisSettings()

    async def execute(self, scan_id: UUID) -> None:
        async with self._uow:
            scan = await self._uow.scans.get_by_id(scan_id)
            if scan is None or scan.status is not ScanStatus.PENDING:
                return  # deleted meanwhile, or already picked up

            scan = replace(scan, status=ScanStatus.RUNNING, started_at=datetime.now(UTC))
            await self._uow.scans.update(scan)
            await self._uow.commit()

            try:
                scan = await self._analyze(scan)
            except Exception as exc:
                await self._uow.rollback()
                if isinstance(exc, _AnalysisAbortedError):
                    message = str(exc)
                else:
                    logger.exception("scan_analysis_failed scan_id=%s", scan_id)
                    message = _UNEXPECTED_FAILURE_MESSAGE
                # Re-read: progress and findings committed before the failure stand.
                current = await self._uow.scans.get_by_id(scan_id)
                if current is None:
                    return
                scan = replace(
                    current,
                    status=ScanStatus.FAILED,
                    error_message=message,
                    completed_at=datetime.now(UTC),
                )

            await self._uow.scans.update(scan)
            await self._uow.commit()

    async def _analyze(self, scan: Scan) -> Scan:
        files = await self._uow.scans.list_files(scan.id)
        reference_cache: dict[str, FindingReference | None] = {}
        seen: set[tuple[UUID, str, str | None, int, int]] = set()
        total_chunks = failed_chunks = consecutive_failures = 0

        for file_index, file in enumerate(files):
            content = await self._storage.read(scan.id, file.id)
            lines = split_lines(content)
            chunks = self._chunker.chunk(
                content, file_path=file.relative_path, language=file.language or UNKNOWN_LANGUAGE
            )

            for chunk_index, chunk in enumerate(chunks, start=1):
                total_chunks += 1
                context = await self._retrieve(chunk)

                findings: list[Finding] = []
                try:
                    analyzed = await self._analyzer.analyze(chunk, context)
                except LLMAnalysisError as exc:
                    failed_chunks += 1
                    consecutive_failures += 1
                    if consecutive_failures >= self._settings.max_consecutive_llm_failures:
                        raise _AnalysisAbortedError(
                            f"The LLM failed on {consecutive_failures} code chunks in a row; "
                            "check that the model is available, then run the scan again."
                        ) from exc
                else:
                    consecutive_failures = 0
                    for item in analyzed:
                        finding = await self._to_finding(
                            scan, file, chunk, lines, item, context, reference_cache
                        )
                        key = (
                            file.id,
                            finding.title.casefold(),
                            finding.cwe_id,
                            finding.location.line_start,
                            finding.location.line_end,
                        )
                        if key not in seen:
                            seen.add(key)
                            findings.append(finding)

                if findings:
                    await self._uow.findings.add_many(findings)
                # 100 is reserved for COMPLETED, so a poller never sees a
                # "100% but still running" scan.
                done = file_index + chunk_index / len(chunks)
                scan = replace(
                    scan,
                    total_findings=scan.total_findings + len(findings),
                    progress_percent=min(99, int(done * 100 / len(files))),
                )
                await self._uow.scans.update(scan)
                await self._uow.commit()

        if total_chunks and failed_chunks == total_chunks:
            raise _AnalysisAbortedError("The LLM could not analyze any of the submitted code.")

        return replace(
            scan,
            status=ScanStatus.COMPLETED,
            progress_percent=100,
            error_message=(
                f"{failed_chunks} of {total_chunks} code chunks could not be analyzed; "
                "this report may be incomplete."
                if failed_chunks
                else None
            ),
            completed_at=datetime.now(UTC),
        )

    async def _retrieve(self, chunk: CodeChunk) -> list[RetrievedKnowledge]:
        try:
            return await self._retriever.query(
                chunk.content[: self._settings.retrieval_query_max_chars],
                top_k=self._settings.retrieval_top_k,
            )
        except Exception as exc:
            # Unlike a bad LLM reply, this is not about one chunk: the vector
            # store is down or unreachable, and every further chunk would
            # fail the same way. Stop, and say what is wrong.
            logger.exception("knowledge_retrieval_failed scan_chunk=%s", chunk.location.file_path)
            raise _AnalysisAbortedError(
                "The knowledge base could not be queried; check that ChromaDB is running, "
                "then run the scan again."
            ) from exc

    async def _to_finding(
        self,
        scan: Scan,
        file: ScanFile,
        chunk: CodeChunk,
        lines: list[str],
        item: AnalyzedFinding,
        context: list[RetrievedKnowledge],
        reference_cache: dict[str, FindingReference | None],
    ) -> Finding:
        line_start, line_end = resolve_line_range(item.line_start, item.line_end, chunk.location)

        cwe = await self._verified_reference(
            normalize_cwe_id(item.cwe_id), KnowledgeSource.CWE, context, reference_cache
        )
        owasp = await self._verified_reference(
            normalize_owasp_category(item.owasp_category),
            KnowledgeSource.OWASP,
            context,
            reference_cache,
        )
        attack = await self._verified_reference(
            normalize_attack_technique_id(item.attack_technique_id),
            KnowledgeSource.ATTACK,
            context,
            reference_cache,
        )

        return Finding(
            id=uuid4(),
            scan_id=scan.id,
            scan_file_id=file.id,
            title=item.title.strip()[:_MAX_TITLE_LENGTH] or "Untitled finding",
            cwe_id=cwe.ref_id if cwe else None,
            owasp_category=owasp.ref_id if owasp else None,
            attack_technique_id=attack.ref_id if attack else None,
            severity=item.severity,
            confidence=min(1.0, max(0.0, item.confidence)),
            location=CodeLocation(file.relative_path, line_start, line_end),
            vulnerable_snippet="\n".join(lines[line_start - 1 : line_end]),
            explanation=item.explanation.strip(),
            recommendation=item.recommendation.strip(),
            fixed_code=item.fixed_code,
            references=[reference for reference in (cwe, owasp, attack) if reference],
            created_at=datetime.now(UTC),
        )

    async def _verified_reference(
        self,
        external_id: str | None,
        source: KnowledgeSource,
        context: list[RetrievedKnowledge],
        cache: dict[str, FindingReference | None],
    ) -> FindingReference | None:
        """The knowledge-base entry `external_id` names, or None if there is
        no such entry - in which case the id was hallucinated (or is simply
        outside what we ingested) and must not be attached to a finding."""
        if external_id is None:
            return None
        if external_id in cache:
            return cache[external_id]

        reference: FindingReference | None = None
        retrieved = next(
            (k for k in context if k.external_id == external_id and k.source == source), None
        )
        if retrieved is not None:
            reference = FindingReference(
                ReferenceSource(source.value), external_id, retrieved.name, retrieved.url
            )
        else:
            record = await self._uow.knowledge_documents.get_by_external_id(external_id)
            if record is not None and record.source == source:
                reference = FindingReference(
                    ReferenceSource(source.value), external_id, record.name, record.url
                )

        cache[external_id] = reference
        return reference
