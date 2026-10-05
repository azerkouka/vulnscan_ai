"""FastAPI dependency-injection wiring.

Kept as a single module so all DI wiring is visible in one place rather than
scattered across routers. Grown as each use case is added.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.application.use_cases.create_scan import CreateScanUseCase, ScanSourceLimits
from app.application.use_cases.delete_scan import DeleteScanUseCase
from app.application.use_cases.export_scan_report import ExportScanReportUseCase
from app.application.use_cases.fail_scans import FailScanUseCase
from app.application.use_cases.get_current_user import GetCurrentUserUseCase
from app.application.use_cases.get_dashboard_summary import GetDashboardSummaryUseCase
from app.application.use_cases.get_knowledge_document import GetKnowledgeDocumentUseCase
from app.application.use_cases.get_knowledge_health import GetKnowledgeHealthUseCase
from app.application.use_cases.get_scan import GetScanUseCase
from app.application.use_cases.get_scan_report import GetScanReportUseCase
from app.application.use_cases.ingest_knowledge import IngestKnowledgeUseCase
from app.application.use_cases.list_knowledge_documents import ListKnowledgeDocumentsUseCase
from app.application.use_cases.list_scans import ListScansUseCase
from app.application.use_cases.login_user import LoginUserUseCase
from app.application.use_cases.logout_user import LogoutUserUseCase
from app.application.use_cases.refresh_token import RefreshTokenUseCase
from app.application.use_cases.register_user import RegisterUserUseCase
from app.application.use_cases.run_scan_analysis import AnalysisSettings, RunScanAnalysisUseCase
from app.core.config import Settings, get_settings
from app.core.exceptions import ForbiddenError, UnauthorizedError
from app.core.logging import get_logger
from app.domain.entities.user import User
from app.domain.ports.archive_extractor import ArchiveExtractor
from app.domain.ports.code_chunker import CodeChunker
from app.domain.ports.job_runner import JobRunner
from app.domain.ports.knowledge_indexer import KnowledgeIndexer
from app.domain.ports.llm_analyzer import LLMAnalyzer
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.report_exporter import ReportExporter
from app.domain.ports.source_storage import SourceStorage
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.value_objects.report_format import ReportFormat
from app.infrastructure.code_analysis.tree_sitter_chunker import TreeSitterChunker
from app.infrastructure.export.json_exporter import JsonReportExporter
from app.infrastructure.export.pdf_exporter import PdfReportExporter
from app.infrastructure.llm.ollama_analyzer import create_ollama_analyzer
from app.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.infrastructure.security.token_service import JwtTokenService
from app.infrastructure.uploads.local_source_storage import LocalSourceStorage
from app.infrastructure.uploads.safe_zip_extractor import SafeZipExtractor

if TYPE_CHECKING:
    # Real import deferred to inside get_knowledge_store() (see its
    # docstring): `chromadb` lives behind the optional `rag` extra, and
    # app.main must stay importable without it (e.g. for auth-only unit
    # tests on a machine that can't compile chroma-hnswlib).
    from app.infrastructure.vectorstore.chroma_knowledge_store import ChromaKnowledgeStore

logger = get_logger(__name__)

_ARCHIVE_EXTENSION = ".zip"
_MEBIBYTE = 1024 * 1024

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_db_session(request: Request) -> AsyncIterator[AsyncSession]:
    session_factory: async_sessionmaker[AsyncSession] = request.app.state.session_factory
    async with session_factory() as session:
        yield session


def get_unit_of_work(session: AsyncSession = Depends(get_db_session)) -> UnitOfWork:
    return SqlAlchemyUnitOfWork(session)


@lru_cache
def get_password_hasher() -> PasswordHasher:
    return Argon2PasswordHasher()


def get_token_service(settings: Settings = Depends(get_settings)) -> TokenService:
    return JwtTokenService(
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        access_token_ttl=timedelta(minutes=settings.access_token_expire_minutes),
    )


def get_register_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    hasher: PasswordHasher = Depends(get_password_hasher),
) -> RegisterUserUseCase:
    return RegisterUserUseCase(uow, hasher)


def get_login_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    hasher: PasswordHasher = Depends(get_password_hasher),
    tokens: TokenService = Depends(get_token_service),
    settings: Settings = Depends(get_settings),
) -> LoginUserUseCase:
    return LoginUserUseCase(uow, hasher, tokens, timedelta(days=settings.refresh_token_expire_days))


def get_refresh_token_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    tokens: TokenService = Depends(get_token_service),
    settings: Settings = Depends(get_settings),
) -> RefreshTokenUseCase:
    return RefreshTokenUseCase(uow, tokens, timedelta(days=settings.refresh_token_expire_days))


def get_logout_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    tokens: TokenService = Depends(get_token_service),
) -> LogoutUserUseCase:
    return LogoutUserUseCase(uow, tokens)


def get_current_user_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    tokens: TokenService = Depends(get_token_service),
) -> GetCurrentUserUseCase:
    return GetCurrentUserUseCase(uow, tokens)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    use_case: GetCurrentUserUseCase = Depends(get_current_user_use_case),
) -> User:
    if credentials is None:
        raise UnauthorizedError("Missing authentication credentials.")
    return await use_case.execute(credentials.credentials)


async def get_current_superuser(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.is_superuser:
        raise ForbiddenError("This action requires administrator privileges.")
    return current_user


@lru_cache
def get_knowledge_store() -> ChromaKnowledgeStore:
    """A single Chroma client/collection handle, reused across requests -
    constructed lazily (only once a knowledge endpoint is actually hit), so
    Chroma being unreachable never breaks unrelated endpoints like auth, and
    `chromadb` (the optional `rag` extra) only needs to be installed on
    machines that actually exercise knowledge endpoints."""
    from app.infrastructure.vectorstore.chroma_knowledge_store import ChromaKnowledgeStore

    settings = get_settings()
    return ChromaKnowledgeStore(
        host=settings.chroma_host,
        port=settings.chroma_port,
        collection_name=f"{settings.chroma_collection_prefix}_knowledge",
    )


def get_ingest_knowledge_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    indexer: KnowledgeIndexer = Depends(get_knowledge_store),
) -> IngestKnowledgeUseCase:
    return IngestKnowledgeUseCase(uow, indexer)


def get_list_knowledge_documents_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
) -> ListKnowledgeDocumentsUseCase:
    return ListKnowledgeDocumentsUseCase(uow)


def get_get_knowledge_document_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
) -> GetKnowledgeDocumentUseCase:
    return GetKnowledgeDocumentUseCase(uow)


def get_knowledge_health_use_case(
    indexer: KnowledgeIndexer = Depends(get_knowledge_store),
) -> GetKnowledgeHealthUseCase:
    return GetKnowledgeHealthUseCase(indexer)


@lru_cache
def get_source_storage() -> SourceStorage:
    return LocalSourceStorage(Path(get_settings().upload_dir))


@lru_cache
def get_archive_extractor() -> ArchiveExtractor:
    settings = get_settings()
    return SafeZipExtractor(
        max_files=settings.zip_max_files,
        max_uncompressed_bytes=settings.zip_max_uncompressed_mb * _MEBIBYTE,
        max_compression_ratio=settings.zip_max_compression_ratio,
        source_extensions=_allowed_extensions(settings) - {_ARCHIVE_EXTENSION},
    )


@lru_cache
def get_code_chunker() -> CodeChunker:
    return TreeSitterChunker(max_chunk_lines=get_settings().chunk_max_lines)


@lru_cache
def get_llm_analyzer() -> LLMAnalyzer:
    """Built on first use, like `get_knowledge_store`: `langchain_ollama`
    (optional `rag` extra) is only imported once a scan actually runs."""
    settings = get_settings()
    return create_ollama_analyzer(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        timeout_seconds=settings.ollama_request_timeout_seconds,
        num_ctx=settings.ollama_num_ctx,
        max_retries=settings.llm_max_retries,
    )


def _allowed_extensions(settings: Settings) -> frozenset[str]:
    return frozenset(extension.lower() for extension in settings.allowed_upload_extensions)


def build_scan_job(
    session_factory: async_sessionmaker[AsyncSession],
) -> Callable[[UUID], Awaitable[None]]:
    """What the job runner executes for one scan. A job outlives the request
    that enqueued it, so it can't borrow that request's session: it opens
    its own, and assembles the analysis pipeline around it."""

    async def run_scan(scan_id: UUID) -> None:
        async with session_factory() as session:
            uow = SqlAlchemyUnitOfWork(session)
            try:
                # Off the event loop: creating the Chroma client connects to the server.
                retriever = await asyncio.to_thread(get_knowledge_store)
                analyzer = get_llm_analyzer()
            except Exception:
                logger.exception("scan_pipeline_unavailable", scan_id=str(scan_id))
                await FailScanUseCase(uow).execute(
                    scan_id,
                    "The analysis pipeline is unavailable: the LLM or the knowledge base "
                    "could not be initialized.",
                )
                return

            use_case = RunScanAnalysisUseCase(
                uow,
                get_source_storage(),
                get_code_chunker(),
                retriever,
                analyzer,
                AnalysisSettings(retrieval_top_k=get_settings().knowledge_retrieval_top_k),
            )
            await use_case.execute(scan_id)

    return run_scan


def get_job_runner(request: Request) -> JobRunner:
    """The process-wide runner created at startup (see `app.main.lifespan`)."""
    runner: JobRunner = request.app.state.job_runner
    return runner


def get_create_scan_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    storage: SourceStorage = Depends(get_source_storage),
    extractor: ArchiveExtractor = Depends(get_archive_extractor),
    job_runner: JobRunner = Depends(get_job_runner),
    settings: Settings = Depends(get_settings),
) -> CreateScanUseCase:
    limits = ScanSourceLimits(
        max_upload_bytes=settings.upload_max_size_mb * _MEBIBYTE,
        allowed_extensions=_allowed_extensions(settings),
        max_active_scans=settings.max_active_scans_per_user,
    )
    return CreateScanUseCase(uow, storage, extractor, job_runner, limits)


def get_list_scans_use_case(uow: UnitOfWork = Depends(get_unit_of_work)) -> ListScansUseCase:
    return ListScansUseCase(uow)


def get_get_scan_use_case(uow: UnitOfWork = Depends(get_unit_of_work)) -> GetScanUseCase:
    return GetScanUseCase(uow)


def get_get_scan_report_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
) -> GetScanReportUseCase:
    return GetScanReportUseCase(uow)


def get_delete_scan_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    storage: SourceStorage = Depends(get_source_storage),
) -> DeleteScanUseCase:
    return DeleteScanUseCase(uow, storage)


def get_dashboard_summary_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
) -> GetDashboardSummaryUseCase:
    return GetDashboardSummaryUseCase(uow)


@lru_cache
def get_report_exporters() -> dict[ReportFormat, ReportExporter]:
    return {ReportFormat.JSON: JsonReportExporter(), ReportFormat.PDF: PdfReportExporter()}


def get_export_scan_report_use_case(
    uow: UnitOfWork = Depends(get_unit_of_work),
    exporters: dict[ReportFormat, ReportExporter] = Depends(get_report_exporters),
) -> ExportScanReportUseCase:
    return ExportScanReportUseCase(uow, exporters)
