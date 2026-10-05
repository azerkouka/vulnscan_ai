"""Shared pytest fixtures.

Sets the minimal environment required by `Settings` *before* the app module
is imported, so tests never depend on a developer's local `.env` file.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://vulnscan:vulnscan@localhost:5432/vulnscan_test"
)
# A tight auth rate limit is a production feature, not something we want
# tripping unrelated tests that log in more than a handful of times.
os.environ.setdefault("AUTH_RATE_LIMIT", "1000/minute")
os.environ.setdefault("SCAN_RATE_LIMIT", "1000/minute")

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.dependencies import (
    get_db_session,
    get_job_runner,
    get_knowledge_store,
    get_source_storage,
)
from app.application.use_cases.run_scan_analysis import RunScanAnalysisUseCase
from app.core.config import get_settings
from app.domain.entities.user import User
from app.domain.ports.job_runner import JobRunner
from app.infrastructure.persistence.models import Base
from app.infrastructure.persistence.repositories.user_repository import SqlAlchemyUserRepository
from app.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.infrastructure.uploads.local_source_storage import LocalSourceStorage
from app.main import create_app
from tests.unit.fakes import (
    FakeCodeChunker,
    FakeKnowledgeIndexer,
    FakeKnowledgeRetriever,
    FakeLLMAnalyzer,
)

if TYPE_CHECKING:
    from app.infrastructure.vectorstore.chroma_knowledge_store import ChromaKnowledgeStore


@pytest.fixture
def client() -> TestClient:
    """A plain client for endpoints that don't touch the database (health)."""
    return TestClient(create_app())


@pytest_asyncio.fixture(scope="session")
async def db_engine() -> AsyncIterator[AsyncEngine]:
    """A real engine against DATABASE_URL, for integration/e2e tests.

    Skips (rather than fails) the requesting tests if no database is
    reachable, so `pytest` stays runnable without Docker for contributors
    working on domain/application code only.

    Uses `NullPool`: pytest-asyncio gives each test function its own event
    loop, but asyncpg connections are bound to the loop that created them.
    A session-scoped engine with the default pool would hand a later test a
    pooled connection tied to an already-closed loop from an earlier test.
    `NullPool` opens a fresh connection on every checkout instead, so each
    test's connection is always bound to *its own*, currently-running loop.
    """
    engine = create_async_engine(os.environ["DATABASE_URL"], poolclass=NullPool)
    try:
        async with engine.connect():
            pass
    except Exception as exc:  # broad on purpose: any connection failure just means "skip"
        await engine.dispose()
        pytest.skip(
            f"Test database not reachable ({exc!r}); start it with `docker compose up -d postgres`."
        )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """One test = one outer transaction, rolled back at the end.

    Code under test is free to call `session.commit()` (our
    `SqlAlchemyUnitOfWork` does) without actually persisting anything past
    the test, because commits inside an already-begun connection-level
    transaction only release a savepoint.
    """
    connection = await db_engine.connect()
    outer_transaction = await connection.begin()
    session = AsyncSession(
        bind=connection, expire_on_commit=False, join_transaction_mode="create_savepoint"
    )

    yield session

    await session.close()
    await outer_transaction.rollback()
    await connection.close()


@pytest_asyncio.fixture
async def api_client(db_session: AsyncSession) -> AsyncIterator[AsyncClient]:
    """An async API test client whose `get_db_session` dependency is pinned
    to the per-test transactional session above, so e2e tests see real
    repository and SQL behavior while staying isolated between tests.

    Deliberately `httpx.AsyncClient` + `ASGITransport`, not
    `starlette.testclient.TestClient`: `TestClient` runs the ASGI app inside
    its own dedicated thread and event loop (an anyio `BlockingPortal`),
    separate from the loop pytest-asyncio runs this fixture (and `db_session`)
    on. Sharing one live `AsyncSession`/asyncpg connection across that loop
    boundary raises "Future ... attached to a different loop" as soon as a
    request tries to use it. Driving the app in-process on the *same* loop
    (what `ASGITransport` does) avoids the problem entirely.
    """
    app = create_app()

    async def _override_get_db_session() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db_session] = _override_get_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture
async def chroma_store() -> AsyncIterator[ChromaKnowledgeStore]:
    """A `ChromaKnowledgeStore` against a real, throwaway collection.

    Skips (like `db_engine`) if either `chromadb` isn't installed locally
    (it's behind the optional `rag` extra - see `dependencies.py`) or no
    Chroma server is reachable, so `pytest` stays runnable for contributors
    without Docker or a Windows machine that can't compile the `rag` extra's
    native dependencies.
    """
    try:
        from app.infrastructure.vectorstore.chroma_knowledge_store import ChromaKnowledgeStore
    except ImportError as exc:
        pytest.skip(f"chromadb not installed (install the 'rag' extra to run this): {exc!r}")

    host = os.environ.get("CHROMA_HOST", "localhost")
    port = int(os.environ.get("CHROMA_PORT", "8000"))
    collection_name = f"test_knowledge_{uuid4().hex[:8]}"

    def _connect() -> ChromaKnowledgeStore:
        store = ChromaKnowledgeStore(host=host, port=port, collection_name=collection_name)
        store._client.heartbeat()  # cheap reachability check; raises if the server is down
        return store

    try:
        store = await asyncio.to_thread(_connect)
    except Exception as exc:  # broad on purpose: any connection failure just means "skip"
        pytest.skip(
            f"Chroma not reachable ({exc!r}); start it with `docker compose up -d chromadb`."
        )

    yield store

    def _cleanup() -> None:
        # Best-effort: the test may never have touched the collection at all
        # (get_or_create_collection is only called lazily on first use).
        with contextlib.suppress(Exception):
            store._client.delete_collection(collection_name)

    await asyncio.to_thread(_cleanup)


@pytest_asyncio.fixture
async def admin_api_client(
    db_session: AsyncSession, chroma_store: ChromaKnowledgeStore
) -> AsyncIterator[AsyncClient]:
    """Like `api_client`, but also wired to the throwaway `chroma_store`
    (so `/knowledge/*` endpoints hit an isolated collection, not whatever
    the app's real singleton points at) and pre-authenticated as a
    superuser - seeded directly via the repository, since registration
    never sets `is_superuser`.
    """
    app = create_app()

    async def _override_get_db_session() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db_session] = _override_get_db_session
    app.dependency_overrides[get_knowledge_store] = lambda: chroma_store

    hasher = Argon2PasswordHasher()
    password = "admin-password-123"
    now = datetime.now(UTC)
    admin = User(
        id=uuid4(),
        email="admin@example.com",
        hashed_password=hasher.hash(password),
        full_name="Admin",
        is_active=True,
        is_superuser=True,
        created_at=now,
        updated_at=now,
    )
    await SqlAlchemyUserRepository(db_session).add(admin)
    await db_session.flush()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        login = await client.post(
            "/api/v1/auth/login", json={"email": admin.email, "password": password}
        )
        client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        yield client


class InlineJobRunner(JobRunner):
    """Runs scan jobs in the test's own task and session instead of in the
    background, so a test can assert on a finished scan right after
    submitting it. Set `paused` to observe a scan while it is still PENDING,
    then `run_pending()` to let it through."""

    def __init__(self, run_scan: Callable[[UUID], Awaitable[None]]) -> None:
        self._run_scan = run_scan
        self._pending: list[UUID] = []
        self.paused = False

    async def enqueue_scan(self, scan_id: UUID) -> None:
        self._pending.append(scan_id)
        if not self.paused:
            await self.run_pending()

    async def run_pending(self) -> None:
        while self._pending:
            await self._run_scan(self._pending.pop(0))


@dataclass
class ScanApiHarness:
    client: AsyncClient
    """Authenticated as a regular (non-admin) user."""
    analyzer: FakeLLMAnalyzer
    indexer: FakeKnowledgeIndexer
    """What the fake retriever searches - index a document to make it citable."""
    jobs: InlineJobRunner
    storage_dir: Path
    max_upload_bytes: int

    def stored_files(self) -> list[Path]:
        return [path for path in self.storage_dir.rglob("*") if path.is_file()]

    async def login_as(self, email: str) -> None:
        """Registers `email` and switches the client over to that user."""
        credentials = {"email": email, "password": "correct-horse-battery"}
        await self.client.post("/api/v1/auth/register", json=credentials)
        login = await self.client.post("/api/v1/auth/login", json=credentials)
        self.client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"


@pytest_asyncio.fixture
async def scan_api(db_session: AsyncSession, tmp_path: Path) -> AsyncIterator[ScanApiHarness]:
    """The API wired for `/scans` tests: real database, real file storage
    (under `tmp_path`) and real zip extraction, but a scripted LLM, an
    in-memory knowledge base, and jobs run inline (`InlineJobRunner`) - the
    LLM is always mocked in tests, per the project rules."""
    app = create_app()
    storage = LocalSourceStorage(tmp_path)
    analyzer = FakeLLMAnalyzer()
    indexer = FakeKnowledgeIndexer()

    async def _run_scan(scan_id: UUID) -> None:
        use_case = RunScanAnalysisUseCase(
            SqlAlchemyUnitOfWork(db_session),
            storage,
            FakeCodeChunker(),
            FakeKnowledgeRetriever(indexer),
            analyzer,
        )
        await use_case.execute(scan_id)

    jobs = InlineJobRunner(_run_scan)
    # A 1 MB cap keeps the "upload too large" test from pushing 10 MB around.
    settings = get_settings().model_copy(update={"upload_max_size_mb": 1})

    async def _override_get_db_session() -> AsyncIterator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_db_session] = _override_get_db_session
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_source_storage] = lambda: storage
    app.dependency_overrides[get_job_runner] = lambda: jobs

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        harness = ScanApiHarness(
            client=client,
            analyzer=analyzer,
            indexer=indexer,
            jobs=jobs,
            storage_dir=tmp_path,
            max_upload_bytes=settings.upload_max_size_mb * 1024 * 1024,
        )
        await harness.login_as("scanner@example.com")
        yield harness
