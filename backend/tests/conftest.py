"""Shared pytest fixtures.

Sets the minimal environment required by `Settings` *before* the app module
is imported, so tests never depend on a developer's local `.env` file.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://vulnscan:vulnscan@localhost:5432/vulnscan_test"
)
# A tight auth rate limit is a production feature, not something we want
# tripping unrelated tests that log in more than a handful of times.
os.environ.setdefault("AUTH_RATE_LIMIT", "1000/minute")

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.api.v1.dependencies import get_db_session
from app.infrastructure.persistence.models import Base
from app.main import create_app


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
