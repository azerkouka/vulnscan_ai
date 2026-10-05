"""FastAPI application factory.

Only wiring lives here: middleware, exception handlers, and router
registration. Business logic belongs in `app.application.use_cases`, never
in this module or in the routers themselves.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.dependencies import build_scan_job
from app.api.v1.routers import auth, dashboard, health, knowledge, scans
from app.application.use_cases.fail_scans import FailInterruptedScansUseCase
from app.core.body_limit import MaxBodySizeMiddleware
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestContextMiddleware
from app.core.rate_limit import limiter
from app.core.security_headers import SecurityHeadersMiddleware
from app.infrastructure.jobs.asyncio_job_runner import AsyncioJobRunner
from app.infrastructure.persistence.database import create_engine, create_session_factory
from app.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    settings = get_settings()
    configure_logging(settings.log_level)

    engine = create_engine(settings.database_url, echo=settings.debug)
    session_factory = create_session_factory(engine)
    app.state.session_factory = session_factory

    job_runner = AsyncioJobRunner(
        build_scan_job(session_factory), max_concurrent_jobs=settings.scan_max_concurrent_jobs
    )
    app.state.job_runner = job_runner

    # Scan jobs run inside this process, so any scan a previous run left
    # unfinished has no job anymore. This assumes a single backend process:
    # with several, one starting up would fail the scans another is running.
    try:
        async with session_factory() as session:
            interrupted = await FailInterruptedScansUseCase(SqlAlchemyUnitOfWork(session)).execute()
        if interrupted:
            logger.warning("interrupted_scans_marked_failed", count=interrupted)
    except Exception:
        # Not worth refusing to start over (e.g. migrations not applied yet).
        logger.exception("interrupted_scans_recovery_failed")

    logger.info("app_startup", environment=settings.environment)
    yield

    await job_runner.shutdown()
    await engine.dispose()
    logger.info("app_shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    # The interactive docs describe every endpoint and load scripts from a
    # CDN: useful in development, needless exposure in production.
    in_production = settings.environment == "production"
    app = FastAPI(
        title=settings.app_name,
        description="RAG-grounded LLM source code vulnerability scanner.",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None if in_production else "/docs",
        redoc_url=None if in_production else "/redoc",
        openapi_url=None if in_production else "/openapi.json",
    )

    app.state.limiter = limiter

    # Pure-ASGI middleware only (see app.core.middleware docstring): mixing in
    # a `BaseHTTPMiddleware`-based one (slowapi's `SlowAPIMiddleware`, or the
    # `@app.middleware("http")` decorator) breaks async SQLAlchemy sessions
    # shared across a request boundary via dependency overrides in tests.
    # Added innermost first; the last one added is the first to see a request.
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=settings.max_request_body_bytes)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        # No cookies are used (tokens travel in the Authorization header), so
        # browsers never need to attach credentials to cross-origin calls.
        allow_credentials=False,
        # Exactly what the API uses - not "*".
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
    # Outermost, so its headers are also on CORS preflights and on errors
    # produced by the middlewares above.
    app.add_middleware(SecurityHeadersMiddleware, hsts=in_production)

    register_exception_handlers(app)

    app.include_router(health.router, prefix=settings.api_v1_prefix)
    app.include_router(auth.router, prefix=settings.api_v1_prefix)
    app.include_router(knowledge.router, prefix=settings.api_v1_prefix)
    app.include_router(scans.router, prefix=settings.api_v1_prefix)
    app.include_router(dashboard.router, prefix=settings.api_v1_prefix)

    return app


app = create_app()
