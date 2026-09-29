"""FastAPI application factory.

Only wiring lives here: middleware, exception handlers, and router
registration. Business logic belongs in `app.application.use_cases`, never
in this module or in the routers themselves.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api.v1.routers import auth, health, knowledge
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger
from app.core.middleware import RequestContextMiddleware
from app.core.rate_limit import limiter
from app.infrastructure.persistence.database import create_engine, create_session_factory

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    settings = get_settings()
    configure_logging(settings.log_level)

    engine = create_engine(settings.database_url, echo=settings.debug)
    app.state.session_factory = create_session_factory(engine)

    logger.info("app_startup", environment=settings.environment)
    yield

    await engine.dispose()
    logger.info("app_shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description="RAG-grounded LLM source code vulnerability scanner.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # Pure-ASGI middleware only (see app.core.middleware docstring): mixing in
    # a `BaseHTTPMiddleware`-based one (slowapi's `SlowAPIMiddleware`, or the
    # `@app.middleware("http")` decorator) breaks async SQLAlchemy sessions
    # shared across a request boundary via dependency overrides in tests.
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    app.include_router(health.router, prefix=settings.api_v1_prefix)
    app.include_router(auth.router, prefix=settings.api_v1_prefix)
    app.include_router(knowledge.router, prefix=settings.api_v1_prefix)
    # Additional routers (scans, reports, dashboard) are registered here as
    # they land in later phases.

    return app


app = create_app()
