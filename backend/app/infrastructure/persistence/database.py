"""Async SQLAlchemy engine/session factory construction.

Created once at app startup (see `app.main.lifespan`) and stored on
`app.state`; `app.api.v1.dependencies.get_db_session` hands out one session
per request from the factory built here.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
    return create_async_engine(database_url, echo=echo, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)
