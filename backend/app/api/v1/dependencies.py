"""FastAPI dependency-injection wiring.

Kept as a single module so all DI wiring is visible in one place rather than
scattered across routers. Grown as each use case is added.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from functools import lru_cache

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.application.use_cases.get_current_user import GetCurrentUserUseCase
from app.application.use_cases.login_user import LoginUserUseCase
from app.application.use_cases.logout_user import LogoutUserUseCase
from app.application.use_cases.refresh_token import RefreshTokenUseCase
from app.application.use_cases.register_user import RegisterUserUseCase
from app.core.config import Settings, get_settings
from app.core.exceptions import UnauthorizedError
from app.domain.entities.user import User
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.token_service import TokenService
from app.domain.ports.unit_of_work import UnitOfWork
from app.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.infrastructure.security.token_service import JwtTokenService

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
