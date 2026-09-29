# Intentionally no `from __future__ import annotations` in this file: slowapi's
# `@limiter.limit(...)` decorator wraps the endpoint in a function defined in
# slowapi's own module. With postponed evaluation, FastAPI has to resolve
# parameter annotations (stored as strings) via the function's `__globals__`,
# which - after wrapping - point at slowapi's namespace instead of this
# module's, so it can't find `RegisterRequest`/`LoginRequest` and silently
# misclassifies the body parameter as a query parameter (422 "Field
# required"). Keeping real annotation objects here sidesteps that entirely.
from fastapi import APIRouter, Depends, Request, status

from app.api.v1.dependencies import (
    get_current_user,
    get_login_use_case,
    get_logout_use_case,
    get_refresh_token_use_case,
    get_register_use_case,
)
from app.api.v1.schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.application.dto.auth import LoginUserInput, RegisterUserInput
from app.application.use_cases.login_user import LoginUserUseCase
from app.application.use_cases.logout_user import LogoutUserUseCase
from app.application.use_cases.refresh_token import RefreshTokenUseCase
from app.application.use_cases.register_user import RegisterUserUseCase
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.domain.entities.user import User

router = APIRouter(prefix="/auth", tags=["auth"])

_auth_rate_limit = get_settings().auth_rate_limit


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account",
)
@limiter.limit(_auth_rate_limit)
async def register(
    request: Request,
    payload: RegisterRequest,
    use_case: RegisterUserUseCase = Depends(get_register_use_case),
) -> UserResponse:
    result = await use_case.execute(
        RegisterUserInput(
            email=payload.email, password=payload.password, full_name=payload.full_name
        )
    )
    return UserResponse.from_dto(result)


@router.post("/login", response_model=TokenResponse, summary="Exchange credentials for tokens")
@limiter.limit(_auth_rate_limit)
async def login(
    request: Request,
    payload: LoginRequest,
    use_case: LoginUserUseCase = Depends(get_login_use_case),
) -> TokenResponse:
    result = await use_case.execute(LoginUserInput(email=payload.email, password=payload.password))
    return TokenResponse.from_dto(result)


@router.post("/refresh", response_model=TokenResponse, summary="Rotate a refresh token")
async def refresh(
    payload: RefreshRequest,
    use_case: RefreshTokenUseCase = Depends(get_refresh_token_use_case),
) -> TokenResponse:
    result = await use_case.execute(payload.refresh_token)
    return TokenResponse.from_dto(result)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Revoke a refresh token",
)
async def logout(
    payload: RefreshRequest,
    use_case: LogoutUserUseCase = Depends(get_logout_use_case),
) -> None:
    await use_case.execute(payload.refresh_token)


@router.get("/me", response_model=UserResponse, summary="Get the current authenticated user")
async def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.from_user(current_user)
