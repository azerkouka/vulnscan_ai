"""Application-wide exception hierarchy and the global FastAPI exception handlers.

Use cases and infrastructure adapters raise these instead of framework-specific
exceptions, keeping `app/domain` and `app/application` free of any FastAPI
import. The API layer maps them to a single, consistent JSON error envelope
and never leaks a stack trace to the client.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger
from app.domain.exceptions import (
    DomainError,
    EmailAlreadyRegisteredError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    KnowledgeDocumentNotFoundError,
    UserNotFoundError,
)

logger = get_logger(__name__)

_DOMAIN_ERROR_STATUS: dict[type[DomainError], int] = {
    EmailAlreadyRegisteredError: status.HTTP_409_CONFLICT,
    InvalidCredentialsError: status.HTTP_401_UNAUTHORIZED,
    InvalidRefreshTokenError: status.HTTP_401_UNAUTHORIZED,
    InactiveUserError: status.HTTP_403_FORBIDDEN,
    UserNotFoundError: status.HTTP_404_NOT_FOUND,
    KnowledgeDocumentNotFoundError: status.HTTP_404_NOT_FOUND,
}


class AppError(Exception):
    """Base class for all application-raised errors."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    error_code: str = "internal_error"

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if error_code:
            self.error_code = error_code


class NotFoundError(AppError):
    status_code = status.HTTP_404_NOT_FOUND
    error_code = "not_found"


class ValidationAppError(AppError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    error_code = "validation_error"


class UnauthorizedError(AppError):
    status_code = status.HTTP_401_UNAUTHORIZED
    error_code = "unauthorized"


class ForbiddenError(AppError):
    status_code = status.HTTP_403_FORBIDDEN
    error_code = "forbidden"


class ConflictError(AppError):
    status_code = status.HTTP_409_CONFLICT
    error_code = "conflict"


class RateLimitedError(AppError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    error_code = "rate_limited"


def _error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content={"error": {"code": code, "message": message}}
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        logger.info("app_error", error_code=exc.error_code, message=exc.message)
        return _error_response(exc.status_code, exc.error_code, exc.message)

    @app.exception_handler(DomainError)
    async def handle_domain_error(_request: Request, exc: DomainError) -> JSONResponse:
        status_code = _DOMAIN_ERROR_STATUS.get(type(exc), status.HTTP_400_BAD_REQUEST)
        error_code = type(exc).__name__.removesuffix("Error")
        logger.info("domain_error", error_code=error_code, message=str(exc))
        return _error_response(status_code, error_code, str(exc))

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return _error_response(exc.status_code, "http_error", str(exc.detail))

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_error", error_type=type(exc).__name__)
        return _error_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "An unexpected error occurred. Please try again later.",
        )


def error_examples() -> dict[str, Any]:
    """Shared OpenAPI example for the error envelope, reused across routers."""
    return {
        "application/json": {
            "example": {"error": {"code": "not_found", "message": "Scan not found."}}
        }
    }
