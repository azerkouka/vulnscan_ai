"""Domain-level errors.

Plain Python exceptions with zero framework knowledge - the API layer
(`app.core.exceptions`) maps each of these to an HTTP status code. The domain
itself never knows what a status code is.
"""

from __future__ import annotations


class DomainError(Exception):
    """Base class for all domain-raised errors."""


class EmailAlreadyRegisteredError(DomainError):
    """Raised when registering an email that already has an account."""


class InvalidCredentialsError(DomainError):
    """Raised on a failed login, or an invalid/expired access token."""


class InvalidRefreshTokenError(DomainError):
    """Raised when a refresh token is unknown, expired, or already used."""


class InactiveUserError(DomainError):
    """Raised when an otherwise-valid user account is deactivated."""


class UserNotFoundError(DomainError):
    """Raised when a referenced user id does not exist."""
