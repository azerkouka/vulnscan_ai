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


class KnowledgeDocumentNotFoundError(DomainError):
    """Raised when a referenced knowledge document external_id does not exist."""


class ScanNotFoundError(DomainError):
    """Raised when a scan id does not exist - or belongs to another user,
    which is deliberately indistinguishable from the caller's side."""


class ScanInProgressError(DomainError):
    """Raised when an operation needs the scan to have finished first."""


class InvalidSourceError(DomainError):
    """Raised when submitted source can't be scanned (empty, binary,
    unsupported extension or language)."""


class SourceTooLargeError(DomainError):
    """Raised when submitted source exceeds the configured upload limit."""


class InvalidArchiveError(DomainError):
    """Raised when an uploaded archive is corrupt or trips a safety limit."""


class LLMAnalysisError(DomainError):
    """Raised when the LLM could not produce a valid analysis for a chunk,
    even after retries."""


class TooManyActiveScansError(DomainError):
    """Raised when a user already has as many unfinished scans as allowed."""


class ReportFormatUnavailableError(DomainError):
    """Raised when a report can't be exported to the requested format on
    this installation (e.g. the PDF libraries are not installed)."""
