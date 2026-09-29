"""Port for everything token-related: signed JWT access tokens, and opaque
(random, hashed-at-rest) refresh tokens. Kept as one port since both halves
are usually backed by the same crypto/config adapter.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    user_id: UUID


class TokenService(ABC):
    @abstractmethod
    def create_access_token(self, user_id: UUID) -> str: ...

    @abstractmethod
    def decode_access_token(self, token: str) -> AccessTokenClaims:
        """Raise `app.domain.exceptions.InvalidCredentialsError` if the token
        is malformed, tampered with, or expired."""

    @abstractmethod
    def generate_refresh_token(self) -> str:
        """A high-entropy opaque value handed to the client - never stored
        as-is, only via `hash_refresh_token`."""

    @abstractmethod
    def hash_refresh_token(self, token_value: str) -> str: ...
