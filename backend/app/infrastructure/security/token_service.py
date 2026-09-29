from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt

from app.domain.exceptions import InvalidCredentialsError
from app.domain.ports.token_service import AccessTokenClaims, TokenService

_TOKEN_TYPE_CLAIM = "type"  # noqa: S105 - a JWT claim name, not a secret
_ACCESS_TOKEN_TYPE = "access"  # noqa: S105 - a JWT claim value, not a secret


class JwtTokenService(TokenService):
    """JWT (HS256) access tokens, and opaque/SHA-256-hashed refresh tokens.

    Refresh tokens are high-entropy random values, not JWTs - a fast hash
    (SHA-256) is appropriate for them at rest, unlike passwords, because
    there is no low-entropy secret to protect against brute force.
    """

    def __init__(self, secret_key: str, algorithm: str, access_token_ttl: timedelta) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._access_token_ttl = access_token_ttl

    def create_access_token(self, user_id: UUID) -> str:
        now = datetime.now(UTC)
        payload = {
            "sub": str(user_id),
            "iat": now,
            "exp": now + self._access_token_ttl,
            _TOKEN_TYPE_CLAIM: _ACCESS_TOKEN_TYPE,
        }
        return jwt.encode(payload, self._secret_key, algorithm=self._algorithm)

    def decode_access_token(self, token: str) -> AccessTokenClaims:
        try:
            payload = jwt.decode(token, self._secret_key, algorithms=[self._algorithm])
        except jwt.InvalidTokenError as exc:
            raise InvalidCredentialsError("Invalid or expired access token.") from exc

        if payload.get(_TOKEN_TYPE_CLAIM) != _ACCESS_TOKEN_TYPE:
            raise InvalidCredentialsError("Token is not an access token.")

        try:
            return AccessTokenClaims(user_id=UUID(payload["sub"]))
        except (KeyError, ValueError) as exc:
            raise InvalidCredentialsError("Malformed access token.") from exc

    def generate_refresh_token(self) -> str:
        return secrets.token_urlsafe(64)

    def hash_refresh_token(self, token_value: str) -> str:
        return hashlib.sha256(token_value.encode("utf-8")).hexdigest()
