from __future__ import annotations

from argon2 import PasswordHasher as Argon2Hasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.domain.ports.password_hasher import PasswordHasher


class Argon2PasswordHasher(PasswordHasher):
    """Argon2id via `argon2-cffi` - the OWASP-recommended default for new
    applications (memory-hard, resistant to GPU cracking)."""

    def __init__(self) -> None:
        self._hasher = Argon2Hasher()

    def hash(self, plain_password: str) -> str:
        return self._hasher.hash(plain_password)

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        try:
            return self._hasher.verify(hashed_password, plain_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
