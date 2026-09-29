import pytest

from app.infrastructure.security.password_hasher import Argon2PasswordHasher


@pytest.mark.unit
def test_hash_then_verify_round_trip() -> None:
    hasher = Argon2PasswordHasher()

    hashed = hasher.hash("correct-horse-battery-staple")

    assert hasher.verify("correct-horse-battery-staple", hashed) is True


@pytest.mark.unit
def test_verify_rejects_wrong_password() -> None:
    hasher = Argon2PasswordHasher()
    hashed = hasher.hash("correct-horse-battery-staple")

    assert hasher.verify("wrong-password", hashed) is False


@pytest.mark.unit
def test_verify_rejects_garbage_hash_without_raising() -> None:
    hasher = Argon2PasswordHasher()

    assert hasher.verify("anything", "not-a-real-argon2-hash") is False


@pytest.mark.unit
def test_hashing_the_same_password_twice_yields_different_hashes() -> None:
    """Argon2 salts each hash, so two hashes of the same input must differ -
    this is what stops rainbow-table attacks and equality-based leaks."""
    hasher = Argon2PasswordHasher()

    assert hasher.hash("same-password") != hasher.hash("same-password")
