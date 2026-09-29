from datetime import timedelta
from uuid import uuid4

import jwt
import pytest

from app.domain.exceptions import InvalidCredentialsError
from app.infrastructure.security.token_service import JwtTokenService


def _service(ttl: timedelta = timedelta(minutes=15)) -> JwtTokenService:
    return JwtTokenService(secret_key="test-secret", algorithm="HS256", access_token_ttl=ttl)


@pytest.mark.unit
def test_access_token_round_trip() -> None:
    service = _service()
    user_id = uuid4()

    token = service.create_access_token(user_id)
    claims = service.decode_access_token(token)

    assert claims.user_id == user_id


@pytest.mark.unit
def test_expired_access_token_is_rejected() -> None:
    service = _service(ttl=timedelta(seconds=-1))
    token = service.create_access_token(uuid4())

    with pytest.raises(InvalidCredentialsError):
        service.decode_access_token(token)


@pytest.mark.unit
def test_tampered_signature_is_rejected() -> None:
    service = _service()
    token = service.create_access_token(uuid4())
    other_service = JwtTokenService(
        secret_key="a-different-secret", algorithm="HS256", access_token_ttl=timedelta(minutes=15)
    )

    with pytest.raises(InvalidCredentialsError):
        other_service.decode_access_token(token)


@pytest.mark.unit
def test_non_access_token_type_is_rejected() -> None:
    service = _service()
    # Craft a token that is validly signed but not an access token.
    foreign_token = jwt.encode(
        {"sub": str(uuid4()), "type": "refresh"}, "test-secret", algorithm="HS256"
    )

    with pytest.raises(InvalidCredentialsError):
        service.decode_access_token(foreign_token)


@pytest.mark.unit
def test_refresh_token_hash_is_deterministic_and_not_reversible_looking() -> None:
    service = _service()
    value = service.generate_refresh_token()

    assert service.hash_refresh_token(value) == service.hash_refresh_token(value)
    assert service.hash_refresh_token(value) != value


@pytest.mark.unit
def test_generated_refresh_tokens_are_unique() -> None:
    service = _service()

    assert service.generate_refresh_token() != service.generate_refresh_token()
