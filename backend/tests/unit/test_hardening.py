"""Security hardening that needs no database: response headers, request-size
limits, error envelopes, production settings, and login timing."""

from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ValidationError
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.application.dto.auth import LoginUserInput
from app.application.dto.scan import CreateScanInput
from app.application.use_cases.create_scan import CreateScanUseCase, ScanSourceLimits
from app.application.use_cases.login_user import LoginUserUseCase
from app.core.body_limit import MaxBodySizeMiddleware
from app.core.config import Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.security_headers import SecurityHeadersMiddleware
from app.domain.exceptions import InvalidCredentialsError, TooManyActiveScansError
from app.domain.value_objects.scan_status import ScanStatus
from app.main import create_app
from tests.unit.fakes import (
    FakeArchiveExtractor,
    FakeJobRunner,
    FakePasswordHasher,
    FakeSourceStorage,
    FakeTokenService,
    FakeUnitOfWork,
)
from tests.unit.helpers import make_scan, make_user

_STRONG_SECRET = "k7Jq2vX9mN4pR8sT1wY6zA3bC5dE0fGhIjKlMnOpQrStUvWx"

# --- Response headers -------------------------------------------------------------


@pytest.mark.unit
def test_api_responses_carry_the_security_headers(client: TestClient) -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'"
    )
    assert response.headers["cache-control"] == "no-store"
    # Not over plain HTTP in development: HSTS is a production (HTTPS) header.
    assert "strict-transport-security" not in response.headers


@pytest.mark.unit
def test_error_responses_carry_the_security_headers_too(client: TestClient) -> None:
    response = client.get("/api/v1/no-such-endpoint")

    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.unit
def test_content_policy_is_not_applied_to_the_interactive_docs(client: TestClient) -> None:
    response = client.get("/docs")

    assert response.status_code == 200
    # Swagger UI loads its script from a CDN; the JSON-only policy would block it.
    assert "content-security-policy" not in response.headers
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.unit
def test_hsts_is_sent_only_when_enabled_and_explicit_headers_are_kept() -> None:
    app = FastAPI()

    @app.get("/file")
    async def file() -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/cached")
    async def cached(request: Request):  # type: ignore[no-untyped-def]
        from fastapi.responses import JSONResponse

        return JSONResponse({"ok": "yes"}, headers={"Cache-Control": "max-age=60"})

    app.add_middleware(SecurityHeadersMiddleware, hsts=True)
    http = TestClient(app)

    assert http.get("/file").headers["strict-transport-security"].startswith("max-age=31536000")
    # An endpoint that sets its own caching policy keeps it.
    assert http.get("/cached").headers["cache-control"] == "max-age=60"


@pytest.mark.unit
def test_cors_allows_the_frontend_origin_with_only_what_the_api_uses(client: TestClient) -> None:
    preflight = client.options(
        "/api/v1/scans",
        headers={
            "Origin": "http://localhost:4200",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
    )

    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "http://localhost:4200"
    allowed_methods = {
        m.strip() for m in preflight.headers["access-control-allow-methods"].split(",")
    }
    assert allowed_methods == {"GET", "POST", "DELETE", "OPTIONS"}
    # Tokens travel in a header, not in cookies: credentials mode stays off.
    assert "access-control-allow-credentials" not in preflight.headers


@pytest.mark.unit
def test_cors_refuses_other_origins_and_methods(client: TestClient) -> None:
    foreign = client.options(
        "/api/v1/scans",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in foreign.headers

    put = client.options(
        "/api/v1/scans",
        headers={"Origin": "http://localhost:4200", "Access-Control-Request-Method": "PUT"},
    )
    assert put.status_code == 400


# --- Request size limit --------------------------------------------------------------


def _echo_app(max_bytes: int) -> FastAPI:
    app = FastAPI()
    register_exception_handlers(app)

    @app.post("/echo")
    async def echo(request: Request) -> dict[str, int]:
        return {"received": len(await request.body())}

    app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_bytes)
    return app


@pytest.mark.unit
async def test_body_within_the_limit_is_accepted() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_echo_app(100)), base_url="http://t"
    ) as http:
        response = await http.post("/echo", content=b"x" * 100)

    assert response.status_code == 200
    assert response.json() == {"received": 100}


@pytest.mark.unit
async def test_declared_oversize_body_is_refused_before_being_read() -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_echo_app(100)), base_url="http://t"
    ) as http:
        response = await http.post("/echo", content=b"x" * 101)

    assert response.status_code == 413
    assert "larger than" in response.json()["error"]["message"]


@pytest.mark.unit
async def test_undeclared_oversize_body_is_cut_off_while_streaming() -> None:
    sent = 0

    async def chunks() -> AsyncIterator[bytes]:
        nonlocal sent
        for _ in range(50):
            sent += 10
            yield b"x" * 10

    # A generator body has no Content-Length: it is sent chunked.
    async with AsyncClient(
        transport=ASGITransport(app=_echo_app(100)), base_url="http://t"
    ) as http:
        response = await http.post("/echo", content=chunks())

    assert response.status_code == 413
    assert "larger than" in response.json()["error"]["message"]


# --- Error envelopes -------------------------------------------------------------------


class _Credentials(BaseModel):
    email: str
    password: str
    age: int


def _error_app() -> FastAPI:
    app = FastAPI()
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    register_exception_handlers(app)

    @app.post("/validate")
    async def validate(payload: _Credentials) -> dict[str, bool]:
        return {"ok": True}

    @app.get("/limited")
    @limiter.limit("1/minute")
    async def limited(request: Request) -> dict[str, bool]:
        return {"ok": True}

    return app


@pytest.mark.unit
def test_validation_errors_use_the_common_envelope_and_never_echo_the_input() -> None:
    http = TestClient(_error_app())

    response = http.post(
        "/validate", json={"email": "a@b.c", "password": "hunter2-secret", "age": "old"}
    )

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"] == [
        {
            "field": "age",
            "message": "Input should be a valid integer, unable to parse string as an integer",
        }
    ]
    assert error["message"].startswith("age: ")
    assert "hunter2-secret" not in response.text
    assert "old" not in response.text


@pytest.mark.unit
def test_rate_limited_requests_use_the_common_envelope() -> None:
    http = TestClient(_error_app())

    assert http.get("/limited").status_code == 200
    blocked = http.get("/limited")

    assert blocked.status_code == 429
    assert blocked.json() == {
        "error": {
            "code": "rate_limited",
            "message": "Too many requests. Please wait a moment and try again.",
        }
    }
    assert blocked.headers["retry-after"] == "60"


# --- Production settings ----------------------------------------------------------------


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {"jwt_secret_key": _STRONG_SECRET, "environment": "production"}
    values.update(overrides)
    return Settings(_env_file=None, **values)  # type: ignore[arg-type]


@pytest.mark.unit
def test_production_accepts_a_strong_configuration() -> None:
    settings = _settings()

    assert settings.environment == "production"


@pytest.mark.unit
@pytest.mark.parametrize(
    ("overrides", "problem"),
    [
        ({"jwt_secret_key": "short"}, "JWT_SECRET_KEY"),
        ({"jwt_secret_key": "change-this-to-a-random-64-byte-secret"}, "JWT_SECRET_KEY"),
        ({"debug": True}, "DEBUG"),
        ({"cors_origins": ["*"]}, "CORS_ORIGINS"),
    ],
)
def test_production_refuses_to_start_with_an_unsafe_setting(
    overrides: dict[str, object], problem: str
) -> None:
    with pytest.raises(ValidationError, match=problem):
        _settings(**overrides)


@pytest.mark.unit
def test_development_is_not_held_to_production_rules() -> None:
    settings = _settings(environment="development", jwt_secret_key="dev", debug=True)

    assert settings.debug is True


@pytest.mark.unit
def test_request_body_limit_follows_the_upload_limit() -> None:
    assert _settings(upload_max_size_mb=10).max_request_body_bytes == 11 * 1024 * 1024


@pytest.mark.unit
def test_api_docs_are_switched_off_in_production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET_KEY", _STRONG_SECRET)
    monkeypatch.setenv("DEBUG", "false")
    get_settings.cache_clear()
    try:
        http = TestClient(create_app())

        assert http.get("/docs").status_code == 404
        assert http.get("/redoc").status_code == 404
        assert http.get("/openapi.json").status_code == 404
        health = http.get("/api/v1/health")
        assert health.status_code == 200
        assert "strict-transport-security" in health.headers
    finally:
        get_settings.cache_clear()


# --- Abuse limits and login timing --------------------------------------------------------


@pytest.mark.unit
async def test_user_cannot_queue_more_scans_than_allowed() -> None:
    uow = FakeUnitOfWork()
    storage = FakeSourceStorage()
    jobs = FakeJobRunner()
    limits = ScanSourceLimits(
        max_upload_bytes=1024, allowed_extensions=frozenset({".py"}), max_active_scans=2
    )
    use_case = CreateScanUseCase(uow, storage, FakeArchiveExtractor(), jobs, limits)
    user_id = uuid4()
    await uow.scans.add(make_scan(user_id=user_id, status=ScanStatus.PENDING), [])
    await uow.scans.add(make_scan(user_id=user_id, status=ScanStatus.RUNNING), [])
    # Finished scans, and other users' scans, don't count against the cap.
    await uow.scans.add(make_scan(user_id=user_id, status=ScanStatus.COMPLETED), [])
    await uow.scans.add(make_scan(status=ScanStatus.RUNNING), [])

    with pytest.raises(TooManyActiveScansError, match="2 scans in progress"):
        await use_case.execute(CreateScanInput(user_id=user_id, content=b"x = 1"))
    assert storage.contents == {}
    assert jobs.enqueued_scan_ids == []

    other_user = await use_case.execute(CreateScanInput(user_id=uuid4(), content=b"x = 1"))
    assert other_user.status is ScanStatus.PENDING


class _CountingHasher(FakePasswordHasher):
    def __init__(self) -> None:
        self.verifications = 0

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        self.verifications += 1
        return super().verify(plain_password, hashed_password)


@pytest.mark.unit
async def test_login_does_the_same_hashing_work_whether_or_not_the_account_exists() -> None:
    uow = FakeUnitOfWork()
    await uow.users.add(make_user(email="known@example.com", hashed_password="hashed:right"))
    hasher = _CountingHasher()
    use_case = LoginUserUseCase(uow, hasher, FakeTokenService(), refresh_token_ttl=_ttl())

    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(LoginUserInput(email="known@example.com", password="wrong"))
    known_account_work = hasher.verifications

    hasher.verifications = 0
    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(LoginUserInput(email="nobody@example.com", password="wrong"))

    assert hasher.verifications == known_account_work == 1


@pytest.mark.unit
async def test_the_decoy_password_cannot_be_used_to_sign_in() -> None:
    uow = FakeUnitOfWork()
    use_case = LoginUserUseCase(
        uow, FakePasswordHasher(), FakeTokenService(), refresh_token_ttl=_ttl()
    )

    with pytest.raises(InvalidCredentialsError):
        await use_case.execute(
            LoginUserInput(
                email="nobody@example.com", password="decoy-password-for-constant-time-login"
            )
        )


def _ttl():  # type: ignore[no-untyped-def]
    from datetime import timedelta

    return timedelta(days=7)
