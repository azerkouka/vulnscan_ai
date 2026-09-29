from app.core.config import Settings


def test_settings_load_required_fields_from_env(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("JWT_SECRET_KEY", "unit-test-secret")

    settings = Settings()  # type: ignore[call-arg]

    assert settings.jwt_secret_key == "unit-test-secret"
    assert settings.app_name == "VulnScan AI"


def test_cors_origins_accepts_comma_separated_string(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("JWT_SECRET_KEY", "unit-test-secret")
    monkeypatch.setenv("CORS_ORIGINS", "http://localhost:4200,https://app.example.com")

    settings = Settings()  # type: ignore[call-arg]

    assert settings.cors_origins == ["http://localhost:4200", "https://app.example.com"]


def test_token_lifetime_defaults_are_short_lived(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("JWT_SECRET_KEY", "unit-test-secret")

    settings = Settings()  # type: ignore[call-arg]

    assert settings.access_token_expire_minutes == 15
    assert settings.refresh_token_expire_days == 7
