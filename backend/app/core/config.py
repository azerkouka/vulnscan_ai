"""Application configuration, sourced from environment variables / .env file.

A single `Settings` instance is created lazily via `get_settings()` (cached) so
it is read once per process and can still be overridden in tests by clearing
the cache and monkeypatching environment variables.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- App ---
    app_name: str = "VulnScan AI"
    environment: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    api_v1_prefix: str = "/api/v1"

    # --- Database ---
    database_url: str = Field(
        default="postgresql+asyncpg://vulnscan:vulnscan@localhost:5432/vulnscan",
        description="Async SQLAlchemy connection string.",
    )
    db_pool_size: int = 10
    db_max_overflow: int = 5

    # --- JWT ---
    jwt_secret_key: str = Field(..., description="Secret used to sign access/refresh tokens.")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # --- CORS ---
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:4200"]
    )

    # --- ChromaDB ---
    chroma_host: str = "localhost"
    chroma_port: int = 8000
    chroma_collection_prefix: str = "vulnscan"

    # --- Knowledge base ingestion ---
    knowledge_data_dir: str = "data/knowledge"
    knowledge_retrieval_top_k: int = 5

    # --- Ollama ---
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    ollama_request_timeout_seconds: int = 120
    ollama_num_ctx: int = 8192
    llm_max_retries: int = 2

    # --- Scan analysis ---
    chunk_max_lines: int = 120
    scan_max_concurrent_jobs: int = 1

    # --- Uploads / scan limits ---
    upload_dir: str = "uploads"
    upload_max_size_mb: int = 10
    zip_max_uncompressed_mb: int = 100
    zip_max_files: int = 2000
    zip_max_compression_ratio: int = 100
    allowed_upload_extensions: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: [
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".php",
            ".cs",
            ".rb",
            ".zip",
        ]
    )

    # --- Rate limiting / abuse protection ---
    auth_rate_limit: str = "5/minute"
    scan_rate_limit: str = "20/minute"
    max_active_scans_per_user: int = 3

    @field_validator("cors_origins", "allowed_upload_extensions", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Allow comma-separated env values, e.g. CORS_ORIGINS=a,b,c."""
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _refuse_unsafe_production_settings(self) -> Self:
        """Fail at startup rather than run in production with a setting that
        defeats the security of the whole API."""
        if self.environment != "production":
            return self
        secret = self.jwt_secret_key
        if len(secret) < _MIN_PRODUCTION_SECRET_LENGTH or secret in _PLACEHOLDER_SECRETS:
            raise ValueError(
                "JWT_SECRET_KEY must be a random value of at least "
                f"{_MIN_PRODUCTION_SECRET_LENGTH} characters in production "
                '(generate one with: python -c "import secrets; print(secrets.token_urlsafe(64))").'
            )
        if self.debug:
            raise ValueError("DEBUG must be false in production.")
        if "*" in self.cors_origins:
            raise ValueError("CORS_ORIGINS must list explicit origins in production, not '*'.")
        return self

    @property
    def max_request_body_bytes(self) -> int:
        """The upload limit plus room for the multipart framing around it."""
        return (self.upload_max_size_mb + 1) * 1024 * 1024


_MIN_PRODUCTION_SECRET_LENGTH = 32
_PLACEHOLDER_SECRETS = frozenset({"change-this-to-a-random-64-byte-secret"})


@lru_cache
def get_settings() -> Settings:
    return Settings()
