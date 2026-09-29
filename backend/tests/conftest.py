"""Shared pytest fixtures.

Sets the minimal environment required by `Settings` *before* the app module
is imported, so tests never depend on a developer's local `.env` file.
"""

from __future__ import annotations

import os

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-not-for-production-use-only")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://vulnscan:vulnscan@localhost:5432/vulnscan_test"
)

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())
