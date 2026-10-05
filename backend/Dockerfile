# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Base: shared env vars for every stage
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ---------------------------------------------------------------------------
# Builder: compile the venv (native libs needed by weasyprint at build time
# for its C-extension deps; asyncpg/tree-sitter ship manylinux wheels)
# ---------------------------------------------------------------------------
FROM base AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
        libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY app ./app

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && pip install ".[rag,chunking,export]"

# ---------------------------------------------------------------------------
# Runtime: slim image, non-root user, only the runtime shared libs
# ---------------------------------------------------------------------------
FROM base AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
        libgdk-pixbuf-2.0-0 shared-mime-info fonts-liberation curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 appuser

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY --chown=appuser:appuser . .
# Submitted source is stored here (UPLOAD_DIR). Created and owned up front
# so the named volume docker-compose mounts on it is writable by appuser -
# a volume mounted on a path missing from the image would belong to root.
RUN mkdir -p /app/uploads && chown appuser:appuser /app/uploads

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
