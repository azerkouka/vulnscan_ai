"""SQLAlchemy 2.0 declarative models.

These are infrastructure-only representations - they never leak into the
domain or application layers. Repositories map between these and the
domain's plain dataclasses (`app.domain.entities`).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    refresh_tokens: Mapped[list[RefreshTokenModel]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="RefreshTokenModel.user_id",
    )


class RefreshTokenModel(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    replaced_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"), default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped[UserModel] = relationship(back_populates="refresh_tokens", foreign_keys=[user_id])


class KnowledgeDocumentModel(Base):
    """Postgres mirror of one ChromaDB knowledge-base entry - see
    `app.domain.ports.knowledge_document_repository` for why this exists
    alongside the vector store."""

    __tablename__ = "knowledge_documents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    external_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str | None] = mapped_column(String(255))
    url: Mapped[str | None] = mapped_column(String(512))
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class ScanModel(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    progress_percent: Mapped[int] = mapped_column(default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    total_files: Mapped[int] = mapped_column(default=0, nullable=False)
    total_findings: Mapped[int] = mapped_column(default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ScanFileModel(Base):
    """Metadata only - the source text itself lives in the `SourceStorage`
    backend, keyed by (scan_id, id)."""

    __tablename__ = "scan_files"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    relative_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    language: Mapped[str | None] = mapped_column(String(32))
    size_bytes: Mapped[int] = mapped_column(nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    loc: Mapped[int] = mapped_column(nullable=False)


class FindingModel(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_file_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_files.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    owasp_category: Mapped[str | None] = mapped_column(String(32))
    attack_technique_id: Mapped[str | None] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line_start: Mapped[int] = mapped_column(nullable=False)
    line_end: Mapped[int] = mapped_column(nullable=False)
    vulnerable_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    fixed_code: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    references: Mapped[list[FindingReferenceModel]] = relationship(
        cascade="all, delete-orphan",
        order_by="FindingReferenceModel.position",
        lazy="selectin",
    )


class FindingReferenceModel(Base):
    __tablename__ = "finding_references"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True, nullable=False
    )
    position: Mapped[int] = mapped_column(nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    ref_id: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str | None] = mapped_column(String(512))
