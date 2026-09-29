"""create knowledge_documents table

Revision ID: 63e0d2199ef5
Revises: e7996eddd79d
Create Date: 2026-09-29 20:10:00.000000

Hand-written to mirror `app.infrastructure.persistence.models.KnowledgeDocumentModel`
exactly - verified against the real models via `alembic upgrade head --sql`.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "63e0d2199ef5"
down_revision: str | None = "e7996eddd79d"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("external_id", sa.String(length=64), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("category", sa.String(length=255), nullable=True),
        sa.Column("url", sa.String(length=512), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_knowledge_documents_external_id"),
        "knowledge_documents",
        ["external_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_knowledge_documents_source"), "knowledge_documents", ["source"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_knowledge_documents_source"), table_name="knowledge_documents")
    op.drop_index(op.f("ix_knowledge_documents_external_id"), table_name="knowledge_documents")
    op.drop_table("knowledge_documents")
