"""create scans, scan_files, findings and finding_references tables

Revision ID: b3f8a1c4d7e2
Revises: 63e0d2199ef5
Create Date: 2026-10-05 19:00:00.000000

Hand-written to mirror `ScanModel`, `ScanFileModel`, `FindingModel` and
`FindingReferenceModel` in `app.infrastructure.persistence.models` exactly.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b3f8a1c4d7e2"
down_revision: str | None = "63e0d2199ef5"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("total_files", sa.Integer(), nullable=False),
        sa.Column("total_findings", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scans_user_id"), "scans", ["user_id"], unique=False)
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)

    op.create_table(
        "scan_files",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("relative_path", sa.String(length=1024), nullable=False),
        sa.Column("language", sa.String(length=32), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("loc", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_files_scan_id"), "scan_files", ["scan_id"], unique=False)

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("scan_file_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("cwe_id", sa.String(length=32), nullable=True),
        sa.Column("owasp_category", sa.String(length=32), nullable=True),
        sa.Column("attack_technique_id", sa.String(length=32), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("file_path", sa.String(length=1024), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("vulnerable_snippet", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("fixed_code", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_file_id"], ["scan_files.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_scan_id"), "findings", ["scan_id"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)

    op.create_table(
        "finding_references",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("ref_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=512), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_finding_references_finding_id"),
        "finding_references",
        ["finding_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_finding_references_finding_id"), table_name="finding_references")
    op.drop_table("finding_references")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index(op.f("ix_findings_scan_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_scan_files_scan_id"), table_name="scan_files")
    op.drop_table("scan_files")
    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_index(op.f("ix_scans_user_id"), table_name="scans")
    op.drop_table("scans")
