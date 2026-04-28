"""Add monitor and monitor run tables for continuous monitoring."""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260407_0002"
down_revision = "20260403_0001"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "monitors",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("config", _json_type(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_message", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_monitors_id", "monitors", ["id"], unique=False)
    op.create_index("ix_monitors_created_by_user_id", "monitors", ["created_by_user_id"], unique=False)
    op.create_index("ix_monitors_name", "monitors", ["name"], unique=False)
    op.create_index("ix_monitors_source_type", "monitors", ["source_type"], unique=False)
    op.create_index("ix_monitors_interval_seconds", "monitors", ["interval_seconds"], unique=False)
    op.create_index("ix_monitors_is_enabled", "monitors", ["is_enabled"], unique=False)
    op.create_index("ix_monitors_next_run_at", "monitors", ["next_run_at"], unique=False)
    op.create_index("ix_monitors_created_at", "monitors", ["created_at"], unique=False)

    op.create_table(
        "monitor_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("monitor_id", sa.Integer(), sa.ForeignKey("monitors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="queued"),
        sa.Column("trigger_type", sa.String(length=50), nullable=False, server_default="manual"),
        sa.Column("diff_summary", _json_type(), nullable=True),
        sa.Column("error_message", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_monitor_runs_id", "monitor_runs", ["id"], unique=False)
    op.create_index("ix_monitor_runs_monitor_id", "monitor_runs", ["monitor_id"], unique=False)
    op.create_index("ix_monitor_runs_job_id", "monitor_runs", ["job_id"], unique=False)
    op.create_index("ix_monitor_runs_snapshot_id", "monitor_runs", ["snapshot_id"], unique=False)
    op.create_index("ix_monitor_runs_status", "monitor_runs", ["status"], unique=False)
    op.create_index("ix_monitor_runs_trigger_type", "monitor_runs", ["trigger_type"], unique=False)
    op.create_index("ix_monitor_runs_created_at", "monitor_runs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_table("monitor_runs")
    op.drop_table("monitors")
