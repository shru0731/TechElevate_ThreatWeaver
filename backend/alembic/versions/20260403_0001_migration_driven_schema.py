"""Create and upgrade the migration-driven schema foundation."""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.engine import Connection
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "20260403_0001"
down_revision = None
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _inspector(connection: Connection):
    return inspect(connection)


def _has_table(connection: Connection, table_name: str) -> bool:
    return table_name in _inspector(connection).get_table_names()


def _has_column(connection: Connection, table_name: str, column_name: str) -> bool:
    if not _has_table(connection, table_name):
        return False
    return column_name in {column["name"] for column in _inspector(connection).get_columns(table_name)}


def _has_index(connection: Connection, table_name: str, index_name: str) -> bool:
    if not _has_table(connection, table_name):
        return False
    return index_name in {index["name"] for index in _inspector(connection).get_indexes(table_name)}


def _add_column_if_missing(table_name: str, column: sa.Column) -> None:
    connection = op.get_bind()
    if _has_column(connection, table_name, column.name):
        return
    with op.batch_alter_table(table_name) as batch_op:
        batch_op.add_column(column)


def _create_index_if_missing(
    table_name: str,
    index_name: str,
    columns: Sequence[str],
    *,
    unique: bool = False,
) -> None:
    connection = op.get_bind()
    if _has_index(connection, table_name, index_name):
        return
    op.create_index(index_name, table_name, list(columns), unique=unique)


def _create_users_table() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)


def _create_network_snapshots_table() -> None:
    op.create_table(
        "network_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False, server_default="json"),
        sa.Column("topology_data", _json_type(), nullable=False),
        sa.Column("risk_scores", _json_type(), nullable=True),
        sa.Column("overall_risk_score", sa.Float(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_network_snapshots_id", "network_snapshots", ["id"], unique=False)
    op.create_index("ix_network_snapshots_name", "network_snapshots", ["name"], unique=False)
    op.create_index("ix_network_snapshots_created_by_user_id", "network_snapshots", ["created_by_user_id"], unique=False)


def _create_network_nodes_table() -> None:
    op.create_table(
        "network_nodes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_id", sa.String(length=255), nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("node_type", sa.String(length=50), nullable=False, server_default="host"),
        sa.Column("vuln", sa.Float(), nullable=False, server_default="0"),
        sa.Column("cvss_max", sa.Float(), nullable=True),
        sa.Column("criticality", sa.String(length=20), nullable=False, server_default="LOW"),
        sa.Column("exposure", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("exploit_in_wild", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("snapshot_id", "node_id", name="uq_network_nodes_snapshot_node_id"),
    )
    op.create_index("ix_network_nodes_id", "network_nodes", ["id"], unique=False)
    op.create_index("ix_network_nodes_snapshot_id", "network_nodes", ["snapshot_id"], unique=False)
    op.create_index("ix_network_nodes_node_id", "network_nodes", ["node_id"], unique=False)


def _create_network_edges_table() -> None:
    op.create_table(
        "network_edges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_node_id", sa.Integer(), sa.ForeignKey("network_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_node_id", sa.Integer(), sa.ForeignKey("network_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("exploitability", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("patch_factor", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("lateral_movement_probability", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_network_edges_id", "network_edges", ["id"], unique=False)
    op.create_index("ix_network_edges_snapshot_id", "network_edges", ["snapshot_id"], unique=False)
    op.create_index("ix_network_edges_source_node_id", "network_edges", ["source_node_id"], unique=False)
    op.create_index("ix_network_edges_target_node_id", "network_edges", ["target_node_id"], unique=False)


def _create_vulnerabilities_table() -> None:
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("network_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cve_id", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="UNKNOWN"),
        sa.Column("exploit_available", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("exploit_in_wild", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("attack_vector", sa.String(length=50), nullable=True),
        sa.Column("attack_complexity", sa.String(length=50), nullable=True),
        sa.Column("patch_available", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("patch_url", sa.String(length=500), nullable=True),
        sa.Column("workaround", sa.String(length=1000), nullable=True),
        sa.Column("published_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_vulnerabilities_id", "vulnerabilities", ["id"], unique=False)
    op.create_index("ix_vulnerabilities_node_id", "vulnerabilities", ["node_id"], unique=False)
    op.create_index("ix_vulnerabilities_cve_id", "vulnerabilities", ["cve_id"], unique=False)


def _create_attack_paths_table() -> None:
    op.create_table(
        "attack_paths",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id"), nullable=False),
        sa.Column("path_data", _json_type(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("entry_node", sa.String(length=255), nullable=True),
        sa.Column("target_node", sa.String(length=255), nullable=True),
        sa.Column("nodes", sa.JSON(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("likelihood", sa.Float(), nullable=True),
        sa.Column("explanation", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_attack_paths_id", "attack_paths", ["id"], unique=False)
    op.create_index("ix_attack_paths_snapshot_id", "attack_paths", ["snapshot_id"], unique=False)


def _create_remediation_plans_table() -> None:
    op.create_table(
        "remediation_plans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("attack_path_id", sa.Integer(), sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=True),
        sa.Column("priority", sa.String(length=20), nullable=False, server_default="MEDIUM"),
        sa.Column("summary", sa.String(length=500), nullable=False),
        sa.Column("recommendation", sa.String(length=2000), nullable=False),
        sa.Column("action_items", sa.JSON(), nullable=True),
        sa.Column("estimated_effort_hours", sa.Float(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("risk_reduction", sa.Float(), nullable=False, server_default="0.7"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="PROPOSED"),
        sa.Column("responsible_team", sa.String(length=255), nullable=True),
        sa.Column("target_completion_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider", sa.String(length=100), nullable=False, server_default="ai_engine"),
        sa.Column("llm_model", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_remediation_plans_id", "remediation_plans", ["id"], unique=False)
    op.create_index("ix_remediation_plans_vulnerability_id", "remediation_plans", ["vulnerability_id"], unique=False)
    op.create_index("ix_remediation_plans_attack_path_id", "remediation_plans", ["attack_path_id"], unique=False)


def _create_refresh_tokens_table() -> None:
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_id", sa.String(length=128), nullable=False),
        sa.Column("token_family", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("replaced_by_token_id", sa.String(length=128), nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_refresh_tokens_id", "refresh_tokens", ["id"], unique=False)
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"], unique=False)
    op.create_index("ix_refresh_tokens_token_id", "refresh_tokens", ["token_id"], unique=True)
    op.create_index("ix_refresh_tokens_token_family", "refresh_tokens", ["token_family"], unique=False)
    op.create_index("ix_refresh_tokens_is_revoked", "refresh_tokens", ["is_revoked"], unique=False)


def _create_audit_logs_table() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action_type", sa.String(length=100), nullable=False),
        sa.Column("entity_type", sa.String(length=100), nullable=False),
        sa.Column("entity_id", sa.String(length=255), nullable=True),
        sa.Column("request_id", sa.String(length=100), nullable=True),
        sa.Column("details", _json_type(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"], unique=False)
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"], unique=False)
    op.create_index("ix_audit_logs_action_type", "audit_logs", ["action_type"], unique=False)
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"], unique=False)
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"], unique=False)


def _create_jobs_table() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("job_type", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="queued"),
        sa.Column("payload", _json_type(), nullable=True),
        sa.Column("result", _json_type(), nullable=True),
        sa.Column("error_message", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_jobs_id", "jobs", ["id"], unique=False)
    op.create_index("ix_jobs_created_by_user_id", "jobs", ["created_by_user_id"], unique=False)
    op.create_index("ix_jobs_job_type", "jobs", ["job_type"], unique=False)
    op.create_index("ix_jobs_status", "jobs", ["status"], unique=False)
    op.create_index("ix_jobs_created_at", "jobs", ["created_at"], unique=False)


def _create_exports_table() -> None:
    op.create_table(
        "exports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("export_format", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="queued"),
        sa.Column("request_payload", _json_type(), nullable=True),
        sa.Column("storage_path", sa.String(length=500), nullable=True),
        sa.Column("download_token", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_exports_id", "exports", ["id"], unique=False)
    op.create_index("ix_exports_snapshot_id", "exports", ["snapshot_id"], unique=False)
    op.create_index("ix_exports_created_by_user_id", "exports", ["created_by_user_id"], unique=False)
    op.create_index("ix_exports_status", "exports", ["status"], unique=False)
    op.create_index("ix_exports_created_at", "exports", ["created_at"], unique=False)
    op.create_index("ix_exports_download_token", "exports", ["download_token"], unique=True)


def _upgrade_existing_core_tables() -> None:
    _add_column_if_missing(
        "users",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
    )

    _add_column_if_missing(
        "network_snapshots",
        sa.Column("risk_scores", _json_type(), nullable=True),
    )
    _add_column_if_missing(
        "network_snapshots",
        sa.Column("overall_risk_score", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "network_snapshots",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
    )
    _create_index_if_missing("network_snapshots", "ix_network_snapshots_created_by_user_id", ["created_by_user_id"])

    _add_column_if_missing(
        "attack_paths",
        sa.Column("path_data", _json_type(), nullable=True),
    )
    _add_column_if_missing(
        "attack_paths",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )
    _add_column_if_missing(
        "attack_paths",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, server_default=sa.func.now()),
    )

    _create_index_if_missing("network_nodes", "ix_network_nodes_snapshot_id", ["snapshot_id"])
    _create_index_if_missing("network_nodes", "ix_network_nodes_node_id", ["node_id"])
    _create_index_if_missing("network_edges", "ix_network_edges_snapshot_id", ["snapshot_id"])
    _create_index_if_missing("network_edges", "ix_network_edges_source_node_id", ["source_node_id"])
    _create_index_if_missing("network_edges", "ix_network_edges_target_node_id", ["target_node_id"])
    _create_index_if_missing("vulnerabilities", "ix_vulnerabilities_node_id", ["node_id"])
    _create_index_if_missing("vulnerabilities", "ix_vulnerabilities_cve_id", ["cve_id"])
    _create_index_if_missing("remediation_plans", "ix_remediation_plans_vulnerability_id", ["vulnerability_id"])
    _create_index_if_missing("remediation_plans", "ix_remediation_plans_attack_path_id", ["attack_path_id"])


def upgrade() -> None:
    connection = op.get_bind()

    if not _has_table(connection, "users"):
        _create_users_table()
    if not _has_table(connection, "network_snapshots"):
        _create_network_snapshots_table()
    if not _has_table(connection, "network_nodes"):
        _create_network_nodes_table()
    if not _has_table(connection, "network_edges"):
        _create_network_edges_table()
    if not _has_table(connection, "vulnerabilities"):
        _create_vulnerabilities_table()
    if not _has_table(connection, "attack_paths"):
        _create_attack_paths_table()
    if not _has_table(connection, "remediation_plans"):
        _create_remediation_plans_table()

    _upgrade_existing_core_tables()

    if not _has_table(connection, "refresh_tokens"):
        _create_refresh_tokens_table()
    if not _has_table(connection, "audit_logs"):
        _create_audit_logs_table()
    if not _has_table(connection, "jobs"):
        _create_jobs_table()
    if not _has_table(connection, "exports"):
        _create_exports_table()


def downgrade() -> None:
    for table_name in [
        "exports",
        "jobs",
        "audit_logs",
        "refresh_tokens",
        "remediation_plans",
        "attack_paths",
        "vulnerabilities",
        "network_edges",
        "network_nodes",
        "network_snapshots",
        "users",
    ]:
        op.drop_table(table_name)
