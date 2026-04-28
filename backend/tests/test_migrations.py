"""Tests for Alembic-backed schema management."""

from __future__ import annotations

import tempfile
from pathlib import Path

from alembic import command
from alembic.config import Config
import sqlalchemy as sa
from sqlalchemy import inspect, text


BACKEND_DIR = Path(__file__).resolve().parents[1]


def _make_db_url() -> tuple[str, Path]:
    db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    db_file.close()
    return f"sqlite:///{db_file.name}", Path(db_file.name)


def _make_alembic_config(db_url: str) -> Config:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    config.set_main_option("sqlalchemy.url", db_url)
    return config


def _cleanup_db(db_path: Path) -> None:
    if db_path.exists():
        db_path.unlink()


def _create_current_core_schema(engine: sa.Engine) -> None:
    metadata = sa.MetaData()

    sa.Table(
        "users",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=50), unique=True, index=True, nullable=False),
        sa.Column("email", sa.String(length=255), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    sa.Table(
        "network_snapshots",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), index=True, nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False, server_default="json"),
        sa.Column("topology_data", sa.JSON(), nullable=False),
        sa.Column("risk_scores", sa.JSON(), nullable=True),
        sa.Column("overall_risk_score", sa.Float(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), index=True, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    sa.Table(
        "network_nodes",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("node_id", sa.String(length=255), index=True, nullable=False),
        sa.Column("label", sa.String(length=255), nullable=True),
        sa.Column("node_type", sa.String(length=50), nullable=False, server_default="host"),
        sa.Column("vuln", sa.Float(), nullable=False, server_default="0"),
        sa.Column("cvss_max", sa.Float(), nullable=True),
        sa.Column("criticality", sa.String(length=20), nullable=False, server_default="LOW"),
        sa.Column("exposure", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("exploit_in_wild", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    sa.Table(
        "network_edges",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("source_node_id", sa.Integer(), sa.ForeignKey("network_nodes.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("target_node_id", sa.Integer(), sa.ForeignKey("network_nodes.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("exploitability", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("patch_factor", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("lateral_movement_probability", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    sa.Table(
        "vulnerabilities",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("node_id", sa.Integer(), sa.ForeignKey("network_nodes.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("cve_id", sa.String(length=50), index=True, nullable=False),
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
        sa.Column("discovered_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    sa.Table(
        "attack_paths",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id"), index=True, nullable=False),
        sa.Column("path_data", sa.JSON(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=True),
        sa.Column("entry_node", sa.String(length=255), nullable=True),
        sa.Column("target_node", sa.String(length=255), nullable=True),
        sa.Column("nodes", sa.JSON(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("likelihood", sa.Float(), nullable=True),
        sa.Column("explanation", sa.String(length=2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    sa.Table(
        "remediation_plans",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True, nullable=False),
        sa.Column("attack_path_id", sa.Integer(), sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), index=True, nullable=True),
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
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    metadata.create_all(bind=engine)


def _create_partial_legacy_schema(engine: sa.Engine) -> None:
    metadata = sa.MetaData()

    sa.Table(
        "users",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(length=50), unique=True, index=True, nullable=False),
        sa.Column("email", sa.String(length=255), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="analyst"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
    )
    sa.Table(
        "network_snapshots",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), index=True, nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False, server_default="json"),
        sa.Column("topology_data", sa.JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), index=True, nullable=True),
    )
    sa.Table(
        "attack_paths",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("network_snapshots.id"), index=True, nullable=False),
        sa.Column("entry_node", sa.String(length=255), nullable=True),
        sa.Column("target_node", sa.String(length=255), nullable=True),
        sa.Column("nodes", sa.JSON(), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("likelihood", sa.Float(), nullable=True),
        sa.Column("explanation", sa.String(length=2000), nullable=True),
    )

    metadata.create_all(bind=engine)


def test_upgrade_empty_database_to_head():
    db_url, db_path = _make_db_url()
    config = _make_alembic_config(db_url)

    try:
        command.upgrade(config, "head")

        engine = sa.create_engine(db_url, future=True)
        tables = set(inspect(engine).get_table_names())
        assert {
            "users",
            "network_snapshots",
            "network_nodes",
            "network_edges",
            "vulnerabilities",
            "attack_paths",
            "remediation_plans",
            "refresh_tokens",
            "audit_logs",
            "jobs",
            "exports",
            "monitors",
            "monitor_runs",
            "alembic_version",
        }.issubset(tables)
        engine.dispose()
    finally:
        _cleanup_db(db_path)


def test_upgrade_preserves_existing_core_data():
    db_url, db_path = _make_db_url()
    engine = sa.create_engine(db_url, future=True)
    _create_current_core_schema(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (id, username, email, hashed_password, role, is_active) "
                "VALUES (1, 'alice', 'alice@example.com', 'hash', 'analyst', 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO network_snapshots "
                "(id, name, source_type, topology_data, risk_scores, overall_risk_score, created_by_user_id) "
                "VALUES (1, 'baseline', 'analysis_request', '{}', '{}', 5.0, 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO network_nodes "
                "(id, snapshot_id, node_id, label, node_type, vuln, criticality, exposure, exploit_in_wild) "
                "VALUES (1, 1, 'A', 'Node A', 'host', 5.0, 'HIGH', 3.0, 0)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO vulnerabilities "
                "(id, node_id, cve_id, name, cvss_score, severity, exploit_available, exploit_in_wild, patch_available) "
                "VALUES (1, 1, 'CVE-2026-0001', 'Example Vuln', 7.1, 'HIGH', 1, 0, 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO attack_paths "
                "(id, snapshot_id, path_data, risk_score, entry_node, target_node, nodes, score, likelihood, explanation) "
                "VALUES (1, 1, '{}', 8.1, 'A', 'B', '[\"A\", \"B\"]', 8.1, 0.7, 'test path')"
            )
        )
        connection.execute(
            text(
                "INSERT INTO remediation_plans "
                "(id, vulnerability_id, attack_path_id, priority, summary, recommendation, confidence, risk_reduction, status, provider) "
                "VALUES (1, 1, 1, 'HIGH', 'summary', 'recommendation', 0.8, 0.6, 'PROPOSED', 'fallback')"
            )
        )

    config = _make_alembic_config(db_url)

    try:
        command.upgrade(config, "head")

        inspector = inspect(engine)
        assert "refresh_tokens" in inspector.get_table_names()
        assert "jobs" in inspector.get_table_names()
        assert "monitors" in inspector.get_table_names()
        assert "monitor_runs" in inspector.get_table_names()
        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM users")).scalar_one() == 1
            assert connection.execute(text("SELECT COUNT(*) FROM network_snapshots")).scalar_one() == 1
            assert connection.execute(text("SELECT COUNT(*) FROM attack_paths")).scalar_one() == 1
            assert connection.execute(text("SELECT COUNT(*) FROM remediation_plans")).scalar_one() == 1
    finally:
        engine.dispose()
        _cleanup_db(db_path)


def test_upgrade_backfills_runtime_patched_columns():
    db_url, db_path = _make_db_url()
    engine = sa.create_engine(db_url, future=True)
    _create_partial_legacy_schema(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO users (id, username, email, hashed_password, role, is_active) "
                "VALUES (1, 'legacy', 'legacy@example.com', 'hash', 'analyst', 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO network_snapshots (id, name, source_type, topology_data, created_by_user_id) "
                "VALUES (1, 'legacy-snapshot', 'json', '{}', 1)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO attack_paths (id, snapshot_id, entry_node, target_node, nodes, score, likelihood, explanation) "
                "VALUES (1, 1, 'internet', 'db', '[\"internet\", \"db\"]', 7.0, 0.5, 'legacy path')"
            )
        )

    config = _make_alembic_config(db_url)

    try:
        command.upgrade(config, "head")

        snapshot_columns = {column["name"] for column in inspect(engine).get_columns("network_snapshots")}
        attack_path_columns = {column["name"] for column in inspect(engine).get_columns("attack_paths")}

        assert {"risk_scores", "overall_risk_score", "created_at"}.issubset(snapshot_columns)
        assert {"path_data", "risk_score", "created_at"}.issubset(attack_path_columns)
        assert "monitors" in inspect(engine).get_table_names()
        assert "monitor_runs" in inspect(engine).get_table_names()
        with engine.connect() as connection:
            assert connection.execute(text("SELECT COUNT(*) FROM network_snapshots")).scalar_one() == 1
            assert connection.execute(text("SELECT COUNT(*) FROM attack_paths")).scalar_one() == 1
    finally:
        engine.dispose()
        _cleanup_db(db_path)


def test_downgrade_and_reupgrade_smoke():
    db_url, db_path = _make_db_url()
    config = _make_alembic_config(db_url)

    try:
        command.upgrade(config, "head")
        command.downgrade(config, "base")
        command.upgrade(config, "head")

        engine = sa.create_engine(db_url, future=True)
        assert "alembic_version" in inspect(engine).get_table_names()
        engine.dispose()
    finally:
        _cleanup_db(db_path)
