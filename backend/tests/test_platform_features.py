import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import uuid

import pytest  # type: ignore[import-not-found]
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

test_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
test_db_file.close()
os.environ["DATABASE_URL"] = f"sqlite:///{test_db_file.name}"

from main import app
from app.api.dependencies import get_db, get_job_service, get_monitor_service
from app.core.config import get_settings
from app.database import Base, register_models
from app.models import ExportRecord, Monitor, User
from app.services.job_service import JobService
from app.services.monitor_service import MonitorService

engine = create_engine(
    f"sqlite:///{test_db_file.name}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_platform_db():
    register_models()
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    try:
        os.unlink(test_db_file.name)
    except OSError:
        pass


@pytest.fixture(autouse=True)
def clean_tables():
    with SessionLocal() as session:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
    yield


@pytest.fixture
def client():
    settings = get_settings()
    original_mode = settings.task_queue_mode
    temp_dir = Path.cwd() / "backend" / f"generated_exports_test_{uuid.uuid4().hex}"
    temp_dir.mkdir(parents=True, exist_ok=True)
    settings.export_storage_dir = temp_dir
    settings.task_queue_mode = "background"

    def override_db():
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    def override_job_service():
        return JobService(session_factory=SessionLocal)

    def override_monitor_service():
        return MonitorService(session_factory=SessionLocal)

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_job_service] = override_job_service
    app.dependency_overrides[get_monitor_service] = override_monitor_service
    with TestClient(app) as test_client:
        yield test_client
    settings.task_queue_mode = original_mode
    shutil.rmtree(temp_dir, ignore_errors=True)
    app.dependency_overrides.clear()


def register_and_login(client: TestClient, username: str, email: str, password: str) -> dict:
    register_response = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert register_response.status_code == 201, register_response.text
    login_response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_response.status_code == 200, login_response.text
    return login_response.json()


def test_ready_endpoint_exposes_operational_checks(client: TestClient):
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["request_id"]
    assert "database" in payload["checks"]
    assert "llm" in payload["checks"]
    assert "queue" in payload["checks"]


def test_validation_errors_use_standard_error_contract(client: TestClient):
    response = client.post("/api/v1/auth/register", json={"username": "broken"})
    assert response.status_code == 422
    payload = response.json()
    assert payload["error_code"] == "validation_error"
    assert payload["message"] == "Validation failed"
    assert payload["request_id"]
    assert "details" in payload


def test_live_analysis_job_runs_to_completion(client: TestClient):
    token_pair = register_and_login(client, "platform", "platform@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    response = client.post(
        "/api/v1/analysis/analyze-live",
        json={
            "source_type": "topology",
            "snapshot_name": "live-analysis",
            "entry_node": "A",
            "target_node": "B",
            "topology": {
                "nodes": [
                    {"id": "A", "type": "host", "vuln": 5.5, "criticality": "HIGH", "cves": ["CVE-2024-0001"]},
                    {"id": "B", "type": "host", "vuln": 7.5, "criticality": "CRITICAL", "cves": ["CVE-2024-0002"]},
                ],
                "edges": [
                    {"source": "A", "target": "B", "exploitability": 0.8, "patch_factor": 0.5, "lateral_movement_probability": 0.7}
                ],
            },
            "enrichment_sources": ["nvd", "cisa_kev"],
        },
        headers=headers,
    )
    assert response.status_code == 202, response.text
    job_id = response.json()["job_id"]
    assert response.json()["dispatch_mode"] == "background"

    job_response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
    assert job_response.status_code == 200
    job_payload = job_response.json()
    assert job_payload["status"] == "succeeded"
    assert job_payload["result"]["snapshot_id"] > 0
    assert job_payload["result"]["warnings"]


def test_live_analysis_job_uses_real_nvd_enrichment_when_available(client: TestClient, monkeypatch):
    token_pair = register_and_login(client, "nvduser", "nvd@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}

    import app.services.ingestion.nvd_client as nvd_client_module

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-0001",
                            "published": "2024-01-02T03:04:05.000",
                            "descriptions": [{"lang": "en", "value": "Critical test CVE"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {
                                            "baseScore": 9.1,
                                            "baseSeverity": "CRITICAL",
                                            "attackVector": "NETWORK",
                                            "attackComplexity": "LOW",
                                        }
                                    }
                                ]
                            },
                        }
                    }
                ]
            }

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url, headers=None, params=None):
            return FakeResponse()

    settings = get_settings()
    settings.nvd_enabled = True
    settings.nvd_api_key = "test-key"
    monkeypatch.setattr(nvd_client_module.httpx, "Client", FakeClient)

    response = client.post(
        "/api/v1/analysis/analyze-live",
        json={
            "source_type": "topology",
            "snapshot_name": "nvd-analysis",
            "entry_node": "A",
            "target_node": "B",
            "topology": {
                "nodes": [
                    {"id": "A", "type": "host", "vuln": 4.0, "criticality": "HIGH", "cves": ["CVE-2024-0001"]},
                    {"id": "B", "type": "host", "vuln": 7.5, "criticality": "CRITICAL", "cves": []},
                ],
                "edges": [
                    {"source": "A", "target": "B", "exploitability": 0.8, "patch_factor": 0.5, "lateral_movement_probability": 0.7}
                ],
            },
            "enrichment_sources": ["nvd"],
        },
        headers=headers,
    )

    assert response.status_code == 202, response.text
    job_id = response.json()["job_id"]

    job_response = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
    assert job_response.status_code == 200
    job_payload = job_response.json()
    assert job_payload["status"] == "succeeded"
    assert job_payload["result"]["warnings"] == []

    snapshot_id = job_payload["result"]["snapshot_id"]
    snapshot_response = client.get(f"/api/v1/analysis/snapshots/{snapshot_id}", headers=headers)
    assert snapshot_response.status_code == 200


def test_export_generation_and_download(client: TestClient):
    token_pair = register_and_login(client, "exporter", "exporter@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    analyze_response = client.post("/api/v1/analysis/analyze", json={"entry_node": "A"}, headers=headers)
    assert analyze_response.status_code == 201, analyze_response.text
    snapshot_id = analyze_response.json()["snapshot_id"]

    export_response = client.post(
        "/api/v1/exports",
        json={"snapshot_id": snapshot_id, "export_format": "json"},
        headers=headers,
    )
    assert export_response.status_code == 202, export_response.text
    export_payload = export_response.json()
    assert export_payload["status"] == "queued"
    assert export_payload["job_id"] is not None

    status_response = client.get(f"/api/v1/exports/{export_payload['id']}", headers=headers)
    assert status_response.status_code == 200
    status_payload = status_response.json()
    assert status_payload["status"] == "succeeded"
    assert status_payload["metadata"]["size_bytes"] > 0

    download_response = client.get(
        f"/api/v1/exports/{export_payload['id']}/download",
        params={"token": status_payload["download_token"]},
        headers=headers,
    )
    assert download_response.status_code == 200
    assert '"snapshot"' in download_response.text


def test_remediation_job_returns_result(client: TestClient):
    token_pair = register_and_login(client, "remediator", "remediator@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    analyze_response = client.post("/api/v1/analysis/analyze", json={"entry_node": "A"}, headers=headers)
    assert analyze_response.status_code == 201, analyze_response.text
    snapshot_id = analyze_response.json()["snapshot_id"]

    response = client.post("/api/v1/jobs/remediation", json={"snapshot_id": snapshot_id}, headers=headers)
    assert response.status_code == 202
    accepted = response.json()
    assert accepted["status"] == "queued"
    assert accepted["dispatch_mode"] == "background"

    status_response = client.get(f"/api/v1/jobs/{accepted['job_id']}", headers=headers)
    assert status_response.status_code == 200
    payload = status_response.json()
    assert payload["status"] == "succeeded"
    assert payload["result"]["snapshot_id"] == snapshot_id
    assert payload["result"]["remediation"]["recommended_actions"]


def test_celery_dispatch_path_marks_job_as_queued(client: TestClient, monkeypatch):
    token_pair = register_and_login(client, "celeryuser", "celery@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    settings = get_settings()
    original_mode = settings.task_queue_mode

    class FakeTask:
        called_with: list[int] = []

        @classmethod
        def delay(cls, job_id: int) -> None:
            cls.called_with.append(job_id)

    import app.services.job_service as job_service_module

    settings.task_queue_mode = "celery"
    monkeypatch.setattr(job_service_module, "celery_app", object())
    monkeypatch.setattr(job_service_module.JobService, "_get_celery_task", lambda self: FakeTask)

    response = client.post(
        "/api/v1/analysis/analyze-live",
        json={
            "source_type": "topology",
            "snapshot_name": "celery-analysis",
            "entry_node": "A",
            "topology": {
                "nodes": [{"id": "A", "type": "host", "vuln": 4.0, "criticality": "MEDIUM"}],
                "edges": [],
            },
        },
        headers=headers,
    )

    settings.task_queue_mode = original_mode
    assert response.status_code == 202, response.text
    payload = response.json()
    assert payload["dispatch_mode"] == "celery"
    assert FakeTask.called_with == [payload["job_id"]]

    job_response = client.get(f"/api/v1/jobs/{payload['job_id']}", headers=headers)
    assert job_response.status_code == 200
    assert job_response.json()["status"] == "queued"
    assert job_response.json()["queue_mode"] == "celery"


def test_export_failure_marks_export_and_job_failed(client: TestClient, monkeypatch):
    token_pair = register_and_login(client, "brokenexport", "brokenexport@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    analyze_response = client.post("/api/v1/analysis/analyze", json={"entry_node": "A"}, headers=headers)
    snapshot_id = analyze_response.json()["snapshot_id"]

    import app.services.export_service as export_service_module

    def failing_generate_export(self, db, export_id: int):
        self.mark_export_failed(db, export_id, "artifact generation failed")
        raise RuntimeError("artifact generation failed")

    monkeypatch.setattr(export_service_module.ExportService, "generate_export", failing_generate_export)

    export_response = client.post(
        "/api/v1/exports",
        json={"snapshot_id": snapshot_id, "export_format": "json"},
        headers=headers,
    )
    assert export_response.status_code == 202, export_response.text
    export_id = export_response.json()["id"]
    job_id = export_response.json()["job_id"]

    export_status = client.get(f"/api/v1/exports/{export_id}", headers=headers)
    assert export_status.status_code == 200
    assert export_status.json()["status"] == "failed"
    assert export_status.json()["error_message"] == "artifact generation failed"

    job_status = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
    assert job_status.status_code == 200
    assert job_status.json()["status"] == "failed"
    assert job_status.json()["error_message"] == "artifact generation failed"

    with SessionLocal() as session:
        export_record = session.get(ExportRecord, export_id)
        assert export_record is not None
        assert export_record.status == "failed"


def test_ready_endpoint_reports_degraded_queue_state(client, monkeypatch):
    settings = get_settings()
    original_mode = settings.task_queue_mode
    settings.task_queue_mode = "celery"

    import app.services.job_service as job_service_module

    monkeypatch.setattr(job_service_module, "celery_app", None)
    monkeypatch.setattr(job_service_module.JobService, "_get_celery_task", lambda self: None)

    response = client.get("/api/v1/ready")
    settings.task_queue_mode = original_mode

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "degraded"
    assert payload["checks"]["queue"]["status"] == "degraded"


def test_monitor_lifecycle_and_latest_result(client: TestClient):
    token_pair = register_and_login(client, "monitoruser", "monitor@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}

    create_response = client.post(
        "/api/v1/monitors",
        json={
            "name": "office-monitor",
            "description": "tracks a small topology",
            "interval_seconds": 60,
            "config": {
                "source_type": "topology",
                "entry_node": "internet",
                "target_node": "db",
                "topology": {
                    "nodes": [
                        {"id": "internet", "type": "external", "vuln": 1.0, "criticality": "LOW"},
                        {"id": "db", "type": "host", "vuln": 6.0, "criticality": "HIGH", "cves": ["CVE-2026-1000"]},
                    ],
                    "edges": [{"source": "internet", "target": "db", "exploitability": 0.8, "lateral_movement_probability": 0.7}],
                },
            },
        },
        headers=headers,
    )
    assert create_response.status_code == 201, create_response.text
    monitor_id = create_response.json()["id"]

    run_response = client.post(f"/api/v1/monitors/{monitor_id}/run", headers=headers)
    assert run_response.status_code == 202, run_response.text
    assert run_response.json()["status"] in {"queued", "succeeded"}

    latest_response = client.get(f"/api/v1/monitors/{monitor_id}/latest", headers=headers)
    assert latest_response.status_code == 200, latest_response.text
    latest_payload = latest_response.json()
    assert latest_payload["latest_run"]["snapshot_id"] is not None
    assert latest_payload["latest_run"]["diff_summary"]["previous_snapshot_id"] is None

    pause_response = client.post(f"/api/v1/monitors/{monitor_id}/pause", headers=headers)
    assert pause_response.status_code == 200
    assert pause_response.json()["is_enabled"] is False

    resume_response = client.post(f"/api/v1/monitors/{monitor_id}/resume", headers=headers)
    assert resume_response.status_code == 200
    assert resume_response.json()["is_enabled"] is True


def test_monitor_second_run_produces_diff(client: TestClient):
    token_pair = register_and_login(client, "diffuser", "diff@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}

    create_response = client.post(
        "/api/v1/monitors",
        json={
            "name": "diff-monitor",
            "interval_seconds": 60,
            "config": {
                "source_type": "topology",
                "entry_node": "internet",
                "topology": {
                    "nodes": [
                        {"id": "internet", "type": "external", "vuln": 1.0, "criticality": "LOW"},
                        {"id": "app", "type": "host", "vuln": 4.0, "criticality": "MEDIUM", "cves": []},
                    ],
                    "edges": [{"source": "internet", "target": "app", "exploitability": 0.4, "lateral_movement_probability": 0.5}],
                },
            },
        },
        headers=headers,
    )
    monitor_id = create_response.json()["id"]

    first_run = client.post(f"/api/v1/monitors/{monitor_id}/run", headers=headers)
    assert first_run.status_code == 202

    patch_response = client.patch(
        f"/api/v1/monitors/{monitor_id}",
        json={
            "config": {
                "source_type": "topology",
                "entry_node": "internet",
                "topology": {
                    "nodes": [
                        {"id": "internet", "type": "external", "vuln": 1.0, "criticality": "LOW"},
                        {"id": "app", "type": "host", "vuln": 7.5, "criticality": "HIGH", "cves": ["CVE-2026-2000"]},
                        {"id": "db", "type": "host", "vuln": 8.0, "criticality": "CRITICAL", "cves": []},
                    ],
                    "edges": [
                        {"source": "internet", "target": "app", "exploitability": 0.4, "lateral_movement_probability": 0.5},
                        {"source": "app", "target": "db", "exploitability": 0.8, "lateral_movement_probability": 0.7},
                    ],
                },
            }
        },
        headers=headers,
    )
    assert patch_response.status_code == 200, patch_response.text

    second_run = client.post(f"/api/v1/monitors/{monitor_id}/run", headers=headers)
    assert second_run.status_code == 202

    latest_response = client.get(f"/api/v1/monitors/{monitor_id}/latest", headers=headers)
    assert latest_response.status_code == 200
    diff_summary = latest_response.json()["latest_run"]["diff_summary"]
    assert diff_summary["material_changes"] is True
    assert "db" in diff_summary["new_nodes"]
    assert diff_summary["changed_nodes"]
    assert diff_summary["new_cves"]


def test_monitor_websocket_receives_run_events(client: TestClient):
    token_pair = register_and_login(client, "wsuser", "ws@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    create_response = client.post(
        "/api/v1/monitors",
        json={
            "name": "ws-monitor",
            "interval_seconds": 60,
            "config": {
                "source_type": "topology",
                "entry_node": "internet",
                "topology": {
                    "nodes": [
                        {"id": "internet", "type": "external", "vuln": 1.0, "criticality": "LOW"},
                        {"id": "host1", "type": "host", "vuln": 5.0, "criticality": "MEDIUM"},
                    ],
                    "edges": [{"source": "internet", "target": "host1", "exploitability": 0.5, "lateral_movement_probability": 0.5}],
                },
            },
        },
        headers=headers,
    )
    monitor_id = create_response.json()["id"]

    event_types: list[str] = []
    with client.websocket_connect(f"/api/v1/monitors/ws?token={token_pair['access_token']}&monitor_id={monitor_id}") as websocket:
        run_response = client.post(f"/api/v1/monitors/{monitor_id}/run", headers=headers)
        assert run_response.status_code == 202
        for _ in range(3):
            event = websocket.receive_json()
            event_types.append(event["type"])
            if event["type"] == "monitor.run.succeeded":
                break

    assert "monitor.run.queued" in event_types
    assert "monitor.run.succeeded" in event_types


def test_monitor_scheduler_polls_due_monitors_once(monkeypatch):
    settings = get_settings()
    original_scheduler_enabled = settings.monitor_scheduler_enabled
    original_min_interval = settings.monitor_min_interval_seconds
    settings.monitor_scheduler_enabled = True
    settings.monitor_min_interval_seconds = 1

    try:
        with SessionLocal() as session:
            user = User(
                username="scheduser",
                email="sched@example.com",
                hashed_password="hash",
                role="analyst",
                is_active=True,
            )
            session.add(user)
            session.flush()
            created = Monitor(
                created_by_user_id=user.id,
                name="scheduled-monitor",
                source_type="topology",
                config={
                    "source_type": "topology",
                    "entry_node": "internet",
                    "topology": {
                        "nodes": [
                            {"id": "internet", "type": "external", "vuln": 1.0, "criticality": "LOW"},
                            {"id": "node1", "type": "host", "vuln": 2.0, "criticality": "LOW"},
                        ],
                        "edges": [
                            {"source": "internet", "target": "node1", "exploitability": 0.3, "lateral_movement_probability": 0.4}
                        ],
                    },
                },
                interval_seconds=5,
                is_enabled=True,
                next_run_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
            session.add(created)
            session.commit()
            session.refresh(created)

        service = MonitorService(session_factory=SessionLocal)
        job_service = JobService(session_factory=SessionLocal)
        queued_first = service.poll_due_monitors(job_service)
        queued_second = service.poll_due_monitors(job_service)

        assert len(queued_first) == 1
        assert queued_second == []
    finally:
        settings.monitor_scheduler_enabled = original_scheduler_enabled
        settings.monitor_min_interval_seconds = original_min_interval
