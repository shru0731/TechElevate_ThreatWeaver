import os
import tempfile
from datetime import timedelta

import pytest  # type: ignore[import-not-found]
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

# Create a temporary SQLite database for tests
test_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
test_db_file.close()
test_db_url = f"sqlite:///{test_db_file.name}"

# Override database URL for tests
os.environ["DATABASE_URL"] = test_db_url

from main import app
from app.api.dependencies import get_db
from app.database import Base, register_models
from app.models import AuditLog, RefreshToken, User
from app.security import create_access_token, hash_password

engine = create_engine(
    test_db_url,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create tables once for the test session."""
    register_models()
    Base.metadata.create_all(bind=engine)
    yield
    try:
        Base.metadata.drop_all(bind=engine)
        os.unlink(test_db_file.name)
    except (OSError, PermissionError):
        pass


@pytest.fixture(scope="function")
def db():
    connection = engine.connect()
    transaction = connection.begin()
    session = SessionLocal(bind=connection)
    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(session: Session, trans) -> None:
        nonlocal nested
        if transaction.is_active and not nested.is_active:
            nested = connection.begin_nested()

    try:
        yield session
    finally:
        event.remove(session, "after_transaction_end", restart_savepoint)
        session.close()
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def client(db):
    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def register_and_login(client: TestClient, username: str, email: str, password: str) -> dict:
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert reg_resp.status_code == 201, f"Register failed: {reg_resp.text}"

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    return login_resp.json()


def create_user_with_role(db: Session, username: str, email: str, password: str, role: str) -> User:
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def test_register_and_login_success(client: TestClient):
    token_pair = register_and_login(client, "alice", "alice@example.com", "Secret123")
    assert token_pair["access_token"]
    assert token_pair["refresh_token"]
    assert token_pair["token_type"] == "bearer"


def test_protected_predict_success(client: TestClient):
    token_pair = register_and_login(client, "bob", "bob@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    resp = client.post(
        "/api/v1/analysis/predict",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert resp.status_code == 200, f"Predict failed: {resp.text}"
    data = resp.json()
    assert "risk_scores" in data
    assert "attack_paths" in data
    assert "remediation" in data


def test_invalid_token_returns_401(client: TestClient):
    headers = {"Authorization": "Bearer invalidtoken"}
    resp = client.post(
        "/api/v1/analysis/predict",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert resp.status_code == 401


def test_expired_token_returns_401(client: TestClient):
    email = "charlie@example.com"
    register_and_login(client, "charlie", email, "Secret123")
    expired_token = create_access_token(data={"sub": email}, expires_delta=timedelta(seconds=-1))
    headers = {"Authorization": f"Bearer {expired_token}"}
    resp = client.post(
        "/api/v1/analysis/predict",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert resp.status_code == 401


def test_analyst_can_access_analysis(client: TestClient):
    token_pair = register_and_login(client, "analyst_user", "analyst@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}
    resp = client.post(
        "/api/v1/analysis/predict",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert resp.status_code == 200


def test_non_analyst_cannot_access_analysis(client: TestClient, db: Session):
    create_user_with_role(db, "invalid_user", "invalid@example.com", "Secret123", "invalid_role")

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "invalid@example.com", "password": "Secret123"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/v1/analysis/predict",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_admin_can_list_users(client: TestClient, db: Session):
    create_user_with_role(db, "admin_user", "admin@example.com", "Admin123", "admin")

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": "Admin123"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/v1/auth/users", headers=headers)
    assert resp.status_code == 200
    users = resp.json()
    assert len(users) >= 1


def test_refresh_rotates_token_pair(client: TestClient, db: Session):
    token_pair = register_and_login(client, "dora", "dora@example.com", "Secret123")

    refresh_resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token_pair["refresh_token"]},
    )
    assert refresh_resp.status_code == 200
    refreshed = refresh_resp.json()
    assert refreshed["access_token"] != token_pair["access_token"]
    assert refreshed["refresh_token"] != token_pair["refresh_token"]

    reuse_resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token_pair["refresh_token"]},
    )
    assert reuse_resp.status_code == 401

    assert db.query(RefreshToken).count() == 2


def test_logout_revokes_refresh_family(client: TestClient):
    token_pair = register_and_login(client, "erin", "erin@example.com", "Secret123")

    logout_resp = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": token_pair["refresh_token"]},
    )
    assert logout_resp.status_code == 204

    refresh_resp = client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": token_pair["refresh_token"]},
    )
    assert refresh_resp.status_code == 401


def test_viewer_can_read_but_not_analyze_or_admin(client: TestClient, db: Session):
    viewer = create_user_with_role(db, "viewer_user", "viewer@example.com", "Viewer123", "viewer")

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "viewer@example.com", "password": "Viewer123"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    me_resp = client.get("/api/v1/auth/me", headers=headers)
    assert me_resp.status_code == 200

    snapshot_resp = client.get(f"/api/v1/analysis/users/{viewer.id}/snapshots", headers=headers)
    assert snapshot_resp.status_code == 200

    predict_resp = client.post(
        "/api/v1/analysis/predict",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert predict_resp.status_code == 403

    users_resp = client.get("/api/v1/auth/users", headers=headers)
    assert users_resp.status_code == 403


def test_create_user_role_validation(client: TestClient, db: Session):
    create_user_with_role(db, "boss", "boss@example.com", "Admin123", "admin")
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"email": "boss@example.com", "password": "Admin123"},
    )
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    invalid_resp = client.post(
        "/api/v1/auth/users",
        json={"username": "badrole", "email": "badrole@example.com", "password": "Secret123", "role": "superuser"},
        headers=headers,
    )
    assert invalid_resp.status_code == 422


def test_audit_logs_created_for_auth_and_analysis(client: TestClient, db: Session):
    token_pair = register_and_login(client, "frank", "frank@example.com", "Secret123")
    headers = {"Authorization": f"Bearer {token_pair['access_token']}"}

    analyze_resp = client.post(
        "/api/v1/analysis/analyze",
        json={"entry_node": "A"},
        headers=headers,
    )
    assert analyze_resp.status_code == 201

    actions = {log.action_type for log in db.query(AuditLog).all()}
    assert "auth.register" in actions
    assert "auth.login" in actions
    assert "analysis.create" in actions
