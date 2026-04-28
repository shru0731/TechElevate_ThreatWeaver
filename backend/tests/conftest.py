"""Pytest configuration and fixtures for tests."""

import tempfile
from pathlib import Path
from typing import Generator

import pytest  # type: ignore[import-not-found]
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.database import Base, register_models
from app.models.user import User
from app.security import hash_password


@pytest.fixture(scope="session")
def test_db_url():
    """Create a temporary SQLite database for testing."""
    db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    db_file.close()
    return f"sqlite:///{db_file.name}"


@pytest.fixture(scope="session")
def engine(test_db_url):
    """Create database engine for testing."""
    register_models()
    engine = create_engine(
        test_db_url,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    engine.dispose()
    db_path = Path(test_db_url.removeprefix("sqlite:///"))
    if db_path.exists():
        db_path.unlink()


@pytest.fixture(scope="function")
def db(engine) -> Generator[Session, None, None]:
    """Create an isolated database session for each test."""
    connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection, autoflush=False, autocommit=False)()
    nested = connection.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def restart_savepoint(session: Session, trans) -> None:
        nonlocal nested
        if transaction.is_active and not nested.is_active:
            nested = connection.begin_nested()

    yield session

    event.remove(session, "after_transaction_end", restart_savepoint)
    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


@pytest.fixture(scope="function")
def test_user(db: Session) -> User:
    """Create a test user in the database."""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=hash_password("Test123!"),
        role="analyst",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user
