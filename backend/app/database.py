from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()

engine = create_engine(settings.database_url, future=True)
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)

_async_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_async_database_url() -> str:
    url = make_url(settings.database_url)
    drivername = url.drivername

    if "+asyncpg" in drivername or "+aiosqlite" in drivername:
        return str(url)

    if drivername in {"postgresql", "postgres"}:
        return str(url.set(drivername="postgresql+asyncpg"))
    if drivername == "postgresql+psycopg2":
        return str(url.set(drivername="postgresql+asyncpg"))
    if drivername == "sqlite":
        return str(url.set(drivername="sqlite+aiosqlite"))

    raise RuntimeError(
        f"Cannot derive an async database URL from driver '{drivername}'. "
        "Configure DATABASE_URL with an async-capable driver to use get_async_db()."
    )


def get_async_session_factory() -> async_sessionmaker[AsyncSession]:
    global _async_session_factory

    if _async_session_factory is None:
        try:
            async_database_url = _build_async_database_url()
            async_engine = create_async_engine(async_database_url, future=True)
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Async database support requires an async driver for the configured DATABASE_URL."
            ) from exc
        _async_session_factory = async_sessionmaker(
            async_engine,
            expire_on_commit=False,
        )

    return _async_session_factory

def register_models() -> None:
    """Import all SQLAlchemy models so metadata is fully populated."""
    from app.models import (  # noqa: F401
        attack_path,
        audit_log,
        background_job,
        export_record,
        monitor,
        monitor_run,
        network_edge,
        network_node,
        refresh_token,
        remediation_plan,
        snapshot,
        user,
        vulnerability,
    )


def init_db() -> None:
    """Load model metadata at startup.

    Schema creation and upgrades are owned by Alembic migrations.
    """
    register_models()
