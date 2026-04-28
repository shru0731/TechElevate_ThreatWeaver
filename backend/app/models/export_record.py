"""SQLAlchemy model for generated exports."""

from datetime import datetime
from typing import Any, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base

if TYPE_CHECKING:
    from app.models.snapshot import NetworkSnapshot
    from app.models.user import User


class ExportRecord(Base):
    """Tracks generated snapshot exports and downloadable artifacts."""

    __tablename__ = "exports"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_snapshots.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    snapshot: Mapped["NetworkSnapshot | None"] = relationship(back_populates="exports")

    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    created_by_user: Mapped["User | None"] = relationship(back_populates="exports")

    export_format: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(50), default="queued", index=True)
    request_payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    storage_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    download_token: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        index=True,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

