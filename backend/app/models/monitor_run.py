from datetime import datetime
from typing import Any, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.database import Base

if TYPE_CHECKING:
    from app.models.background_job import BackgroundJob
    from app.models.monitor import Monitor
    from app.models.snapshot import NetworkSnapshot


class MonitorRun(Base):
    __tablename__ = "monitor_runs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    monitor_id: Mapped[int] = mapped_column(ForeignKey("monitors.id", ondelete="CASCADE"), index=True)
    monitor: Mapped["Monitor"] = relationship(back_populates="runs")
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id", ondelete="SET NULL"), index=True, nullable=True)
    job: Mapped["BackgroundJob | None"] = relationship()
    snapshot_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_snapshots.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    snapshot: Mapped["NetworkSnapshot | None"] = relationship()
    status: Mapped[str] = mapped_column(String(50), default="queued", index=True)
    trigger_type: Mapped[str] = mapped_column(String(50), default="manual", index=True)
    diff_summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    error_message: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
