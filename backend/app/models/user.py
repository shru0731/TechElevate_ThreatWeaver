from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.background_job import BackgroundJob
    from app.models.export_record import ExportRecord
    from app.models.monitor import Monitor
    from app.models.refresh_token import RefreshToken
    from app.models.snapshot import NetworkSnapshot


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    snapshots: Mapped[list["NetworkSnapshot"]] = relationship(back_populates="created_by_user")
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="actor_user")
    jobs: Mapped[list["BackgroundJob"]] = relationship(back_populates="created_by_user")
    exports: Mapped[list["ExportRecord"]] = relationship(back_populates="created_by_user")
    monitors: Mapped[list["Monitor"]] = relationship(back_populates="created_by_user")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
