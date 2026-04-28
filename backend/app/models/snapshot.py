from datetime import datetime
from typing import Any, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, JSON, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.export_record import ExportRecord
    from app.models.user import User
    from app.models.network_node import NetworkNode
    from app.models.network_edge import NetworkEdge
    from app.models.attack_path import AttackPathRecord


class NetworkSnapshot(Base):
    __tablename__ = "network_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(50), default="json")
    topology_data: Mapped[dict[str, Any]] = mapped_column(JSON)
    risk_scores: Mapped[dict[str, float] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    overall_risk_score: Mapped[float | None] = mapped_column(nullable=True)
    created_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), index=True, nullable=True)
    created_by_user: Mapped["User | None"] = relationship(back_populates="snapshots")
    
    # Relationships to normalized entities
    nodes: Mapped[list["NetworkNode"]] = relationship(back_populates="snapshot", cascade="all, delete-orphan")
    edges: Mapped[list["NetworkEdge"]] = relationship(back_populates="snapshot", cascade="all, delete-orphan")
    attack_paths: Mapped[list["AttackPathRecord"]] = relationship(back_populates="snapshot")
    exports: Mapped[list["ExportRecord"]] = relationship(back_populates="snapshot")
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
