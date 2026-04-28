from datetime import datetime

from typing import Any, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, JSON, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.snapshot import NetworkSnapshot
    from app.models.remediation_plan import RemediationPlan


class AttackPathRecord(Base):
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("network_snapshots.id"), index=True)
    snapshot: Mapped["NetworkSnapshot"] = relationship(back_populates="attack_paths")
    path_data: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    risk_score: Mapped[float | None] = mapped_column(nullable=True)
    entry_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    nodes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    score: Mapped[float | None] = mapped_column(nullable=True)
    likelihood: Mapped[float | None] = mapped_column(nullable=True)
    explanation: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    
    # Relationships to remediation plans
    remediation_plans: Mapped[list["RemediationPlan"]] = relationship(
        back_populates="attack_path",
        cascade="all, delete-orphan"
    )
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
