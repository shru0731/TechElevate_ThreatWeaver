"""SQLAlchemy model for remediation plans."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Float, JSON, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability
    from app.models.attack_path import AttackPathRecord


class RemediationPlan(Base):
    """Represents a remediation plan for addressing a vulnerability in an attack path."""

    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    
    # Links to vulnerability and attack path
    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True)
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="remediation_plans")
    
    attack_path_id: Mapped[int | None] = mapped_column(
        ForeignKey("attack_paths.id", ondelete="CASCADE"), 
        index=True, 
        nullable=True
    )
    attack_path: Mapped["AttackPathRecord | None"] = relationship(back_populates="remediation_plans")
    
    # Remediation details
    priority: Mapped[str] = mapped_column(String(20), default="MEDIUM")  # CRITICAL, HIGH, MEDIUM, LOW
    summary: Mapped[str] = mapped_column(String(500))  # Brief summary of the remediation
    recommendation: Mapped[str] = mapped_column(String(2000))  # Detailed recommendation
    
    # Action items
    action_items: Mapped[list[str] | None] = mapped_column(JSON(), nullable=True)  # Structured action list stored as JSON
    estimated_effort_hours: Mapped[float | None] = mapped_column(Float, nullable=True)  # Time to implement
    
    # Metrics
    confidence: Mapped[float] = mapped_column(Float, default=0.8)  # Confidence in remediation effectiveness 0-1
    risk_reduction: Mapped[float] = mapped_column(Float, default=0.7)  # Expected risk reduction 0-1
    
    # Implementation tracking
    status: Mapped[str] = mapped_column(String(50), default="PROPOSED")  # PROPOSED, IN_PROGRESS, COMPLETED, REJECTED
    responsible_team: Mapped[str | None] = mapped_column(String(255), nullable=True)  # Team responsible
    target_completion_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Provider information
    provider: Mapped[str] = mapped_column(String(100), default="ai_engine")  # Which LLM/system provided this
    llm_model: Mapped[str | None] = mapped_column(String(100), nullable=True)  # Which model was used
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )
    
    def __repr__(self) -> str:
        return f"<RemediationPlan(vulnerability_id={self.vulnerability_id}, priority={self.priority}, status={self.status})>"
