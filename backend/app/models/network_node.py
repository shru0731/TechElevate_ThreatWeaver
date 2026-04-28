"""SQLAlchemy model for normalized network nodes."""

from datetime import datetime
from typing import Any, TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.snapshot import NetworkSnapshot
    from app.models.vulnerability import Vulnerability
    from app.models.network_edge import NetworkEdge


class NetworkNode(Base):
    """Represents a single node in a network topology snapshot."""

    __tablename__ = "network_nodes"
    __table_args__ = (
        UniqueConstraint("snapshot_id", "node_id", name="uq_network_nodes_snapshot_node_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("network_snapshots.id", ondelete="CASCADE"), index=True)
    snapshot: Mapped["NetworkSnapshot"] = relationship(back_populates="nodes")
    
    # Node identification
    node_id: Mapped[str] = mapped_column(String(255), index=True)  # e.g., "A", "B", "C"
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)  # Human-readable name
    node_type: Mapped[str] = mapped_column(String(50), default="host")  # e.g., "host", "network", "service"
    
    # Risk attributes
    vuln: Mapped[float] = mapped_column(Float, default=0.0)  # Vulnerability score 0-10
    cvss_max: Mapped[float | None] = mapped_column(Float, nullable=True)  # Max CVSS score
    criticality: Mapped[str] = mapped_column(String(20), default="LOW")  # LOW, MEDIUM, HIGH, CRITICAL
    exposure: Mapped[float] = mapped_column(Float, default=1.0)  # Exposure factor 0-10
    exploit_in_wild: Mapped[bool] = mapped_column(Boolean, default=False)  # Known exploit available
    
    # Relationships
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(
        back_populates="node", 
        cascade="all, delete-orphan"
    )
    outgoing_edges: Mapped[list["NetworkEdge"]] = relationship(
        foreign_keys="NetworkEdge.source_node_id",
        back_populates="source_node",
        cascade="all, delete-orphan"
    )
    incoming_edges: Mapped[list["NetworkEdge"]] = relationship(
        foreign_keys="NetworkEdge.target_node_id",
        back_populates="target_node",
        cascade="all, delete-orphan"
    )
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    
    def __repr__(self) -> str:
        return f"<NetworkNode(snapshot_id={self.snapshot_id}, node_id={self.node_id}, criticality={self.criticality})>"
