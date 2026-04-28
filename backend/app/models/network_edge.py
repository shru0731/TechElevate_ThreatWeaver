"""SQLAlchemy model for normalized network edges."""

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Float, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

if TYPE_CHECKING:
    from app.models.network_node import NetworkNode
    from app.models.snapshot import NetworkSnapshot


class NetworkEdge(Base):
    """Represents a single edge/connection between nodes in a network topology."""

    __tablename__ = "network_edges"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("network_snapshots.id", ondelete="CASCADE"), index=True)
    snapshot: Mapped["NetworkSnapshot"] = relationship(back_populates="edges")
    
    # Edge endpoints
    source_node_id: Mapped[int] = mapped_column(ForeignKey("network_nodes.id", ondelete="CASCADE"), index=True)
    source_node: Mapped["NetworkNode"] = relationship(
        foreign_keys=[source_node_id],
        back_populates="outgoing_edges"
    )
    
    target_node_id: Mapped[int] = mapped_column(ForeignKey("network_nodes.id", ondelete="CASCADE"), index=True)
    target_node: Mapped["NetworkNode"] = relationship(
        foreign_keys=[target_node_id],
        back_populates="incoming_edges"
    )
    
    # Edge risk attributes
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)  # CVSS score for this edge
    exploitability: Mapped[float] = mapped_column(Float, default=1.0)  # Exploitability factor 0-10
    patch_factor: Mapped[float] = mapped_column(Float, default=1.0)  # Patch availability 0-1
    lateral_movement_probability: Mapped[float] = mapped_column(Float, default=1.0)  # Lateral movement probability 0-1
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    
    def __repr__(self) -> str:
        return f"<NetworkEdge(snapshot_id={self.snapshot_id}, source={self.source_node_id}, target={self.target_node_id})>"
