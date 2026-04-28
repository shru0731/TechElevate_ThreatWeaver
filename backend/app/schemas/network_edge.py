"""Pydantic schemas for normalized network edges."""

from datetime import datetime
from typing import Optional

from pydantic import Field

from app.schemas.common import APIModel


class NetworkEdgeCreate(APIModel):
    """Schema for creating a network edge."""
    
    source_node_id: int = Field(..., description="ID of the source node")
    target_node_id: int = Field(..., description="ID of the target node")
    cvss: Optional[float] = Field(None, ge=0, le=10, description="CVSS score for this edge")
    exploitability: float = Field(default=1.0, ge=0, le=10, description="Exploitability factor")
    patch_factor: float = Field(default=1.0, ge=0, le=1, description="Patch availability factor")
    lateral_movement_probability: float = Field(default=1.0, ge=0, le=1, description="Lateral movement probability")


class NetworkEdgeResponse(APIModel):
    """Schema for returning network edge information."""
    
    id: int
    snapshot_id: int
    source_node_id: int
    target_node_id: int
    cvss: Optional[float] = None
    exploitability: float
    patch_factor: float
    lateral_movement_probability: float
    created_at: datetime


class NetworkEdgeDetailResponse(NetworkEdgeResponse):
    """Extended edge response with node details."""
    
    source_node_name: Optional[str] = Field(None, description="Source node identifier")
    target_node_name: Optional[str] = Field(None, description="Target node identifier")
