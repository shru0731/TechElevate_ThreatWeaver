"""Pydantic schemas for normalized network nodes."""

from datetime import datetime
from typing import Optional

from pydantic import Field

from app.schemas.common import APIModel


class NetworkNodeCreate(APIModel):
    """Schema for creating a network node."""
    
    node_id: str = Field(..., description="Unique identifier for the node (e.g., 'A', 'Web-Server')")
    label: Optional[str] = Field(None, description="Human-readable label for the node")
    node_type: str = Field(default="host", description="Type of node: host, network, service")
    vuln: float = Field(default=0.0, ge=0, le=10, description="Vulnerability score")
    cvss_max: Optional[float] = Field(None, ge=0, le=10, description="Maximum CVSS score")
    criticality: str = Field(default="LOW", description="Criticality level: LOW, MEDIUM, HIGH, CRITICAL")
    exposure: float = Field(default=1.0, ge=0, le=10, description="Exposure factor")
    exploit_in_wild: bool = Field(default=False, description="Whether exploit is in the wild")


class NetworkNodeResponse(APIModel):
    """Schema for returning network node information."""
    
    id: int
    snapshot_id: int
    node_id: str
    label: Optional[str] = None
    node_type: str
    vuln: float
    cvss_max: Optional[float] = None
    criticality: str
    exposure: float
    exploit_in_wild: bool
    created_at: datetime


class NetworkNodeDetailResponse(NetworkNodeResponse):
    """Extended node response with vulnerability details."""
    
    vulnerabilities: list = Field(default_factory=list, description="List of vulnerabilities on this node")
    outgoing_edges: list = Field(default_factory=list, description="Outgoing connections from this node")
    incoming_edges: list = Field(default_factory=list, description="Incoming connections to this node")
