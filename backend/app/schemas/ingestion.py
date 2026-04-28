from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from app.schemas.analysis import TopologySchema
from app.schemas.common import APIModel


class IngestionRequest(APIModel):
    source_type: Literal["topology", "nmap_xml", "nmap_live"] = "topology"
    snapshot_name: str | None = None
    entry_node: str = "internet"
    target_node: str | None = None
    max_depth: int = Field(default=5, ge=1, le=10)
    top_n_paths: int = Field(default=3, ge=1, le=10)
    topology: TopologySchema | None = None
    nmap_xml: str | None = None
    cidr: str | None = None
    enrichment_sources: list[Literal["nvd", "cisa_kev", "shodan"]] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_payload(self) -> "IngestionRequest":
        if self.source_type == "topology" and self.topology is None:
            raise ValueError("Topology payload is required for topology ingestion")
        if self.source_type == "nmap_xml" and not self.nmap_xml:
            raise ValueError("Nmap XML payload is required for nmap_xml ingestion")
        if self.source_type == "nmap_live" and not self.cidr:
            raise ValueError("CIDR is required for nmap_live ingestion")
        return self


class IngestionSummary(APIModel):
    source_type: str
    node_count: int
    edge_count: int
    warnings: list[str] = Field(default_factory=list)
