from datetime import datetime
from typing import Any, Literal

from pydantic import ConfigDict, Field, confloat, field_validator, model_validator

from app.schemas.common import APIModel


class NodeSchema(APIModel):
    id: str
    type: str  # e.g., "external", "host", "network"
    criticality: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "LOW"
    # Legacy fields for backward compatibility with ingestion services
    vuln: float = Field(default=1.0, ge=0, le=10, description="Vulnerability score")
    exposure: float = Field(default=1.0, ge=0, le=10, description="Exposure factor")
    cves: list[str] = Field(default_factory=list)
    cvss_max: float | None = None
    vulnerability_details: list["EnrichedVulnerabilitySchema"] = Field(default_factory=list)
    exploit_in_wild: bool = False
    # New normalized fields (optional for backward compatibility)
    ip: str | None = None
    hostname: str | None = None
    os: str | None = None
    services: list[dict[str, Any]] = Field(default_factory=list)
    criticality_weight: int | None = None
    cve_list: list[str] = Field(default_factory=list)  # alias for cves
    nrs: confloat(ge=0, le=100) | None = None
    patch_status: Literal["PATCHED", "PARTIALLY_PATCHED", "UNPATCHED"] | None = None
    network_segment: str | None = None
    coordinates: dict[str, float] | None = None

    @field_validator("services")
    @classmethod
    def validate_services(cls, services: list[dict[str, Any]]) -> list[dict[str, Any]]:
        required_keys = {"port", "protocol", "service", "version"}
        normalized_services: list[dict[str, Any]] = []

        for service in services:
            if set(service.keys()) != required_keys:
                raise ValueError(
                    "Each service must contain exactly: port, protocol, service, version."
                )
            if not isinstance(service["port"], int):
                raise ValueError("Service port must be an integer.")
            if not all(isinstance(service[key], str) for key in ("protocol", "service", "version")):
                raise ValueError("Service protocol, service, and version must be strings.")
            normalized_services.append(service)

        return normalized_services

    @field_validator("coordinates")
    @classmethod
    def validate_coordinates(
        cls, coordinates: dict[str, float] | None
    ) -> dict[str, float] | None:
        if coordinates is None:
            return None
        if set(coordinates.keys()) != {"x", "y"}:
            raise ValueError("Coordinates must contain exactly x and y keys.")
        return coordinates

    @model_validator(mode="after")
    def populate_criticality_weight(self) -> "NodeSchema":
        weight_map = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
        }
        expected_weight = weight_map.get(self.criticality, 1)
        if self.criticality_weight is None:
            self.criticality_weight = expected_weight
        elif self.criticality_weight != expected_weight:
            raise ValueError(
                f"criticality_weight must be {expected_weight} for criticality {self.criticality}."
            )
        return self


class EdgeSchema(APIModel):
    id: str = ""
    source: str
    target: str
    # Legacy fields for backward compatibility with ingestion services
    exploitability: float | None = Field(default=None, ge=0, le=1, description="Exploitability score (legacy)")
    lateral_movement_probability: float | None = Field(default=None, ge=0, le=1, description="Lateral movement probability (legacy)")
    cvss: float | None = None
    patch_factor: float | None = None
    # New normalized fields
    protocol: str | None = None
    cve_id: str | None = None
    attack_type: str | None = None
    mitre_technique: str | None = None
    etp: confloat(ge=0, le=1) | None = None  # exploitability probability (new)
    weight: float | None = None
    requires_auth: bool = False
    exploit_in_wild: bool = False
    direction: Literal["unidirectional", "bidirectional"] = "unidirectional"

    @model_validator(mode="before")
    @classmethod
    def map_legacy_fields(cls, values: dict) -> dict:
        """Map legacy exploitability -> etp for backward compatibility."""
        if values.get("exploitability") is not None and values.get("etp") is None:
            values["etp"] = values["exploitability"]
        return values

    @model_validator(mode="after")
    def populate_weight(self) -> "EdgeSchema":
        if self.etp is None:
            self.etp = 0.5  # default if neither etp nor exploitability provided
        expected_weight = 1 - self.etp
        if self.weight is None:
            self.weight = expected_weight
        elif abs(self.weight - expected_weight) > 1e-9:
            raise ValueError(f"weight must be 1 - etp ({expected_weight}).")
        return self


class TopologySchema(APIModel):
    nodes: list[NodeSchema]
    edges: list[EdgeSchema]


class AnalysisRequest(APIModel):
    user_id: int | None = None
    snapshot_name: str | None = None
    entry_node: str
    target_node: str | None = None
    max_depth: int = Field(default=5, ge=1, le=10)
    top_n_paths: int = Field(default=3, ge=1, le=10)
    topology: TopologySchema | None = None


class HopDetailSchema(APIModel):
    """Per-hop CVE annotation for an attack path edge."""
    from_node: str = Field(alias="from")
    to_node: str = Field(alias="to")
    cves: list[str] = Field(default_factory=list)
    etp: float
    edge_cvss: float | None = None


class PathAnalysisSchema(APIModel):
    nodes: list[str]
    score: float
    likelihood: float
    explanation: str
    hops: list[HopDetailSchema] = Field(default_factory=list)


class RemediationSchema(APIModel):
    summary: str
    recommended_actions: list[str]
    confidence: float
    provider: str


class RemediationRequest(APIModel):
    attack_paths: list[PathAnalysisSchema]


class EnrichedVulnerabilitySchema(APIModel):
    cve_id: str
    name: str
    description: str | None = None
    cvss_score: float = Field(default=0.0, ge=0, le=10)
    severity: str = "UNKNOWN"
    exploit_available: bool = False
    exploit_in_wild: bool = False
    attack_vector: str | None = None
    attack_complexity: str | None = None
    patch_available: bool = False
    patch_url: str | None = None
    workaround: str | None = None
    published_date: datetime | None = None


# Normalized data response schemas
class VulnerabilityDetailResponse(APIModel):
    """Normalized vulnerability/CVE response."""
    id: int
    cve_id: str
    name: str
    description: str | None = None
    cvss_score: float = 0.0
    severity: str = "UNKNOWN"
    exploit_available: bool = False
    exploit_in_wild: bool = False
    attack_vector: str | None = None
    patch_available: bool = False
    patch_url: str | None = None
    
    model_config = ConfigDict(from_attributes=True)


class NetworkNodeDetailResponse(APIModel):
    """Normalized network node response with vulnerabilities."""
    id: int
    node_id: str
    label: str | None = None
    node_type: str = "host"
    vuln: float = 0.0
    criticality: str = "LOW"
    exposure: float = 1.0
    exploit_in_wild: bool = False
    vulnerabilities: list[VulnerabilityDetailResponse] = Field(default_factory=list)
    
    model_config = ConfigDict(from_attributes=True)


class NetworkEdgeDetailResponse(APIModel):
    """Normalized network edge response with node details."""
    id: int
    source_node_id: int
    target_node_id: int
    source_node_label: str | None = None
    target_node_label: str | None = None
    exploitability: float = 1.0
    lateral_movement_probability: float = 1.0
    
    model_config = ConfigDict(from_attributes=True)


class RemediationPlanDetailResponse(APIModel):
    """Normalized remediation plan response."""
    id: int
    priority: str = "MEDIUM"
    summary: str
    recommendation: str
    confidence: float = 0.8
    risk_reduction: float = 0.7
    status: str = "PROPOSED"
    provider: str = "ai_engine"
    
    model_config = ConfigDict(from_attributes=True)


class AnalysisResponse(APIModel):
    risk_scores: dict[str, float]
    attack_paths: list[PathAnalysisSchema]
    remediation: RemediationSchema


class AttackPathRecordSchema(APIModel):
    id: int
    snapshot_id: int
    path_data: dict
    risk_score: float | None = None
    entry_node: str | None = None
    target_node: str | None = None
    nodes: list[str] = Field(default_factory=list)
    score: float | None = None
    likelihood: float | None = None
    explanation: str | None = None
    created_at: str | None = None


class SnapshotSchema(APIModel):
    id: int
    name: str
    source_type: str
    topology_data: dict
    risk_scores: dict[str, float] = Field(default_factory=dict)
    overall_risk_score: float | None = None
    created_by_user_id: int | None = None
    created_at: str | None = None


class SnapshotWithNormalizedDataSchema(APIModel):
    """Extended snapshot response with normalized data."""
    id: int
    name: str
    source_type: str
    topology_data: dict
    risk_scores: dict[str, float] = Field(default_factory=dict)
    overall_risk_score: float | None = None
    created_by_user_id: int | None = None
    created_at: str | None = None
    nodes: list[NetworkNodeDetailResponse] = Field(default_factory=list)
    edges: list[NetworkEdgeDetailResponse] = Field(default_factory=list)
    
    model_config = ConfigDict(from_attributes=True)


class SnapshotResultSchema(APIModel):
    snapshot: SnapshotSchema
    attack_paths: list[AttackPathRecordSchema]


class UserSnapshotSchema(APIModel):
    id: int
    name: str
    source_type: str
    risk_scores: dict[str, float] = Field(default_factory=dict)
    overall_risk_score: float | None = None
    attack_path_count: int
    created_at: str | None = None


class PersistedAnalysisResponse(AnalysisResponse):
    snapshot_id: int
    attack_record_ids: list[int]


NodeSchema.model_rebuild()