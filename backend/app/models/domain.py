from dataclasses import dataclass, field


@dataclass(slots=True)
class AssetNode:
    node_id: str
    asset_type: str
    vulnerability_score: float
    criticality: float = 1.0
    exposure: float = 1.0
    cves: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AttackEdge:
    source: str
    target: str
    exploitability: float = 1.0
    lateral_movement_probability: float = 1.0


@dataclass(slots=True)
class AttackPath:
    nodes: list[str]
    score: float
    likelihood: float
    explanation: str
    hop_details: list[dict] = field(default_factory=list)


@dataclass(slots=True)
class RemediationPlan:
    summary: str
    recommended_actions: list[str]
    confidence: float
    provider: str
