import logging
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import (
    AttackPath,
    AttackPathRecord,
    NetworkSnapshot,
    NetworkNode,
    NetworkEdge,
    Vulnerability,
    User,
)
from app.models.remediation_plan import RemediationPlan as RemediationPlanDB
from app.schemas.analysis import AnalysisRequest


logger = logging.getLogger(__name__)


class PersistenceService:
    """Owns DB persistence and retrieval for analysis results."""

    def create_snapshot(self, db: Session, request: AnalysisRequest) -> NetworkSnapshot:
        if request.user_id is not None and db.get(User, request.user_id) is None:
            raise ValueError(f"User {request.user_id} does not exist")
        if request.topology is None:
            raise ValueError("Topology data is required to persist a snapshot")

        snapshot = NetworkSnapshot(
            name=request.snapshot_name or f"{request.entry_node}-analysis",
            source_type="analysis_request",
            topology_data=request.topology.model_dump(mode="json"),
            created_by_user_id=request.user_id,
        )
        db.add(snapshot)
        db.flush()
        
        self._persist_nodes(db, snapshot, request.topology)
        self._persist_edges(db, snapshot, request.topology)
        
        return snapshot

    def _persist_nodes(self, db: Session, snapshot: NetworkSnapshot, topology) -> None:
        node_map = {}
        
        for node_schema in topology.nodes:
            node = NetworkNode(
                snapshot_id=snapshot.id,
                node_id=node_schema.id,
                label=getattr(node_schema, "label", node_schema.id),
                node_type=getattr(node_schema, "type", "host"),
                vuln=node_schema.vuln,
                cvss_max=node_schema.cvss_max,
                criticality=str(node_schema.criticality),
                exposure=node_schema.exposure,
                exploit_in_wild=node_schema.exploit_in_wild,
            )
            db.add(node)
            db.flush()
            
            node_map[node_schema.id] = node.id
            self._persist_node_vulnerabilities(db, node, node_schema)
        
        snapshot._node_map = node_map

    def _persist_node_vulnerabilities(self, db: Session, node: NetworkNode, node_schema) -> None:
        cves = getattr(node_schema, "cves", [])
        vulnerability_details = {
            detail.cve_id.upper(): detail
            for detail in getattr(node_schema, "vulnerability_details", [])
        }
        for cve_id in cves:
            detail = vulnerability_details.get(cve_id.upper())
            vuln = Vulnerability(
                node_id=node.id,
                cve_id=cve_id,
                name=detail.name if detail is not None else cve_id,
                description=detail.description if detail is not None else None,
                cvss_score=detail.cvss_score if detail is not None else 0.0,
                severity=detail.severity if detail is not None else "UNKNOWN",
                exploit_available=detail.exploit_available if detail is not None else False,
                exploit_in_wild=(
                    detail.exploit_in_wild if detail is not None else node_schema.exploit_in_wild
                ),
                attack_vector=detail.attack_vector if detail is not None else None,
                attack_complexity=detail.attack_complexity if detail is not None else None,
                patch_available=detail.patch_available if detail is not None else False,
                patch_url=detail.patch_url if detail is not None else None,
                workaround=detail.workaround if detail is not None else None,
                published_date=detail.published_date if detail is not None else None,
            )
            db.add(vuln)

    def _persist_edges(self, db: Session, snapshot: NetworkSnapshot, topology) -> None:
        node_map = getattr(snapshot, "_node_map", {})
        
        if not node_map:
            nodes = db.query(NetworkNode).filter(NetworkNode.snapshot_id == snapshot.id).all()
            node_map = {node.node_id: node.id for node in nodes}
        
        for edge_schema in topology.edges:
            source_node_id = node_map.get(edge_schema.source)
            target_node_id = node_map.get(edge_schema.target)
            
            if source_node_id and target_node_id:
                edge = NetworkEdge(
                    snapshot_id=snapshot.id,
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    cvss=edge_schema.cvss,
                    exploitability=edge_schema.exploitability,
                    patch_factor=edge_schema.patch_factor,
                    lateral_movement_probability=edge_schema.lateral_movement_probability,
                )
                db.add(edge)

    def _persist_attack_path_remediations(
        self,
        db: Session,
        attack_path_record: AttackPathRecord,
        attack_path: AttackPath,
        remediation_data: dict | None,
    ) -> None:
        if not attack_path.nodes:
            return
        
        summary = remediation_data.get("summary", "") if remediation_data else ""
        recommendation = remediation_data.get("recommended_actions", []) if remediation_data else []
        confidence = remediation_data.get("confidence", 0.8) if remediation_data else 0.8
        provider = remediation_data.get("provider", "ai_engine") if remediation_data else "ai_engine"
        
        if isinstance(recommendation, list):
            recommendation_str = " | ".join(recommendation)
        else:
            recommendation_str = str(recommendation)
        
        for node_id_str in attack_path.nodes:
            node = (
                db.query(NetworkNode)
                .filter(
                    NetworkNode.node_id == node_id_str,
                    NetworkNode.snapshot_id == attack_path_record.snapshot_id,
                )
                .first()
            )
            
            if not node:
                continue
            
            vulnerabilities = (
                db.query(Vulnerability)
                .filter(Vulnerability.node_id == node.id)
                .all()
            )
            
            for vuln in vulnerabilities:
                remediation_plan = RemediationPlanDB(
                    vulnerability_id=vuln.id,
                    attack_path_id=attack_path_record.id,
                    priority="CRITICAL" if attack_path.score > 7.0 else "HIGH" if attack_path.score > 5.0 else "MEDIUM",
                    summary=summary or f"Remediation for {vuln.cve_id} on {node_id_str}",
                    recommendation=recommendation_str or f"Address vulnerability {vuln.cve_id}",
                    confidence=confidence,
                    provider=provider,
                    risk_reduction=min(0.7 * (attack_path.score / 10.0), 0.95),
                    status="PROPOSED",
                )
                db.add(remediation_plan)

    def save_analysis(
        self,
        db: Session,
        snapshot_id: int,
        attack_paths: Iterable[AttackPath],
        risk_scores: dict[str, float],
        target_node: str | None,
        remediation_data: dict | None = None,
    ) -> list[AttackPathRecord]:
        snapshot = db.get(NetworkSnapshot, snapshot_id)
        if snapshot is None:
            raise ValueError(f"Snapshot {snapshot_id} does not exist")

        snapshot.risk_scores = risk_scores
        records: list[AttackPathRecord] = []

        for path in attack_paths:
            path_payload = {
                "nodes": path.nodes,
                "score": path.score,
                "likelihood": path.likelihood,
                "explanation": path.explanation,
            }
            record = AttackPathRecord(
                snapshot_id=snapshot_id,
                path_data=path_payload,
                risk_score=path.score,
                entry_node=path.nodes[0] if path.nodes else None,
                target_node=target_node or (path.nodes[-1] if path.nodes else None),
                nodes=path.nodes,
                score=path.score,
                likelihood=path.likelihood,
                explanation=path.explanation,
            )
            db.add(record)
            db.flush()
            records.append(record)
            
            self._persist_attack_path_remediations(
                db,
                record,
                path,
                remediation_data,
            )

        db.flush()

        logger.info("Snapshot %s analyzed with overall risk (GNRI) %.2f", snapshot_id, snapshot.overall_risk_score)
        return records

    def persist_attack_path_remediation(
        self,
        db: Session,
        attack_path_record: AttackPathRecord,
        attack_path: AttackPath,
        remediation_data: dict | None,
    ) -> list[int]:
        self._persist_attack_path_remediations(db, attack_path_record, attack_path, remediation_data)
        db.flush()
        return [
            plan.id
            for plan in db.query(RemediationPlanDB).filter(RemediationPlanDB.attack_path_id == attack_path_record.id).all()
        ]

    def get_snapshot_results(self, db: Session, snapshot_id: int) -> NetworkSnapshot | None:
        statement = (
            select(NetworkSnapshot)
            .options(
                selectinload(NetworkSnapshot.attack_paths).selectinload(AttackPathRecord.remediation_plans),
                selectinload(NetworkSnapshot.nodes).selectinload(NetworkNode.vulnerabilities).selectinload(Vulnerability.remediation_plans),
                selectinload(NetworkSnapshot.edges).selectinload(NetworkEdge.source_node).selectinload(NetworkNode.vulnerabilities),
                selectinload(NetworkSnapshot.edges).selectinload(NetworkEdge.target_node),
            )
            .where(NetworkSnapshot.id == snapshot_id)
        )
        return db.scalar(statement)

    def get_user_snapshots(self, db: Session, user_id: int) -> list[NetworkSnapshot]:
        statement = (
            select(NetworkSnapshot)
            .options(
                selectinload(NetworkSnapshot.attack_paths).selectinload(AttackPathRecord.remediation_plans),
                selectinload(NetworkSnapshot.nodes).selectinload(NetworkNode.vulnerabilities),
                selectinload(NetworkSnapshot.edges),
            )
            .where(NetworkSnapshot.created_by_user_id == user_id)
            .order_by(NetworkSnapshot.created_at.desc())
        )
        return list(db.scalars(statement).all())
    
    def get_snapshot_nodes(self, db: Session, snapshot_id: int) -> list[NetworkNode]:
        statement = (
            select(NetworkNode)
            .options(selectinload(NetworkNode.vulnerabilities))
            .where(NetworkNode.snapshot_id == snapshot_id)
            .order_by(NetworkNode.node_id)
        )
        return list(db.scalars(statement).all())
    
    def get_snapshot_edges(self, db: Session, snapshot_id: int) -> list[NetworkEdge]:
        statement = (
            select(NetworkEdge)
            .options(
                selectinload(NetworkEdge.source_node),
                selectinload(NetworkEdge.target_node),
            )
            .where(NetworkEdge.snapshot_id == snapshot_id)
        )
        return list(db.scalars(statement).all())
    
    def get_node_vulnerabilities(self, db: Session, node_id: int) -> list[Vulnerability]:
        statement = (
            select(Vulnerability)
            .options(selectinload(Vulnerability.remediation_plans))
            .where(Vulnerability.node_id == node_id)
        )
        return list(db.scalars(statement).all())