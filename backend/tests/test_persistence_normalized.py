"""Tests for normalized database persistence."""

from datetime import datetime

import pytest  # type: ignore[import-not-found]
from sqlalchemy.orm import Session

from app.models import NetworkSnapshot, NetworkNode, NetworkEdge, Vulnerability, AttackPathRecord
from app.models.remediation_plan import RemediationPlan as RemediationPlanDB
from app.models.domain import AttackPath
from app.services.persistence_service import PersistenceService
from app.schemas.analysis import (
    AnalysisRequest,
    EnrichedVulnerabilitySchema,
    TopologySchema,
    NodeSchema,
    EdgeSchema,
)


@pytest.fixture
def persistence_service():
    """Fixture for PersistenceService."""
    return PersistenceService()


@pytest.fixture
def sample_topology():
    """Create a sample topology for testing."""
    nodes = [
        NodeSchema(
            id="A",
            type="host",
            vuln=2.5,
            criticality="LOW",
            cves=["CVE-2021-0001"],
        ),
        NodeSchema(
            id="B",
            type="host",
            vuln=7.5,
            criticality="HIGH",
            cves=["CVE-2021-0002", "CVE-2021-0003"],
        ),
        NodeSchema(
            id="C",
            type="service",
            vuln=5.0,
            criticality="MEDIUM",
            cves=[],
        ),
    ]
    
    edges = [
        EdgeSchema(source="A", target="B", exploitability=0.8),
        EdgeSchema(source="B", target="C", exploitability=0.6),
    ]
    
    return TopologySchema(nodes=nodes, edges=edges)


class TestNormalizedPersistence:
    """Tests for normalized snapshot persistence."""

    def test_create_snapshot_with_normalized_nodes(self, db: Session, persistence_service, sample_topology):
        """Test that snapshot creation normalizes and stores nodes."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-snapshot",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Verify snapshot was created
        assert snapshot.id is not None
        assert snapshot.name == "test-snapshot"
        
        # Verify nodes were persisted
        nodes = db.query(NetworkNode).filter(NetworkNode.snapshot_id == snapshot.id).all()
        assert len(nodes) == 3
        
        node_ids = {node.node_id for node in nodes}
        assert node_ids == {"A", "B", "C"}
        
        # Verify node attributes
        node_b = next(n for n in nodes if n.node_id == "B")
        assert node_b.vuln == 7.5
        assert node_b.criticality == "HIGH"

    def test_create_snapshot_with_normalized_edges(self, db: Session, persistence_service, sample_topology):
        """Test that snapshot creation normalizes and stores edges."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-edges",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Verify edges were persisted
        edges = db.query(NetworkEdge).filter(NetworkEdge.snapshot_id == snapshot.id).all()
        assert len(edges) == 2
        
        # Verify edge connections exist (using node IDs from db)
        assert all(edge.source_node_id and edge.target_node_id for edge in edges)

    def test_create_snapshot_with_vulnerabilities(self, db: Session, persistence_service, sample_topology):
        """Test that CVE data is persisted to vulnerabilities table."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-vulns",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Verify vulnerabilities were persisted
        vulns = db.query(Vulnerability).all()
        cve_ids = {v.cve_id for v in vulns}
        
        # Should have 3 CVEs from the topology
        assert len(cve_ids) >= 3
        assert "CVE-2021-0001" in cve_ids
        assert "CVE-2021-0002" in cve_ids
        assert "CVE-2021-0003" in cve_ids

    def test_create_snapshot_persists_real_enriched_vulnerability_fields(self, db: Session, persistence_service):
        topology = TopologySchema(
            nodes=[
                NodeSchema(
                    id="A",
                    type="host",
                    vuln=8.8,
                    cvss_max=8.8,
                    criticality="HIGH",
                    cves=["CVE-2024-1234"],
                    vulnerability_details=[
                        EnrichedVulnerabilitySchema(
                            cve_id="CVE-2024-1234",
                            name="CVE-2024-1234",
                            description="Remote code execution in sample service",
                            cvss_score=8.8,
                            severity="HIGH",
                            attack_vector="NETWORK",
                            attack_complexity="LOW",
                            published_date=datetime.fromisoformat("2024-01-02T03:04:05"),
                        )
                    ],
                )
            ],
            edges=[],
        )
        request = AnalysisRequest(user_id=None, snapshot_name="enriched-vulns", entry_node="A", topology=topology)

        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()

        vuln = db.query(Vulnerability).filter(Vulnerability.node_id == snapshot.nodes[0].id).one()
        assert vuln.name == "CVE-2024-1234"
        assert vuln.description == "Remote code execution in sample service"
        assert vuln.cvss_score == 8.8
        assert vuln.severity == "HIGH"
        assert vuln.attack_vector == "NETWORK"
        assert vuln.attack_complexity == "LOW"
        assert vuln.published_date is not None

    def test_get_snapshot_nodes(self, db: Session, persistence_service, sample_topology):
        """Test retrieving normalized nodes for a snapshot."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-retrieve",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Retrieve nodes
        nodes = persistence_service.get_snapshot_nodes(db, snapshot.id)
        assert len(nodes) == 3
        
        # Verify node data
        node_a = next(n for n in nodes if n.node_id == "A")
        assert node_a.criticality == "LOW"

    def test_get_snapshot_edges(self, db: Session, persistence_service, sample_topology):
        """Test retrieving normalized edges for a snapshot."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-edges-retrieve",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Retrieve edges
        edges = persistence_service.get_snapshot_edges(db, snapshot.id)
        assert len(edges) == 2


class TestForeignKeyRelationships:
    """Tests for foreign key relationships."""

    def test_snapshot_to_nodes_relationship(self, db: Session, persistence_service, sample_topology):
        """Test that snapshot properly relates to nodes."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-relationship",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Refresh to load relationships
        db.refresh(snapshot)
        
        # Verify relationship
        assert len(snapshot.nodes) == 3
        node_ids = {node.node_id for node in snapshot.nodes}
        assert node_ids == {"A", "B", "C"}

    def test_snapshot_to_edges_relationship(self, db: Session, persistence_service, sample_topology):
        """Test that snapshot properly relates to edges."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-edge-relationship",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Refresh to load relationships
        db.refresh(snapshot)
        
        # Verify relationship
        assert len(snapshot.edges) == 2

    def test_node_to_vulnerabilities_relationship(self, db: Session, persistence_service, sample_topology):
        """Test that nodes properly relate to vulnerabilities."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-vuln-relationship",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Get nodes with vulnerabilities
        nodes = persistence_service.get_snapshot_nodes(db, snapshot.id)
        
        # Node B should have 2 CVEs
        node_b = next(n for n in nodes if n.node_id == "B")
        assert len(node_b.vulnerabilities) == 2
        
        # Node A should have 1 CVE
        node_a = next(n for n in nodes if n.node_id == "A")
        assert len(node_a.vulnerabilities) == 1

    def test_cascade_delete_on_snapshot(self, db: Session, persistence_service, sample_topology):
        """Test that deleting snapshot cascades to nodes and edges."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-cascade",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        snapshot_id = snapshot.id
        db.commit()
        
        # Verify data exists
        nodes_before = db.query(NetworkNode).filter(NetworkNode.snapshot_id == snapshot_id).count()
        edges_before = db.query(NetworkEdge).filter(NetworkEdge.snapshot_id == snapshot_id).count()
        assert nodes_before == 3
        assert edges_before == 2
        
        # Delete snapshot
        db.delete(snapshot)
        db.commit()
        
        # Verify cascade delete worked
        nodes_after = db.query(NetworkNode).filter(NetworkNode.snapshot_id == snapshot_id).count()
        edges_after = db.query(NetworkEdge).filter(NetworkEdge.snapshot_id == snapshot_id).count()
        assert nodes_after == 0
        assert edges_after == 0


class TestNormalizedQueries:
    """Tests for querying normalized data."""

    def test_get_node_by_snapshot_and_id(self, db: Session, persistence_service, sample_topology):
        """Test querying a specific node."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-query-node",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Query specific node
        node = db.query(NetworkNode).filter(
            NetworkNode.snapshot_id == snapshot.id,
            NetworkNode.node_id == "B",
        ).first()
        
        assert node is not None
        assert node.criticality == "HIGH"
        assert node.vuln == 7.5

    def test_get_edges_for_source_node(self, db: Session, persistence_service, sample_topology):
        """Test querying edges from a specific source node."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-edges-source",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Get node A
        node_a = db.query(NetworkNode).filter(
            NetworkNode.snapshot_id == snapshot.id,
            NetworkNode.node_id == "A",
        ).first()
        
        # Get outgoing edges
        outgoing = db.query(NetworkEdge).filter(
            NetworkEdge.source_node_id == node_a.id,
        ).all()
        
        assert len(outgoing) == 1
        assert outgoing[0].target_node.node_id == "B"

    def test_get_vulnerabilities_for_node(self, db: Session, persistence_service, sample_topology):
        """Test querying vulnerabilities for a specific node."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-node-vulns",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Get node B and its vulnerabilities
        node_b = db.query(NetworkNode).filter(
            NetworkNode.snapshot_id == snapshot.id,
            NetworkNode.node_id == "B",
        ).first()
        
        vulns = persistence_service.get_node_vulnerabilities(db, node_b.id)
        assert len(vulns) == 2


class TestSnapshotRetrieval:
    """Tests for snapshot retrieval with normalized data."""

    def test_get_snapshot_results_with_relationships(self, db: Session, persistence_service, sample_topology):
        """Test retrieving snapshot with all normalized relationships."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-full-retrieve",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Retrieve snapshot with relationships
        retrieved = persistence_service.get_snapshot_results(db, snapshot.id)
        
        assert retrieved is not None
        assert len(retrieved.nodes) == 3
        assert len(retrieved.edges) == 2

    def test_get_user_snapshots_with_normalized_data(self, db: Session, persistence_service, sample_topology, test_user):
        """Test retrieving user snapshots with normalized data."""
        request = AnalysisRequest(
            user_id=test_user.id,
            snapshot_name="user-snapshot",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Retrieve user snapshots
        snapshots = persistence_service.get_user_snapshots(db, test_user.id)
        
        assert len(snapshots) >= 1
        user_snapshot = next(s for s in snapshots if s.id == snapshot.id)
        assert len(user_snapshot.nodes) == 3


class TestRemediationPersistence:
    """Tests for remediation plan persistence."""

    def test_save_analysis_persists_remediation_plans(
        self, db: Session, persistence_service, sample_topology
    ):
        """Test that attack paths generate and persist remediation plans."""
        # Create snapshot
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-remediation",
            entry_node="A",
            target_node="C",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Create mock attack paths
        attack_paths = [
            AttackPath(
                nodes=["A", "B"],
                score=8.5,
                likelihood=0.75,
                explanation="Path from A to B exploiting SMB vulnerability",
            ),
        ]
        
        # Create remediation data
        remediation_data = {
            "summary": "Patch SMB service and restrict network access",
            "recommended_actions": ["Apply SMB security patches", "Update firewall rules"],
            "confidence": 0.85,
            "provider": "gpt-4",
        }
        
        # Save analysis with remediation
        records = persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores={"A": 2.5, "B": 7.5, "C": 5.0},
            target_node="C",
            remediation_data=remediation_data,
        )
        
        db.commit()
        
        # Verify attack path record was created
        assert len(records) == 1
        assert records[0].nodes == ["A", "B"]
        
        # Verify remediation plans were persisted
        rem_plans = db.query(RemediationPlanDB).filter(
            RemediationPlanDB.attack_path_id == records[0].id
        ).all()
        
        # Should have remediation plans for vulnerabilities in the path
        assert len(rem_plans) > 0

    def test_remediation_plan_vulnerability_link(
        self, db: Session, persistence_service, sample_topology
    ):
        """Test that remediation plans are properly linked to vulnerabilities."""
        # Create snapshot
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-rem-link",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        db.commit()
        
        # Create attack path
        attack_paths = [
            AttackPath(
                nodes=["B"],
                score=7.5,
                likelihood=0.8,
                explanation="Direct vulnerability on B",
            ),
        ]
        
        # Save analysis
        records = persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores={"B": 7.5},
            target_node="B",
        )
        db.commit()
        
        # Get remediation plans for the attack path
        rem_plans = db.query(RemediationPlanDB).filter(
            RemediationPlanDB.attack_path_id == records[0].id
        ).all()
        
        # Verify each remediation plan links to a vulnerability
        for rem_plan in rem_plans:
            assert rem_plan.vulnerability_id is not None
            assert rem_plan.vulnerability is not None
            assert rem_plan.vulnerability.node.node_id == "B"

    def test_remediation_plan_status_tracking(
        self, db: Session, persistence_service, sample_topology
    ):
        """Test that remediation plan status can be tracked."""
        # Create snapshot and attack path
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-rem-status",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        
        attack_paths = [
            AttackPath(
                nodes=["A", "B"],
                score=6.0,
                likelihood=0.7,
                explanation="Test path",
            ),
        ]
        
        records = persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores={"A": 2.5, "B": 7.5},
            target_node="B",
        )
        db.commit()
        
        # Retrieve remediation plans
        rem_plans = db.query(RemediationPlanDB).filter(
            RemediationPlanDB.attack_path_id == records[0].id
        ).all()
        
        assert len(rem_plans) > 0
        
        # Update status
        for rem_plan in rem_plans:
            rem_plan.status = "IN_PROGRESS"
        
        db.commit()
        
        # Verify status update
        updated_plans = db.query(RemediationPlanDB).filter(
            RemediationPlanDB.attack_path_id == records[0].id
        ).all()
        
        assert all(p.status == "IN_PROGRESS" for p in updated_plans)

    def test_remediation_plan_priority_calculation(
        self, db: Session, persistence_service, sample_topology
    ):
        """Test that remediation plan priority is set based on attack score."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-rem-priority",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        
        # High-severity attack path
        attack_paths = [
            AttackPath(
                nodes=["B"],
                score=9.0,  # Critical score
                likelihood=0.9,
                explanation="Critical vulnerability",
            ),
        ]
        
        records = persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores={"B": 7.5},
            target_node="B",
        )
        db.commit()
        
        # Check priority
        rem_plans = db.query(RemediationPlanDB).filter(
            RemediationPlanDB.attack_path_id == records[0].id
        ).all()
        
        # Should be CRITICAL priority for high score
        assert all(p.priority == "CRITICAL" for p in rem_plans)

    def test_multiple_attack_paths_generate_multiple_remediations(
        self, db: Session, persistence_service, sample_topology
    ):
        """Test that multiple attack paths generate multiple remediation plans."""
        request = AnalysisRequest(
            user_id=None,
            snapshot_name="test-multi-paths",
            entry_node="A",
            topology=sample_topology,
        )
        
        snapshot = persistence_service.create_snapshot(db, request)
        
        # Multiple attack paths
        attack_paths = [
            AttackPath(
                nodes=["A", "B"],
                score=8.0,
                likelihood=0.75,
                explanation="Path 1",
            ),
            AttackPath(
                nodes=["B", "C"],
                score=6.5,
                likelihood=0.6,
                explanation="Path 2",
            ),
        ]
        
        records = persistence_service.save_analysis(
            db=db,
            snapshot_id=snapshot.id,
            attack_paths=attack_paths,
            risk_scores={"A": 2.5, "B": 7.5, "C": 5.0},
            target_node="C",
        )
        db.commit()
        
        # Count total remediation plans
        total_rem_plans = db.query(RemediationPlanDB).filter(
            RemediationPlanDB.attack_path_id.in_([r.id for r in records])
        ).count()
        
        # Should have remediation plans for each path
        assert total_rem_plans > 0
