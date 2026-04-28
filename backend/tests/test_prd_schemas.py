import json
from pathlib import Path

from app.schemas.analysis import EdgeSchema, NodeSchema


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "prd"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


def test_prd_node_schema_fixture_validates() -> None:
    payload = load_fixture("node_object.json")

    node = NodeSchema(**payload)

    assert node.id == payload["id"]
    assert node.criticality_weight == 7


def test_prd_edge_schema_fixture_validates() -> None:
    payload = load_fixture("edge_object.json")

    edge = EdgeSchema(**payload)

    assert edge.id == payload["id"]
    assert edge.weight == payload["weight"]
