import json
from pathlib import Path

from app.core.config import get_settings
from app.schemas.analysis import TopologySchema


class TopologyRepository:
    """Loads topology snapshots from the configured local data source."""

    def __init__(self, topology_path: Path | None = None) -> None:
        settings = get_settings()
        self._topology_path = topology_path or settings.default_topology_path

    def load_default_topology(self) -> TopologySchema:
        return self.load_topology(self._topology_path)

    def load_topology(self, topology_path: Path) -> TopologySchema:
        with topology_path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
        return TopologySchema.model_validate(payload)
