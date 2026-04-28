from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import ExportRecord, NetworkSnapshot
from app.services.persistence_service import PersistenceService


class ExportService:
    def __init__(self, storage_dir: Path) -> None:
        self._storage_dir = storage_dir
        self._persistence_service = PersistenceService()

    def create_export_record(
        self,
        db: Session,
        *,
        snapshot_id: int,
        export_format: str,
        created_by_user_id: int | None,
        job_id: int | None = None,
    ) -> ExportRecord:
        snapshot = db.get(NetworkSnapshot, snapshot_id)
        if snapshot is None:
            raise ValueError("Snapshot not found")

        export_record = ExportRecord(
            snapshot_id=snapshot_id,
            created_by_user_id=created_by_user_id,
            export_format=export_format,
            status="queued",
            request_payload={
                "job_id": job_id,
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "snapshot_id": snapshot_id,
                "export_format": export_format,
            } if job_id is not None else {
                "requested_at": datetime.now(timezone.utc).isoformat(),
                "snapshot_id": snapshot_id,
                "export_format": export_format,
            },
            download_token=secrets.token_urlsafe(24),
        )
        db.add(export_record)
        db.flush()
        return export_record

    def build_export_payload(self, db: Session, export_id: int) -> tuple[ExportRecord, dict]:
        export_record = db.get(ExportRecord, export_id)
        if export_record is None:
            raise ValueError("Export not found")

        snapshot = self._persistence_service.get_snapshot_results(db, export_record.snapshot_id)
        if snapshot is None:
            raise ValueError("Snapshot not found")

        payload = {
            "snapshot": {
                "id": snapshot.id,
                "name": snapshot.name,
                "source_type": snapshot.source_type,
                "risk_scores": snapshot.risk_scores or {},
                "overall_risk_score": snapshot.overall_risk_score,
                "created_at": snapshot.created_at.isoformat() if snapshot.created_at else None,
            },
            "attack_paths": [
                {
                    "id": record.id,
                    "nodes": record.nodes or [],
                    "score": record.score,
                    "likelihood": record.likelihood,
                    "explanation": record.explanation,
                }
                for record in snapshot.attack_paths
            ],
            "remediation_plans": [
                {
                    "attack_path_id": record.id,
                    "items": [
                        {
                            "priority": plan.priority,
                            "summary": plan.summary,
                            "recommendation": plan.recommendation,
                            "status": plan.status,
                        }
                        for plan in record.remediation_plans
                    ],
                }
                for record in snapshot.attack_paths
            ],
        }
        return export_record, payload

    def generate_export(self, db: Session, export_id: int) -> ExportRecord:
        export_record, payload = self.build_export_payload(db, export_id)

        export_record.status = "running"
        request_payload = dict(export_record.request_payload or {})
        request_payload["started_at"] = datetime.now(timezone.utc).isoformat()
        export_record.request_payload = request_payload

        self._storage_dir.mkdir(parents=True, exist_ok=True)
        extension = export_record.export_format
        snapshot_id = payload["snapshot"]["id"]
        file_path = self._storage_dir / f"snapshot_{snapshot_id}_export_{export_record.id}.{extension}"
        if export_record.export_format == "json":
            artifact_bytes = json.dumps(payload, indent=2).encode("utf-8")
            file_path.write_bytes(artifact_bytes)
        elif export_record.export_format == "csv":
            artifact_bytes = self._build_csv(payload).encode("utf-8")
            file_path.write_bytes(artifact_bytes)
        elif export_record.export_format == "pdf":
            artifact_bytes = self._build_pdf(payload)
            file_path.write_bytes(artifact_bytes)
        else:
            raise ValueError("Unsupported export format")

        export_record.storage_path = str(file_path)
        export_record.status = "succeeded"
        export_record.completed_at = datetime.now(timezone.utc)
        request_payload = dict(export_record.request_payload or {})
        request_payload["artifact"] = {
            "file_name": file_path.name,
            "size_bytes": len(artifact_bytes),
            "sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "generated_at": export_record.completed_at.isoformat() if export_record.completed_at else None,
        }
        export_record.request_payload = request_payload
        return export_record

    def mark_export_failed(self, db: Session, export_id: int, error_message: str) -> None:
        export_record = db.get(ExportRecord, export_id)
        if export_record is None:
            return
        export_record.status = "failed"
        export_record.completed_at = datetime.now(timezone.utc)
        request_payload = dict(export_record.request_payload or {})
        request_payload["error_message"] = error_message
        request_payload["failed_at"] = export_record.completed_at.isoformat() if export_record.completed_at else None
        export_record.request_payload = request_payload

    def _build_csv(self, payload: dict) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["snapshot_id", "path_id", "score", "likelihood", "nodes", "explanation"])
        for path in payload["attack_paths"]:
            writer.writerow(
                [
                    payload["snapshot"]["id"],
                    path["id"],
                    path["score"],
                    path["likelihood"],
                    " -> ".join(path["nodes"]),
                    path["explanation"],
                ]
            )
        return buffer.getvalue()

    def _build_pdf(self, payload: dict) -> bytes:
        text = "\n".join(
            [
                "ThreatWeaver Export",
                f"Snapshot: {payload['snapshot']['name']} (#{payload['snapshot']['id']})",
                f"Overall Risk: {payload['snapshot']['overall_risk_score']}",
                "",
            ]
            + [
                f"Path {path['id']}: {' -> '.join(path['nodes'])} | score={path['score']} | likelihood={path['likelihood']}"
                for path in payload["attack_paths"]
            ]
        )
        sanitized = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content = f"BT /F1 12 Tf 72 720 Td ({sanitized}) Tj ET"
        pdf = (
            "%PDF-1.4\n"
            "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj\n"
            f"4 0 obj << /Length {len(content)} >> stream\n{content}\nendstream endobj\n"
            "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
            "xref\n0 6\n0000000000 65535 f \n"
            "0000000010 00000 n \n0000000063 00000 n \n0000000122 00000 n \n0000000248 00000 n \n0000000000 00000 n \n"
            "trailer << /Root 1 0 R /Size 6 >>\nstartxref\n0\n%%EOF"
        )
        return pdf.encode("utf-8")
