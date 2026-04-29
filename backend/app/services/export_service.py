from __future__ import annotations

import csv
import hashlib
import io
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session
from weasyprint import HTML

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
        """Generate a professional PDF report using WeasyPrint."""
        html_content = self._render_pdf_html(payload)
        # WeasyPrint expects HTML object; write_pdf returns bytes
        pdf_bytes = HTML(string=html_content).write_pdf()
        return pdf_bytes

    def _render_pdf_html(self, payload: dict) -> str:
        """Create an HTML string for the PDF report."""
        snapshot = payload["snapshot"]
        attack_paths = payload["attack_paths"]
        remediation_plans = payload.get("remediation_plans", [])

        # Build remediation mapping for each attack path
        remediation_by_path = {rp["attack_path_id"]: rp["items"] for rp in remediation_plans if "attack_path_id" in rp}

        # Create rows for attack paths table
        path_rows = ""
        for path in attack_paths:
            path_id = path["id"]
            nodes = " → ".join(path.get("nodes", []))
            score = path.get("score", "N/A")
            likelihood = path.get("likelihood", "N/A")
            explanation = path.get("explanation", "")[:300]  # Truncate for table
            remediations = remediation_by_path.get(path_id, [])
            remediation_text = "<br>".join([f"• {item['summary']}" for item in remediations[:2]]) if remediations else "—"
            path_rows += f"""
        <tr>
            <td>{path_id}</td>
            <td>{nodes}</td>
            <td>{score}</td>
            <td>{likelihood}</td>
            <td>{explanation}</td>
            <td>{remediation_text}</td>
        </tr>
            """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>ThreatWeaver Export – Snapshot {snapshot['id']}</title>
            <style>
                @page {{
                    size: A4;
                    margin: 2cm;
                    @top-center {{
                        content: "ThreatWeaver – Confidential";
                        font-size: 9pt;
                        color: #666;
                    }}
                    @bottom-center {{
                        content: "Page " counter(page) " of " counter(pages);
                        font-size: 9pt;
                    }}
                }}
                body {{
                    font-family: 'Helvetica', 'Arial', sans-serif;
                    color: #1e2a3a;
                    line-height: 1.4;
                    background: white;
                }}
                h1 {{
                    font-size: 24pt;
                    border-bottom: 2px solid #0f172a;
                    padding-bottom: 0.2em;
                    margin-bottom: 0.5em;
                }}
                h2 {{
                    font-size: 16pt;
                    margin-top: 1.5em;
                    background: #f1f5f9;
                    padding: 0.3em 0.5em;
                    border-left: 4px solid #3b82f6;
                }}
                .risk-score {{
                    display: inline-block;
                    padding: 0.2em 0.6em;
                    border-radius: 12px;
                    font-weight: bold;
                    background: #fee2e2;
                    color: #b91c1c;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 1em 0;
                    font-size: 9pt;
                }}
                th, td {{
                    border: 1px solid #ccc;
                    padding: 8px 6px;
                    text-align: left;
                    vertical-align: top;
                }}
                th {{
                    background: #e2e8f0;
                    font-weight: 600;
                }}
                tr:nth-child(even) {{
                    background: #f8fafc;
                }}
                .footer {{
                    font-size: 8pt;
                    color: #475569;
                    text-align: center;
                    margin-top: 2em;
                    border-top: 1px solid #ccc;
                    padding-top: 1em;
                }}
            </style>
        </head>
        <body>
            <h1>ThreatWeaver Security Report</h1>
            <p><strong>Snapshot:</strong> {snapshot['name']} (ID {snapshot['id']})<br>
            <strong>Source Type:</strong> {snapshot.get('source_type', 'N/A')}<br>
            <strong>Analysis Date:</strong> {snapshot.get('created_at', 'N/A')}</p>

            <h2>Overall Risk Assessment</h2>
            <p><strong>Global Network Risk Index (GNRI):</strong> 
            <span class="risk-score">{snapshot.get('overall_risk_score', 'N/A')} / 100</span></p>

            <h2>Attack Paths ({len(attack_paths)})</h2>
            <table>
                <thead>
                    <tr><th>ID</th><th>Path</th><th>Score</th><th>Likelihood</th><th>Explanation</th><th>Top Remediations</th></tr>
                </thead>
                <tbody>
                    {path_rows}
                </tbody>
            </table>

            <div class="footer">
                Generated by ThreatWeaver • Export ID {snapshot.get('id', '')} • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
            </div>
        </body>
        </html>
        """
        return html