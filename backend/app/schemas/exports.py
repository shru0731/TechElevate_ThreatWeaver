from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from app.schemas.common import APIModel


class ExportRequest(APIModel):
    snapshot_id: int
    export_format: Literal["json", "csv", "pdf"] = "json"


class ExportResponse(APIModel):
    id: int
    snapshot_id: int | None = None
    created_by_user_id: int | None = None
    export_format: str
    status: str
    storage_path: str | None = None
    download_token: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None
    job_id: int | None = None
    metadata: dict[str, Any] | None = None
    error_message: str | None = None
