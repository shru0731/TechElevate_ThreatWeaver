from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import APIModel


class JobAcceptedResponse(APIModel):
    job_id: int
    status: str
    message: str
    dispatch_mode: str | None = None


class JobStatusResponse(APIModel):
    id: int
    job_type: str
    status: str
    queue_mode: str | None = None
    payload: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    error_message: str | None = None
    created_by_user_id: int | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    dispatched_at: datetime | None = None


class RemediationJobRequest(APIModel):
    snapshot_id: int
    attack_path_ids: list[int] = Field(default_factory=list)
