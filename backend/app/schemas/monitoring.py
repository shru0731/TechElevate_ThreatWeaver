from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, model_validator

from app.core.config import get_settings
from app.schemas.analysis import SnapshotSchema
from app.schemas.common import APIModel
from app.schemas.ingestion import IngestionRequest


class MonitorCreate(APIModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    interval_seconds: int = Field(ge=1)
    config: IngestionRequest

    @model_validator(mode="after")
    def validate_monitor(self) -> "MonitorCreate":
        settings = get_settings()
        if self.interval_seconds < settings.monitor_min_interval_seconds:
            raise ValueError(
                f"interval_seconds must be at least {settings.monitor_min_interval_seconds}"
            )
        return self


class MonitorUpdate(APIModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    interval_seconds: int | None = Field(default=None, ge=1)
    is_enabled: bool | None = None
    config: IngestionRequest | None = None

    @model_validator(mode="after")
    def validate_monitor(self) -> "MonitorUpdate":
        settings = get_settings()
        if self.interval_seconds is not None and self.interval_seconds < settings.monitor_min_interval_seconds:
            raise ValueError(
                f"interval_seconds must be at least {settings.monitor_min_interval_seconds}"
            )
        return self


class MonitorResponse(APIModel):
    id: int
    name: str
    description: str | None = None
    source_type: str
    interval_seconds: int
    is_enabled: bool
    config: IngestionRequest
    created_by_user_id: int | None = None
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    next_run_at: datetime | None = None
    last_error_message: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class MonitorRunResponse(APIModel):
    id: int
    monitor_id: int
    job_id: int | None = None
    snapshot_id: int | None = None
    status: str
    trigger_type: str
    diff_summary: dict[str, Any] | None = None
    error_message: str | None = None
    created_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None


class MonitorRunAcceptedResponse(APIModel):
    monitor_id: int
    run_id: int
    job_id: int | None = None
    status: str
    dispatch_mode: str | None = None


class MonitorLatestResultResponse(APIModel):
    monitor: MonitorResponse
    latest_run: MonitorRunResponse
    snapshot: SnapshotSchema | None = None


class MonitorEvent(APIModel):
    type: str
    monitor_id: int
    run_id: int | None = None
    status: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
