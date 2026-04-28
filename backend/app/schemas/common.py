from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str | None = None
    request_id: str | None = None
    checks: dict[str, object] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error_code: str
    message: str
    request_id: str | None = None
    details: dict[str, object] | None = None


class APIModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
