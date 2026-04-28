"""Pydantic schemas for remediation plans."""

from datetime import datetime
from typing import Optional

from pydantic import Field

from app.schemas.common import APIModel


class RemediationPlanCreate(APIModel):
    """Schema for creating a remediation plan."""
    
    vulnerability_id: int = Field(..., description="ID of the vulnerability")
    attack_path_id: Optional[int] = Field(None, description="Associated attack path ID")
    priority: str = Field(default="MEDIUM", description="Priority: CRITICAL, HIGH, MEDIUM, LOW")
    summary: str = Field(..., description="Brief summary of the remediation")
    recommendation: str = Field(..., description="Detailed recommendation")
    estimated_effort_hours: Optional[float] = Field(None, description="Estimated hours to implement")
    confidence: float = Field(default=0.8, ge=0, le=1, description="Confidence in effectiveness")
    risk_reduction: float = Field(default=0.7, ge=0, le=1, description="Expected risk reduction")
    responsible_team: Optional[str] = Field(None, description="Team responsible for implementation")
    target_completion_date: Optional[datetime] = Field(None, description="Target completion date")
    provider: str = Field(default="ai_engine", description="Which system provided this recommendation")
    llm_model: Optional[str] = Field(None, description="Which LLM model was used")


class RemediationPlanResponse(APIModel):
    """Schema for returning remediation plan information."""
    
    id: int
    vulnerability_id: int
    attack_path_id: Optional[int] = None
    priority: str
    summary: str
    recommendation: str
    estimated_effort_hours: Optional[float] = None
    confidence: float
    risk_reduction: float
    status: str
    responsible_team: Optional[str] = None
    target_completion_date: Optional[datetime] = None
    provider: str
    llm_model: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RemediationPlanUpdateStatus(APIModel):
    """Schema for updating remediation plan status."""
    
    status: str = Field(..., description="New status: PROPOSED, IN_PROGRESS, COMPLETED, REJECTED")
    responsible_team: Optional[str] = Field(None, description="Responsible team")
    target_completion_date: Optional[datetime] = Field(None, description="Target completion date")


class RemediationPlanDetailResponse(RemediationPlanResponse):
    """Extended remediation response with related vulnerability."""
    
    vulnerability: Optional[dict] = Field(None, description="Associated vulnerability details")


class RemediationTaskQueuedResponse(APIModel):
    task_id: str
    status: str
    attack_path_id: int


class RemediationTaskStatusResponse(APIModel):
    task_id: str
    status: str
    result: Optional[dict] = None
    error: Optional[str] = None
