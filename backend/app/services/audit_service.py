"""Helper utilities for writing audit events."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.request_context import get_request_id
from app.models.audit_log import AuditLog


def record_audit_event(
    db: Session,
    *,
    action_type: str,
    entity_type: str,
    entity_id: str | None = None,
    actor_user_id: int | None = None,
    request_id: str | None = None,
    details: dict | None = None,
) -> AuditLog:
    resolved_request_id = request_id or get_request_id()
    event = AuditLog(
        actor_user_id=actor_user_id,
        action_type=action_type,
        entity_type=entity_type,
        entity_id=entity_id,
        request_id=resolved_request_id,
        details=details,
    )
    db.add(event)
    db.flush()
    return event
