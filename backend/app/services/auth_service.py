"""Authentication service handling registration, login, refresh, and logout."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import RefreshToken, User
from app.security import (
    build_refresh_token,
    create_access_token,
    get_access_token_expires_in,
    get_refresh_token_expires_in,
    hash_password,
    hash_refresh_token,
    rotate_refresh_token,
    split_refresh_token,
    verify_password,
)
from app.services.audit_service import record_audit_event


class AuthService:
    """Business-logic layer for authentication and refresh-token lifecycle."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def _get_by_email(self, email: str) -> User | None:
        return self.db.query(User).filter(User.email == email).first()

    def _get_by_username(self, username: str) -> User | None:
        return self.db.query(User).filter(User.username == username).first()

    def _access_expiry_delta(self) -> timedelta:
        return timedelta(seconds=get_access_token_expires_in())

    def _refresh_expiry_delta(self) -> timedelta:
        return timedelta(seconds=get_refresh_token_expires_in())

    def register_user(self, payload, role: str = "analyst") -> User:
        if self._get_by_email(payload.email) is not None:
            raise ValueError("A user with this email already exists")
        if self._get_by_username(payload.username) is not None:
            raise ValueError("A user with this username already exists")

        user = User(
            username=payload.username,
            email=payload.email,
            hashed_password=hash_password(payload.password),
            role=role,
            is_active=True,
        )
        self.db.add(user)
        self.db.flush()
        record_audit_event(
            self.db,
            actor_user_id=user.id,
            action_type="auth.register",
            entity_type="user",
            entity_id=str(user.id),
            details={"role": user.role, "email": user.email},
        )
        return user

    def authenticate_user(self, payload) -> dict[str, str | int]:
        user: User | None = None
        identifier = payload.email or payload.username or "unknown"
        if payload.email:
            user = self._get_by_email(payload.email)
        elif payload.username:
            user = self._get_by_username(payload.username)

        if user is None:
            record_audit_event(
                self.db,
                action_type="auth.login_failed",
                entity_type="user",
                details={"identifier": identifier, "reason": "user_not_found"},
            )
            raise ValueError("Incorrect username/email or password")
        if not verify_password(payload.password, user.hashed_password):
            record_audit_event(
                self.db,
                actor_user_id=user.id,
                action_type="auth.login_failed",
                entity_type="user",
                entity_id=str(user.id),
                details={"identifier": identifier, "reason": "invalid_password"},
            )
            raise ValueError("Incorrect username/email or password")

        token_pair = self._issue_token_pair(user)
        record_audit_event(
            self.db,
            actor_user_id=user.id,
            action_type="auth.login",
            entity_type="user",
            entity_id=str(user.id),
            details={"role": user.role},
        )
        return token_pair

    def refresh_user_session(self, refresh_token: str) -> dict[str, str | int]:
        token_record = self._get_valid_refresh_token(refresh_token)
        token_record.is_revoked = True
        token_record.revoked_at = datetime.now(timezone.utc)
        rotated_pair = self._issue_token_pair(token_record.user, token_family=token_record.token_family)
        replacement_token_id, _ = split_refresh_token(rotated_pair["refresh_token"])
        token_record.replaced_by_token_id = replacement_token_id
        self.db.flush()
        record_audit_event(
            self.db,
            actor_user_id=token_record.user_id,
            action_type="auth.refresh",
            entity_type="refresh_token",
            entity_id=token_record.token_id,
            details={"token_family": token_record.token_family},
        )
        return rotated_pair

    def logout_user(self, refresh_token: str) -> None:
        token_record = self._get_valid_refresh_token(refresh_token)
        revoked_at = datetime.now(timezone.utc)
        family_records = (
            self.db.query(RefreshToken)
            .filter(RefreshToken.token_family == token_record.token_family)
            .all()
        )
        for record in family_records:
            record.is_revoked = True
            record.revoked_at = revoked_at
        self.db.flush()
        record_audit_event(
            self.db,
            actor_user_id=token_record.user_id,
            action_type="auth.logout",
            entity_type="refresh_token_family",
            entity_id=token_record.token_family,
            details={"revoked_count": len(family_records)},
        )

    def get_user_by_email(self, email: str) -> User | None:
        return self._get_by_email(email)

    def _issue_token_pair(self, user: User, token_family: str | None = None) -> dict[str, str | int]:
        access_token = create_access_token(
            data={"sub": user.email, "role": user.role},
            expires_delta=self._access_expiry_delta(),
        )

        if token_family is None:
            refresh_token, token_id, token_family = build_refresh_token()
        else:
            refresh_token, token_id, token_family = rotate_refresh_token(token_family)

        refresh_record = RefreshToken(
            user_id=user.id,
            token_id=token_id,
            token_family=token_family,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=datetime.now(timezone.utc) + self._refresh_expiry_delta(),
        )
        self.db.add(refresh_record)
        self.db.flush()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "access_token_expires_in": get_access_token_expires_in(),
            "refresh_token_expires_in": get_refresh_token_expires_in(),
        }

    def _is_expired(self, expires_at: datetime) -> bool:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return expires_at <= datetime.now(timezone.utc)

    def _get_valid_refresh_token(self, refresh_token: str) -> RefreshToken:
        token_id, _ = split_refresh_token(refresh_token)
        token_record = self.db.query(RefreshToken).filter(RefreshToken.token_id == token_id).first()
        if token_record is None:
            raise ValueError("Invalid refresh token")
        if token_record.is_revoked:
            raise ValueError("Refresh token has been revoked")
        if self._is_expired(token_record.expires_at):
            raise ValueError("Refresh token has expired")
        if token_record.token_hash != hash_refresh_token(refresh_token):
            raise ValueError("Invalid refresh token")
        return token_record
