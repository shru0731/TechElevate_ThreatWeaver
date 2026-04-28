"""Security utilities for password hashing, access tokens, and role checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import get_settings
from app.models import User

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMIN = "admin"

VALID_ROLES = {ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMIN}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.setdefault("jti", secrets.token_urlsafe(8))
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def get_access_token_expires_in() -> int:
    settings = get_settings()
    return settings.access_token_expire_minutes * 60


def get_refresh_token_expires_in() -> int:
    settings = get_settings()
    return settings.refresh_token_expire_days * 24 * 60 * 60


def build_refresh_token() -> tuple[str, str, str]:
    token_id = secrets.token_urlsafe(18)
    token_family = secrets.token_urlsafe(18)
    token_secret = secrets.token_urlsafe(32)
    return f"{token_id}.{token_secret}", token_id, token_family


def rotate_refresh_token(token_family: str) -> tuple[str, str, str]:
    token_id = secrets.token_urlsafe(18)
    token_secret = secrets.token_urlsafe(32)
    return f"{token_id}.{token_secret}", token_id, token_family


def split_refresh_token(refresh_token: str) -> tuple[str, str]:
    try:
        token_id, token_secret = refresh_token.split(".", 1)
    except ValueError as exc:
        raise ValueError("Invalid refresh token") from exc
    if not token_id or not token_secret:
        raise ValueError("Invalid refresh token")
    return token_id, token_secret


def hash_refresh_token(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    payload = decode_access_token(token)
    email: Optional[str] = payload.get("sub")
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def require_role(required_role: str):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    return role_checker


def require_admin(current_user: User = Depends(require_role(ROLE_ADMIN))):
    return current_user


def require_viewer_or_above(current_user: User = Depends(get_current_user)):
    if current_user.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    return current_user


def require_analyst_or_admin(current_user: User = Depends(get_current_user)):
    if current_user.role not in {ROLE_ANALYST, ROLE_ADMIN}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    return current_user
