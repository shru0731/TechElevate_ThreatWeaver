"""Pydantic schemas for authentication endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import EmailStr, Field, model_validator

from app.schemas.common import APIModel

VALID_AUTH_ROLES = {"viewer", "analyst", "admin"}


class RegisterRequest(APIModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)


class CreateUserRequest(APIModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: str = Field(default="analyst", description="User role: viewer, analyst, or admin")

    @model_validator(mode="after")
    def validate_role(self) -> "CreateUserRequest":
        if self.role not in VALID_AUTH_ROLES:
            raise ValueError("Role must be one of viewer, analyst, or admin")
        return self


class LoginRequest(APIModel):
    username: str | None = None
    email: EmailStr | None = None
    password: str = Field(..., min_length=6)

    @model_validator(mode="before")
    @classmethod
    def validate_identifier(cls, values: Any) -> Any:
        if isinstance(values, dict) and not values.get("email") and not values.get("username"):
            raise ValueError("Either email or username must be provided")
        return values


class TokenPairResponse(APIModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    access_token_expires_in: int
    refresh_token_expires_in: int


class RefreshTokenRequest(APIModel):
    refresh_token: str = Field(..., min_length=20)


class LogoutRequest(APIModel):
    refresh_token: str = Field(..., min_length=20)


class UserResponse(APIModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
