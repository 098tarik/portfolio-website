"""
Security Module - JWT and Password Hashing Utilities

This module provides:
- Password hashing and verification using Argon2
- JWT token creation and validation
- User authentication utilities
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from sqlalchemy.orm import Session

from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from app.db.database import get_db
from app.models.blog import User
from app.schemas.user import TokenData, UserResponse

# ============================================================================
# PASSWORD HASHING
# ============================================================================
password_hash = PasswordHash.recommended()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a plain password using Argon2."""
    return password_hash.hash(password)


# ============================================================================
# JWT TOKEN HANDLING
# ============================================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Dictionary with token payload (should include "sub" for username)
        expires_delta: Custom expiration time (defaults to ACCESS_TOKEN_EXPIRE_MINUTES)
    
    Returns:
        Encoded JWT token as string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)]
) -> UserResponse:
    """
    Get the current authenticated user from JWT token.
    
    Validates the token, extracts the username, and retrieves the user from database.
    Raises HTTPException if token is invalid or user not found.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return UserResponse.from_orm(user)


async def get_current_active_user(
    current_user: Annotated[UserResponse, Depends(get_current_user)],
) -> UserResponse:
    """
    Get the current active user (not disabled).
    
    Raises HTTPException if user is disabled.
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_current_admin_user(
    current_user: Annotated[UserResponse, Depends(get_current_active_user)],
) -> UserResponse:
    """
    Get the current user and verify they are an admin.
    
    Raises HTTPException if user is not an admin.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions. Admin access required."
        )
    return current_user


async def authenticate_user(
    db: Session,
    username: str,
    password: str
) -> User | None:
    """
    Authenticate a user by username and password.
    
    Returns the user if credentials are valid, None otherwise.
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user
