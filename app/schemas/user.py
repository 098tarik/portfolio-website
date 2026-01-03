"""
User Schemas - Data Validation & Serialization

Schemas for user registration, login, and responses.
"""

from pydantic import BaseModel


class UserRegister(BaseModel):
    """Schema for user registration"""
    username: str
    email: str
    full_name: str
    password: str


class UserLogin(BaseModel):
    """Schema for user login (alternative to OAuth2PasswordRequestForm)"""
    username: str
    password: str


class UserResponse(BaseModel):
    """Schema for returning user data (no password or hashed_password)"""
    id: int
    username: str
    email: str
    full_name: str
    is_admin: bool = False
    disabled: bool = False
    
    class Config:
        from_attributes = True


class Token(BaseModel):
    """Schema for JWT token response"""
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """Schema for token payload data"""
    username: str | None = None
