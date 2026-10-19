"""
Pydantic models for Guest User management.
"""

from typing import Optional
from pydantic import BaseModel, Field


class GuestUser(BaseModel):
    """Model for ClearPass guest user"""
    id: Optional[int] = None
    username: str = Field(..., description="Guest username")
    password: str = Field(..., description="Guest password")
    role_name: Optional[str] = Field(None, description="User role name")
    role_id: Optional[int] = Field(None, description="User role ID (required by API)")
    expire_time: Optional[str] = Field(None, description="Account expiration time")
    sponsor_profile: Optional[str] = Field(None, description="Sponsor profile")
    enabled: bool = Field(True, description="Whether account is enabled")