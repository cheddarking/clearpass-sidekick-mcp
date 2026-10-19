"""
Pydantic models for API Client management.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ApiClient(BaseModel):
    """Model for ClearPass API client"""
    id: Optional[int] = None
    client_id: str = Field(..., description="Unique client identifier")
    client_secret: Optional[str] = Field(None, description="Client secret (write-only)")
    description: str = Field(..., description="Description of the API client")
    enabled: bool = Field(True, description="Whether the client is enabled")
    grant_types: List[str] = Field(default=["client_credentials"], description="OAuth2 grant types")
    scope: str = Field(default="read", description="API access scope")