"""
Pydantic models for Audit, Logs, and Insight management.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SystemEvent(BaseModel):
    """Model for a System Event"""
    id: Optional[int] = None
    source: str = Field(..., description="Source of the event (e.g., 'System', 'Policy Manager')")
    level: str = Field(..., description="Severity level of the event (e.g., 'INFO', 'WARN', 'ERROR')")
    category: str = Field(..., description="Category of the event (e.g., 'Authentication', 'System Monitor')")
    action: str = Field(..., description="Action performed (e.g., 'User Login', 'Service Restart')")
    description: str = Field(..., description="Detailed description of the event.")
    timestamp: str = Field(..., description="Timestamp of the event (ISO 8601 format).")
    # Include other fields as per API response, e.g., hostname, user_ip


class SystemEventCreate(BaseModel):
    """Model for creating a new System Event"""
    source: str = Field(..., description="Source of the event.")
    level: str = Field(..., description="Level of the event (e.g., INFO, WARN, ERROR, FATAL).")
    category: str = Field(..., description="Category of the event.")
    action: str = Field(..., description="Action related to the event.")
    description: str = Field(..., description="Description of the event.")
    timestamp: str = Field(..., description="Timestamp for the event (ISO 8601 format e.g. YYYY-MM-DDTHH:mm:ss.sssZ).")


class LoginAudit(BaseModel):
    """Model for an Admin Login Audit record"""
    id: Optional[int] = None # Assuming an ID might be present
    admin_username: str = Field(..., description="Username of the admin.")
    login_time: str = Field(..., description="Login timestamp (ISO 8601).")
    logout_time: Optional[str] = Field(None, description="Logout timestamp (ISO 8601).")
    source_ip: str = Field(..., description="IP address from which the admin logged in.")
    status: str = Field(..., description="Login status (e.g., 'Success', 'Failure').")
    # Add other relevant fields from API response


class InsightAlertConfig(BaseModel):
    """Model for an Insight Alert configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the alert (auto-generated on create).")
    name: str = Field(..., description="Name of the alert.")
    description: Optional[str] = Field(None, description="Description of the alert.")
    category: str = Field(..., description="Category of the alert (e.g., 'Authentication', 'Endpoint').")
    subcategory: str = Field(..., description="Subcategory (template name) of the alert.")
    email_targets: Optional[List[str]] = Field(None, description="List of email addresses for notifications.")
    sms_targets: Optional[List[str]] = Field(None, description="List of SMS targets for notifications.")
    config: Optional[Dict[str, Any]] = Field(None, description="Alert filter configurations and CSV column settings.")
    severity: str = Field(..., description="Severity: 'CRITICAL' or 'WARNING'.")
    threshold: int = Field(..., description="Numeric threshold value to trigger the alert.")
    interval: int = Field(..., description="Numeric interval for checking the alert condition.")
    interval_unit: str = Field(..., description="Interval unit: 'MINUTE' or 'HOUR'.") # pyclearpass doc says minute/hour, API might use upper
    is_enabled: bool = Field(default=True, description="Enable/Disable the alert.")
    is_muted: bool = Field(default=False, description="Mute/Unmute the alert.")


class InsightReportConfig(BaseModel):
    """Model for an Insight Report configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the report (auto-generated on create).")
    name: str = Field(..., description="Name of the report.")
    description: Optional[str] = Field(None, description="Description of the report.")
    category: str = Field(..., description="Category of the report (e.g., 'Audit', 'Monitoring').")
    subcategory: str = Field(..., description="Subcategory (template name) of the report.")
    format: str = Field(default="CSV", description="Report format (e.g., 'CSV', 'PDF').") # pyclearpass has 'CSV', 'XML', 'HTML'
    email_targets: Optional[List[str]] = Field(None, description="List of email addresses for report delivery.")
    config: Optional[Dict[str, Any]] = Field(None, description="Report filter configurations and column settings.")
    schedule: Optional[Dict[str, Any]] = Field(None, description="Report scheduling configuration.")
    is_enabled: bool = Field(default=True, description="Enable/Disable the report generation.")
    # Add other relevant fields from pyclearpass models (e.g. run_status, last_run_time)