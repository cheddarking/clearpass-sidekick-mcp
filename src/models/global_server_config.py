"""
Pydantic models for Global Server Configuration management.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AdminPrivilege(BaseModel):
    """Model for Admin Privilege configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the admin privilege")
    name: str = Field(..., description="Name of the admin privilege")
    description: Optional[str] = Field(None, description="Description of the admin privilege")
    access_type: Optional[str] = Field(None, description="Property to decide the access type of the user")
    cppm_privileges: Dict[str, str] = Field(..., description="Privilege list in JSON object format (e.g., {'con':'RWD', 'mon':'RW'})")
    insight_privileges: Optional[Dict[str, str]] = Field(None, description="Privilege list in JSON object format (e.g., {'report': 'RWD', 'dashboard':'RW'})")
    allow_passwords: bool = Field(default=False, description="If selected, all passwords may be displayed in the response")
    allow_security_configs: bool = Field(default=False, description="If selected, Admin user will have access for security configuration")


class AdminUser(BaseModel):
    """Model for Admin User configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the admin user")
    user_id: str = Field(..., description="User ID of the admin")
    name: Optional[str] = Field(None, description="Name of the admin user")
    password: Optional[str] = Field(None, description="Password for the admin user")
    privilege_level: Optional[str] = Field(None, description="Privilege level for the admin user")
    enabled: bool = Field(default=True, description="Whether the admin user is enabled")


class AdminPasswordPolicy(BaseModel):
    """Model for Admin User Password Policy"""
    min_length: Optional[int] = Field(None, description="Minimum password length")
    max_length: Optional[int] = Field(None, description="Maximum password length")
    require_uppercase: Optional[bool] = Field(None, description="Require uppercase letters")
    require_lowercase: Optional[bool] = Field(None, description="Require lowercase letters")
    require_numbers: Optional[bool] = Field(None, description="Require numbers")
    require_special_chars: Optional[bool] = Field(None, description="Require special characters")
    password_history: Optional[int] = Field(None, description="Number of previous passwords to remember")
    max_age_days: Optional[int] = Field(None, description="Maximum age of password in days")


class ApplicationLicense(BaseModel):
    """Model for Application License"""
    license_id: Optional[str] = Field(None, description="License ID")
    product_name: Optional[str] = Field(None, description="Product name")
    license_type: Optional[str] = Field(None, description="License type")
    quantity: Optional[int] = Field(None, description="Licensed quantity")
    expiration_date: Optional[str] = Field(None, description="License expiration date")
    status: Optional[str] = Field(None, description="License status")


class Attribute(BaseModel):
    """Model for Attribute configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the attribute")
    entity_name: str = Field(..., description="Entity name for the attribute")
    name: str = Field(..., description="Name of the attribute")
    description: Optional[str] = Field(None, description="Description of the attribute")
    data_type: Optional[str] = Field(None, description="Data type of the attribute")
    default_value: Optional[str] = Field(None, description="Default value for the attribute")
    mandatory: bool = Field(default=False, description="Whether the attribute is mandatory")


class ClusterParameters(BaseModel):
    """Model for Cluster Parameters configuration"""
    cluster_name: Optional[str] = Field(None, description="Name of the cluster")
    database_replication_enabled: Optional[bool] = Field(None, description="Whether database replication is enabled")
    insights_enabled: Optional[bool] = Field(None, description="Whether insights are enabled")
    zone_cache_enabled: Optional[bool] = Field(None, description="Whether zone cache is enabled")
    # Add more fields based on actual cluster parameters structure


class DataFilter(BaseModel):
    """Model for Data Filter configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the data filter")
    name: str = Field(..., description="Name of the data filter")
    description: Optional[str] = Field(None, description="Description of the data filter")
    filter_expression: str = Field(..., description="Filter expression")
    entity_name: str = Field(..., description="Entity name to apply the filter to")


class FileBackupServer(BaseModel):
    """Model for File Backup Server configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the backup server")
    host_address: str = Field(..., description="Host address of the backup server")
    protocol: Optional[str] = Field(None, description="Protocol for backup (FTP, SFTP, etc.)")
    username: Optional[str] = Field(None, description="Username for backup server")
    password: Optional[str] = Field(None, description="Password for backup server")
    backup_path: Optional[str] = Field(None, description="Path for backup files")


class LocalUserPasswordPolicy(BaseModel):
    """Model for Local User Password Policy"""
    min_length: Optional[int] = Field(None, description="Minimum password length")
    max_length: Optional[int] = Field(None, description="Maximum password length")
    require_uppercase: Optional[bool] = Field(None, description="Require uppercase letters")
    require_lowercase: Optional[bool] = Field(None, description="Require lowercase letters")
    require_numbers: Optional[bool] = Field(None, description="Require numbers")
    require_special_chars: Optional[bool] = Field(None, description="Require special characters")
    password_history: Optional[int] = Field(None, description="Number of previous passwords to remember")
    max_age_days: Optional[int] = Field(None, description="Maximum age of password in days")


class MessagingSetup(BaseModel):
    """Model for Messaging Setup configuration"""
    smtp_server: Optional[str] = Field(None, description="SMTP server for email notifications")
    smtp_port: Optional[int] = Field(None, description="SMTP server port")
    smtp_username: Optional[str] = Field(None, description="SMTP username")
    smtp_password: Optional[str] = Field(None, description="SMTP password")
    enable_tls: Optional[bool] = Field(None, description="Enable TLS for SMTP")
    sender_email: Optional[str] = Field(None, description="Sender email address")


class OperatorProfile(BaseModel):
    """Model for Operator Profile configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the operator profile")
    name: str = Field(..., description="Name of the operator profile")
    description: Optional[str] = Field(None, description="Description of the operator profile")
    privilege_level: Optional[str] = Field(None, description="Privilege level for the operator")
    sponsor_privileges: Optional[Dict[str, Any]] = Field(None, description="Sponsor privileges configuration")
    guest_account_restrictions: Optional[Dict[str, Any]] = Field(None, description="Guest account restrictions")


class PolicyManagerZone(BaseModel):
    """Model for Policy Manager Zone configuration"""
    zone_id: Optional[str] = Field(None, description="Zone ID")
    name: str = Field(..., description="Name of the policy manager zone")
    description: Optional[str] = Field(None, description="Description of the zone")
    template: Optional[str] = Field(None, description="Zone template")
    cluster_role: Optional[str] = Field(None, description="Cluster role for the zone")


class SNMPTrapReceiver(BaseModel):
    """Model for SNMP Trap Receiver configuration"""
    id: Optional[int] = Field(None, description="Numeric ID of the SNMP trap receiver")
    name: str = Field(..., description="Name of the SNMP trap receiver")
    host_address: str = Field(..., description="Host address of the trap receiver")
    port: int = Field(default=162, description="Port for SNMP traps")
    version: str = Field(default="v2c", description="SNMP version (v1, v2c, v3)")
    community: Optional[str] = Field(None, description="SNMP community string")
    enabled: bool = Field(default=True, description="Whether the trap receiver is enabled") 