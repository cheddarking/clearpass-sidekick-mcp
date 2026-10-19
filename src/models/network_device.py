"""
Network Device Models for ClearPass Sidekick

This module contains Pydantic models for network device management,
including basic device information, advanced configuration settings,
validation, statistics, and bulk operations.
"""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


# =============================================================================
# Core Network Device Models
# =============================================================================

class NetworkDevice(BaseModel):
    """Model for ClearPass network device"""
    id: Optional[int] = Field(None, description="Device ID")
    name: str = Field(..., description="Device name")
    ip_address: str = Field(..., description="Device IP address")
    description: Optional[str] = Field(None, description="Device description")
    
    # Authentication and Security
    radius_secret: str = Field(..., description="RADIUS shared secret")
    tacacs_secret: Optional[str] = Field(None, description="TACACS+ shared secret")
    
    # Vendor Information
    vendor_name: str = Field(default="Aruba", description="Device vendor")
    vendor_id: Optional[int] = Field(None, description="Vendor ID")
    
    # CoA Configuration
    coa_capable: bool = Field(default=True, description="Change of Authorization capability")
    coa_port: Optional[int] = Field(None, description="CoA port number")
    
    # RadSec Configuration
    radsec_enabled: Optional[bool] = Field(None, description="RadSec enabled flag")
    
    # Advanced Features
    attributes: Optional[Dict[str, Any]] = Field(None, description="Additional device attributes")
    template_name: Optional[str] = Field(None, description="Template used to create this device")
    
    # Status and Monitoring
    status: Optional[str] = Field(None, description="Device status")
    last_seen: Optional[str] = Field(None, description="Last seen timestamp")


class NetworkDeviceCreate(BaseModel):
    """Model for creating a new network device"""
    name: str = Field(..., description="Device name")
    ip_address: str = Field(..., description="Device IP address")
    radius_secret: str = Field(..., description="RADIUS shared secret")
    tacacs_secret: Optional[str] = Field(None, description="TACACS+ shared secret")
    vendor_name: str = Field(default="Aruba", description="Device vendor")
    coa_capable: bool = Field(default=True, description="Change of Authorization capability")
    coa_port: Optional[int] = Field(None, description="CoA port number")
    radsec_enabled: Optional[bool] = Field(None, description="Enable RadSec for this device")
    description: Optional[str] = Field(None, description="Device description")


class NetworkDeviceUpdate(BaseModel):
    """Model for updating an existing network device"""
    name: Optional[str] = Field(None, description="New device name")
    ip_address: Optional[str] = Field(None, description="New device IP address")
    radius_secret: Optional[str] = Field(None, description="New RADIUS shared secret")
    tacacs_secret: Optional[str] = Field(None, description="New TACACS+ shared secret")
    vendor_name: Optional[str] = Field(None, description="New device vendor")
    coa_capable: Optional[bool] = Field(None, description="New Change of Authorization capability")
    coa_port: Optional[int] = Field(None, description="New CoA port number")
    radsec_enabled: Optional[bool] = Field(None, description="New RadSec enabled status")
    description: Optional[str] = Field(None, description="New device description")


# =============================================================================
# Advanced Configuration Models (Moved from policy_elements.py)
# =============================================================================

class SNMPReadSettings(BaseModel):
    """Model for SNMP Read Settings"""
    enabled: Optional[bool] = Field(None, description="Whether SNMP read is enabled")
    community: Optional[str] = Field(None, description="SNMP read community string")
    version: Optional[str] = Field(None, description="SNMP version (v1, v2c, v3)")
    security_name: Optional[str] = Field(None, description="SNMPv3 security name")
    auth_protocol: Optional[str] = Field(None, description="SNMPv3 authentication protocol")
    auth_key: Optional[str] = Field(None, description="SNMPv3 authentication key")
    privacy_protocol: Optional[str] = Field(None, description="SNMPv3 privacy protocol")
    privacy_key: Optional[str] = Field(None, description="SNMPv3 privacy key")


class SNMPWriteSettings(BaseModel):
    """Model for SNMP Write Settings"""
    enabled: Optional[bool] = Field(None, description="Whether SNMP write is enabled")
    community: Optional[str] = Field(None, description="SNMP write community string")
    version: Optional[str] = Field(None, description="SNMP version (v1, v2c, v3)")
    security_name: Optional[str] = Field(None, description="SNMPv3 security name")
    auth_protocol: Optional[str] = Field(None, description="SNMPv3 authentication protocol")
    auth_key: Optional[str] = Field(None, description="SNMPv3 authentication key")
    privacy_protocol: Optional[str] = Field(None, description="SNMPv3 privacy protocol")
    privacy_key: Optional[str] = Field(None, description="SNMPv3 privacy key")


class RadSecSettings(BaseModel):
    """Model for RadSec (RADIUS over TLS) Settings"""
    enabled: Optional[bool] = Field(None, description="Whether RadSec is enabled")
    port: Optional[int] = Field(None, description="RadSec port number")
    certificate: Optional[str] = Field(None, description="RadSec certificate")
    private_key: Optional[str] = Field(None, description="RadSec private key")
    ca_certificate: Optional[str] = Field(None, description="RadSec CA certificate")
    verify_certificate: Optional[bool] = Field(None, description="Whether to verify peer certificate")


class CLISettings(BaseModel):
    """Model for CLI Configuration Settings"""
    enabled: Optional[bool] = Field(None, description="Whether CLI access is enabled")
    protocol: Optional[str] = Field(None, description="CLI protocol (SSH, Telnet)")
    port: Optional[int] = Field(None, description="CLI port number")
    username: Optional[str] = Field(None, description="CLI username")
    password: Optional[str] = Field(None, description="CLI password")
    enable_password: Optional[str] = Field(None, description="CLI enable password")
    timeout: Optional[int] = Field(None, description="CLI connection timeout")


class OnConnectEnforcementSettings(BaseModel):
    """Model for OnConnect Enforcement Settings"""
    enabled: Optional[bool] = Field(None, description="Whether OnConnect enforcement is enabled")
    action: Optional[str] = Field(None, description="OnConnect enforcement action")
    vlan_id: Optional[int] = Field(None, description="VLAN ID for enforcement")
    user_role: Optional[str] = Field(None, description="User role for enforcement")
    attributes: Optional[Dict[str, Any]] = Field(None, description="Additional enforcement attributes")


class NetworkDeviceTemplate(BaseModel):
    """Model for Network Device Template"""
    template_name: str = Field(..., description="Name of the template")
    template_description: Optional[str] = Field(None, description="Description of the template")
    vendor_name: str = Field(..., description="Default vendor name")
    device_type: Optional[str] = Field(None, description="Device type (switch, ap, router, firewall)")
    default_settings: Optional[Dict[str, Any]] = Field(None, description="Default device settings")
    snmp_read_settings: Optional[SNMPReadSettings] = Field(None, description="Default SNMP read settings")
    snmp_write_settings: Optional[SNMPWriteSettings] = Field(None, description="Default SNMP write settings")
    radsec_settings: Optional[RadSecSettings] = Field(None, description="Default RadSec settings")
    cli_settings: Optional[CLISettings] = Field(None, description="Default CLI settings")
    onconnect_settings: Optional[OnConnectEnforcementSettings] = Field(None, description="Default OnConnect settings")


class EnhancedNetworkDevice(BaseModel):
    """Enhanced model for Network Device with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the network device")
    name: str = Field(..., description="Name of the network device")
    ip_address: str = Field(..., description="IP or Subnet Address of the network device")
    description: Optional[str] = Field(None, description="Description of the network device")
    
    # Authentication and Security
    radius_secret: Optional[str] = Field(None, description="RADIUS Shared Secret")
    tacacs_secret: Optional[str] = Field(None, description="TACACS+ Shared Secret")
    
    # Vendor Information
    vendor_name: Optional[str] = Field(None, description="Vendor Name")
    vendor_id: Optional[int] = Field(None, description="Vendor ID")
    
    # CoA Configuration
    coa_capable: Optional[bool] = Field(None, description="CoA capability flag")
    coa_port: Optional[int] = Field(None, description="CoA port number")
    
    # RadSec Configuration
    radsec_enabled: Optional[bool] = Field(None, description="RadSec enabled flag")
    radsec_config: Optional[RadSecSettings] = Field(None, description="RadSec configuration")
    
    # SNMP Configuration
    snmp_read: Optional[SNMPReadSettings] = Field(None, description="SNMP read settings")
    snmp_write: Optional[SNMPWriteSettings] = Field(None, description="SNMP write settings")
    
    # CLI Configuration
    cli_config: Optional[CLISettings] = Field(None, description="CLI configuration")
    
    # OnConnect Enforcement
    onConnect_enforcement: Optional[OnConnectEnforcementSettings] = Field(None, description="OnConnect enforcement settings")
    
    # Additional Attributes
    attributes: Optional[Dict[str, Any]] = Field(None, description="Additional device attributes")
    template_name: Optional[str] = Field(None, description="Template used to create this device")
    device_group_memberships: Optional[List[str]] = Field(None, description="Device group memberships")
    
    # Status and Monitoring
    status: Optional[str] = Field(None, description="Device status")
    last_seen: Optional[str] = Field(None, description="Last seen timestamp")
    created_date: Optional[str] = Field(None, description="Device creation date")
    last_modified: Optional[str] = Field(None, description="Last modification date")


# =============================================================================
# Operation and Management Models
# =============================================================================

class NetworkDeviceBulkOperation(BaseModel):
    """Model for bulk operations on network devices"""
    device_ids: List[int] = Field(..., description="List of device IDs to operate on")
    operation_type: str = Field(..., description="Type of operation (update, delete, configure)")
    operation_data: Dict[str, Any] = Field(..., description="Data for the operation")
    confirm_operation: bool = Field(False, description="Confirmation flag for destructive operations")


class DeviceConfigurationUpdate(BaseModel):
    """Model for device configuration updates"""
    device_id: int = Field(..., description="ID of the network device")
    configuration_type: str = Field(..., description="Type of configuration (snmp, radsec, cli, onconnect)")
    configuration_data: Dict[str, Any] = Field(..., description="Configuration data")
    validate_before_apply: bool = Field(True, description="Validate configuration before applying")


class DeviceValidationResult(BaseModel):
    """Model for device validation results"""
    device_id: int = Field(..., description="ID of the validated device")
    valid: bool = Field(..., description="Whether the device configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    connectivity_test: Optional[Dict[str, Any]] = Field(None, description="Connectivity test results")
    configuration_test: Optional[Dict[str, Any]] = Field(None, description="Configuration test results")


class DeviceStatistics(BaseModel):
    """Model for device statistics and monitoring"""
    device_id: int = Field(..., description="ID of the network device")
    authentication_stats: Optional[Dict[str, int]] = Field(None, description="Authentication statistics")
    accounting_stats: Optional[Dict[str, int]] = Field(None, description="Accounting statistics")
    coa_stats: Optional[Dict[str, int]] = Field(None, description="CoA statistics")
    snmp_stats: Optional[Dict[str, int]] = Field(None, description="SNMP statistics")
    connection_status: Optional[str] = Field(None, description="Current connection status")
    last_activity: Optional[str] = Field(None, description="Last activity timestamp")


class DeviceDeploymentPlan(BaseModel):
    """Model for device deployment planning"""
    plan_name: str = Field(..., description="Name of the deployment plan")
    devices: List[Dict[str, Any]] = Field(..., description="List of devices to deploy")
    rollback_plan: Optional[Dict[str, Any]] = Field(None, description="Rollback plan if deployment fails")
    validation_required: bool = Field(True, description="Whether validation is required")
    deployment_schedule: Optional[str] = Field(None, description="Scheduled deployment time")


class DeviceBackupConfiguration(BaseModel):
    """Model for device configuration backup"""
    device_id: int = Field(..., description="ID of the network device")
    backup_name: str = Field(..., description="Name of the backup")
    backup_type: str = Field(..., description="Type of backup (full, incremental)")
    backup_data: Dict[str, Any] = Field(..., description="Backup configuration data")
    created_date: Optional[str] = Field(None, description="Backup creation date")
    notes: Optional[str] = Field(None, description="Backup notes")


class DeviceComplianceCheck(BaseModel):
    """Model for device compliance checking"""
    device_id: int = Field(..., description="ID of the network device")
    compliance_policy: str = Field(..., description="Compliance policy to check against")
    compliance_result: Optional[bool] = Field(None, description="Compliance check result")
    violations: Optional[List[str]] = Field(None, description="List of compliance violations")
    recommendations: Optional[List[str]] = Field(None, description="Compliance recommendations")
    check_date: Optional[str] = Field(None, description="Date of compliance check")


# =============================================================================
# Response and Filter Models
# =============================================================================

class NetworkDeviceFilter(BaseModel):
    """Model for filtering network devices"""
    filter_expression: Optional[str] = Field(None, description="JSON filter expression")
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')")
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination")
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)")
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate total count")


class NetworkDeviceResponse(BaseModel):
    """Model for generic network device API responses"""
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Human-readable status message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    total_count: Optional[int] = Field(None, description="Total number of items (if requested)")
    error_details: Optional[str] = Field(None, description="Error details if operation failed")