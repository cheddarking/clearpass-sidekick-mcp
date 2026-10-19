"""
Pydantic models for ClearPass Enforcement Profile operations.

This module provides focused models for the most common enforcement profile
use cases (80% of real-world networking scenarios) with a template-driven approach.
"""

from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field


# ============================================================================
# Core Enforcement Profile Models
# ============================================================================

class ProfileAttribute(BaseModel):
    """Individual attribute within an enforcement profile.

    ``type`` must be a NAMESPACED ClearPass attribute type. A bare ``"RADIUS"``
    is rejected by ClearPass 6.12.4 with
    ``422 Invalid value specified for attribute -> type``. Valid namespaces
    include ``Radius:IETF`` (standard RFC RADIUS attributes),
    ``Radius:Aruba`` / ``Radius:Cisco`` / ... (vendor-specific attributes) and
    ``cpass:HTTP`` (ClearPass internal/HTTP enforcement).
    """
    type: str = Field(
        ...,
        description=(
            "Namespaced attribute type, e.g. 'Radius:IETF' for standard RADIUS "
            "attributes, 'Radius:Aruba' for Aruba VSAs, 'cpass:HTTP' for "
            "ClearPass HTTP enforcement. A bare 'RADIUS' is rejected (422)."
        ),
    )
    name: str = Field(..., description="Name of the attribute")
    value: str = Field(..., description="Value of the attribute")


class TacacsServiceParam(BaseModel):
    """TACACS+ service parameter for enforcement profiles."""
    type: str = Field(..., description="Type of the TACACS+ parameter")
    name: str = Field(..., description="Name of the TACACS+ parameter")
    value: str = Field(..., description="Value of the TACACS+ parameter")


class DURConfig(BaseModel):
    """Downloadable User Role (DUR) configuration element."""
    type: str = Field(..., description="Type of the DUR configuration")
    name: str = Field(..., description="Name of the DUR configuration")
    value: str = Field(..., description="Value of the DUR configuration")


class EnforcementProfile(BaseModel):
    """Complete enforcement profile with all configuration options."""
    id: Optional[int] = Field(None, description="Unique identifier for the enforcement profile")
    name: str = Field(..., description="Name of the enforcement profile")
    description: Optional[str] = Field(None, description="Description of the enforcement profile")
    type: str = Field(..., description="Enforcement profile type")
    agent_template: Optional[str] = Field(None, description="Agent enforcement profile template")
    post_auth_template: Optional[str] = Field(None, description="Post authentication enforcement profile template")
    radius_dyn_authz_template: Optional[str] = Field(None, description="RADIUS dynamic authorization template")
    action: Optional[str] = Field(None, description="Enforcement profile action")
    device_group_list: Optional[List[str]] = Field(None, description="List of device groups")
    attributes: Optional[List[ProfileAttribute]] = Field(None, description="Profile attributes")
    tacacs_service_params: Optional[List[TacacsServiceParam]] = Field(None, description="TACACS+ service parameters")
    dur_config: Optional[List[DURConfig]] = Field(None, description="Downloadable User Role configuration")


class EnforcementProfileSummary(BaseModel):
    """Summary view of enforcement profile for listing operations."""
    id: int = Field(..., description="Unique identifier")
    name: str = Field(..., description="Profile name")
    description: Optional[str] = Field(None, description="Profile description")
    type: str = Field(..., description="Profile type")
    action: Optional[str] = Field(None, description="Profile action")
    device_group_count: Optional[int] = Field(None, description="Number of device groups")
    attribute_count: Optional[int] = Field(None, description="Number of attributes")


# ============================================================================
# Template System Models
# ============================================================================

class ProfileTemplate(BaseModel):
    """Predefined template for common enforcement profile scenarios."""
    name: str = Field(..., description="Template name")
    display_name: str = Field(..., description="Human-readable template name")
    description: str = Field(..., description="Template description and use case")
    category: Literal["user_access", "device_access", "guest_access"] = Field(
        ..., description="Template category"
    )
    profile_type: str = Field(..., description="Enforcement profile type for this template")
    default_attributes: List[ProfileAttribute] = Field(
        default_factory=list, description="Default attributes for this template"
    )
    recommended_qos: Optional[str] = Field(None, description="Recommended QoS profile")
    recommended_acls: Optional[List[str]] = Field(None, description="Recommended ACL rules")
    time_limits: Optional[Dict[str, Any]] = Field(None, description="Time-based restrictions")


class TemplateInstance(BaseModel):
    """Instance of a template being applied to create a profile."""
    template_name: str = Field(..., description="Name of the template to use")
    profile_name: str = Field(..., description="Name for the new profile")
    profile_description: Optional[str] = Field(None, description="Custom description for the profile")
    customizations: Optional[Dict[str, Any]] = Field(
        None, description="Template customizations"
    )


# ============================================================================
# Request/Response Models
# ============================================================================

class CreateEnforcementProfileRequest(BaseModel):
    """Request model for creating enforcement profiles."""
    name: str = Field(..., description="Profile name")
    description: Optional[str] = Field(None, description="Profile description")
    type: str = Field(..., description="Profile type")
    agent_template: Optional[str] = Field(None, description="Agent template")
    post_auth_template: Optional[str] = Field(None, description="Post auth template")
    radius_dyn_authz_template: Optional[str] = Field(None, description="RADIUS template")
    action: Optional[str] = Field(None, description="Profile action")
    device_group_list: Optional[List[str]] = Field(None, description="Device groups")
    attributes: Optional[List[ProfileAttribute]] = Field(None, description="Attributes")
    tacacs_service_params: Optional[List[TacacsServiceParam]] = Field(None, description="TACACS+ params")
    dur_config: Optional[List[DURConfig]] = Field(None, description="DUR configuration")


class UpdateEnforcementProfileRequest(BaseModel):
    """Request model for updating enforcement profiles."""
    name: Optional[str] = Field(None, description="Profile name")
    description: Optional[str] = Field(None, description="Profile description")
    type: Optional[str] = Field(None, description="Profile type")
    agent_template: Optional[str] = Field(None, description="Agent template")
    post_auth_template: Optional[str] = Field(None, description="Post auth template")
    radius_dyn_authz_template: Optional[str] = Field(None, description="RADIUS template")
    action: Optional[str] = Field(None, description="Profile action")
    device_group_list: Optional[List[str]] = Field(None, description="Device groups")
    attributes: Optional[List[ProfileAttribute]] = Field(None, description="Attributes")
    tacacs_service_params: Optional[List[TacacsServiceParam]] = Field(None, description="TACACS+ params")
    dur_config: Optional[List[DURConfig]] = Field(None, description="DUR configuration")


class EnforcementProfileListResponse(BaseModel):
    """Response model for listing enforcement profiles."""
    embedded: Dict[str, List[EnforcementProfileSummary]] = Field(
        ..., description="Embedded profiles list", alias="_embedded"
    )
    count: Optional[int] = Field(None, description="Total count of profiles")


class ValidationResult(BaseModel):
    """Result of enforcement profile validation."""
    is_valid: bool = Field(..., description="Whether the profile configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="Configuration warnings")
    errors: List[str] = Field(default_factory=list, description="Configuration errors")
    conflicts: List[str] = Field(default_factory=list, description="Detected conflicts")
    dependencies: List[str] = Field(default_factory=list, description="Missing dependencies")


# ============================================================================
# Filter and Search Models
# ============================================================================

class EnforcementProfileFilter(BaseModel):
    """Filter criteria for enforcement profile searches."""
    name_contains: Optional[str] = Field(None, description="Filter by name substring")
    type: Optional[str] = Field(None, description="Filter by profile type")
    action: Optional[str] = Field(None, description="Filter by profile action")
    has_attributes: Optional[bool] = Field(None, description="Filter by presence of attributes")
    has_qos: Optional[bool] = Field(None, description="Filter by presence of QoS configuration")
    created_after: Optional[str] = Field(None, description="Filter by creation date")
    template_used: Optional[str] = Field(None, description="Filter by template used")


# ============================================================================
# Predefined Templates Configuration
# ============================================================================

# These templates represent the most common networking scenarios.
#
# Attribute-type namespaces
# -------------------------
# ClearPass 6.12.4 requires every enforcement-profile attribute to carry a
# NAMESPACED type; a bare "RADIUS" is rejected with
# "422 Invalid value specified for attribute -> type".
#
# Every attribute used by these five templates is a standard RFC RADIUS
# attribute, so all of them belong to the IETF dictionary (`Radius:IETF`):
#   Session-Timeout        RFC 2865 attr 27
#   Idle-Timeout           RFC 2865 attr 28
#   Acct-Interim-Interval  RFC 2869 attr 85
#   Tunnel-Type            RFC 2868 attr 64
#   Tunnel-Medium-Type     RFC 2868 attr 65
# A vendor namespace (`Radius:Aruba`, `Radius:Cisco`, ...) would be wrong here:
# those dictionaries contain only that vendor's VSAs and do not define these
# names. `cpass:HTTP` is reserved for ClearPass HTTP enforcement payloads and
# carries no RADIUS attributes at all. The templates deliberately stay
# vendor-neutral so they work on any NAS.
#
# Enumerated values
# -----------------
# ClearPass validates enumerated RADIUS values against its own dictionary
# labels, which carry the numeric code in parentheses. "VLAN", "13" and
# "Virtual LANs (VLAN)" are all rejected with
# "422 Value ... is not one of the allowed values"; the accepted spellings are
# "VLAN (13)" for Tunnel-Type and "IEEE-802 (6)" for Tunnel-Medium-Type
# (verified live on 6.12.4).
PREDEFINED_TEMPLATES = {
    "corporate_employee": ProfileTemplate(
        name="corporate_employee",
        display_name="Corporate Employee",
        description="Standard corporate employee access with 8-hour session timeout and business traffic allowed",
        category="user_access",
        profile_type="RADIUS",
        default_attributes=[
            ProfileAttribute(type="Radius:IETF", name="Session-Timeout", value="28800"),  # 8 hours
            ProfileAttribute(type="Radius:IETF", name="Acct-Interim-Interval", value="300")
        ],
        recommended_qos="Standard-Bandwidth",
        recommended_acls=["Allow-Business-Traffic"],
        time_limits={"session_timeout": 28800, "idle_timeout": None}
    ),
    
    "guest_internet": ProfileTemplate(
        name="guest_internet",
        display_name="Guest Internet Access",
        description="Guest internet access with 4-hour time limit and bandwidth restrictions",
        category="guest_access",
        profile_type="RADIUS",
        default_attributes=[
            ProfileAttribute(type="Radius:IETF", name="Session-Timeout", value="14400"),  # 4 hours
            ProfileAttribute(type="Radius:IETF", name="Idle-Timeout", value="1800")  # 30 minutes
        ],
        recommended_qos="Guest-Limited",
        recommended_acls=["Internet-Only", "Block-Internal-Resources"],
        time_limits={"session_timeout": 14400, "idle_timeout": 1800}
    ),
    
    "contractor_limited": ProfileTemplate(
        name="contractor_limited",
        display_name="Contractor Limited Access",
        description="Contractor access to specific resources with VLAN assignment",
        category="user_access",
        profile_type="RADIUS",
        default_attributes=[
            ProfileAttribute(type="Radius:IETF", name="Session-Timeout", value="28800"),
            ProfileAttribute(type="Radius:IETF", name="Tunnel-Type", value="VLAN (13)"),
            ProfileAttribute(type="Radius:IETF", name="Tunnel-Medium-Type", value="IEEE-802 (6)")
        ],
        recommended_qos="Standard-Bandwidth",
        recommended_acls=["Contractor-Resources-Only"]
    ),
    
    "iot_device": ProfileTemplate(
        name="iot_device",
        display_name="IoT Device Access",
        description="IoT device access with device-to-device communication restrictions",
        category="device_access",
        profile_type="RADIUS",
        default_attributes=[
            ProfileAttribute(type="Radius:IETF", name="Session-Timeout", value="86400"),  # 24 hours
            ProfileAttribute(type="Radius:IETF", name="Tunnel-Type", value="VLAN (13)"),
            ProfileAttribute(type="Radius:IETF", name="Tunnel-Medium-Type", value="IEEE-802 (6)")
        ],
        recommended_qos="IoT-Limited",
        recommended_acls=["IoT-Restricted"]
    ),
    
    "executive_access": ProfileTemplate(
        name="executive_access",
        display_name="Executive Enhanced Access",
        description="Executive access with enhanced privileges and priority bandwidth",
        category="user_access",
        profile_type="RADIUS",
        default_attributes=[
            ProfileAttribute(type="Radius:IETF", name="Session-Timeout", value="43200"),  # 12 hours
            ProfileAttribute(type="Radius:IETF", name="Acct-Interim-Interval", value="300")
        ],
        recommended_qos="High-Priority",
        recommended_acls=["Executive-Enhanced-Access"]
    )
} 