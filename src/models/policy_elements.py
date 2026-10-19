"""
Pydantic models for Policy Elements operations.

This file contains models for all policy elements including roles, role mappings,
enforcement policies, authentication sources, and other ClearPass policy components.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any, Union


# ================================
# ROLES MODELS
# ================================

class Role(BaseModel):
    """Model for a ClearPass Role"""
    id: Optional[int] = Field(None, description="Numeric ID of the role")
    name: str = Field(..., description="Name of the role")
    description: Optional[str] = Field(None, description="Description of the role")


class RoleCreate(BaseModel):
    """Model for creating a new Role"""
    name: str = Field(..., description="Name of the role")
    description: Optional[str] = Field(None, description="Description of the role")


class RoleUpdate(BaseModel):
    """Model for updating an existing Role"""
    name: Optional[str] = Field(None, description="New name of the role")
    description: Optional[str] = Field(None, description="New description of the role")


# ================================
# ROLE MAPPING MODELS
# ================================

class RoleMappingRule(BaseModel):
    """Model for a Role Mapping Rule condition"""
    name: Optional[str] = Field(None, description="Name of the rule")
    condition: Optional[Dict[str, Any]] = Field(None, description="Rule condition expression")
    result: Optional[str] = Field(None, description="Role name to assign when rule matches")
    enabled: Optional[bool] = Field(True, description="Whether the rule is enabled")


class RoleMapping(BaseModel):
    """Model for a ClearPass Role Mapping"""
    id: Optional[int] = Field(None, description="Numeric ID of the role mapping")
    name: str = Field(..., description="Role mapping policy name")
    description: Optional[str] = Field(None, description="Role mapping description")
    default_role_name: str = Field(..., description="Default role name when no rules match")
    rule_combine_algo: str = Field(..., description="Rule evaluation algorithm (e.g., 'first-applicable', 'permit-overrides')")
    rules: List[RoleMappingRule] = Field(..., description="List of role mapping rules")


class RoleMappingCreate(BaseModel):
    """Model for creating a new Role Mapping"""
    name: str = Field(..., description="Role mapping policy name")
    description: Optional[str] = Field(None, description="Role mapping description")
    default_role_name: str = Field(..., description="Default role name when no rules match")
    rule_combine_algo: str = Field(..., description="Rule evaluation algorithm (e.g., 'first-applicable', 'permit-overrides')")
    rules: List[Dict[str, Any]] = Field(..., description="List of role mapping rules in pyclearpass format")


class RoleMappingUpdate(BaseModel):
    """Model for updating an existing Role Mapping"""
    name: Optional[str] = Field(None, description="New role mapping policy name")
    description: Optional[str] = Field(None, description="New role mapping description")
    default_role_name: Optional[str] = Field(None, description="New default role name")
    rule_combine_algo: Optional[str] = Field(None, description="New rule evaluation algorithm")
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="New list of role mapping rules")


# ================================
# ENFORCEMENT POLICY MODELS
# ================================

class EnforcementPolicyRule(BaseModel):
    """Model for an Enforcement Policy Rule"""
    name: Optional[str] = Field(None, description="Name of the enforcement rule")
    description: Optional[str] = Field(None, description="Description of the enforcement rule")
    condition: Optional[Dict[str, Any]] = Field(None, description="Rule condition expression")
    enforcement_profile: Optional[str] = Field(None, description="Enforcement profile to apply when rule matches")
    enabled: Optional[bool] = Field(True, description="Whether the rule is enabled")
    action: Optional[str] = Field(None, description="Action to take when rule matches")


class EnforcementPolicy(BaseModel):
    """Model for a ClearPass Enforcement Policy"""
    id: Optional[int] = Field(None, description="Numeric ID of the enforcement policy")
    name: str = Field(..., description="Name of the enforcement policy")
    description: Optional[str] = Field(None, description="Description of the enforcement policy")
    enforcement_type: str = Field(..., description="Enforcement type (e.g., 'RADIUS', 'SNMP', 'HTTP')")
    default_enforcement_profile: str = Field(..., description="Default enforcement profile for unmatched cases")
    rule_eval_algo: str = Field(..., description="Rule evaluation algorithm (e.g., 'first-applicable', 'permit-overrides')")
    rules: List[EnforcementPolicyRule] = Field(..., description="List of enforcement policy rules")


class EnforcementPolicyCreate(BaseModel):
    """Model for creating a new Enforcement Policy"""
    name: str = Field(..., description="Name of the enforcement policy")
    description: Optional[str] = Field(None, description="Description of the enforcement policy")
    enforcement_type: str = Field(..., description="Enforcement type (e.g., 'RADIUS', 'SNMP', 'HTTP')")
    default_enforcement_profile: str = Field(..., description="Default enforcement profile for unmatched cases")
    rule_eval_algo: str = Field(..., description="Rule evaluation algorithm (e.g., 'first-applicable', 'permit-overrides')")
    rules: List[Dict[str, Any]] = Field(..., description="List of enforcement policy rules in pyclearpass format")


class EnforcementPolicyUpdate(BaseModel):
    """Model for updating an existing Enforcement Policy"""
    name: Optional[str] = Field(None, description="New name of the enforcement policy")
    description: Optional[str] = Field(None, description="New description of the enforcement policy")
    enforcement_type: Optional[str] = Field(None, description="New enforcement type")
    default_enforcement_profile: Optional[str] = Field(None, description="New default enforcement profile")
    rule_eval_algo: Optional[str] = Field(None, description="New rule evaluation algorithm")
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="New list of enforcement policy rules")


# ================================
# AUTHENTICATION SOURCE MODELS
# ================================

class AuthenticationSource(BaseModel):
    """Model for a ClearPass Authentication Source"""
    id: Optional[int] = Field(None, description="Numeric ID of the authentication source")
    name: str = Field(..., description="Name of the authentication source")
    description: Optional[str] = Field(None, description="Description of the authentication source")
    type: str = Field(..., description="Type of the authentication source (e.g., 'Active Directory', 'LDAP', 'Database')")
    use_for_authorization: Optional[bool] = Field(None, description="Enable to use this Authentication Source for authorization")
    authorization_source_names: Optional[List[str]] = Field(None, description="Additional auth-sources from which to fetch role-mapping attributes")
    server_timeout: int = Field(..., description="Timeout if the Authentication source fails to send a response")
    cache_timeout: int = Field(..., description="Duration in seconds for which the attributes are cached")
    cppm_primary_auth_source_connection_details: Optional[Dict[str, Any]] = Field(None, description="Authentication source connection details")


class AuthenticationSourceCreate(BaseModel):
    """Model for creating a new Authentication Source"""
    name: str = Field(..., description="Name of the authentication source")
    description: Optional[str] = Field(None, description="Description of the authentication source")
    type: str = Field(..., description="Type of the authentication source")
    use_for_authorization: Optional[bool] = Field(False, description="Enable to use this Authentication Source for authorization")
    authorization_source_names: Optional[List[str]] = Field(None, description="Additional auth-sources from which to fetch role-mapping attributes")
    server_timeout: int = Field(30, description="Timeout if the Authentication source fails to send a response")
    cache_timeout: int = Field(300, description="Duration in seconds for which the attributes are cached")
    cppm_primary_auth_source_connection_details: Dict[str, Any] = Field(..., description="Authentication source connection details")


class AuthenticationSourceUpdate(BaseModel):
    """Model for updating an existing Authentication Source"""
    name: Optional[str] = Field(None, description="New name of the authentication source")
    description: Optional[str] = Field(None, description="New description of the authentication source")
    type: Optional[str] = Field(None, description="New type of the authentication source")
    use_for_authorization: Optional[bool] = Field(None, description="New authorization usage setting")
    authorization_source_names: Optional[List[str]] = Field(None, description="New list of additional auth-sources")
    server_timeout: Optional[int] = Field(None, description="New server timeout value")
    cache_timeout: Optional[int] = Field(None, description="New cache timeout value")
    cppm_primary_auth_source_connection_details: Optional[Dict[str, Any]] = Field(None, description="New authentication source connection details")


# ================================
# NETWORK DEVICE GROUP MODELS
# ================================

class NetworkDeviceGroup(BaseModel):
    """Model for a ClearPass Network Device Group"""
    id: Optional[int] = Field(None, description="Numeric ID of the network device group")
    name: str = Field(..., description="Name of the network device group")
    description: Optional[str] = Field(None, description="Description of the network device group")
    group_format: str = Field(..., description="Format of the network devices (e.g., 'list', 'range', 'subnet')")
    value: str = Field(..., description="Network devices in the specified format")


class NetworkDeviceGroupCreate(BaseModel):
    """Model for creating a new Network Device Group"""
    name: str = Field(..., description="Name of the network device group")
    description: Optional[str] = Field(None, description="Description of the network device group")
    group_format: str = Field(..., description="Format of the network devices (e.g., 'list', 'range', 'subnet')")
    value: str = Field(..., description="Network devices in the specified format")


class NetworkDeviceGroupUpdate(BaseModel):
    """Model for updating an existing Network Device Group"""
    name: Optional[str] = Field(None, description="New name of the network device group")
    description: Optional[str] = Field(None, description="New description of the network device group")
    group_format: Optional[str] = Field(None, description="New format of the network devices")
    value: Optional[str] = Field(None, description="New network devices in the specified format")


# ================================
# POSTURE POLICY MODELS
# ================================

class PosturePolicy(BaseModel):
    """Model for a ClearPass Posture Policy"""
    id: Optional[int] = Field(None, description="Numeric ID of the posture policy")
    name: str = Field(..., description="Name of the posture policy")
    description: Optional[str] = Field(None, description="Description of the posture policy")
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="List of posture policy rules")
    rule_combine_algo: Optional[str] = Field(None, description="Rule evaluation algorithm")
    default_posture_token: Optional[str] = Field(None, description="Default posture token for non-compliant endpoints")


class PosturePolicyCreate(BaseModel):
    """Model for creating a new Posture Policy"""
    name: str = Field(..., description="Name of the posture policy")
    description: Optional[str] = Field(None, description="Description of the posture policy")
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="List of posture policy rules in pyclearpass format")
    rule_combine_algo: Optional[str] = Field(None, description="Rule evaluation algorithm")
    default_posture_token: Optional[str] = Field(None, description="Default posture token for non-compliant endpoints")


class PosturePolicyUpdate(BaseModel):
    """Model for updating an existing Posture Policy"""
    name: Optional[str] = Field(None, description="New name of the posture policy")
    description: Optional[str] = Field(None, description="New description of the posture policy")
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="New list of posture policy rules")
    rule_combine_algo: Optional[str] = Field(None, description="New rule evaluation algorithm")
    default_posture_token: Optional[str] = Field(None, description="New default posture token")


# =============================================================================
# ENHANCED POSTURE POLICY MODELS (Chunk 4.1)
# =============================================================================

class PostureRule(BaseModel):
    """Model for a Posture Policy Rule"""
    rule_name: str = Field(..., description="Name of the posture rule")
    rule_type: str = Field(..., description="Type of posture rule (e.g., 'file_exists', 'registry_key', 'process_running')")
    condition: str = Field(..., description="Rule condition expression")
    remediation_action: Optional[str] = Field(None, description="Remediation action to take if rule fails")
    enabled: bool = Field(True, description="Whether the rule is enabled")
    severity: Optional[str] = Field(None, description="Rule severity level (low, medium, high, critical)")


class ComplianceCheck(BaseModel):
    """Model for endpoint compliance checking"""
    check_id: Optional[int] = Field(None, description="ID of the compliance check")
    check_name: str = Field(..., description="Name of the compliance check")
    check_type: str = Field(..., description="Type of check (antivirus, patch, configuration)")
    check_criteria: Dict[str, Any] = Field(..., description="Criteria for the compliance check")
    required: bool = Field(True, description="Whether this check is required for compliance")
    weight: Optional[float] = Field(None, description="Weight of this check in overall compliance score")


class RemediationAction(BaseModel):
    """Model for remediation actions"""
    action_id: Optional[int] = Field(None, description="ID of the remediation action")
    action_name: str = Field(..., description="Name of the remediation action")
    action_type: str = Field(..., description="Type of action (quarantine, redirect, download, install)")
    action_details: Dict[str, Any] = Field(..., description="Details and parameters for the action")
    automated: bool = Field(False, description="Whether the action is automated")
    user_interaction_required: bool = Field(True, description="Whether user interaction is required")


class PosturePolicyTemplate(BaseModel):
    """Model for Posture Policy Template"""
    template_name: str = Field(..., description="Name of the template")
    template_description: Optional[str] = Field(None, description="Description of the template")
    target_os: str = Field(..., description="Target operating system (Windows, macOS, Linux)")
    default_rules: List[PostureRule] = Field(..., description="Default rules for this template")
    default_compliance_checks: List[ComplianceCheck] = Field(..., description="Default compliance checks")
    default_remediation_actions: List[RemediationAction] = Field(..., description="Default remediation actions")
    compliance_threshold: Optional[float] = Field(None, description="Minimum compliance score threshold")


class EnhancedPosturePolicy(BaseModel):
    """Enhanced model for Posture Policy with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the posture policy")
    name: str = Field(..., description="Name of the posture policy")
    description: Optional[str] = Field(None, description="Description of the posture policy")
    
    # Core ClearPass fields (based on pyclearpass)
    posture_agent: Optional[str] = Field(None, description="Posture Agent configuration")
    host_os: Optional[str] = Field(None, description="Host Operating System")
    plugin_version: Optional[str] = Field(None, description="Plugin Version")
    roles: Optional[List[str]] = Field(None, description="Restrict by Roles")
    policy_xml: Optional[str] = Field(None, description="Posture Policy XML")
    
    # Enhanced features
    rules: Optional[List[PostureRule]] = Field(None, description="Enhanced posture rules")
    compliance_checks: Optional[List[ComplianceCheck]] = Field(None, description="Compliance checks")
    remediation_actions: Optional[List[RemediationAction]] = Field(None, description="Remediation actions")
    rule_combine_algo: Optional[str] = Field(None, description="Rule evaluation algorithm")
    default_posture_token: Optional[str] = Field(None, description="Default posture token")
    compliance_threshold: Optional[float] = Field(None, description="Minimum compliance score")
    template_name: Optional[str] = Field(None, description="Template used to create this policy")
    
    # Monitoring and Statistics
    usage_statistics: Optional[Dict[str, int]] = Field(None, description="Usage statistics")
    last_modified: Optional[str] = Field(None, description="Last modification timestamp")
    created_date: Optional[str] = Field(None, description="Creation timestamp")


class PosturePolicyValidationResult(BaseModel):
    """Model for posture policy validation results"""
    policy_id: int = Field(..., description="ID of the validated policy")
    valid: bool = Field(..., description="Whether the policy configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    rule_conflicts: Optional[List[Dict[str, Any]]] = Field(None, description="List of rule conflicts")
    compliance_coverage: Optional[float] = Field(None, description="Percentage of compliance areas covered")
    suggestions: Optional[List[str]] = Field(None, description="List of improvement suggestions")


class PosturePolicyStatistics(BaseModel):
    """Model for posture policy statistics"""
    policy_id: int = Field(..., description="ID of the posture policy")
    total_evaluations: int = Field(..., description="Total number of policy evaluations")
    compliant_endpoints: Optional[int] = Field(None, description="Number of compliant endpoints")
    non_compliant_endpoints: Optional[int] = Field(None, description="Number of non-compliant endpoints")
    rule_statistics: Optional[Dict[str, int]] = Field(None, description="Statistics by rule")
    remediation_statistics: Optional[Dict[str, int]] = Field(None, description="Remediation action statistics")
    compliance_trend: Optional[List[Dict[str, Any]]] = Field(None, description="Compliance trend over time")
    last_evaluation: Optional[str] = Field(None, description="Last evaluation timestamp")


class PosturePolicyDeployment(BaseModel):
    """Model for posture policy deployment"""
    deployment_name: str = Field(..., description="Name of the deployment")
    policy_ids: List[int] = Field(..., description="List of policy IDs to deploy")
    target_groups: List[str] = Field(..., description="Target device/user groups")
    deployment_schedule: Optional[str] = Field(None, description="Scheduled deployment time")
    rollback_plan: Optional[Dict[str, Any]] = Field(None, description="Rollback plan")
    validation_required: bool = Field(True, description="Whether validation is required")
    test_mode: bool = Field(False, description="Deploy in test mode first")


# =============================================================================
# RADIUS Dynamic Authorization Template Models (Chunk 4.2)
# =============================================================================

class RADIUSAttribute(BaseModel):
    """Model for RADIUS Dynamic Authorization Template Attribute"""
    name: str = Field(..., description="RADIUS attribute name")
    value: Optional[str] = Field(None, description="RADIUS attribute value")
    type: str = Field(..., description="RADIUS attribute type (e.g., 'string', 'integer', 'ipaddr')")
    input_required: Optional[str] = Field(None, description="Whether input is required for this attribute")
    vendor_specific: Optional[bool] = Field(False, description="Whether this is a vendor-specific attribute")
    vendor_id: Optional[int] = Field(None, description="Vendor ID for vendor-specific attributes")


class CoAAction(BaseModel):
    """Model for Change of Authorization (CoA) Action"""
    action_type: str = Field(..., description="Type of CoA action (disconnect, coa-request, dm-request)")
    action_description: Optional[str] = Field(None, description="Description of the action")
    attributes: List[RADIUSAttribute] = Field(..., description="RADIUS attributes for the CoA action")
    target_session: Optional[str] = Field(None, description="Target session identifier")
    timeout: Optional[int] = Field(30, description="Timeout for the CoA action in seconds")


class DynamicAuthRule(BaseModel):
    """Model for Dynamic Authorization Rule"""
    rule_name: str = Field(..., description="Name of the dynamic authorization rule")
    condition: str = Field(..., description="Rule condition expression")
    action: CoAAction = Field(..., description="CoA action to execute when rule matches")
    enabled: bool = Field(True, description="Whether the rule is enabled")
    priority: Optional[int] = Field(None, description="Rule priority order")


class RADIUSCoATemplate(BaseModel):
    """Model for RADIUS Change of Authorization Template"""
    id: Optional[int] = Field(None, description="Numeric ID of the RADIUS Dynamic Authorization Template")
    name: str = Field(..., description="Name of the RADIUS Dynamic Authorization Template")
    display_name: str = Field(..., description="Display name of the template")
    description: Optional[str] = Field(None, description="Description of the template")
    vendor_name: str = Field(..., description="Vendor name for the template")
    template_type: str = Field(..., description="Template type (e.g., 'CoA', 'Disconnect', 'Custom')")
    attributes: List[RADIUSAttribute] = Field(..., description="List of RADIUS attributes in the template")


class RADIUSCoATemplateCreate(BaseModel):
    """Model for creating a new RADIUS Dynamic Authorization Template"""
    name: str = Field(..., description="Name of the RADIUS Dynamic Authorization Template")
    display_name: str = Field(..., description="Display name of the template")
    description: Optional[str] = Field(None, description="Description of the template")
    vendor_name: str = Field(..., description="Vendor name for the template")
    template_type: str = Field(..., description="Template type (e.g., 'CoA', 'Disconnect', 'Custom')")
    attributes: List[Dict[str, Any]] = Field(..., description="List of RADIUS attributes in pyclearpass format")


class RADIUSCoATemplateUpdate(BaseModel):
    """Model for updating an existing RADIUS Dynamic Authorization Template"""
    name: Optional[str] = Field(None, description="New name of the template")
    display_name: Optional[str] = Field(None, description="New display name of the template")
    description: Optional[str] = Field(None, description="New description of the template")
    vendor_name: Optional[str] = Field(None, description="New vendor name for the template")
    template_type: Optional[str] = Field(None, description="New template type")
    attributes: Optional[List[Dict[str, Any]]] = Field(None, description="New list of RADIUS attributes")


class EnhancedRADIUSCoATemplate(BaseModel):
    """Enhanced model for RADIUS Dynamic Authorization Template with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the template")
    name: str = Field(..., description="Name of the template")
    display_name: str = Field(..., description="Display name of the template")
    description: Optional[str] = Field(None, description="Description of the template")
    vendor_name: str = Field(..., description="Vendor name for the template")
    template_type: str = Field(..., description="Template type")
    attributes: List[RADIUSAttribute] = Field(..., description="Enhanced RADIUS attributes")
    
    # Enhanced features
    dynamic_rules: Optional[List[DynamicAuthRule]] = Field(None, description="Dynamic authorization rules")
    enforcement_policies: Optional[List[str]] = Field(None, description="Associated enforcement policies")
    usage_statistics: Optional[Dict[str, int]] = Field(None, description="Template usage statistics")
    test_results: Optional[Dict[str, Any]] = Field(None, description="Template testing results")
    deployment_status: Optional[str] = Field(None, description="Deployment status")
    created_date: Optional[str] = Field(None, description="Creation timestamp")
    last_modified: Optional[str] = Field(None, description="Last modification timestamp")


class CoATemplateValidationResult(BaseModel):
    """Model for CoA template validation results"""
    template_id: int = Field(..., description="ID of the validated template")
    valid: bool = Field(..., description="Whether the template configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    attribute_validation: Optional[Dict[str, str]] = Field(None, description="Attribute-specific validation results")
    compatibility_issues: Optional[List[str]] = Field(None, description="Vendor compatibility issues")
    suggestions: Optional[List[str]] = Field(None, description="Improvement suggestions")


class CoATemplateStatistics(BaseModel):
    """Model for CoA template usage statistics"""
    template_id: int = Field(..., description="ID of the CoA template")
    total_executions: int = Field(..., description="Total number of template executions")
    successful_executions: Optional[int] = Field(None, description="Number of successful executions")
    failed_executions: Optional[int] = Field(None, description="Number of failed executions")
    execution_statistics: Optional[Dict[str, int]] = Field(None, description="Statistics by execution type")
    device_statistics: Optional[Dict[str, int]] = Field(None, description="Statistics by device vendor")
    performance_metrics: Optional[Dict[str, float]] = Field(None, description="Performance metrics")
    last_execution: Optional[str] = Field(None, description="Last execution timestamp")


class CoATemplateDeployment(BaseModel):
    """Model for CoA template deployment"""
    deployment_name: str = Field(..., description="Name of the deployment")
    template_ids: List[int] = Field(..., description="List of template IDs to deploy")
    target_devices: List[str] = Field(..., description="Target device groups or individual devices")
    deployment_schedule: Optional[str] = Field(None, description="Scheduled deployment time")
    rollback_plan: Optional[Dict[str, Any]] = Field(None, description="Rollback plan")
    validation_required: bool = Field(True, description="Whether validation is required")
    test_mode: bool = Field(False, description="Deploy in test mode first")


class CoASessionTarget(BaseModel):
    """Model for CoA session targeting"""
    session_id: Optional[str] = Field(None, description="Session ID to target")
    username: Optional[str] = Field(None, description="Username to target")
    calling_station_id: Optional[str] = Field(None, description="Calling Station ID (MAC address)")
    framed_ip_address: Optional[str] = Field(None, description="Framed IP address")
    nas_ip_address: Optional[str] = Field(None, description="NAS IP address")
    additional_attributes: Optional[Dict[str, str]] = Field(None, description="Additional targeting attributes")


class CoAExecutionResult(BaseModel):
    """Model for CoA execution results"""
    execution_id: Optional[str] = Field(None, description="Unique execution ID")
    template_id: int = Field(..., description="ID of the executed template")
    target_session: CoASessionTarget = Field(..., description="Target session information")
    execution_status: str = Field(..., description="Execution status (success, failed, timeout)")
    response_code: Optional[int] = Field(None, description="RADIUS response code")
    response_message: Optional[str] = Field(None, description="Response message")
    execution_time: Optional[float] = Field(None, description="Execution time in seconds")
    executed_attributes: Optional[List[RADIUSAttribute]] = Field(None, description="Attributes that were executed")
    error_details: Optional[str] = Field(None, description="Error details if execution failed")
    execution_timestamp: Optional[str] = Field(None, description="Execution timestamp")


# ================================
# CONFIGURATION SERVICE MODELS  
# ================================

class ConfigurationService(BaseModel):
    """Model for a ClearPass Configuration Service"""
    id: Optional[int] = Field(None, description="Numeric ID of the configuration service")
    name: str = Field(..., description="Name of the configuration service")
    description: Optional[str] = Field(None, description="Description of the configuration service")
    template: str = Field(..., description="Template of the service (e.g., 'RADIUS', 'TACACS+', 'HTTP')")
    enabled: Optional[bool] = Field(None, description="Whether the service is enabled")
    order_no: Optional[int] = Field(None, description="Order number of the service")
    monitor_mode: Optional[bool] = Field(None, description="Enable to monitor network access without enforcement")
    rules_match_type: Optional[str] = Field(None, description="Matches ANY/ALL of the rule conditions")
    enf_policy: str = Field(..., description="Enforcement policy name for the service")
    role_mapping_policy: Optional[str] = Field(None, description="Role mapping policy name")


class ConfigurationServiceCreate(BaseModel):
    """Model for creating a new Configuration Service"""
    name: str = Field(..., description="Name of the configuration service")
    description: Optional[str] = Field(None, description="Description of the configuration service")
    template: str = Field(..., description="Template of the service (e.g., 'RADIUS', 'TACACS+', 'HTTP')")
    enabled: Optional[bool] = Field(True, description="Whether the service should be enabled")
    order_no: Optional[int] = Field(None, description="Order number of the service")
    monitor_mode: Optional[bool] = Field(False, description="Enable to monitor network access without enforcement")
    rules_match_type: Optional[str] = Field("ANY", description="Matches ANY/ALL of the rule conditions")
    enf_policy: str = Field(..., description="Enforcement policy name for the service")
    role_mapping_policy: Optional[str] = Field(None, description="Role mapping policy name")
    rules_conditions: Optional[List[Dict[str, Any]]] = Field(None, description="List of service rule conditions")
    auth_methods: Optional[List[Dict[str, Any]]] = Field(None, description="List of authentication methods")
    auth_sources: Optional[List[Dict[str, Any]]] = Field(None, description="List of authentication sources")


class ConfigurationServiceUpdate(BaseModel):
    """Model for updating an existing Configuration Service"""
    name: Optional[str] = Field(None, description="New name of the configuration service")
    description: Optional[str] = Field(None, description="New description of the configuration service")
    template: Optional[str] = Field(None, description="New template of the service")
    enabled: Optional[bool] = Field(None, description="New enabled status")
    order_no: Optional[int] = Field(None, description="New order number of the service")
    monitor_mode: Optional[bool] = Field(None, description="New monitor mode setting")
    rules_match_type: Optional[str] = Field(None, description="New rule matching type")
    enf_policy: Optional[str] = Field(None, description="New enforcement policy name")
    role_mapping_policy: Optional[str] = Field(None, description="New role mapping policy name")
    rules_conditions: Optional[List[Dict[str, Any]]] = Field(None, description="New list of service rule conditions")
    auth_methods: Optional[List[Dict[str, Any]]] = Field(None, description="New list of authentication methods")
    auth_sources: Optional[List[Dict[str, Any]]] = Field(None, description="New list of authentication sources")


# ================================
# TACACS SERVICE DICTIONARY MODELS
# ================================

class TacacsServiceDictionary(BaseModel):
    """Model for a ClearPass TACACS+ Service Dictionary"""
    id: Optional[int] = Field(None, description="Numeric ID of the TACACS+ service dictionary")
    name: str = Field(..., description="Name of the TACACS+ service dictionary")
    description: Optional[str] = Field(None, description="Description of the TACACS+ service dictionary")
    tacacs_service: str = Field(..., description="TACACS+ service name")
    tacacs_protocol: str = Field(..., description="TACACS+ protocol")
    attributes: Optional[List[Dict[str, Any]]] = Field(None, description="List of TACACS+ attributes")


class TacacsServiceDictionaryCreate(BaseModel):
    """Model for creating a new TACACS+ Service Dictionary"""
    name: str = Field(..., description="Name of the TACACS+ service dictionary")
    description: Optional[str] = Field(None, description="Description of the TACACS+ service dictionary")
    tacacs_service: str = Field(..., description="TACACS+ service name")
    tacacs_protocol: str = Field(..., description="TACACS+ protocol")
    attributes: Optional[List[Dict[str, Any]]] = Field(None, description="List of TACACS+ attributes")


class TacacsServiceDictionaryUpdate(BaseModel):
    """Model for updating an existing TACACS+ Service Dictionary"""
    name: Optional[str] = Field(None, description="New name of the TACACS+ service dictionary")
    description: Optional[str] = Field(None, description="New description of the TACACS+ service dictionary")
    tacacs_service: Optional[str] = Field(None, description="New TACACS+ service name")
    tacacs_protocol: Optional[str] = Field(None, description="New TACACS+ protocol")
    attributes: Optional[List[Dict[str, Any]]] = Field(None, description="New list of TACACS+ attributes")


# ================================
# SHARED MODELS
# ================================

class PolicyElementFilter(BaseModel):
    """Model for filtering policy elements"""
    filter_expression: Optional[str] = Field(None, description="JSON filter expression")
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')")
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination")
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)")
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate total count")


class PolicyElementResponse(BaseModel):
    """Model for generic policy element API responses"""
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Human-readable status message")
    data: Optional[Dict[str, Any]] = Field(None, description="Response data")
    total_count: Optional[int] = Field(None, description="Total number of items (if requested)")
    error_details: Optional[str] = Field(None, description="Error details if operation failed")


# =============================================================================
# Authentication Methods Models (Chunk 2.1)
# =============================================================================

class AuthMethodDetails(BaseModel):
    """Model for Authentication Method Details"""
    # This covers EAP-specific configuration
    eap_type: Optional[str] = Field(None, description="EAP type (e.g., 'PEAP', 'TLS', 'TTLS', 'FAST')")
    server_cert: Optional[str] = Field(None, description="Server certificate for EAP-TLS")
    ca_cert: Optional[str] = Field(None, description="Certificate Authority certificate")
    private_key: Optional[str] = Field(None, description="Private key for EAP-TLS")
    anonymous_identity: Optional[str] = Field(None, description="Anonymous identity for EAP tunneling methods")
    trust_all_certs: Optional[bool] = Field(None, description="Trust all certificates")
    validate_cert_cn: Optional[bool] = Field(None, description="Validate certificate Common Name")
    use_pac: Optional[bool] = Field(None, description="Use Protected Access Credential (PAC) for EAP-FAST")
    pac_provisioning: Optional[str] = Field(None, description="PAC provisioning mode (manual/automatic)")
    # Additional configuration options
    config: Optional[Dict[str, Any]] = Field(None, description="Additional method-specific configuration")


class AuthMethodInnerMethod(BaseModel):
    """Model for Inner Authentication Method"""
    method_name: str = Field(..., description="Name of the inner authentication method")
    method_type: str = Field(..., description="Type of the inner method")
    priority: Optional[int] = Field(None, description="Priority order for inner method")


class AuthenticationMethod(BaseModel):
    """Model for a ClearPass Authentication Method"""
    id: Optional[int] = Field(None, description="Numeric ID of the authentication method")
    name: str = Field(..., description="Name of the authentication method")
    description: Optional[str] = Field(None, description="Description of the authentication method")
    method_type: str = Field(..., description="Type of the authentication method (e.g., 'EAP-TLS', 'EAP-PEAP', 'EAP-TTLS')")
    details: Optional[AuthMethodDetails] = Field(None, description="Detailed configuration for the authentication method")
    inner_methods: Optional[List[AuthMethodInnerMethod]] = Field(None, description="List of inner authentication methods for tunneled EAP types")


class AuthenticationMethodCreate(BaseModel):
    """Model for creating a new Authentication Method"""
    name: str = Field(..., description="Name of the authentication method")
    method_type: str = Field(..., description="Type of the authentication method (e.g., 'EAP-TLS', 'EAP-PEAP', 'EAP-TTLS', 'PAP', 'CHAP')")
    description: Optional[str] = Field(None, description="Description of the authentication method")
    details: Optional[Dict[str, Any]] = Field(None, description="Method-specific configuration details in pyclearpass format")
    inner_methods: Optional[List[Dict[str, Any]]] = Field(None, description="List of inner methods in pyclearpass format")


class AuthenticationMethodUpdate(BaseModel):
    """Model for updating an existing Authentication Method"""
    name: Optional[str] = Field(None, description="New name of the authentication method")
    description: Optional[str] = Field(None, description="New description of the authentication method")
    method_type: Optional[str] = Field(None, description="New type of the authentication method")
    details: Optional[Dict[str, Any]] = Field(None, description="New method-specific configuration details")
    inner_methods: Optional[List[Dict[str, Any]]] = Field(None, description="New list of inner methods")


# =============================================================================
# Enhanced Authentication Sources Models (Chunk 2.2)
# =============================================================================

class AuthSourceConnectionDetails(BaseModel):
    """Model for Authentication Source Connection Details"""
    server_type: Optional[str] = Field(None, description="Server type (e.g., 'Active Directory', 'LDAP')")
    server_name: Optional[str] = Field(None, description="Primary server hostname or IP")
    port: Optional[int] = Field(None, description="Server port number")
    bind_dn: Optional[str] = Field(None, description="Bind DN for LDAP/AD connection")
    bind_password: Optional[str] = Field(None, description="Bind password (write-only)")
    search_base: Optional[str] = Field(None, description="Search base DN")
    search_filter: Optional[str] = Field(None, description="Search filter")
    ssl_enabled: Optional[bool] = Field(None, description="Enable SSL/TLS connection")
    ssl_cert: Optional[str] = Field(None, description="SSL certificate")


class AuthSourceBackupConnection(BaseModel):
    """Model for Authentication Source Backup Connection"""
    server_name: str = Field(..., description="Backup server hostname or IP")
    port: Optional[int] = Field(None, description="Backup server port number")
    priority: Optional[int] = Field(None, description="Priority order for backup servers")
    enabled: Optional[bool] = Field(True, description="Whether this backup is enabled")


class AuthSourceRADIUSAttribute(BaseModel):
    """Model for Authentication Source RADIUS Attributes"""
    attribute_name: str = Field(..., description="RADIUS attribute name")
    attribute_value: Optional[str] = Field(None, description="RADIUS attribute value")
    vendor_id: Optional[int] = Field(None, description="Vendor-specific attribute ID")
    attribute_type: Optional[str] = Field(None, description="Attribute type (e.g., 'string', 'integer')")


class AuthSourceFilter(BaseModel):
    """Model for Authentication Source Filters"""
    filter_name: str = Field(..., description="Name of the filter")
    filter_expression: str = Field(..., description="Filter expression/rule")
    filter_type: Optional[str] = Field(None, description="Type of filter (e.g., 'user', 'group')")
    enabled: Optional[bool] = Field(True, description="Whether this filter is enabled")


class EnhancedAuthenticationSource(BaseModel):
    """Enhanced model for Authentication Source with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the authentication source")
    name: str = Field(..., description="Name of the authentication source")
    description: Optional[str] = Field(None, description="Description of the authentication source")
    type: str = Field(..., description="Type of the authentication source")
    use_for_authorization: Optional[bool] = Field(None, description="Enable to use this source for authorization")
    authorization_source_names: Optional[List[str]] = Field(None, description="Additional auth-sources for role-mapping")
    server_timeout: int = Field(..., description="Server timeout in seconds")
    cache_timeout: int = Field(..., description="Cache timeout in seconds")
    
    # Enhanced features
    connection_details: Optional[AuthSourceConnectionDetails] = Field(None, description="Primary connection details")
    backup_connections: Optional[List[AuthSourceBackupConnection]] = Field(None, description="Backup server connections")
    radius_attributes: Optional[List[AuthSourceRADIUSAttribute]] = Field(None, description="RADIUS attributes configuration")
    filters: Optional[List[AuthSourceFilter]] = Field(None, description="Authentication source filters")


class AuthSourceConnectionTest(BaseModel):
    """Model for testing authentication source connections"""
    auth_source_id: int = Field(..., description="ID of the authentication source to test")
    test_username: Optional[str] = Field(None, description="Test username for connection validation")
    test_password: Optional[str] = Field(None, description="Test password for connection validation")
    connection_type: Optional[str] = Field("primary", description="Connection type to test ('primary' or 'backup')")


class AuthSourceBackupConfiguration(BaseModel):
    """Model for configuring authentication source backups"""
    auth_source_id: int = Field(..., description="ID of the authentication source")
    backup_connections: List[AuthSourceBackupConnection] = Field(..., description="List of backup connections")
    failover_enabled: Optional[bool] = Field(True, description="Enable automatic failover to backup servers")
    failover_timeout: Optional[int] = Field(30, description="Timeout before failover in seconds")


class AuthSourceFilterConfiguration(BaseModel):
    """Model for configuring authentication source filters"""
    auth_source_id: int = Field(..., description="ID of the authentication source")
    filters: List[AuthSourceFilter] = Field(..., description="List of authentication filters")
    filter_logic: Optional[str] = Field("AND", description="Logic for combining filters (AND/OR)")


# =============================================================================
# Enhanced Network Device Groups Models (Chunk 3.1)
# =============================================================================

class DeviceGroupMember(BaseModel):
    """Model for Network Device Group Member"""
    device_id: Optional[int] = Field(None, description="ID of the network device")
    device_name: Optional[str] = Field(None, description="Name of the network device")
    device_ip: Optional[str] = Field(None, description="IP address of the network device")
    added_date: Optional[str] = Field(None, description="Date when device was added to group")
    status: Optional[str] = Field(None, description="Status of the device in group")


class GroupPolicyAssignment(BaseModel):
    """Model for Policy Assignment to Network Device Group"""
    group_id: int = Field(..., description="ID of the network device group")
    policy_type: str = Field(..., description="Type of policy (e.g., 'enforcement', 'role_mapping', 'posture')")
    policy_name: str = Field(..., description="Name of the policy to assign")
    priority: Optional[int] = Field(None, description="Priority order for policy application")
    enabled: Optional[bool] = Field(True, description="Whether this policy assignment is enabled")


class NetworkDeviceGroupTemplate(BaseModel):
    """Model for Network Device Group Template"""
    template_name: str = Field(..., description="Name of the template")
    template_description: Optional[str] = Field(None, description="Description of the template")
    group_format: str = Field(..., description="Default group format for template")
    default_policies: Optional[List[GroupPolicyAssignment]] = Field(None, description="Default policy assignments")
    configuration_settings: Optional[Dict[str, Any]] = Field(None, description="Template configuration settings")
    device_type: Optional[str] = Field(None, description="Target device type (e.g., 'switch', 'ap', 'router')")


class EnhancedNetworkDeviceGroup(BaseModel):
    """Enhanced model for Network Device Group with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the network device group")
    name: str = Field(..., description="Name of the network device group")
    description: Optional[str] = Field(None, description="Description of the network device group")
    group_format: str = Field(..., description="Format of the network devices")
    value: str = Field(..., description="Network devices in the specified format")
    
    # Enhanced features
    members: Optional[List[DeviceGroupMember]] = Field(None, description="List of group members")
    policy_assignments: Optional[List[GroupPolicyAssignment]] = Field(None, description="Assigned policies")
    parent_group_id: Optional[int] = Field(None, description="Parent group ID for hierarchical structure")
    child_group_ids: Optional[List[int]] = Field(None, description="List of child group IDs")
    device_count: Optional[int] = Field(None, description="Number of devices in group")
    template_name: Optional[str] = Field(None, description="Template used to create this group")
    created_date: Optional[str] = Field(None, description="Date when group was created")
    last_modified: Optional[str] = Field(None, description="Date when group was last modified")


class DeviceGroupBulkOperation(BaseModel):
    """Model for bulk operations on network device groups"""
    group_ids: List[int] = Field(..., description="List of group IDs to operate on")
    operation_type: str = Field(..., description="Type of operation (update, delete, assign_policy)")
    operation_data: Dict[str, Any] = Field(..., description="Data for the operation")
    confirm_operation: bool = Field(False, description="Confirmation flag for destructive operations")


class DeviceGroupMembershipUpdate(BaseModel):
    """Model for updating device group membership"""
    group_id: int = Field(..., description="ID of the network device group")
    devices_to_add: Optional[List[str]] = Field(None, description="List of device IPs/names to add")
    devices_to_remove: Optional[List[str]] = Field(None, description="List of device IPs/names to remove")
    update_mode: str = Field("append", description="Update mode: 'append', 'replace', 'remove'")


class GroupValidationResult(BaseModel):
    """Model for group validation results"""
    group_id: int = Field(..., description="ID of the validated group")
    valid: bool = Field(..., description="Whether the group configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    conflicts: Optional[List[Dict[str, Any]]] = Field(None, description="List of conflicts with other groups")
    suggestions: Optional[List[str]] = Field(None, description="List of improvement suggestions")


class DeviceGroupStatistics(BaseModel):
    """Model for device group statistics"""
    group_id: int = Field(..., description="ID of the network device group")
    total_devices: int = Field(..., description="Total number of devices in group")
    active_devices: Optional[int] = Field(None, description="Number of active devices")
    device_types: Optional[Dict[str, int]] = Field(None, description="Count by device type")
    policy_usage: Optional[Dict[str, int]] = Field(None, description="Count by assigned policies")
    last_activity: Optional[str] = Field(None, description="Last activity timestamp")


# =============================================================================
# Application Dictionary Models (Phase 5, Chunk 5.1)
# =============================================================================

class AppAttribute(BaseModel):
    """Model for Application Dictionary Attribute"""
    attr_name: str = Field(..., description="Application Dictionary Attribute Name")
    attr_type: str = Field(..., description="Application Dictionary Attribute Type (e.g., 'string', 'integer', 'boolean')")
    allowed_values: Optional[str] = Field(None, description="Allowed Values for Application Dictionary Attributes in CSV format")


class ApplicationDictionary(BaseModel):
    """Model for a ClearPass Application Dictionary"""
    id: Optional[int] = Field(None, description="Numeric ID of the application dictionary")
    name: str = Field(..., description="Name of the Application Dictionary")
    description: Optional[str] = Field(None, description="Description of the Application Dictionary")
    attributes: List[AppAttribute] = Field(..., description="List of Application Dictionary Attributes")


class ApplicationDictionaryCreate(BaseModel):
    """Model for creating a new Application Dictionary"""
    name: str = Field(..., description="Name of the Application Dictionary (must be unique)")
    description: Optional[str] = Field(None, description="Description of the Application Dictionary")
    attributes: List[Dict[str, Any]] = Field(..., description="List of Application Dictionary Attributes in pyclearpass format")


class ApplicationDictionaryUpdate(BaseModel):
    """Model for updating an existing Application Dictionary"""
    name: Optional[str] = Field(None, description="New name of the Application Dictionary")
    description: Optional[str] = Field(None, description="New description of the Application Dictionary")
    attributes: Optional[List[Dict[str, Any]]] = Field(None, description="New list of Application Dictionary Attributes")


class AppIdentificationRule(BaseModel):
    """Model for Application Identification Rule"""
    rule_name: str = Field(..., description="Name of the application identification rule")
    rule_expression: str = Field(..., description="Rule expression for application identification")
    application_category: Optional[str] = Field(None, description="Category of the application")
    priority: Optional[int] = Field(None, description="Priority order for rule evaluation")
    enabled: bool = Field(True, description="Whether the rule is enabled")


class EnhancedApplicationDictionary(BaseModel):
    """Enhanced model for Application Dictionary with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the application dictionary")
    name: str = Field(..., description="Name of the Application Dictionary")
    description: Optional[str] = Field(None, description="Description of the Application Dictionary")
    attributes: List[AppAttribute] = Field(..., description="List of Application Dictionary Attributes")
    
    # Enhanced features
    identification_rules: Optional[List[AppIdentificationRule]] = Field(None, description="Application identification rules")
    usage_statistics: Optional[Dict[str, int]] = Field(None, description="Usage statistics")
    policy_associations: Optional[List[str]] = Field(None, description="Associated policy names")
    created_date: Optional[str] = Field(None, description="Creation timestamp")
    last_modified: Optional[str] = Field(None, description="Last modification timestamp")
    active_applications: Optional[int] = Field(None, description="Number of active applications using this dictionary")


class ApplicationDictionaryValidationResult(BaseModel):
    """Model for application dictionary validation results"""
    dictionary_id: int = Field(..., description="ID of the validated application dictionary")
    valid: bool = Field(..., description="Whether the dictionary configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    attribute_conflicts: Optional[List[Dict[str, Any]]] = Field(None, description="List of attribute conflicts")
    suggestions: Optional[List[str]] = Field(None, description="List of improvement suggestions")


class ApplicationDictionaryStatistics(BaseModel):
    """Model for application dictionary statistics"""
    dictionary_id: int = Field(..., description="ID of the application dictionary")
    total_applications: int = Field(..., description="Total number of applications using this dictionary")
    active_applications: Optional[int] = Field(None, description="Number of currently active applications")
    attribute_usage: Optional[Dict[str, int]] = Field(None, description="Usage count by attribute")
    policy_usage: Optional[Dict[str, int]] = Field(None, description="Usage count by policy")
    last_activity: Optional[str] = Field(None, description="Last activity timestamp")


# ============================================================================
# RADIUS Dictionary Models
# ============================================================================

class RADIUSAttributeValue(BaseModel):
    """Model for RADIUS Dictionary Attribute Valid Values"""
    value: str = Field(..., description="Attribute valid value")
    description: Optional[str] = Field(None, description="Description of the valid value")


class RADIUSDictionaryAttribute(BaseModel):
    """Model for RADIUS Dictionary Attribute"""
    attr_id: int = Field(..., description="RADIUS Dictionary Attribute ID")
    attr_name: str = Field(..., description="RADIUS Dictionary Attribute Name")
    attr_type: str = Field(..., description="RADIUS Dictionary Attribute Type (e.g., 'string', 'integer', 'ipaddr', 'date', 'octets')")
    attr_profile: str = Field(..., description="RADIUS Dictionary Attribute Profile ('in', 'out', or 'in out')")
    extra_data: Optional[str] = Field(None, description="RADIUS Dictionary Attribute Extra Data")
    valid_values: Optional[List[Dict[str, str]]] = Field(None, description="RADIUS Dictionary Attribute Valid Values")


class RADIUSDictionary(BaseModel):
    """Model for a ClearPass RADIUS Dictionary"""
    id: Optional[int] = Field(None, description="Numeric ID of the RADIUS Dictionary")
    vendor_id: int = Field(..., description="Vendor ID of RADIUS Dictionary")
    vendor_name: str = Field(..., description="Vendor Name of RADIUS Dictionary")
    prefix: str = Field(..., description="Vendor Prefix of RADIUS Dictionary")
    enabled: Optional[bool] = Field(None, description="Is RADIUS Dictionary enabled?")
    attributes: List[RADIUSDictionaryAttribute] = Field(..., description="Attributes of RADIUS Dictionary")


class RADIUSDictionaryCreate(BaseModel):
    """Model for creating a new RADIUS Dictionary"""
    vendor_id: int = Field(..., description="Vendor ID of RADIUS Dictionary (must be unique)")
    vendor_name: str = Field(..., description="Vendor Name of RADIUS Dictionary")
    prefix: str = Field(..., description="Vendor Prefix of RADIUS Dictionary")
    enabled: bool = Field(default=True, description="Is RADIUS Dictionary enabled?")
    attributes: List[Dict[str, Any]] = Field(..., description="Attributes of RADIUS Dictionary in pyclearpass format")


class RADIUSDictionaryUpdate(BaseModel):
    """Model for updating an existing RADIUS Dictionary"""
    vendor_id: Optional[int] = Field(None, description="New Vendor ID of RADIUS Dictionary")
    vendor_name: Optional[str] = Field(None, description="New Vendor Name of RADIUS Dictionary")
    prefix: Optional[str] = Field(None, description="New Vendor Prefix of RADIUS Dictionary")
    enabled: Optional[bool] = Field(None, description="New enabled status of RADIUS Dictionary")
    attributes: Optional[List[Dict[str, Any]]] = Field(None, description="New Attributes of RADIUS Dictionary")


class VendorSpecificAttribute(BaseModel):
    """Model for Vendor-Specific RADIUS Attribute"""
    vendor_id: int = Field(..., description="Vendor ID for this attribute")
    vendor_name: str = Field(..., description="Vendor name for this attribute")
    attribute_id: int = Field(..., description="Vendor-specific attribute ID")
    attribute_name: str = Field(..., description="Vendor-specific attribute name")
    attribute_type: str = Field(..., description="Attribute type")
    profile: str = Field(..., description="Attribute profile (in/out/in out)")
    description: Optional[str] = Field(None, description="Attribute description")
    allowed_values: Optional[List[str]] = Field(None, description="List of allowed values")


class EnhancedRADIUSDictionary(BaseModel):
    """Enhanced model for RADIUS Dictionary with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the RADIUS Dictionary")
    vendor_id: int = Field(..., description="Vendor ID of RADIUS Dictionary")
    vendor_name: str = Field(..., description="Vendor Name of RADIUS Dictionary")
    prefix: str = Field(..., description="Vendor Prefix of RADIUS Dictionary")
    enabled: Optional[bool] = Field(None, description="Is RADIUS Dictionary enabled?")
    attributes: List[RADIUSDictionaryAttribute] = Field(..., description="Enhanced RADIUS Dictionary Attributes")
    
    # Enhanced features
    vendor_specific_attributes: Optional[List[VendorSpecificAttribute]] = Field(None, description="Vendor-specific attributes")
    usage_statistics: Optional[Dict[str, int]] = Field(None, description="Dictionary usage statistics")
    policy_associations: Optional[List[str]] = Field(None, description="Associated policy names")
    validation_status: Optional[str] = Field(None, description="Dictionary validation status")
    test_results: Optional[Dict[str, Any]] = Field(None, description="Dictionary testing results")
    created_date: Optional[str] = Field(None, description="Creation timestamp")
    last_modified: Optional[str] = Field(None, description="Last modification timestamp")
    attribute_count: Optional[int] = Field(None, description="Number of attributes in dictionary")


class RADIUSDictionaryValidationResult(BaseModel):
    """Model for RADIUS dictionary validation results"""
    dictionary_id: int = Field(..., description="ID of the validated RADIUS dictionary")
    valid: bool = Field(..., description="Whether the dictionary configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    attribute_conflicts: Optional[List[Dict[str, Any]]] = Field(None, description="List of attribute conflicts")
    vendor_compliance: Optional[Dict[str, str]] = Field(None, description="Vendor compliance check results")
    suggestions: Optional[List[str]] = Field(None, description="List of improvement suggestions")


class RADIUSDictionaryStatistics(BaseModel):
    """Model for RADIUS dictionary statistics"""
    dictionary_id: int = Field(..., description="ID of the RADIUS dictionary")
    vendor_name: str = Field(..., description="Vendor name of the dictionary")
    total_attributes: int = Field(..., description="Total number of attributes in dictionary")
    enabled_attributes: Optional[int] = Field(None, description="Number of enabled attributes")
    usage_frequency: Optional[Dict[str, int]] = Field(None, description="Usage frequency by attribute")
    policy_usage: Optional[Dict[str, int]] = Field(None, description="Usage count by policy")
    authentication_usage: Optional[int] = Field(None, description="Authentication message usage count")
    accounting_usage: Optional[int] = Field(None, description="Accounting message usage count")
    last_activity: Optional[str] = Field(None, description="Last activity timestamp")


class RADIUSDictionaryTestResult(BaseModel):
    """Model for RADIUS dictionary testing results"""
    dictionary_id: int = Field(..., description="ID of the tested dictionary")
    test_type: str = Field(..., description="Type of test performed")
    test_status: str = Field(..., description="Test status (passed, failed, warning)")
    test_details: Dict[str, Any] = Field(..., description="Detailed test results")
    attribute_tests: Optional[List[Dict[str, Any]]] = Field(None, description="Individual attribute test results")
    vendor_compatibility: Optional[Dict[str, str]] = Field(None, description="Vendor compatibility test results")
    test_timestamp: Optional[str] = Field(None, description="Test execution timestamp")
    recommendations: Optional[List[str]] = Field(None, description="Test-based recommendations")


# =============================================================================
# PROXY TARGET MODELS (Phase 6.1)
# =============================================================================

class ProxyTarget(BaseModel):
    """Model for a ClearPass Proxy Target"""
    id: Optional[int] = Field(None, description="Numeric ID of the proxy target")
    name: str = Field(..., description="Name of the proxy target")
    host_name: str = Field(..., description="Host name of the proxy target")
    description: Optional[str] = Field(None, description="Description of the proxy target")
    authentication_port: Optional[int] = Field(1812, description="Authentication port of the proxy target")
    proxy_type: str = Field(..., description="The proxy type, either RADIUS or RadSec")
    accounting_port: Optional[int] = Field(1813, description="Accounting port of the proxy target")
    secret: Optional[str] = Field(None, description="Shared Secret of the proxy target")
    radsec_port: Optional[int] = Field(2083, description="The RadSec proxy port number (Should be 2083)")


class ProxyTargetCreate(BaseModel):
    """Model for creating a new Proxy Target"""
    name: str = Field(..., description="Name of the proxy target (must be unique)")
    host_name: str = Field(..., description="Host name of the proxy target")
    proxy_type: str = Field(..., description="The proxy type, either RADIUS or RadSec")
    description: Optional[str] = Field(None, description="Description of the proxy target")
    authentication_port: Optional[int] = Field(1812, description="Authentication port of the proxy target")
    accounting_port: Optional[int] = Field(1813, description="Accounting port of the proxy target")
    secret: Optional[str] = Field(None, description="Shared Secret of the proxy target")
    radsec_port: Optional[int] = Field(2083, description="The RadSec proxy port number (Should be 2083)")


class ProxyTargetUpdate(BaseModel):
    """Model for updating an existing Proxy Target"""
    name: Optional[str] = Field(None, description="New name of the proxy target")
    host_name: Optional[str] = Field(None, description="New host name of the proxy target")
    description: Optional[str] = Field(None, description="New description of the proxy target")
    authentication_port: Optional[int] = Field(None, description="New authentication port of the proxy target")
    proxy_type: Optional[str] = Field(None, description="New proxy type, either RADIUS or RadSec")
    accounting_port: Optional[int] = Field(None, description="New accounting port of the proxy target")
    secret: Optional[str] = Field(None, description="New shared Secret of the proxy target")
    radsec_port: Optional[int] = Field(None, description="New RadSec proxy port number")


class ProxyRoute(BaseModel):
    """Model for Proxy Routing Rule"""
    route_id: Optional[int] = Field(None, description="ID of the proxy route")
    realm_pattern: str = Field(..., description="Realm pattern for routing (e.g., '@company.com', 'DEFAULT')")
    proxy_target_id: int = Field(..., description="ID of the proxy target to route to")
    priority: Optional[int] = Field(None, description="Priority order for route evaluation")
    enabled: bool = Field(True, description="Whether this route is enabled")
    strip_realm: Optional[bool] = Field(False, description="Whether to strip realm from username before forwarding")
    fallback_enabled: Optional[bool] = Field(False, description="Enable fallback to next route on failure")


class ProxyLoadBalancing(BaseModel):
    """Model for Proxy Load Balancing Configuration"""
    balancing_type: str = Field(..., description="Load balancing type (round-robin, weighted, failover)")
    proxy_targets: List[Dict[str, Any]] = Field(..., description="List of proxy targets with weights/priorities")
    health_check_enabled: bool = Field(True, description="Enable health checking of proxy targets")
    health_check_interval: Optional[int] = Field(30, description="Health check interval in seconds")
    failover_timeout: Optional[int] = Field(5, description="Timeout before marking target as failed")


class EnhancedProxyTarget(BaseModel):
    """Enhanced model for Proxy Target with advanced features"""
    id: Optional[int] = Field(None, description="Numeric ID of the proxy target")
    name: str = Field(..., description="Name of the proxy target")
    host_name: str = Field(..., description="Host name of the proxy target")
    description: Optional[str] = Field(None, description="Description of the proxy target")
    authentication_port: Optional[int] = Field(1812, description="Authentication port of the proxy target")
    proxy_type: str = Field(..., description="The proxy type, either RADIUS or RadSec")
    accounting_port: Optional[int] = Field(1813, description="Accounting port of the proxy target")
    secret: Optional[str] = Field(None, description="Shared Secret of the proxy target")
    radsec_port: Optional[int] = Field(2083, description="The RadSec proxy port number")
    
    # Enhanced features
    routing_rules: Optional[List[ProxyRoute]] = Field(None, description="Associated routing rules")
    load_balancing: Optional[ProxyLoadBalancing] = Field(None, description="Load balancing configuration")
    connection_status: Optional[str] = Field(None, description="Current connection status")
    last_health_check: Optional[str] = Field(None, description="Last health check timestamp")
    usage_statistics: Optional[Dict[str, int]] = Field(None, description="Proxy usage statistics")
    created_date: Optional[str] = Field(None, description="Creation timestamp")
    last_modified: Optional[str] = Field(None, description="Last modification timestamp")


class ProxyTargetValidationResult(BaseModel):
    """Model for proxy target validation results"""
    target_id: int = Field(..., description="ID of the validated proxy target")
    valid: bool = Field(..., description="Whether the proxy target configuration is valid")
    warnings: List[str] = Field(default_factory=list, description="List of validation warnings")
    errors: List[str] = Field(default_factory=list, description="List of validation errors")
    connectivity_test: Optional[Dict[str, str]] = Field(None, description="Connectivity test results")
    certificate_validation: Optional[Dict[str, str]] = Field(None, description="Certificate validation for RadSec")
    suggestions: Optional[List[str]] = Field(None, description="Configuration improvement suggestions")


class ProxyTargetStatistics(BaseModel):
    """Model for proxy target statistics"""
    target_id: int = Field(..., description="ID of the proxy target")
    total_requests: int = Field(..., description="Total number of proxy requests")
    successful_requests: Optional[int] = Field(None, description="Number of successful proxy requests")
    failed_requests: Optional[int] = Field(None, description="Number of failed proxy requests")
    authentication_requests: Optional[int] = Field(None, description="Number of authentication requests")
    accounting_requests: Optional[int] = Field(None, description="Number of accounting requests")
    average_response_time: Optional[float] = Field(None, description="Average response time in milliseconds")
    last_activity: Optional[str] = Field(None, description="Last activity timestamp")


class ProxyTargetTestResult(BaseModel):
    """Model for proxy target testing results"""
    target_id: int = Field(..., description="ID of the tested proxy target")
    test_type: str = Field(..., description="Type of test performed")
    test_status: str = Field(..., description="Test status (passed, failed, warning)")
    test_details: Dict[str, Any] = Field(..., description="Detailed test results")
    connectivity_test: Optional[Dict[str, str]] = Field(None, description="Connectivity test results")
    authentication_test: Optional[Dict[str, str]] = Field(None, description="Authentication test results")
    accounting_test: Optional[Dict[str, str]] = Field(None, description="Accounting test results")
    certificate_test: Optional[Dict[str, str]] = Field(None, description="Certificate test results for RadSec")
    test_timestamp: Optional[str] = Field(None, description="Test execution timestamp")
    recommendations: Optional[List[str]] = Field(None, description="Test-based recommendations") 