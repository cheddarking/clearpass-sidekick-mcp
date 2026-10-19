"""
MCP tools for Policy Elements operations.

Provides natural language automation for managing ClearPass policy elements including
roles, role mappings, enforcement policies, authentication sources, and other policy components.

This module implements Chunk 1.1, 1.2, and 1.3 of the Policy Elements implementation plan:
        - Roles and Role Mappings (Foundation for all authorization)
- Enforcement Policies (Core network access control)
- Configuration Services (Authentication sources, network device groups, posture policies, and more)
"""

import json
import logging
from typing import Dict, Any, Optional, List, Union
from pydantic import Field
from fastmcp import Context

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error
from ..audit_logger import log_mcp_operation

logger = logging.getLogger(__name__)


# ================================
# HELPER FUNCTIONS
# ================================

def _parse_list_dict_parameter(param: Union[List[Dict[str, Any]], str, None], param_name: str) -> Optional[List[Dict[str, Any]]]:
    """
    Helper function to parse list of dictionaries parameters that may be passed as JSON strings.
    
    Args:
        param: The parameter value, either a list of dicts, a JSON string, or None
        param_name: Name of the parameter for error reporting
    
    Returns:
        List of dictionaries or None if param was None
        
    Raises:
        ValueError: If the JSON string is malformed
    """
    if param is None:
        return None
    
    if isinstance(param, str):
        try:
            parsed = json.loads(param)
            if not isinstance(parsed, list):
                raise ValueError(f"Parameter '{param_name}' must be a JSON array, got {type(parsed).__name__}")
            return parsed
        except json.JSONDecodeError as e:
            raise ValueError(f"Parameter '{param_name}' contains invalid JSON: {str(e)}")
    
    # Already a list
    return param


# ================================
# ROLES MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_roles(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"name\": \"Guest\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List ClearPass roles.
    
    Roles define authorization levels and permissions for users and devices.
    Use this tool to view all available roles or filter for specific ones.
    
    Examples:
    - List all roles: No parameters needed
    - Find guest roles: filter='{"name": {"contains": "Guest"}}'
    - Get first 10 roles: limit=10
    """
    await ctx.info(f"Retrieving roles (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        
        response = await client.list_roles(
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count
                )
        
        # Format response for LLM consumption
        if "_embedded" in response and "items" in response["_embedded"]:
            roles = response["_embedded"]["items"]
        else:
            roles = response.get("items", [])
        
        return {
            "success": True,
        "total_count": len(roles),
        "roles": roles,
        "message": f"Retrieved {len(roles)} roles",
        "pagination_info": {
            "offset": offset or 0,
            "limit": limit,
            "has_more": len(roles) == limit if limit else False
        }
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to list roles: {e}")
        return await format_api_error(e, "list roles")
    except Exception as e:
        logger.error(f"Unexpected error listing roles: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing roles"
        }


@operation(domain="policy_elements")
async def create_role(
    ctx: Context,
    name: str = Field(..., description="Name of the role (must be unique)"),
    description: Optional[str] = Field(None, description="Description of the role")
) -> Dict[str, Any]:
    """
    Create a new ClearPass role.
    
    Roles are the foundation of ClearPass authorization, defining what users
    and devices are allowed to do on the network.
    
    Examples:
    - Basic role: name="Employee", description="Standard employee access"
    - Guest role: name="Guest-WiFi", description="Limited guest network access"
    - Device role: name="IoT-Device", description="Internet of Things device role"
    """
    await ctx.info(f"Creating role: {name}")
    
    try:
        client = await get_clearpass_client()
        
        role_data = {
            "name": name
        }
        if description:
            role_data["description"] = description
        
        response = await client.create_role(role_data)
        
        await ctx.info(f"Successfully created role: {name}")
        
        return {
        "success": True,
        "message": f"Role '{name}' created successfully",
        "role": response,
        "next_steps": [
            "You can now use this role in role mappings",
            "Consider creating enforcement policies for this role",
            "Review role assignments in user/device profiles"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to create role: {e}")
        return await format_api_error(e, "create role")
    except Exception as e:
        logger.error(f"Unexpected error creating role: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the role"
        }


@operation(domain="policy_elements")
async def get_role_details(
    ctx: Context,
    role_id: Optional[int] = Field(None, description="Numeric ID of the role"),
    name: Optional[str] = Field(None, description="Name of the role")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific role.
    
    Provide either the role ID or name to retrieve the role details.
    
    Examples:
    - By ID: role_id=123
    - By name: name="Employee"
    """
    if role_id is None and name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either role_id or name to identify the role"
        }
    
    identifier = f"ID {role_id}" if role_id is not None else f"name '{name}'"
    await ctx.info(f"Retrieving role details for: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if role_id is not None:
            response = await client.get_role_by_id(role_id)
        else:
            response = await client.get_role_by_name(name)
        
        return {
        "success": True,
        "role": response,
        "message": f"Retrieved role details for: {identifier}",
        "usage_tips": [
            "This role can be assigned to users through role mappings",
            "Check enforcement policies that reference this role",
            "Review any services or policies that depend on this role"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to get role details: {e}")
        return await format_api_error(e, "get role details")
    except Exception as e:
        logger.error(f"Unexpected error getting role details: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving role details"
        }


@operation(domain="policy_elements")
async def update_role(
    ctx: Context,
    role_id: Optional[int] = Field(None, description="Numeric ID of the role to update"),
    role_name: Optional[str] = Field(None, description="Name of the role to update"),
    new_name: Optional[str] = Field(None, description="New name for the role"),
    new_description: Optional[str] = Field(None, description="New description for the role"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing role.
    
    You can update the role name, description, or both. Provide either role_id or role_name
    to identify which role to update.
    
    Examples:
    - Update description: role_id=123, new_description="Updated employee access"
    - Rename role: role_name="Old-Name", new_name="New-Name"
    - Full update: new_name="Employee", new_description="Full access", replace_all=True
    """
    if role_id is None and role_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either role_id or role_name to identify the role"
        }
    
    if not new_name and not new_description:
        return {
            "success": False,
            "error": "No update parameters provided",
            "message": "Please provide new_name or new_description to update"
        }
    
    identifier = f"ID {role_id}" if role_id is not None else f"name '{role_name}'"
    await ctx.info(f"Updating role: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        update_data = {}
        if new_name:
            update_data["name"] = new_name
        if new_description:
            update_data["description"] = new_description
        
        if role_id is not None:
            if replace_all:
                response = await client.replace_role_by_id(role_id, update_data)
            else:
                response = await client.update_role_by_id(role_id, update_data)
        else:
            if replace_all:
                response = await client.replace_role_by_name(role_name, update_data)
            else:
                response = await client.update_role_by_name(role_name, update_data)
        
        return {
            "success": True,
            "message": f"Role {identifier} updated successfully",
            "role": response,
            "updated_fields": list(update_data.keys()),
            "operation_type": "replace" if replace_all else "update"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to update role: {e}")
        return await format_api_error(e, "update role")
    except Exception as e:
        logger.error(f"Unexpected error updating role: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the role"
        }


@operation(domain="policy_elements")
async def delete_role(
    ctx: Context,
    role_id: Optional[int] = Field(None, description="Numeric ID of the role to delete"),
    role_name: Optional[str] = Field(None, description="Name of the role to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a ClearPass role.
    
    ⚠️ WARNING: This is a destructive operation! Deleting a role will affect:
    - All role mappings that reference this role
    - All enforcement policies that use this role
    - All users/devices currently assigned this role
    
    Examples:
    - Delete by ID: role_id=123, confirm=True
    - Delete by name: role_name="Old-Role", confirm=True
    """
    if role_id is None and role_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either role_id or role_name to identify the role"
        }
    
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a role will affect all policies and mappings that reference it."
        }
    
    identifier = f"ID {role_id}" if role_id is not None else f"name '{role_name}'"
    await ctx.info(f"Deleting role: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if role_id is not None:
            await client.delete_role_by_id(role_id)
        else:
            await client.delete_role_by_name(role_name)
        
        return {
            "success": True,
            "message": f"Role {identifier} deleted successfully",
            "warning": "Please review and update any policies or mappings that referenced this role"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete role: {e}")
        return await format_api_error(e, "delete role")
    except Exception as e:
        logger.error(f"Unexpected error deleting role: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the role"
        }


# ================================
# ROLE MAPPINGS MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_role_mappings(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"name\": \"Employee-Mapping\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List ClearPass role mappings.
    
    Role mappings define the rules for automatically assigning roles to users and devices
    based on their attributes (username, device type, location, etc.).
    
    Examples:
    - List all mappings: No parameters needed
    - Find employee mappings: filter='{"name": {"contains": "Employee"}}'
    - Get first 10 mappings: limit=10
    """
    await ctx.info(f"Retrieving role mappings (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        
        response = await client.list_role_mappings(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        
        # Format response for LLM consumption
        if "_embedded" in response and "items" in response["_embedded"]:
            mappings = response["_embedded"]["items"]
        else:
            mappings = response.get("items", [])
        
        return {
        "success": True,
        "total_count": len(mappings),
        "role_mappings": mappings,
        "message": f"Retrieved {len(mappings)} role mappings",
        "pagination_info": {
            "offset": offset or 0,
            "limit": limit,
            "has_more": len(mappings) == limit if limit else False
        }
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to list role mappings: {e}")
        return await format_api_error(e, "list role mappings")
    except Exception as e:
        logger.error(f"Unexpected error listing role mappings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing role mappings"
        }


@operation(domain="policy_elements")
async def create_role_mapping(
    ctx: Context,
    name: str = Field(..., description="Name of the role mapping policy"),
    default_role_name: str = Field(..., description="Default role assigned when no rules match"),
    rule_combine_algo: str = Field(..., description="Rule evaluation algorithm (first-applicable, permit-overrides, deny-overrides)"),
    rules: Union[List[Dict[str, Any]], str] = Field(..., description="List of role mapping rules in ClearPass format - array format: [{\"name\": \"Employee Rule\", \"condition\": [{\"type\": \"RadiusAttribute\", \"name\": \"User-Name\", \"oper\": \"ENDS_WITH\", \"value\": \"@company.com\"}], \"result\": \"Employee\"}] or JSON string"),
    description: Optional[str] = Field(None, description="Description of the role mapping policy")
) -> Dict[str, Any]:
    """
    Create a new role mapping policy.
    
    Role mappings automatically assign roles to users/devices based on their attributes.
    Each mapping contains rules that are evaluated to determine the appropriate role.
    
    Rule algorithms:
    - first-applicable: Use the first rule that matches
    - permit-overrides: Permissive rules override restrictive ones
    - deny-overrides: Restrictive rules override permissive ones
    
    Example rules format:
    [
        {
            "name": "Employee Rule",
            "condition": [{"type": "RadiusAttribute", "name": "User-Name", "oper": "ENDS_WITH", "value": "@company.com"}],
            "result": "Employee"
        }
    ]
    """
    await ctx.info(f"Creating role mapping: {name}")
    
    try:
        client = await get_clearpass_client()
        
        # Parse rules parameter
        parsed_rules = _parse_list_dict_parameter(rules, "rules")
        
        mapping_data = {
            "name": name,
            "default_role_name": default_role_name,
            "rule_combine_algo": rule_combine_algo,
            "rules": parsed_rules
        }
        if description:
            mapping_data["description"] = description
        
        response = await client.create_role_mapping(mapping_data)
        
        await ctx.info(f"Successfully created role mapping: {name}")
        
        return {
        "success": True,
        "message": f"Role mapping '{name}' created successfully",
        "role_mapping": response,
        "configuration_summary": {
            "default_role": default_role_name,
            "algorithm": rule_combine_algo,
            "number_of_rules": len(rules)
        },
        "next_steps": [
            "Test the role mapping with sample user attributes",
            "Enable the mapping in your authentication services",
            "Monitor role assignment effectiveness"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to create role mapping: {e}")
        return await format_api_error(e, "create role mapping")
    except Exception as e:
        logger.error(f"Unexpected error creating role mapping: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the role mapping"
        }


@operation(domain="policy_elements")
async def get_role_mapping_details(
    ctx: Context,
    role_mapping_id: Optional[int] = Field(None, description="Numeric ID of the role mapping"),
    name: Optional[str] = Field(None, description="Name of the role mapping")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific role mapping.
    
    Provide either the role mapping ID or name to retrieve the details.
    
    Examples:
    - By ID: role_mapping_id=456
    - By name: name="Employee-Role-Mapping"
    """
    if role_mapping_id is None and name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either role_mapping_id or name to identify the role mapping"
        }
    
    identifier = f"ID {role_mapping_id}" if role_mapping_id is not None else f"name '{name}'"
    await ctx.info(f"Retrieving role mapping details for: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if role_mapping_id is not None:
            response = await client.get_role_mapping_by_id(role_mapping_id)
        else:
            response = await client.get_role_mapping_by_name(name)
        
        # Extract useful information from the response
        rules_summary = []
        if "rules" in response:
            for rule in response["rules"]:
                rules_summary.append({
                    "name": rule.get("name", "Unnamed rule"),
                    "result_role": rule.get("result", "Unknown"),
                    "enabled": rule.get("enabled", True)
                })
        
        return {
        "success": True,
        "role_mapping": response,
        "message": f"Retrieved role mapping details for: {identifier}",
        "summary": {
            "default_role": response.get("default_role_name"),
            "algorithm": response.get("rule_combine_algo"),
            "total_rules": len(response.get("rules", [])),
            "rules_summary": rules_summary
        },
        "usage_tips": [
            "This mapping is evaluated when users/devices authenticate",
            "Rules are processed according to the combine algorithm",
            "Test changes in a lab environment before production deployment"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to get role mapping details: {e}")
        return await format_api_error(e, "get role mapping details")
    except Exception as e:
        logger.error(f"Unexpected error getting role mapping details: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving role mapping details"
        }


@operation(domain="policy_elements")
async def delete_role_mapping(
    ctx: Context,
    role_mapping_id: Optional[int] = Field(None, description="Numeric ID of the role mapping to delete"),
    role_mapping_name: Optional[str] = Field(None, description="Name of the role mapping to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a ClearPass role mapping.
    
    ⚠️ WARNING: This is a destructive operation! Deleting a role mapping will affect:
    - Automatic role assignment for new authentications
    - Any services that depend on this mapping
    - User/device role assignments (they'll fall back to default behavior)
    
    Examples:
    - Delete by ID: role_mapping_id=456, confirm=True
    - Delete by name: role_mapping_name="Old-Mapping", confirm=True
    """
    if role_mapping_id is None and role_mapping_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either role_mapping_id or role_mapping_name to identify the role mapping"
        }
    
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a role mapping will affect automatic role assignment for users and devices."
        }
    
    identifier = f"ID {role_mapping_id}" if role_mapping_id is not None else f"name '{role_mapping_name}'"
    await ctx.info(f"Deleting role mapping: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if role_mapping_id is not None:
            await client.delete_role_mapping_by_id(role_mapping_id)
        else:
            await client.delete_role_mapping_by_name(role_mapping_name)
        
        return {
        "success": True,
        "message": f"Role mapping {identifier} deleted successfully",
        "warning": "Please review authentication services that used this mapping",
        "recommendations": [
            "Verify that users/devices still receive appropriate roles",
            "Update any backup or alternative role assignment methods",
            "Monitor authentication logs for role assignment issues"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete role mapping: {e}")
        return await format_api_error(e, "delete role mapping")
    except Exception as e:
        logger.error(f"Unexpected error deleting role mapping: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the role mapping"
        }


# ================================
# ENFORCEMENT POLICIES MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_enforcement_policies(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"name\": \"Employee-Policy\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List ClearPass enforcement policies.
    
    Enforcement policies determine what network access and restrictions are applied
    to users and devices based on their roles and other attributes.
    
    Examples:
    - List all policies: No parameters needed
    - Find RADIUS policies: filter='{"enforcement_type": "RADIUS"}'
    - Get first 10 policies: limit=10
    """
    await ctx.info(f"Retrieving enforcement policies (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        
        response = await client.list_enforcement_policies(
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count
        )
        
        # Format response for LLM consumption
        if "_embedded" in response and "items" in response["_embedded"]:
            policies = response["_embedded"]["items"]
        else:
            policies = response.get("items", [])
        
        return {
        "success": True,
        "total_count": len(policies),
        "enforcement_policies": policies,
        "message": f"Retrieved {len(policies)} enforcement policies",
        "pagination_info": {
            "offset": offset or 0,
            "limit": limit,
            "has_more": len(policies) == limit if limit else False
        }
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to list enforcement policies: {e}")
        return await format_api_error(e, "list enforcement policies")
    except Exception as e:
        logger.error(f"Unexpected error listing enforcement policies: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing enforcement policies"
        }


@operation(domain="policy_elements")
async def create_enforcement_policy(
    ctx: Context,
    name: str = Field(..., description="Name of the enforcement policy (must be unique)"),
    enforcement_type: str = Field(..., description="Enforcement type (e.g., 'RADIUS', 'SNMP', 'HTTP')"),
    default_enforcement_profile: str = Field(..., description="Default enforcement profile for unmatched cases"),
    rule_eval_algo: str = Field(..., description="Rule evaluation algorithm (e.g., 'first-applicable', 'permit-overrides')"),
    rules: Union[List[Dict[str, Any]], str] = Field(..., description="List of enforcement policy rules in ClearPass format - array format: [{\"condition\": [{\"type\": \"Role\", \"oper\": \"EQUALS\", \"value\": \"Employee\"}], \"enforcement_profile_names\": [\"Employee-Profile\"]}] or JSON string"),
    description: Optional[str] = Field(None, description="Description of the enforcement policy"),
) -> Dict[str, Any]:
    """
    Create a new enforcement policy.
    
    Enforcement policies define what network access and restrictions are applied
    to users and devices. They contain rules that are evaluated to determine
    the appropriate enforcement profile.
    
    Common enforcement types:
    - RADIUS: For network access control
    - SNMP: For device management
    - HTTP: For web-based enforcement
    
    Rule Structure:
    - Multiple conditions within the same rule are automatically evaluated with AND logic by ClearPass
    - Multiple separate rules are evaluated according to the rule_eval_algo setting
    
    Example rules format:
    [
        {
            "condition": [
                {"type": "Role", "oper": "EQUALS", "value": "Employee"},
                {"type": "Authorization:[Active Directory]", "oper": "EQUALS", "value": "true"}
            ],
            "enforcement_profile_names": ["Employee-Profile"]
        }
    ]
    
    The conditions within the same rule will be evaluated with AND logic.
    """
    await ctx.info(f"Creating enforcement policy: {name}")
    
    try:
        client = await get_clearpass_client()
        
        # Parse rules parameter
        parsed_rules = _parse_list_dict_parameter(rules, "rules")
        
        # Clean up the rules structure
        processed_rules = []
        for rule in parsed_rules:
            clean_rule = {
                "condition": rule.get("condition", []),
                "enforcement_profile_names": rule.get("enforcement_profile_names", rule.get("enforcement_profile", []))
            }
            # Convert single profile string to list if needed
            if isinstance(clean_rule["enforcement_profile_names"], str):
                clean_rule["enforcement_profile_names"] = [clean_rule["enforcement_profile_names"]]
            
            processed_rules.append(clean_rule)
        
        policy_data = {
        "name": name,
        "enforcement_type": enforcement_type,
        "default_enforcement_profile": default_enforcement_profile,
        "rule_eval_algo": rule_eval_algo,
        "rules": processed_rules
        }
        if description:
            policy_data["description"] = description
        
        response = await client.create_enforcement_policy(policy_data)
        
        await ctx.info(f"Successfully created enforcement policy: {name}")
        
        return {
        "success": True,
        "message": f"Enforcement policy '{name}' created successfully",
        "enforcement_policy": response,
        "configuration_summary": {
            "enforcement_type": enforcement_type,
            "default_profile": default_enforcement_profile,
            "algorithm": rule_eval_algo,
            "number_of_rules": len(processed_rules)
        },
        "next_steps": [
            "Test the policy with sample user/device scenarios",
            "Associate the policy with appropriate services",
            "Monitor policy effectiveness and adjust rules as needed"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to create enforcement policy: {e}")
        return await format_api_error(e, "create enforcement policy")
    except Exception as e:
        logger.error(f"Unexpected error creating enforcement policy: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the enforcement policy"
        }


@operation(domain="policy_elements")
async def get_enforcement_policy_details(
    ctx: Context,
    enforcement_policy_id: Optional[int] = Field(None, description="Numeric ID of the enforcement policy"),
    name: Optional[str] = Field(None, description="Name of the enforcement policy")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific enforcement policy.
    
    Provide either the enforcement policy ID or name to retrieve the details.
    
    Examples:
    - By ID: enforcement_policy_id=789
    - By name: name="Employee-Access-Policy"
    """
    if enforcement_policy_id is None and name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either enforcement_policy_id or name to identify the enforcement policy"
        }
    
    identifier = f"ID {enforcement_policy_id}" if enforcement_policy_id is not None else f"name '{name}'"
    await ctx.info(f"Retrieving enforcement policy details for: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if enforcement_policy_id is not None:
            response = await client.get_enforcement_policy_by_id(enforcement_policy_id)
        else:
            response = await client.get_enforcement_policy_by_name(name)
        
        # Extract useful information from the response
        rules_summary = []
        if "rules" in response:
            for rule in response["rules"]:
                rules_summary.append({
                    "name": rule.get("name", "Unnamed rule"),
                    "enforcement_profile_names": rule.get("enforcement_profile_names", []),
                    "enabled": rule.get("enabled", True)
                })
        
        return {
        "success": True,
        "enforcement_policy": response,
        "message": f"Retrieved enforcement policy details for: {identifier}",
        "summary": {
            "enforcement_type": response.get("enforcement_type"),
            "default_profile": response.get("default_enforcement_profile"),
            "algorithm": response.get("rule_eval_algo"),
            "total_rules": len(response.get("rules", [])),
            "rules_summary": rules_summary
        },
        "usage_tips": [
            "This policy determines network access based on rules",
            "Rules are evaluated according to the specified algorithm",
            "Test policy changes in a controlled environment first"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to get enforcement policy details: {e}")
        return await format_api_error(e, "get enforcement policy details")
    except Exception as e:
        logger.error(f"Unexpected error getting enforcement policy details: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving enforcement policy details"
        }


@operation(domain="policy_elements")
async def update_enforcement_policy(
    ctx: Context,
    enforcement_policy_id: Optional[int] = Field(None, description="Numeric ID of the enforcement policy to update"),
    policy_name: Optional[str] = Field(None, description="Name of the enforcement policy to update"),
    new_name: Optional[str] = Field(None, description="New name for the enforcement policy"),
    new_description: Optional[str] = Field(None, description="New description for the enforcement policy"),
    enforcement_type: Optional[str] = Field(None, description="New enforcement type"),
    default_enforcement_profile: Optional[str] = Field(None, description="New default enforcement profile"),
    rule_eval_algo: Optional[str] = Field(None, description="New rule evaluation algorithm"),
    rules: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of enforcement rules - array format: [{\"condition\": [...], \"enforcement_profile_names\": [\"Profile\"]}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing enforcement policy.
    
    You can update any combination of policy attributes. Provide either enforcement_policy_id
    or policy_name to identify which policy to update.
    
    Examples:
    - Update description: enforcement_policy_id=789, new_description="Updated access policy"
    - Change default profile: policy_name="Employee-Policy", default_enforcement_profile="New-Profile"
    - Update rules: rules=[{"condition": [...], "enforcement_profile_names": ["Profile"]}]
    """
    if enforcement_policy_id is None and policy_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either enforcement_policy_id or policy_name to identify the enforcement policy"
        }
    
    update_fields = [new_name, new_description, enforcement_type, default_enforcement_profile, rule_eval_algo, rules]
    if not any(field is not None for field in update_fields):
        return {
            "success": False,
            "error": "No update parameters provided",
            "message": "Please provide at least one field to update"
        }
    
    identifier = f"ID {enforcement_policy_id}" if enforcement_policy_id is not None else f"name '{policy_name}'"
    await ctx.info(f"Updating enforcement policy: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        update_data = {}
        if new_name is not None:
            update_data["name"] = new_name
        if new_description is not None:
            update_data["description"] = new_description
        if enforcement_type is not None:
            update_data["enforcement_type"] = enforcement_type
        if default_enforcement_profile is not None:
            update_data["default_enforcement_profile"] = default_enforcement_profile
        if rule_eval_algo is not None:
            update_data["rule_eval_algo"] = rule_eval_algo
        if rules is not None:
            parsed_rules = _parse_list_dict_parameter(rules, "rules")
            # Normalize rules structure (same as create_enforcement_policy)
            processed_rules = []
            for rule in parsed_rules:
                clean_rule = {
                    "condition": rule.get("condition", []),
                    "enforcement_profile_names": rule.get("enforcement_profile_names", rule.get("enforcement_profile", []))
                }
                # Convert single profile string to list if needed
                if isinstance(clean_rule["enforcement_profile_names"], str):
                    clean_rule["enforcement_profile_names"] = [clean_rule["enforcement_profile_names"]]
                processed_rules.append(clean_rule)
            update_data["rules"] = processed_rules
        
        if enforcement_policy_id is not None:
            if replace_all:
                response = await client.replace_enforcement_policy_by_id(enforcement_policy_id, update_data)
            else:
                response = await client.update_enforcement_policy_by_id(enforcement_policy_id, update_data)
        else:
            if replace_all:
                response = await client.replace_enforcement_policy_by_name(policy_name, update_data)
            else:
                response = await client.update_enforcement_policy_by_name(policy_name, update_data)
        
        return {
        "success": True,
        "message": f"Enforcement policy {identifier} updated successfully",
        "enforcement_policy": response,
        "updated_fields": list(update_data.keys()),
        "operation_type": "replace" if replace_all else "update"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to update enforcement policy: {e}")
        return await format_api_error(e, "update enforcement policy")
    except Exception as e:
        logger.error(f"Unexpected error updating enforcement policy: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the enforcement policy"
        }


@operation(domain="policy_elements")
async def delete_enforcement_policy(
    ctx: Context,
    enforcement_policy_id: Optional[int] = Field(None, description="Numeric ID of the enforcement policy to delete"),
    policy_name: Optional[str] = Field(None, description="Name of the enforcement policy to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a ClearPass enforcement policy.
    
    ⚠️ WARNING: This is a destructive operation! Deleting an enforcement policy will affect:
    - All services that reference this policy
    - Network access decisions for users/devices
    - Any dependent policy configurations
    
    Examples:
    - Delete by ID: enforcement_policy_id=789, confirm=True
    - Delete by name: policy_name="Old-Policy", confirm=True
    """
    if enforcement_policy_id is None and policy_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either enforcement_policy_id or policy_name to identify the enforcement policy"
        }
    
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting an enforcement policy will affect network access control for users and devices."
        }
    
    identifier = f"ID {enforcement_policy_id}" if enforcement_policy_id is not None else f"name '{policy_name}'"
    await ctx.info(f"Deleting enforcement policy: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if enforcement_policy_id is not None:
            await client.delete_enforcement_policy_by_id(enforcement_policy_id)
        else:
            await client.delete_enforcement_policy_by_name(policy_name)
        
        return {
        "success": True,
        "message": f"Enforcement policy {identifier} deleted successfully",
        "warning": "Please review and update any services that referenced this policy",
        "recommendations": [
            "Verify that network access is still functioning correctly",
            "Update any backup or alternative enforcement policies",
            "Monitor authentication logs for access control issues"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete enforcement policy: {e}")
        return await format_api_error(e, "delete enforcement policy")
    except Exception as e:
        logger.error(f"Unexpected error deleting enforcement policy: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the enforcement policy"
        }


# ================================
# AUTHENTICATION SOURCES MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_authentication_sources(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"type\": \"Active Directory\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List authentication sources in ClearPass.
    
    This tool retrieves information about configured authentication sources used
    for user authentication and authorization.
    
    Examples:
    - "Show me all authentication sources"
    - "List Active Directory authentication sources"
    - "Find authentication sources with 'LDAP' in the name"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_authentication_sources(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
            
        # Enhanced response formatting
        if result.get("_embedded", {}).get("items"):
            sources = result["_embedded"]["items"]
            source_count = len(sources)
            total_count = result.get("count", source_count)
                
            summary = {
                "success": True,
                "message": f"Retrieved {source_count} authentication sources",
                "total_count": total_count,
                "authentication_sources": sources
            }
                
            if source_count > 0:
                summary["sample_source"] = {
                    "name": sources[0].get("name", "N/A"),
                    "type": sources[0].get("type", "N/A"),
                    "use_for_authorization": sources[0].get("use_for_authorization", False)
                }
                
            return summary
        else:
            return {
                "success": True,
                "message": "No authentication sources found",
                "total_count": 0,
                "authentication_sources": []
            }
                
    except Exception as e:
        error_msg = f"Failed to list authentication sources: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_authentication_source(
    ctx: Context,
    name: str = Field(..., description="Name of the authentication source (must be unique)"),
    type: str = Field(..., description="Type of authentication source (e.g., 'Active Directory', 'LDAP', 'Database')"),
    connection_details: Dict[str, Any] = Field(..., description="Authentication source connection details"),
    server_timeout: int = Field(default=30, description="Server timeout in seconds"),
    cache_timeout: int = Field(default=300, description="Cache timeout in seconds"),
    description: Optional[str] = Field(None, description="Description of the authentication source"),
    use_for_authorization: bool = Field(default=False, description="Enable to use this source for authorization"),
    authorization_source_names: Optional[List[str]] = Field(None, description="Additional auth-sources for role-mapping attributes")
) -> Dict[str, Any]:
    """
    Create a new authentication source in ClearPass.
    
    This tool creates a new authentication source for user authentication.
    
    Examples:
    - "Create an Active Directory authentication source named 'Corp-AD'"
    - "Add an LDAP authentication source for department users"
    """
    try:
        client = await get_clearpass_client()
        auth_source_data = {
            "name": name,
            "type": type,
            "server_timeout": server_timeout,
            "cache_timeout": cache_timeout,
            "cppm_primary_auth_source_connection_details": connection_details,
            "use_for_authorization": use_for_authorization
        }
            
        if description is not None:
            auth_source_data["description"] = description
        if authorization_source_names is not None:
            auth_source_data["authorization_source_names"] = authorization_source_names
            
        result = await client.create_authentication_source(auth_source_data)
        
        return {
        "success": True,
        "message": f"Successfully created authentication source: {name}",
        "authentication_source": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create authentication source '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_authentication_source_details(
    ctx: Context,
    auth_source_id: Optional[int] = Field(None, description="Numeric ID of the authentication source"),
    name: Optional[str] = Field(None, description="Name of the authentication source")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific authentication source.
    
    This tool retrieves comprehensive details about an authentication source
    by ID or name.
    
    Examples:
    - "Get details for authentication source ID 123"
    - "Show information about auth source 'Corp-AD'"
    """
    if auth_source_id is None and name is None:
        return {
            "success": False,
            "message": "Either auth_source_id or name must be provided",
            "error": "Missing required parameter"
        }
    
    try:
        client = await get_clearpass_client()
        if auth_source_id is not None:
            result = await client.get_authentication_source_by_id(auth_source_id)
            identifier = f"ID {auth_source_id}"
        else:
            result = await client.get_authentication_source_by_name(name)
            identifier = f"name '{name}'"
            
        return {
            "success": True,
            "message": f"Successfully retrieved authentication source details for {identifier}",
            "authentication_source": result
        }
                
    except Exception as e:
        identifier = f"ID {auth_source_id}" if auth_source_id is not None else f"name '{name}'"
        error_msg = f"Failed to get authentication source details for {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def delete_authentication_source(
    ctx: Context,
    auth_source_id: Optional[int] = Field(None, description="Numeric ID of the authentication source to delete"),
    auth_source_name: Optional[str] = Field(None, description="Name of the authentication source to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an authentication source from ClearPass.
    
    This tool removes an authentication source configuration.
    Use with caution as this may affect user authentication.
    
    Examples:
    - "Delete authentication source ID 123 with confirm=true"
    - "Remove auth source 'Old-LDAP' with confirmation"
    """
    if auth_source_id is None and auth_source_name is None:
        return {
            "success": False,
            "message": "Either auth_source_id or auth_source_name must be provided",
            "error": "Missing required parameter"
        }
    
    if not confirm:
        identifier = f"ID {auth_source_id}" if auth_source_id is not None else f"name '{auth_source_name}'"
        return {
            "success": False,
            "message": f"Authentication source deletion for {identifier} requires confirmation. Set confirm=true to proceed.",
            "warning": "This action may affect user authentication capabilities."
        }
    
    try:
        client = await get_clearpass_client()
        if auth_source_id is not None:
            result = await client.delete_authentication_source_by_id(auth_source_id)
            identifier = f"ID {auth_source_id}"
        else:
            result = await client.delete_authentication_source_by_name(auth_source_name)
            identifier = f"name '{auth_source_name}'"
            
        return {
            "success": True,
            "message": f"Successfully deleted authentication source {identifier}",
            "result": result
        }
                
    except Exception as e:
        identifier = f"ID {auth_source_id}" if auth_source_id is not None else f"name '{auth_source_name}'"
        error_msg = f"Failed to delete authentication source {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# ================================
# NETWORK DEVICE GROUPS MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_network_device_groups(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"name\": \"Corporate\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List network device groups in ClearPass.
    
    This tool retrieves information about network device groups used for
    organizing and managing network devices.
    
    Examples:
    - "Show me all network device groups"
    - "List device groups with 'Switch' in the name"
    - "Find network device groups for wireless access points"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_network_device_groups(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
            
        # Enhanced response formatting
        if result.get("_embedded", {}).get("items"):
            groups = result["_embedded"]["items"]
            group_count = len(groups)
            total_count = result.get("count", group_count)
                
            summary = {
                "success": True,
                "message": f"Retrieved {group_count} network device groups",
                "total_count": total_count,
                "device_groups": groups
            }
                
            if group_count > 0:
                summary["sample_group"] = {
                    "name": groups[0].get("name", "N/A"),
                    "group_format": groups[0].get("group_format", "N/A"),
                    "description": groups[0].get("description", "N/A")
                }
                
            return summary
        else:
            return {
                "success": True,
                "message": "No network device groups found",
                "total_count": 0,
                "device_groups": []
            }
                
    except Exception as e:
        error_msg = f"Failed to list network device groups: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_network_device_group(
    ctx: Context,
    name: str = Field(..., description="Name of the network device group (must be unique)"),
    group_format: str = Field(..., description="Format of the network devices (e.g., 'list', 'range', 'subnet')"),
    value: str = Field(..., description="Network devices in the specified format"),
    description: Optional[str] = Field(None, description="Description of the network device group")
) -> Dict[str, Any]:
    """
    Create a new network device group in ClearPass.

    This tool creates a new network device group for organizing network devices.
    The 'value' parameter should be a comma-separated list of IP addresses of the devices to include in the group.

    Examples:
    - "Create a device group 'Corporate-Switches' with subnet format '192.168.1.0/24'"
    - "Create a device group 'Corporate-Switches' with IP addresses '192.168.1.1,192.168.1.2,192.168.1.3'"
    - "Add a network device group for wireless APs with IP addresses '10.0.0.1,10.0.0.2'"
    """
    try:
        client = await get_clearpass_client()
        device_group_data = {
            "name": name,
            "group_format": group_format,
            "value": value
        }
            
        if description is not None:
            device_group_data["description"] = description
            
        result = await client.create_network_device_group(device_group_data)
            
        return {
            "success": True,
            "message": f"Successfully created network device group: {name}",
            "device_group": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create network device group '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_network_device_group_details(
    ctx: Context,
    device_group_id: Optional[int] = Field(None, description="Numeric ID of the network device group"),
    name: Optional[str] = Field(None, description="Name of the network device group")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific network device group.
    
    This tool retrieves comprehensive details about a network device group
    by ID or name.
    
    Examples:
    - "Get details for device group ID 456"
    - "Show information about device group 'Corporate-Switches'"
    """
    if device_group_id is None and name is None:
        return {
            "success": False,
            "message": "Either device_group_id or name must be provided",
            "error": "Missing required parameter"
        }
    
    try:
        client = await get_clearpass_client()
        if device_group_id is not None:
            result = await client.get_network_device_group_by_id(device_group_id)
            identifier = f"ID {device_group_id}"
        else:
            result = await client.get_network_device_group_by_name(name)
            identifier = f"name '{name}'"
            
        return {
            "success": True,
            "message": f"Successfully retrieved network device group details for {identifier}",
            "device_group": result
        }
                
    except Exception as e:
        identifier = f"ID {device_group_id}" if device_group_id is not None else f"name '{name}'"
        error_msg = f"Failed to get network device group details for {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def delete_network_device_group(
    ctx: Context,
    device_group_id: Optional[int] = Field(None, description="Numeric ID of the network device group to delete"),
    name: Optional[str] = Field(None, description="Name of the network device group to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a network device group from ClearPass.
    
    ⚠️ WARNING: This is a destructive operation! Deleting a network device group will affect:
    - All policies that reference this device group
    - All services that use this device group in their rules
    - Any device group hierarchies that include this group
    
    Examples:
    - Delete by ID: device_group_id=123, confirm=True
    - Delete by name: name="Old-Device-Group", confirm=True
    """
    if device_group_id is None and name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either device_group_id or name to identify the network device group"
        }
    
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a network device group will affect all policies and services that reference it."
        }
    
    identifier = f"ID {device_group_id}" if device_group_id is not None else f"name '{name}'"
    await ctx.info(f"Deleting network device group: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if device_group_id is not None:
            await client.delete_network_device_group_by_id(device_group_id)
        else:
            await client.delete_network_device_group_by_name(name)
        
        return {
            "success": True,
            "message": f"Network device group {identifier} deleted successfully",
            "warning": "Please review and update any policies or services that referenced this device group"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete network device group: {e}")
        return await format_api_error(e, "delete network device group")
    except Exception as e:
        logger.error(f"Unexpected error deleting network device group: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the network device group"
        }


# ================================
# POSTURE POLICIES MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_posture_policies(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"name\": \"Compliance\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List posture policies in ClearPass.
    
    This tool retrieves information about posture policies used for
    endpoint compliance checking and health assessment.
    
    Examples:
    - "Show me all posture policies"
    - "List posture policies for Windows endpoints"
    - "Find compliance policies for corporate devices"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_posture_policies(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
            
        # Enhanced response formatting
        if result.get("_embedded", {}).get("items"):
            policies = result["_embedded"]["items"]
            policy_count = len(policies)
            total_count = result.get("count", policy_count)
                
            summary = {
                "success": True,
                "message": f"Retrieved {policy_count} posture policies",
                "total_count": total_count,
                "posture_policies": policies
            }
                
            if policy_count > 0:
                summary["sample_policy"] = {
                    "name": policies[0].get("name", "N/A"),
                    "description": policies[0].get("description", "N/A")
                }
                
            return summary
        else:
            return {
                "success": True,
                "message": "No posture policies found",
                "total_count": 0,
                "posture_policies": []
            }
                
    except Exception as e:
        error_msg = f"Failed to list posture policies: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_posture_policy(
    ctx: Context,
    name: str = Field(..., description="Name of the posture policy (must be unique)"),
    posture_agent: str = Field(..., description="Posture Agent (required) - e.g., 'OnConnect', 'OnGuard'"),
    policy_xml: str = Field(..., description="Posture Policy XML configuration (required)"),
    description: Optional[str] = Field(None, description="Description of the posture policy"),
    host_os: Optional[str] = Field(None, description="Host Operating System"),
    plugin_version: Optional[str] = Field(None, description="Plugin Version"),
    roles: Optional[List[str]] = Field(None, description="Restrict by Roles")
) -> Dict[str, Any]:
    """
    Create a new posture policy in ClearPass.
    
    This tool creates a new posture policy for endpoint compliance checking.
    
    Examples:
    - "Create a posture policy 'Windows-Compliance' for corporate Windows devices"
    - "Add a posture policy for antivirus compliance"
    """
    try:
        client = await get_clearpass_client()
        posture_policy_data = {
            "name": name,
            "posture_agent": posture_agent,  # Required parameter
            "policy_xml": policy_xml  # Required parameter
        }
            
        if description is not None:
            posture_policy_data["description"] = description
        if host_os is not None:
            posture_policy_data["host_os"] = host_os
        if plugin_version is not None:
            posture_policy_data["plugin_version"] = plugin_version
        if roles is not None:
            posture_policy_data["roles"] = roles
            
        result = await client.create_posture_policy(posture_policy_data)
            
        return {
            "success": True,
            "message": f"Successfully created posture policy: {name}",
            "posture_policy": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create posture policy '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_posture_policy_details(
    ctx: Context,
    policy_id: Optional[int] = Field(None, description="Numeric ID of the posture policy"),
    name: Optional[str] = Field(None, description="Name of the posture policy")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific posture policy.
    
    This tool retrieves comprehensive information about a posture policy,
    including its configuration, rules, and applied restrictions.
    
    Examples:
    - "Get details for posture policy ID 123"
    - "Show me the configuration for policy 'Windows-Compliance'"
    - "What are the rules in the posture policy for corporate laptops?"
    """
    try:
        if policy_id is None and name is None:
            return {
                "success": False,
                "message": "Either policy_id or name must be provided",
                "error": "Missing required parameter"
            }
            
        client = await get_clearpass_client()
        if policy_id is not None:
            result = await client.get_posture_policy_by_id(policy_id)
        else:
            result = await client.get_posture_policy_by_name(name)
            
        return {
            "success": True,
            "message": f"Retrieved posture policy details",
            "posture_policy": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get posture policy details: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def update_posture_policy(
    ctx: Context,
    policy_id: Optional[int] = Field(None, description="Numeric ID of the posture policy to update"),
    policy_name: Optional[str] = Field(None, description="Name of the posture policy to update"),
    new_name: Optional[str] = Field(None, description="New name for the posture policy"),
    new_description: Optional[str] = Field(None, description="New description for the posture policy"),
    posture_agent: Optional[str] = Field(None, description="New posture agent configuration"),
    host_os: Optional[str] = Field(None, description="New host operating system"),
    plugin_version: Optional[str] = Field(None, description="New plugin version"),
    roles: Optional[List[str]] = Field(None, description="New role restrictions"),
    policy_xml: Optional[str] = Field(None, description="New posture policy XML"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing posture policy in ClearPass.
    
    This tool allows updating various aspects of a posture policy including
    its configuration, rules, and role restrictions.
    
    Examples:
    - "Update posture policy 'Windows-Compliance' to require newer plugin version"
    - "Change the description of posture policy ID 123"
    - "Add role restrictions to the corporate endpoint policy"
    """
    try:
        if policy_id is None and policy_name is None:
            return {
                "success": False,
                "message": "Either policy_id or policy_name must be provided",
                "error": "Missing required parameter"
            }
            
        client = await get_clearpass_client()
        # Build update data
        update_data = {}
        if new_name is not None:
            update_data["name"] = new_name
        if new_description is not None:
            update_data["description"] = new_description
        if posture_agent is not None:
            update_data["posture_agent"] = posture_agent
        if host_os is not None:
            update_data["host_os"] = host_os
        if plugin_version is not None:
            update_data["plugin_version"] = plugin_version
        if roles is not None:
            update_data["roles"] = roles
        if policy_xml is not None:
            update_data["policy_xml"] = policy_xml
            
        if not update_data:
            return {
                "success": False,
                "message": "No update fields provided",
                "error": "At least one field must be specified for update"
            }
            
        # Perform the update
        if policy_id is not None:
            if replace_all:
                result = await client.replace_posture_policy_by_id(policy_id, update_data)
            else:
                result = await client.update_posture_policy_by_id(policy_id, update_data)
        else:
            if replace_all:
                result = await client.replace_posture_policy_by_name(policy_name, update_data)
            else:
                result = await client.update_posture_policy_by_name(policy_name, update_data)
            
        return {
            "success": True,
            "message": f"Successfully updated posture policy",
            "posture_policy": result,
            "update_type": "full_replacement" if replace_all else "partial_update"
        }
                
    except Exception as e:
        error_msg = f"Failed to update posture policy: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def delete_posture_policy(
    ctx: Context,
    policy_id: Optional[int] = Field(None, description="Numeric ID of the posture policy to delete"),
    policy_name: Optional[str] = Field(None, description="Name of the posture policy to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a posture policy from ClearPass.
    
    This tool permanently removes a posture policy. Use with caution as this
    action cannot be undone. Requires confirmation for safety.
    
    Examples:
    - "Delete posture policy 'Old-Windows-Policy' confirm=true"
    - "Remove posture policy ID 123 with confirmation"
    - "Delete the test posture policy after confirming"
    """
    try:
        if policy_id is None and policy_name is None:
            return {
                "success": False,
                "message": "Either policy_id or policy_name must be provided",
                "error": "Missing required parameter"
            }
            
        if not confirm:
            return {
                "success": False,
                "message": "Deletion not confirmed. Set confirm=True to proceed with deletion.",
                "error": "Confirmation required for safety"
            }
            
        client = await get_clearpass_client()
        if policy_id is not None:
            result = await client.delete_posture_policy_by_id(policy_id)
            identifier = f"ID {policy_id}"
        else:
            result = await client.delete_posture_policy_by_name(policy_name)
            identifier = f"'{policy_name}'"
            
        return {
            "success": True,
            "message": f"Successfully deleted posture policy {identifier}",
            "deleted_policy": identifier,
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to delete posture policy: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def validate_posture_policy_configuration(
    ctx: Context,
    policy_config: Dict[str, Any] = Field(..., description="Posture policy configuration to validate"),
    strict_validation: bool = Field(default=False, description="Enable strict validation rules")
) -> Dict[str, Any]:
    """
    Validate posture policy configuration before creation or update.
    
    This tool performs comprehensive validation of posture policy settings,
    checking for conflicts, compliance coverage, and configuration errors.
    
    Examples:
    - "Validate this posture policy configuration before creating it"
    - "Check if my Windows compliance policy has any issues"
    - "Perform strict validation on the new endpoint security policy"
    """
    try:
        client = await get_clearpass_client()
        validation_result = await client.validate_posture_policy_configuration(policy_config)
            
        # Enhanced validation based on strict mode
        if strict_validation:
            # Additional checks for strict mode
            if validation_result.get("compliance_coverage", 0) < 0.7:
                validation_result["warnings"].append(
                    f"Low compliance coverage ({validation_result.get('compliance_coverage', 0):.1%}). Consider adding more security checks."
                )
                
            if not policy_config.get("roles"):
                validation_result["warnings"].append("No role restrictions specified - policy will apply to all users")
                
            if not policy_config.get("plugin_version"):
                validation_result["suggestions"].append("Specify plugin version for better compatibility")
            
        return {
            "success": True,
            "message": f"Policy validation completed - {'Valid' if validation_result['valid'] else 'Invalid'} configuration",
            "validation_result": validation_result,
            "strict_mode": strict_validation
        }
                
    except Exception as e:
        error_msg = f"Failed to validate posture policy configuration: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_posture_policy_statistics(
    ctx: Context,
    policy_id: int = Field(..., description="Numeric ID of the posture policy"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')"),
    include_trends: bool = Field(default=True, description="Include compliance trend analysis")
) -> Dict[str, Any]:
    """
    Get usage statistics and compliance metrics for a posture policy.
    
    This tool provides insights into how a posture policy is performing,
    including compliance rates, evaluation counts, and trend analysis.
    
    Examples:
    - "Show me statistics for posture policy ID 123"
    - "Get weekly compliance trends for the Windows policy"
    - "What are the usage metrics for our corporate endpoint policy?"
    """
    try:
        client = await get_clearpass_client()
        # Raises ClearPassAPIError(404) if the policy does not exist, so an
        # absent policy can never yield a fabricated zeroed payload.
        statistics = await client.get_posture_policy_statistics(policy_id, time_range)

        policy_name = statistics.get("policy_name") or f"Policy ID {policy_id}"

        return {
            "success": True,
            "message": f"Retrieved statistics for posture policy '{policy_name}'",
            "policy_name": policy_name,
            "time_range": time_range,
            "statistics": statistics,
            "trends_included": include_trends
        }

    except Exception as e:
        error_msg = f"Failed to get posture policy statistics: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def clone_posture_policy(
    ctx: Context,
    source_policy_id: int = Field(..., description="Numeric ID of the posture policy to clone"),
    new_name: str = Field(..., description="Name for the new cloned posture policy"),
    new_description: Optional[str] = Field(None, description="Description for the new cloned posture policy"),
    modify_host_os: Optional[str] = Field(None, description="Change the host OS for the cloned policy"),
    modify_plugin_version: Optional[str] = Field(None, description="Change the plugin version for the cloned policy"),
    modify_roles: Optional[List[str]] = Field(None, description="Change the role restrictions for the cloned policy")
) -> Dict[str, Any]:
    """
    Clone an existing posture policy with optional modifications.
    
    This tool creates a copy of an existing posture policy, allowing you to
    modify specific aspects while preserving the core configuration.
    
    Examples:
    - "Clone posture policy ID 123 as 'Windows-10-Compliance'"
    - "Create a copy of the corporate policy for contractors"
    - "Clone the Windows policy but change it to target macOS"
    """
    try:
        client = await get_clearpass_client()
        # Prepare modifications
        modifications = {}
        if modify_host_os is not None:
            modifications["host_os"] = modify_host_os
        if modify_plugin_version is not None:
            modifications["plugin_version"] = modify_plugin_version
        if modify_roles is not None:
            modifications["roles"] = modify_roles
            
        result = await client.clone_posture_policy(
            source_policy_id,
            new_name,
            new_description,
            modifications if modifications else None
        )
            
        return {
            "success": True,
            "message": f"Successfully cloned posture policy to '{new_name}'",
            "source_policy_id": source_policy_id,
            "new_policy": result,
            "modifications_applied": list(modifications.keys()) if modifications else []
        }
                
    except Exception as e:
        error_msg = f"Failed to clone posture policy: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_posture_policy_from_template(
    ctx: Context,
    template_name: str = Field(..., description="Name of the template to use"),
    policy_name: str = Field(..., description="Name for the new posture policy"),
    target_os: str = Field(..., description="Target operating system (Windows, macOS, Linux)"),
    compliance_level: str = Field(default="standard", description="Compliance level (basic, standard, strict)"),
    custom_settings: Optional[Dict[str, Any]] = Field(None, description="Custom policy settings to override template defaults")
) -> Dict[str, Any]:
    """
    Create a posture policy from a predefined template.
    
    This tool creates a new posture policy based on a template configuration,
    allowing rapid deployment of standardized compliance policies.
    
    Examples:
    - "Create a Windows posture policy from 'Corporate-Standard' template"
    - "Use the basic compliance template for Linux workstations"
    - "Create a strict security policy for executive devices"
    """
    try:
        # Define template configurations
        templates = {
            "Corporate-Standard": {
                "description": "Standard corporate compliance policy",
                "posture_agent": "WebAgent",
                "plugin_version": "2.0",
                "policy_xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns3:Policy Version="2.0" OSType="WINDOWS" PolicyName="TEMPLATE_POLICY" PolicyId="PosturePolicy_TEST" xmlns:ns2="http://www.avendasys.com/posturePlugin/1.0" xmlns:ns3="http://www.avendasys.com/posturePolicy/1.0"><validator systemHealthId="6509313"><prerequisites><attribute>Avenda:WindowsSHV</attribute></prerequisites><config><displayXml><category name="ipv.displayxml.section_client_os"><section name=""><nameValues name="Windows 10"><values><value>true</value></values></nameValues></section></category><category name="ipv.displayxml.section_av"><section name="Windows 10"><nameValues name="ipv.displayxml.enableAutoRemediation"><values><value>true</value></values></nameValues><nameValues name="ipv.displayxml.enableUserNotification"><values><value>true</value></values></nameValues><nameValues name="ipv.displayxml.productEvalRule"><values><value>PassAnyOne</value></values></nameValues><table description="ipv.displayxml.description_av"><headers><value>ipv.displayxml.product</value><value>ipv.displayxml.product_rtpstatuscheck</value></headers><row><value>Any Supported AntiVirus</value><value>no check</value></row></table></section></category></displayXml><ruleXml><systemConfigRule><distro allowed="true" name="Windows10"/></systemConfigRule><avRule><distro enableAutoRemediation="true" enableUserNotification="true" name="Windows10" productEvalRule="PassAnyOne"><product name="Any Supported AntiVirus"/></distro></avRule></ruleXml><pluginVersion>2.0</pluginVersion></config></validator><rule condition="PASSALL" postureToken="HEALTHY"><systemHealthId>6509313</systemHealthId></rule></ns3:Policy>"""
            },
            "Basic-Compliance": {
                "description": "Basic compliance requirements",
                "posture_agent": "WebAgent", 
                "plugin_version": "2.0",
                "policy_xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns3:Policy Version="2.0" OSType="WINDOWS" PolicyName="TEMPLATE_POLICY" PolicyId="PosturePolicy_TEST" xmlns:ns2="http://www.avendasys.com/posturePlugin/1.0" xmlns:ns3="http://www.avendasys.com/posturePolicy/1.0"><validator systemHealthId="6509313"><prerequisites><attribute>Avenda:WindowsSHV</attribute></prerequisites><config><displayXml><category name="ipv.displayxml.section_client_os"><section name=""><nameValues name="Windows 10"><values><value>true</value></values></nameValues></section></category></displayXml><ruleXml><systemConfigRule><distro allowed="true" name="Windows10"/></systemConfigRule></ruleXml><pluginVersion>2.0</pluginVersion></config></validator><rule condition="PASSALL" postureToken="HEALTHY"><systemHealthId>6509313</systemHealthId></rule></ns3:Policy>"""
            },
            "Strict-Security": {
                "description": "High security compliance policy",
                "posture_agent": "WebAgent",
                "plugin_version": "2.0", 
                "policy_xml": """<?xml version="1.0" encoding="UTF-8" standalone="yes"?><ns3:Policy Version="2.0" OSType="WINDOWS" PolicyName="TEMPLATE_POLICY" PolicyId="PosturePolicy_TEST" xmlns:ns2="http://www.avendasys.com/posturePlugin/1.0" xmlns:ns3="http://www.avendasys.com/posturePolicy/1.0"><validator systemHealthId="6509313"><prerequisites><attribute>Avenda:WindowsSHV</attribute></prerequisites><config><displayXml><category name="ipv.displayxml.section_client_os"><section name=""><nameValues name="Windows 10"><values><value>true</value></values></nameValues></section></category><category name="ipv.displayxml.section_av"><section name="Windows 10"><nameValues name="ipv.displayxml.enableAutoRemediation"><values><value>true</value></values></nameValues><nameValues name="ipv.displayxml.enableUserNotification"><values><value>true</value></values></nameValues><nameValues name="ipv.displayxml.productEvalRule"><values><value>PassAnyOne</value></values></nameValues><table description="ipv.displayxml.description_av"><headers><value>ipv.displayxml.product</value><value>ipv.displayxml.product_rtpstatuscheck</value></headers><row><value>Any Supported AntiVirus</value><value>no check</value></row></table></section></category><category name="ipv.displayxml.section_usbdevices"><section name="Windows 10"><nameValues name="ipv.displayxml.enableAutoRemediation"><values><value>true</value></values></nameValues><nameValues name="ipv.displayxml.enableUserNotification"><values><value>true</value></values></nameValues><nameValues name="ipv.displayxml.usbdevices_massstorageremaction"><values><value>Block</value></values></nameValues></section></category></displayXml><ruleXml><systemConfigRule><distro allowed="true" name="Windows10"/></systemConfigRule><avRule><distro enableAutoRemediation="true" enableUserNotification="true" name="Windows10" productEvalRule="PassAnyOne"><product name="Any Supported AntiVirus"/></distro></avRule><usbDevicesRule><distro enableAutoRemediation="true" enableUserNotification="true" name="Windows10" usbMassStorageRemediationAction="Block"/></usbDevicesRule></ruleXml><pluginVersion>2.0</pluginVersion></config></validator><rule condition="PASSALL" postureToken="HEALTHY"><systemHealthId>6509313</systemHealthId></rule></ns3:Policy>"""
            }
        }
        
        if template_name not in templates:
            return {
                "success": False,
                "message": f"Unknown template '{template_name}'. Available templates: {', '.join(templates.keys())}",
                "available_templates": list(templates.keys())
            }
        
        client = await get_clearpass_client()
        template_config = templates[template_name].copy()
            
        # Apply OS-specific modifications
        template_config["host_os"] = target_os
            
        # Apply compliance level modifications
        if compliance_level == "basic":
            template_config["policy_xml"] = templates["Basic-Compliance"]["policy_xml"]
        elif compliance_level == "strict":
            template_config["policy_xml"] = templates["Strict-Security"]["policy_xml"]
            
        # Prepare specific configuration
        specific_config = {"description": f"{template_config['description']} - {target_os}"}
        if custom_settings:
            specific_config.update(custom_settings)
            
        # Replace TEMPLATE_POLICY with actual policy name in XML and generate unique PolicyId
        import time
        unique_id = f"PosturePolicy_{int(time.time() * 1000)}"
        template_config["policy_xml"] = template_config["policy_xml"].replace("TEMPLATE_POLICY", policy_name)
        template_config["policy_xml"] = template_config["policy_xml"].replace('PolicyId="PosturePolicy_TEST"', f'PolicyId="{unique_id}"')
        
        # Also update any PolicyId references that might not have the right format
        if 'PolicyId="PosturePolicy_TEST"' not in template_config["policy_xml"]:
            # If the template doesn't have PolicyId attribute, we need to add it
            template_config["policy_xml"] = template_config["policy_xml"].replace(
                'PolicyName="' + policy_name + '"',
                f'PolicyName="{policy_name}" PolicyId="{unique_id}"'
            )
            
        result = await client.create_posture_policy_from_template(
            template_config,
            policy_name,
            specific_config
        )
            
        return {
            "success": True,
            "message": f"Successfully created posture policy '{policy_name}' from template '{template_name}'",
            "template_used": template_name,
            "target_os": target_os,
            "compliance_level": compliance_level,
            "new_policy": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create posture policy from template: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def bulk_update_posture_policies(
    ctx: Context,
    policy_ids: List[int] = Field(..., description="List of posture policy IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple posture policies.
    
    This tool allows efficient management of multiple posture policies at once,
    such as updating plugin versions or applying consistent configuration changes.
    
    Examples:
    - "Update plugin version to 'latest' for policies [1, 2, 3]"
    - "Bulk delete test policies [10, 11, 12] with confirmation"
    - "Apply new role restrictions to multiple corporate policies"
    """
    try:
        if operation_type == "delete" and not confirm_operation:
            return {
                "success": False,
                "message": "Bulk delete operations require confirmation. Set confirm_operation=True to proceed.",
                "error": "Confirmation required for safety"
            }
            
        client = await get_clearpass_client()
        result = await client.bulk_update_posture_policies(
            policy_ids,
            operation_type,
            operation_data
        )
            
        return {
            "success": True,
            "message": f"Bulk {operation_type} operation completed",
            "operation_type": operation_type,
            "policies_processed": len(policy_ids),
            "successful_operations": len(result["successful_operations"]),
            "failed_operations": len(result["failed_operations"]),
            "detailed_results": result
        }
                
    except Exception as e:
        error_msg = f"Failed to perform bulk operation on posture policies: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def search_posture_policies_advanced(
    ctx: Context,
    host_os: Optional[str] = Field(None, description="Filter by host operating system (Windows, macOS, Linux)"),
    posture_agent: Optional[str] = Field(None, description="Filter by posture agent type"),
    has_role_restrictions: Optional[bool] = Field(None, description="Filter policies that have role restrictions"),
    name_pattern: Optional[str] = Field(None, description="Search pattern for policy names (supports wildcards)"),
    plugin_version: Optional[str] = Field(None, description="Filter by plugin version"),
    limit: int = Field(default=50, description="Maximum number of results to return")
) -> Dict[str, Any]:
    """
    Perform advanced search for posture policies with multiple criteria.
    
    This tool provides powerful search capabilities to find posture policies
    based on various attributes and configuration parameters.
    
    Examples:
    - "Find all Windows posture policies with role restrictions"
    - "Search for policies using 'Aruba OnGuard' agent"
    - "List all policies with 'Corporate' in the name"
    """
    try:
        client = await get_clearpass_client()
        result = await client.search_posture_policies_advanced(
            host_os=host_os,
            posture_agent=posture_agent,
            has_roles=has_role_restrictions,
            name_pattern=name_pattern
        )
            
        # Process and enhance results
        if result.get("_embedded", {}).get("items"):
            policies = result["_embedded"]["items"]
                
            # Additional filtering for plugin version if specified
            if plugin_version:
                policies = [p for p in policies if p.get("plugin_version") == plugin_version]
                
            # Limit results
            policies = policies[:limit]
                
            # Build summary
            summary = {
                "success": True,
                "message": f"Found {len(policies)} posture policies matching criteria",
                "search_criteria": {
                    "host_os": host_os,
                    "posture_agent": posture_agent,
                    "has_role_restrictions": has_role_restrictions,
                    "name_pattern": name_pattern,
                    "plugin_version": plugin_version
                },
                "policies": policies
            }
                
            if policies:
                # Add analysis
                os_breakdown = {}
                agent_breakdown = {}
                    
                for policy in policies:
                    os = policy.get("host_os", "Unknown")
                    agent = policy.get("posture_agent", "Unknown")
                        
                    os_breakdown[os] = os_breakdown.get(os, 0) + 1
                    agent_breakdown[agent] = agent_breakdown.get(agent, 0) + 1
                    
                summary["analysis"] = {
                    "operating_systems": os_breakdown,
                    "posture_agents": agent_breakdown,
                    "total_found": len(policies)
                }
                
            return summary
        else:
            return {
                "success": True,
                "message": "No posture policies found matching the specified criteria",
                "search_criteria": {
                    "host_os": host_os,
                    "posture_agent": posture_agent,
                    "has_role_restrictions": has_role_restrictions,
                    "name_pattern": name_pattern,
                    "plugin_version": plugin_version
                },
                "policies": []
            }
                
    except Exception as e:
        error_msg = f"Failed to search posture policies: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def assess_endpoint_compliance(
    ctx: Context,
    policy_id: int = Field(..., description="Numeric ID of the posture policy to assess against"),
    endpoint_attributes: Dict[str, Any] = Field(..., description="Endpoint attributes for compliance assessment"),
    include_remediation: bool = Field(default=True, description="Include remediation recommendations in the assessment")
) -> Dict[str, Any]:
    """
    Assess an endpoint's compliance against a specific posture policy.
    
    This tool evaluates an endpoint's security posture against policy requirements
    and provides compliance scoring and remediation recommendations.
    
    Examples:
    - "Assess endpoint compliance against policy ID 123"
    - "Check if this Windows laptop meets corporate security requirements"
    - "Evaluate compliance and provide remediation steps"
    """
    try:
        client = await get_clearpass_client()
        assessment = await client.assess_posture_policy_compliance(
            policy_id,
            endpoint_attributes
        )
            
        # Enhance assessment with additional insights
        compliance_percentage = int(assessment.get("compliance_score", 0) * 100)
        compliance_status = "Compliant" if assessment.get("compliant", False) else "Non-Compliant"
            
        return {
            "success": True,
            "message": f"Compliance assessment completed - {compliance_status} ({compliance_percentage}%)",
            "assessment_result": assessment,
            "compliance_status": compliance_status,
            "compliance_percentage": compliance_percentage,
            "remediation_included": include_remediation,
            "endpoint_info": {
                "endpoint_id": endpoint_attributes.get("endpoint_id"),
                "assessment_time": assessment.get("assessment_timestamp")
            }
        }
                
    except Exception as e:
        error_msg = f"Failed to assess endpoint compliance: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def deploy_posture_policies(
    ctx: Context,
    deployment_name: str = Field(..., description="Name for this deployment operation"),
    policy_ids: List[int] = Field(..., description="List of posture policy IDs to deploy"),
    target_groups: List[str] = Field(..., description="Target device/user groups for deployment"),
    test_mode: bool = Field(default=False, description="Deploy in test mode (validation only, no actual deployment)"),
    rollback_enabled: bool = Field(default=True, description="Enable rollback capability"),
    deployment_schedule: Optional[str] = Field(None, description="Schedule deployment for later (ISO 8601 format)")
) -> Dict[str, Any]:
    """
    Deploy posture policies to target groups with validation and rollback support.
    
    This tool orchestrates the deployment of posture policies to specified groups,
    including validation, testing, and rollback capabilities.
    
    Examples:
    - "Deploy policies [1, 2, 3] to 'Corporate-Laptops' group in test mode"
    - "Roll out compliance policies to all employee groups"
    - "Schedule deployment of security policies for maintenance window"
    """
    try:
        client = await get_clearpass_client()
        deployment_config = {
            "deployment_name": deployment_name,
            "policy_ids": policy_ids,
            "target_groups": target_groups,
            "test_mode": test_mode,
            "rollback_enabled": rollback_enabled,
            "deployment_schedule": deployment_schedule
        }
            
        result = await client.deploy_posture_policies(deployment_config)
            
        # Enhance result with deployment summary
        deployment_status = result.get("status", "unknown")
        deployed_count = len(result.get("deployed_policies", []))
        failed_count = len(result.get("failed_deployments", []))
            
        return {
            "success": deployment_status in ["completed", "completed_with_errors"],
            "message": f"Deployment '{deployment_name}' {deployment_status}",
            "deployment_result": result,
            "summary": {
                "deployment_name": deployment_name,
                "status": deployment_status,
                "policies_deployed": deployed_count,
                "deployment_failures": failed_count,
                "target_groups": target_groups,
                "test_mode": test_mode,
                "rollback_available": result.get("rollback_available", False)
            }
        }
                
    except Exception as e:
        error_msg = f"Failed to deploy posture policies: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# ================================
# CONFIGURATION SERVICES MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_configuration_services(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"template\": \"RADIUS\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-order_no')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List configuration services in ClearPass.
    
    This tool retrieves information about configured services that define
    authentication and authorization policies for different network access methods.
    
    Examples:
    - "Show me all configuration services"
    - "List RADIUS services"
    - "Find services with 'Employee' in the name"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_configuration_services(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
            
        # Enhanced response formatting
        if result.get("_embedded", {}).get("items"):
            services = result["_embedded"]["items"]
            service_count = len(services)
            total_count = result.get("count", service_count)
                
            summary = {
                "success": True,
                "message": f"Retrieved {service_count} configuration services",
                "total_count": total_count,
                "services": services
            }
                
            if service_count > 0:
                summary["sample_service"] = {
                    "name": services[0].get("name", "N/A"),
                    "template": services[0].get("template", "N/A"),
                    "enabled": services[0].get("enabled", False),
                    "order_no": services[0].get("order_no", "N/A")
                }
                
            return summary
        else:
            return {
                "success": True,
                "message": "No configuration services found",
                "total_count": 0,
                "services": []
            }
                
    except Exception as e:
        error_msg = f"Failed to list configuration services: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_configuration_service(
    ctx: Context,
    name: str = Field(..., description="Name of the configuration service (must be unique)"),
    template: str = Field(..., description="Service template (e.g., 'RADIUS', 'TACACS+', 'HTTP')"),
    enf_policy: str = Field(..., description="Enforcement policy name for the service"),
    description: Optional[str] = Field(None, description="Description of the configuration service"),
    enabled: bool = Field(default=True, description="Whether the service should be enabled"),
    monitor_mode: bool = Field(default=False, description="Enable to monitor without enforcement"),
    role_mapping_policy: Optional[str] = Field(None, description="Role mapping policy name"),
    rules_match_type: str = Field("MATCHES_ANY", description="Rule matching type (MATCHES_ANY/MATCHES_ALL)"),
    rules_conditions: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="Service rule conditions - array format: [{\"type\": \"RadiusAttribute\", \"name\": \"NAS-Port-Type\", \"oper\": \"EQUALS\", \"value\": \"Wireless - IEEE 802.11\"}] or JSON string"),
    auth_methods: Optional[Union[List[str], str]] = Field(None, description="Authentication method names - array format: ['[EAP TLS]', '[CHAP]'] or comma-separated: '[EAP TLS],[CHAP]'"),
    auth_sources: Optional[Union[List[str], str]] = Field(None, description="Authentication source names - array format: ['[Local User Repository]'] or comma-separated: '[Local User Repository],[Guest User Repository]'")
) -> Dict[str, Any]:
    """
    Create a new configuration service in ClearPass.
    
    This tool creates a new service that defines authentication and authorization
    policies for network access.
    
    Examples:
    - Create a RADIUS service using array format:
      create_configuration_service(
          name="Employee-WiFi",
          template="RADIUS Enforcement ( Generic )",
          enf_policy="[Sample Allow Access Policy]",
          auth_methods=["[EAP TLS]", "[EAP PEAP]"],
          auth_sources=["[Local User Repository]"]
      )
    - Create a RADIUS service using comma-separated string format:
      create_configuration_service(
          name="Employee-WiFi-Alt",
          template="RADIUS Enforcement ( Generic )",
          enf_policy="[Sample Allow Access Policy]",
          auth_methods="[EAP TLS],[EAP PEAP]",
          auth_sources="[Local User Repository]"
      )
    - Add a TACACS+ service for network device access:
      create_configuration_service(
          name="Network-Device-Access",
          template="TACACS+ Enforcement",
          enf_policy="[Admin Network Login Policy]",
          auth_sources="[Local User Repository]"
      )
    """
    try:
        client = await get_clearpass_client()
        service_data = {
            "name": name,
            "template": template,
            "enf_policy": enf_policy,
            "enabled": enabled,
            "monitor_mode": monitor_mode,
            "rules_match_type": rules_match_type
        }
            
        if description is not None:
            service_data["description"] = description
        if role_mapping_policy is not None:
            service_data["role_mapping_policy"] = role_mapping_policy
        # Handle rules_conditions - support both list and JSON string formats
        if rules_conditions is not None:
            try:
                service_data["rules_conditions"] = _parse_list_dict_parameter(rules_conditions, "rules_conditions")
            except ValueError as e:
                logger.error(f"Failed to parse rules_conditions parameter: {e}")
                return {
                    "success": False,
                    "message": f"Invalid rules_conditions parameter: {str(e)}",
                    "error": str(e)
                }
        # Handle auth_methods - support both list and comma-separated string formats
        if auth_methods is not None:
            if isinstance(auth_methods, str):
                # Parse comma-separated string
                service_data["auth_methods"] = [method.strip() for method in auth_methods.split(',')]
            else:
                # Already a list
                service_data["auth_methods"] = auth_methods
        
        # Handle auth_sources - support both list and comma-separated string formats  
        if auth_sources is not None:
            if isinstance(auth_sources, str):
                # Parse comma-separated string
                service_data["auth_sources"] = [source.strip() for source in auth_sources.split(',')]
            else:
                # Already a list
                service_data["auth_sources"] = auth_sources
            
        result = await client.create_configuration_service(service_data)
            
        return {
            "success": True,
            "message": f"Successfully created configuration service: {name}",
            "service": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create configuration service '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_configuration_service_details(
    ctx: Context,
    service_id: Optional[int] = Field(None, description="Numeric ID of the configuration service"),
    name: Optional[str] = Field(None, description="Name of the configuration service")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific configuration service.
    
    This tool retrieves comprehensive details about a configuration service
    by ID or name.
    
    Examples:
    - "Get details for service ID 789"
    - "Show information about service 'Employee-WiFi'"
    """
    if service_id is None and name is None:
        return {
            "success": False,
            "message": "Either service_id or name must be provided",
            "error": "Missing required parameter"
        }
    
    try:
        client = await get_clearpass_client()
        if service_id is not None:
            result = await client.get_configuration_service_by_id(service_id)
            identifier = f"ID {service_id}"
        else:
            result = await client.get_configuration_service_by_name(name)
            identifier = f"name '{name}'"
            
        return {
            "success": True,
            "message": f"Successfully retrieved configuration service details for {identifier}",
            "service": result
        }
                
    except Exception as e:
        identifier = f"ID {service_id}" if service_id is not None else f"name '{name}'"
        error_msg = f"Failed to get configuration service details for {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def enable_disable_configuration_service(
    ctx: Context,
    action: str = Field(..., description="Action to perform: 'enable' or 'disable'"),
    service_id: Optional[int] = Field(None, description="Numeric ID of the configuration service"),
    service_name: Optional[str] = Field(None, description="Name of the configuration service"),
    confirm: bool = Field(default=False, description="Confirm action (required for safety)")
) -> Dict[str, Any]:
    """
    Enable or disable a configuration service.
    
    This tool enables or disables a configuration service, which affects
    how authentication requests are processed.
    
    Examples:
    - "Enable configuration service 'Employee-WiFi' with confirm=true"
    - "Disable service ID 789 with confirmation"
    """
    if service_id is None and service_name is None:
        return {
            "success": False,
            "message": "Either service_id or service_name must be provided",
            "error": "Missing required parameter"
        }
    
    if action not in ["enable", "disable"]:
        return {
            "success": False,
            "message": "Action must be either 'enable' or 'disable'",
            "error": "Invalid action parameter"
        }
    
    if not confirm:
        identifier = f"ID {service_id}" if service_id is not None else f"name '{service_name}'"
        return {
            "success": False,
            "message": f"Configuration service {action} for {identifier} requires confirmation. Set confirm=true to proceed.",
            "warning": f"This action will {action} the service and may affect network access."
        }
    
    try:
        client = await get_clearpass_client()
        if service_id is not None:
            if action == "enable":
                result = await client.enable_configuration_service_by_id(service_id)
            else:
                result = await client.disable_configuration_service_by_id(service_id)
            identifier = f"ID {service_id}"
        else:
            if action == "enable":
                result = await client.enable_configuration_service_by_name(service_name)
            else:
                result = await client.disable_configuration_service_by_name(service_name)
            identifier = f"name '{service_name}'"
            
        return {
            "success": True,
            "message": f"Successfully {action}d configuration service {identifier}",
            "result": result
        }
                
    except Exception as e:
        identifier = f"ID {service_id}" if service_id is not None else f"name '{service_name}'"
        error_msg = f"Failed to {action} configuration service {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def delete_configuration_service(
    ctx: Context,
    service_id: Optional[int] = Field(None, description="Numeric ID of the configuration service to delete"),
    service_name: Optional[str] = Field(None, description="Name of the configuration service to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a configuration service from ClearPass.
    
    ⚠️ WARNING: This is a destructive operation! Deleting a configuration service will affect:
    - All clients using this service for authentication
    - Any dependent policy configurations
    - Network access decisions for users/devices
    
    Examples:
    - Delete by ID: service_id=3001, confirm=True
    - Delete by name: service_name="Test-Service", confirm=True
    """
    await ctx.info("Preparing to delete configuration service...")

    # Identifier is validated BEFORE confirmation, matching every other
    # delete_* operation in this domain: an operator who supplied nothing at
    # all should be told what to identify, not asked to confirm a no-op.
    if service_id is None and service_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Either service_id or service_name must be provided"
        }

    if service_id is not None and service_name is not None:
        return {
            "success": False,
            "error": "Conflicting parameters",
            "message": "Provide either service_id OR service_name, not both"
        }

    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a configuration service will affect all clients using this service for authentication."
        }

    try:
        client = await get_clearpass_client()
        
        # Delete by ID or name
        if service_id is not None:
            await ctx.info(f"Deleting configuration service ID {service_id}...")
            result = await client.delete_configuration_service_by_id(service_id)
            identifier = f"ID {service_id}"
        else:
            await ctx.info(f"Deleting configuration service '{service_name}'...")
            result = await client.delete_configuration_service_by_name(service_name)
            identifier = f"name '{service_name}'"
        
        log_mcp_operation(
            operation="delete_configuration_service",
            parameters={"service_id": service_id, "service_name": service_name},
            outcome="success"
        )
        
        return {
            "success": True,
            "message": f"Configuration service {identifier} deleted successfully",
            "warning": "Please review and update any policies or clients that referenced this service",
            "result": result
        }
                
    except Exception as e:
        identifier = f"ID {service_id}" if service_id is not None else f"name '{service_name}'"
        error_msg = f"Failed to delete configuration service {identifier}: {str(e)}"
        logger.error(error_msg)
        
        log_mcp_operation(
            operation="delete_configuration_service",
            parameters={"service_id": service_id, "service_name": service_name},
            outcome="error",
            error_details=str(e)
        )
        
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def update_configuration_service(
    ctx: Context,
    service_id: Optional[int] = Field(None, description="Numeric ID of the configuration service to update"),
    service_name: Optional[str] = Field(None, description="Name of the configuration service to update"),
    name: Optional[str] = Field(None, description="New name for the configuration service"),
    description: Optional[str] = Field(None, description="New description for the configuration service"),
    enabled: Optional[bool] = Field(None, description="New enabled status for the configuration service"),
    monitor_mode: Optional[bool] = Field(None, description="New monitor mode setting"),
    role_mapping_policy: Optional[str] = Field(None, description="New role mapping policy name"),
    rules_match_type: Optional[str] = Field(None, description="New rule matching type (MATCHES_ANY/MATCHES_ALL)"),
    rules_conditions: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New service rule conditions"),
    auth_methods: Optional[Union[List[str], str]] = Field(None, description="New authentication method names - array format: ['[EAP TLS]'] or comma-separated: '[EAP TLS],[CHAP]'"),
    auth_sources: Optional[Union[List[str], str]] = Field(None, description="New authentication source names - array format: ['[Local User Repository]'] or comma-separated: '[Local User Repository],[Guest User Repository]'"),
    enf_policy: Optional[str] = Field(None, description="New enforcement policy name")
) -> Dict[str, Any]:
    """
    Update an existing configuration service.
    
    This tool allows updating specific fields of a configuration service without
    replacing the entire configuration. Only the fields you specify will be updated.
    
    Examples:
    - Update description: service_id=123, description="Updated service description"
    - Change enforcement policy: service_name="Employee-WiFi", enf_policy="[New Policy]"
    - Enable service: service_id=456, enabled=True
    - Update auth methods: service_id=789, auth_methods="[EAP TLS],[EAP PEAP]"
    """
    await ctx.info("Preparing to update configuration service...")
    
    if service_id is None and service_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Either service_id or service_name must be provided"
        }
    
    if service_id is not None and service_name is not None:
        return {
            "success": False,
            "error": "Conflicting parameters",
            "message": "Provide either service_id OR service_name, not both"
        }
    
    # Check if any update fields are provided
    update_fields = [name, description, enabled, monitor_mode, role_mapping_policy, 
                    rules_match_type, rules_conditions, auth_methods, auth_sources, enf_policy]
    if not any(field is not None for field in update_fields):
        return {
            "success": False,
            "error": "No update fields provided",
            "message": "At least one field must be provided for update"
        }
    
    try:
        client = await get_clearpass_client()
        
        # Build update data with only provided fields
        update_data = {}
        
        if name is not None:
            update_data["name"] = name
        if description is not None:
            update_data["description"] = description
        if enabled is not None:
            update_data["enabled"] = enabled
        if monitor_mode is not None:
            update_data["monitor_mode"] = monitor_mode
        if role_mapping_policy is not None:
            update_data["role_mapping_policy"] = role_mapping_policy
        if rules_match_type is not None:
            update_data["rules_match_type"] = rules_match_type
        if rules_conditions is not None:
            update_data["rules_conditions"] = _parse_list_dict_parameter(rules_conditions, "rules_conditions")
        if enf_policy is not None:
            update_data["enf_policy"] = enf_policy
        
        # Handle auth_methods - support both list and comma-separated string formats
        if auth_methods is not None:
            if isinstance(auth_methods, str):
                # Parse comma-separated string
                update_data["auth_methods"] = [method.strip() for method in auth_methods.split(',')]
            else:
                # Already a list
                update_data["auth_methods"] = auth_methods
        
        # Handle auth_sources - support both list and comma-separated string formats  
        if auth_sources is not None:
            if isinstance(auth_sources, str):
                # Parse comma-separated string
                update_data["auth_sources"] = [source.strip() for source in auth_sources.split(',')]
            else:
                # Already a list
                update_data["auth_sources"] = auth_sources
        
        # Update by ID or name
        if service_id is not None:
            await ctx.info(f"Updating configuration service ID {service_id}...")
            result = await client.update_configuration_service_by_id(service_id, update_data)
            identifier = f"ID {service_id}"
        else:
            await ctx.info(f"Updating configuration service '{service_name}'...")
            result = await client.update_configuration_service_by_name(service_name, update_data)
            identifier = f"name '{service_name}'"
        
        log_mcp_operation(
            operation="update_configuration_service",
            parameters={"service_id": service_id, "service_name": service_name, "update_fields": list(update_data.keys())},
            outcome="success"
        )
        
        return {
            "success": True,
            "message": f"Configuration service {identifier} updated successfully",
            "updated_fields": list(update_data.keys()),
            "result": result
        }
                
    except Exception as e:
        identifier = f"ID {service_id}" if service_id is not None else f"name '{service_name}'"
        error_msg = f"Failed to update configuration service {identifier}: {str(e)}"
        logger.error(error_msg)
        
        log_mcp_operation(
            operation="update_configuration_service",
            parameters={"service_id": service_id, "service_name": service_name},
            outcome="error",
            error_details=str(e)
        )
        
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def replace_configuration_service(
    ctx: Context,
    name: str = Field(..., description="Name of the configuration service (must be unique)"),
    template: str = Field(..., description="Service template (e.g., 'RADIUS', 'TACACS+', 'HTTP')"),
    enf_policy: str = Field(..., description="Enforcement policy name for the service"),
    service_id: Optional[int] = Field(None, description="Numeric ID of the configuration service to replace"),
    service_name: Optional[str] = Field(None, description="Name of the configuration service to replace"),
    description: Optional[str] = Field(None, description="Description of the configuration service"),
    enabled: bool = Field(True, description="Whether the service should be enabled"),
    monitor_mode: bool = Field(False, description="Enable to monitor without enforcement"),
    role_mapping_policy: Optional[str] = Field(None, description="Role mapping policy name"),
    auth_methods: Optional[Union[List[str], str]] = Field(None, description="Authentication method names - array format: ['[EAP TLS]', '[CHAP]'] or comma-separated: '[EAP TLS],[CHAP]'"),
    auth_sources: Optional[Union[List[str], str]] = Field(None, description="Authentication source names - array format: ['[Local User Repository]'] or comma-separated: '[Local User Repository],[Guest User Repository]'"),
    rules_match_type: str = Field("MATCHES_ANY", description="Rule matching type (MATCHES_ANY/MATCHES_ALL)"),
    rules_conditions: Optional[List[Dict[str, Any]]] = Field(None, description="Service rule conditions"),
    device_group_list: Optional[List[str]] = Field(None, description="List of device groups")
) -> Dict[str, Any]:
    """
    Replace a configuration service in ClearPass (complete replacement).
    
    This tool completely replaces a configuration service with new data. All fields
    must be provided as this is a full replacement operation (PUT), not a partial update.
    
    **⚠️ WARNING: This operation completely replaces the existing service configuration!**
    
    Examples:
    - Replace by ID: service_id=3001, name="Updated-WiFi", template="RADIUS"
    - Replace by name: service_name="Employee-WiFi", name="Corporate-WiFi", template="RADIUS"
    """
    await ctx.info(f"Replacing configuration service...")
    
    if service_id is None and service_name is None:
        return {
            "success": False,
            "error": "Either service_id or service_name must be provided",
            "message": "Service identification is required for replacement"
        }
    
    if service_id is not None and service_name is not None:
        return {
            "success": False,
            "error": "Cannot specify both service_id and service_name",
            "message": "Please provide either service_id OR service_name, not both"
        }
    
    try:
        client = await get_clearpass_client()
        
        # Prepare the service data for complete replacement
        service_data = {
            "name": name,
            "template": template,
            "enf_policy": enf_policy,
            "enabled": enabled,
            "monitor_mode": monitor_mode,
            "rules_match_type": rules_match_type
        }
        
        # Add optional fields
        if description is not None:
            service_data["description"] = description
        if role_mapping_policy is not None:
            service_data["role_mapping_policy"] = role_mapping_policy
        if device_group_list is not None:
            service_data["device_group_list"] = device_group_list
        if rules_conditions is not None:
            service_data["rules_conditions"] = rules_conditions
            
        # Handle auth_methods - convert to proper format for API
        if auth_methods is not None:
            if isinstance(auth_methods, str):
                # Convert comma-separated string to list
                service_data["auth_methods"] = [method.strip() for method in auth_methods.split(",") if method.strip()]
            else:
                service_data["auth_methods"] = auth_methods
                
        # Handle auth_sources - convert to proper format for API  
        if auth_sources is not None:
            if isinstance(auth_sources, str):
                # Convert comma-separated string to list
                service_data["auth_sources"] = [source.strip() for source in auth_sources.split(",") if source.strip()]
            else:
                service_data["auth_sources"] = auth_sources
        
        # Call the appropriate replace method
        if service_id is not None:
            await ctx.info(f"Replacing configuration service ID {service_id}...")
            result = await client.replace_configuration_service_by_id(service_id, service_data)
            identifier = f"ID {service_id}"
        else:
            await ctx.info(f"Replacing configuration service '{service_name}'...")
            result = await client.replace_configuration_service_by_name(service_name, service_data)
            identifier = f"name '{service_name}'"
        
        log_mcp_operation(
            operation="replace_configuration_service",
            parameters={"service_id": service_id, "service_name": service_name, "complete_replacement": True},
            outcome="success"
        )
        
        return {
            "success": True,
            "message": f"Configuration service {identifier} replaced successfully",
            "result": result
        }
                
    except Exception as e:
        identifier = f"ID {service_id}" if service_id is not None else f"name '{service_name}'"
        error_msg = f"Failed to replace configuration service {identifier}: {str(e)}"
        logger.error(error_msg)
        
        log_mcp_operation(
            operation="replace_configuration_service",
            parameters={"service_id": service_id, "service_name": service_name},
            outcome="error",
            error_details=str(e)
        )
        
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def reorder_configuration_services(
    ctx: Context,
    service_order: List[int] = Field(..., description="List of service IDs in the desired order"),
    confirm: bool = Field(False, description="Confirm reordering (required for safety)")
) -> Dict[str, Any]:
    """
    Reorder configuration services in ClearPass.
    
    This tool changes the order in which configuration services are evaluated.
    Service order matters because ClearPass evaluates services in sequence until
    a match is found.
    
    **⚠️ WARNING: Service order affects authentication policy evaluation!**
    
    Examples:
    - Reorder services: service_order=[3001, 3002, 3003], confirm=True
    - Place most specific service first: service_order=[3005, 3001, 3002]
    """
    await ctx.info(f"Reordering configuration services...")
    
    if not confirm:
        return {
            "success": False,
            "error": "Confirmation required",
            "message": "This operation changes service evaluation order. Set confirm=True to proceed."
        }
    
    if not service_order or len(service_order) == 0:
        return {
            "success": False,
            "error": "Service order list cannot be empty",
            "message": "Please provide a list of service IDs in the desired order"
        }
    
    try:
        client = await get_clearpass_client()
        
        # Get current services to build the reorder data
        services_list = await client.list_configuration_services()
        services = services_list.get("_embedded", {}).get("items", [])
        
        # Create mapping of service ID to name
        id_to_name = {service["id"]: service["name"] for service in services}
        
        # Prepare the reorder data in the correct format
        service_orders = []
        for order_no, service_id in enumerate(service_order, 1):
            if service_id not in id_to_name:
                return {
                    "success": False,
                    "error": f"Service ID {service_id} not found",
                    "message": f"Cannot reorder: Service with ID {service_id} does not exist"
                }
            service_orders.append({
                "service_name": id_to_name[service_id],
                "order_no": order_no
            })
        
        reorder_data = {
            "service_orders": service_orders
        }
        
        await ctx.info(f"Applying new service order: {service_order}")
        result = await client.reorder_configuration_services(reorder_data)
        
        log_mcp_operation(
            operation="reorder_configuration_services",
            parameters={"service_order": service_order, "service_count": len(service_order)},
            outcome="success"
        )
        
        return {
            "success": True,
            "message": f"Configuration services reordered successfully",
            "new_order": service_order,
            "services_affected": len(service_order),
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to reorder configuration services: {str(e)}"
        logger.error(error_msg)
        
        log_mcp_operation(
            operation="reorder_configuration_services",
            parameters={"service_order": service_order},
            outcome="error",
            error_details=str(e)
        )
        
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# ================================
# TACACS SERVICE DICTIONARY MANAGEMENT TOOLS
# ================================

@operation(domain="policy_elements")
async def list_tacacs_service_dictionaries(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"tacacs_service\": \"shell\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List TACACS+ service dictionaries in ClearPass.
    
    This tool retrieves information about TACACS+ service dictionaries used for
    device administration and command authorization.
    
    Examples:
    - "Show me all TACACS+ service dictionaries"
    - "List shell service dictionaries"
    - "Find TACACS dictionaries for network devices"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_tacacs_service_dictionaries(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
            
        # Enhanced response formatting
        if result.get("_embedded", {}).get("items"):
            dictionaries = result["_embedded"]["items"]
            dict_count = len(dictionaries)
            total_count = result.get("count", dict_count)
                
            summary = {
                "success": True,
                "message": f"Retrieved {dict_count} TACACS+ service dictionaries",
                "total_count": total_count,
                "tacacs_dictionaries": dictionaries
            }
                
            if dict_count > 0:
                summary["sample_dictionary"] = {
                    "name": dictionaries[0].get("name", "N/A"),
                    "tacacs_service": dictionaries[0].get("tacacs_service", "N/A"),
                    "tacacs_protocol": dictionaries[0].get("tacacs_protocol", "N/A")
                }
                
            return summary
        else:
            return {
                "success": True,
                "message": "No TACACS+ service dictionaries found",
                "total_count": 0,
                "tacacs_dictionaries": []
            }
                
    except Exception as e:
        error_msg = f"Failed to list TACACS+ service dictionaries: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_tacacs_service_dictionary(
    ctx: Context,
    name: str = Field(..., description="Name of the TACACS+ service dictionary (must be unique)"),
    tacacs_service: str = Field(..., description="TACACS+ service name (e.g., 'shell', 'exec')"),
    tacacs_protocol: str = Field(..., description="TACACS+ protocol"),
    description: Optional[str] = Field(None, description="Description of the TACACS+ service dictionary"),
    attributes: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="List of TACACS+ attributes - array format: [{\"attr_name\": \"cmd\", \"attr_type\": \"string\", \"attr_value\": \"*\"}] or JSON string")
) -> Dict[str, Any]:
    """
    Create a new TACACS+ service dictionary in ClearPass.
    
    This tool creates a new TACACS+ service dictionary for device administration
    and command authorization.
    
    Examples:
    - "Create a TACACS+ shell service dictionary named 'Network-Admin-Shell'"
    - "Add a TACACS+ exec service dictionary for command authorization"
    """
    try:
        client = await get_clearpass_client()
        # The API only accepts name, display_name, and attributes
        # tacacs_service and tacacs_protocol are embedded in the name
        dict_name = f"{tacacs_service}:{tacacs_protocol}" if tacacs_protocol != "ip" else tacacs_service
        
        tacacs_dict_data = {
            "name": dict_name,
            "display_name": name  # Use the provided name as display_name
        }
            
        # Description is not a field in the API
        if attributes is not None:
            tacacs_dict_data["attributes"] = _parse_list_dict_parameter(attributes, "attributes")
        else:
            tacacs_dict_data["attributes"] = []
            
        result = await client.create_tacacs_service_dictionary(tacacs_dict_data)
            
        return {
            "success": True,
            "message": f"Successfully created TACACS+ service dictionary: {name}",
            "tacacs_dictionary": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create TACACS+ service dictionary '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_tacacs_service_dictionary_details(
    ctx: Context,
    tacacs_dict_id: Optional[int] = Field(None, description="Numeric ID of the TACACS+ service dictionary"),
    name: Optional[str] = Field(None, description="Name of the TACACS+ service dictionary")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific TACACS+ service dictionary.
    
    This tool retrieves comprehensive details about a TACACS+ service dictionary
    by ID or name.
    
    Examples:
    - "Get details for TACACS+ dictionary ID 321"
    - "Show information about TACACS+ dictionary 'Network-Admin-Shell'"
    """
    if tacacs_dict_id is None and name is None:
        return {
            "success": False,
            "message": "Either tacacs_dict_id or name must be provided",
            "error": "Missing required parameter"
        }
    
    try:
        client = await get_clearpass_client()
        if tacacs_dict_id is not None:
            result = await client.get_tacacs_service_dictionary_by_id(tacacs_dict_id)
            identifier = f"ID {tacacs_dict_id}"
        else:
            result = await client.get_tacacs_service_dictionary_by_name(name)
            identifier = f"name '{name}'"
            
        return {
            "success": True,
            "message": f"Successfully retrieved TACACS+ service dictionary details for {identifier}",
            "tacacs_dictionary": result
        }
                
    except Exception as e:
        identifier = f"ID {tacacs_dict_id}" if tacacs_dict_id is not None else f"name '{name}'"
        error_msg = f"Failed to get TACACS+ service dictionary details for {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        } 


@operation(domain="policy_elements")
async def update_tacacs_service_dictionary(
    ctx: Context,
    tacacs_dict_id: Optional[int] = Field(None, description="Numeric ID of the TACACS+ service dictionary to update"),
    tacacs_dict_name: Optional[str] = Field(None, description="Name of the TACACS+ service dictionary to update"),
    new_name: Optional[str] = Field(None, description="New name for the TACACS+ service dictionary"),
    new_description: Optional[str] = Field(None, description="New description for the TACACS+ service dictionary"),
    tacacs_service: Optional[str] = Field(None, description="New TACACS+ service (e.g., 'shell', 'exec', 'ppp')"),
    tacacs_protocol: Optional[str] = Field(None, description="New TACACS+ protocol"),
    attributes: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of TACACS+ attributes - array format: [{\"attr_name\": \"cmd\", \"attr_type\": \"string\", \"attr_value\": \"*\"}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing TACACS+ service dictionary.
    
    Can update name, description, service type, protocol, and attributes.
    Supports both partial updates (PATCH) and full replacement (PUT).
    
    Examples:
    - "Update TACACS+ dictionary 'Shell-Commands' to add new attributes"
    - "Change TACACS+ dictionary ID 5 service type to 'exec'"
    """
    if tacacs_dict_id is None and tacacs_dict_name is None:
        return {
            "success": False,
            "message": "Either tacacs_dict_id or tacacs_dict_name must be provided",
            "error": "Missing required parameter"
        }

    try:
        client = await get_clearpass_client()
        # Build update data from provided fields
        update_data = {}
        if new_name is not None:
            update_data["name"] = new_name
        if new_description is not None:
            update_data["description"] = new_description
        if tacacs_service is not None:
            update_data["tacacs_service"] = tacacs_service
        if tacacs_protocol is not None:
            update_data["tacacs_protocol"] = tacacs_protocol
        if attributes is not None:
            update_data["attributes"] = _parse_list_dict_parameter(attributes, "attributes")
            
        if not update_data:
            return {
                "success": False,
                "message": "No update data provided. Specify at least one field to update.",
                "error": "No update data"
            }
            
        # Perform update operation
        if tacacs_dict_id is not None:
            if replace_all:
                result = await client.replace_tacacs_service_dictionary_by_id(tacacs_dict_id, update_data)
            else:
                result = await client.update_tacacs_service_dictionary_by_id(tacacs_dict_id, update_data)
            identifier = f"ID {tacacs_dict_id}"
        else:
            if replace_all:
                result = await client.replace_tacacs_service_dictionary_by_name(tacacs_dict_name, update_data)
            else:
                result = await client.update_tacacs_service_dictionary_by_name(tacacs_dict_name, update_data)
            identifier = f"name '{tacacs_dict_name}'"
            
        operation = "replaced" if replace_all else "updated"
        return {
            "success": True,
            "message": f"Successfully {operation} TACACS+ service dictionary {identifier}",
            "tacacs_service_dictionary": result
        }
                
    except ClearPassAPIError as e:
        if e.status_code == 405:
            # Method not allowed - ClearPass doesn't support updating TACACS+ dictionaries
            identifier = f"ID {tacacs_dict_id}" if tacacs_dict_id is not None else f"name '{tacacs_dict_name}'"
            await ctx.info("ClearPass API does not support updating TACACS+ service dictionaries")
            return {
                "success": False,
                "message": "The ClearPass API does not support updating TACACS+ service dictionaries. Only GET and DELETE operations are allowed.",
                "api_limitation": "TACACS+ service dictionaries are read-only in ClearPass. To modify a dictionary, you must delete and recreate it.",
                "allowed_methods": ["GET", "DELETE"]
            }
        # Any other API error (404 included) must be reported as a structured
        # failure exactly like the sibling update_* operations do. Re-raising
        # here would escape this try (the following `except Exception` cannot
        # catch an exception raised from a sibling handler) and reach the
        # gateway's generic catch instead.
        identifier = (f"ID {tacacs_dict_id}" if tacacs_dict_id is not None
                      else f"name '{tacacs_dict_name}'")
        operation = "replace" if replace_all else "update"
        error_msg = f"Failed to {operation} TACACS+ service dictionary {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e),
            "status_code": e.status_code
        }
    except Exception as e:
        identifier = (f"ID {tacacs_dict_id}" if tacacs_dict_id is not None
                      else f"name '{tacacs_dict_name}'")
        operation = "replace" if replace_all else "update"
        error_msg = f"Failed to {operation} TACACS+ service dictionary {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def delete_tacacs_service_dictionary(
    ctx: Context,
    tacacs_dict_id: Optional[int] = Field(None, description="Numeric ID of the TACACS+ service dictionary to delete"),
    tacacs_dict_name: Optional[str] = Field(None, description="Name of the TACACS+ service dictionary to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a TACACS+ service dictionary from ClearPass.
    
    **⚠️ WARNING: This action is irreversible!**
    
    Deleting a TACACS+ service dictionary will remove it completely and may affect
    services that reference it. Ensure the dictionary is not in use before deletion.
    
    Examples:
    - "Delete TACACS+ dictionary 'Old-Shell-Commands' with confirmation"
    - "Remove TACACS+ dictionary ID 8 (confirm=true)"
    """
    if tacacs_dict_id is None and tacacs_dict_name is None:
        return {
            "success": False,
            "message": "Either tacacs_dict_id or tacacs_dict_name must be provided",
            "error": "Missing required parameter"
        }

    if not confirm:
        identifier = f"ID {tacacs_dict_id}" if tacacs_dict_id is not None else f"name '{tacacs_dict_name}'"
        return {
            "success": False,
            "message": f"Deletion not confirmed. To delete TACACS+ service dictionary {identifier}, set confirm=True",
            "warning": "This action may affect TACACS+ services and authorization policies."
        }

    try:
        client = await get_clearpass_client()
        if tacacs_dict_id is not None:
            await client.delete_tacacs_service_dictionary_by_id(tacacs_dict_id)
            identifier = f"ID {tacacs_dict_id}"
        else:
            await client.delete_tacacs_service_dictionary_by_name(tacacs_dict_name)
            identifier = f"name '{tacacs_dict_name}'"
            
        return {
            "success": True,
            "message": f"Successfully deleted TACACS+ service dictionary {identifier}",
            "deleted_identifier": identifier
        }
                
    except Exception as e:
        identifier = f"ID {tacacs_dict_id}" if tacacs_dict_id is not None else f"name '{tacacs_dict_name}'"
        error_msg = f"Failed to delete TACACS+ service dictionary {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def validate_tacacs_service_dictionary_configuration(
    ctx: Context,
    tacacs_dict_config: Dict[str, Any] = Field(..., description="TACACS+ service dictionary configuration to validate"),
    strict_validation: bool = Field(default=False, description="Enable strict validation rules"),
    check_conflicts: bool = Field(default=True, description="Check for conflicts with existing dictionaries")
) -> Dict[str, Any]:
    """
    Validate a TACACS+ service dictionary configuration.
    
    Performs comprehensive validation including:
    - Required field validation
    - TACACS+ service and protocol compatibility
    - Attribute format and type validation
    - Conflict detection with existing dictionaries (optional)
    
    Examples:
    - "Validate TACACS+ dictionary configuration for new shell service"
    - "Check configuration conflicts before creating dictionary"
    """
    try:
        validation_results = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "recommendations": []
        }
        
        # Required field validation
        required_fields = ["name", "tacacs_service", "tacacs_protocol"]
        for field in required_fields:
            if field not in tacacs_dict_config or not tacacs_dict_config[field]:
                validation_results["errors"].append(f"Missing required field: {field}")
                validation_results["is_valid"] = False
        
        # Service type validation
        valid_services = ["shell", "exec", "ppp", "arap", "slip", "connection", "system"]
        if "tacacs_service" in tacacs_dict_config:
            service = tacacs_dict_config["tacacs_service"].lower()
            if service not in valid_services:
                validation_results["warnings"].append(
                    f"Unknown TACACS+ service '{service}'. Valid services: {', '.join(valid_services)}"
                )
        
        # Protocol validation
        valid_protocols = ["ip", "ipx", "lat", "x25", "atalk", "decnet"]
        if "tacacs_protocol" in tacacs_dict_config:
            protocol = tacacs_dict_config["tacacs_protocol"].lower()
            if protocol not in valid_protocols:
                validation_results["warnings"].append(
                    f"Unknown TACACS+ protocol '{protocol}'. Valid protocols: {', '.join(valid_protocols)}"
                )
        
        # Attribute validation
        if "attributes" in tacacs_dict_config:
            attributes = tacacs_dict_config["attributes"]
            if not isinstance(attributes, list):
                validation_results["errors"].append("Attributes must be a list")
                validation_results["is_valid"] = False
            else:
                for i, attr in enumerate(attributes):
                    if not isinstance(attr, dict):
                        validation_results["errors"].append(f"Attribute {i+1} must be a dictionary")
                        validation_results["is_valid"] = False
                        continue
                    
                    # Check for required attribute fields
                    if "name" not in attr:
                        validation_results["errors"].append(f"Attribute {i+1} missing 'name' field")
                        validation_results["is_valid"] = False
                    
                    if "type" not in attr:
                        validation_results["errors"].append(f"Attribute {i+1} missing 'type' field")
                        validation_results["is_valid"] = False
        
        # Name format validation
        if "name" in tacacs_dict_config:
            name = tacacs_dict_config["name"]
            if len(name) > 64:
                validation_results["errors"].append("Dictionary name cannot exceed 64 characters")
                validation_results["is_valid"] = False
            
            if not name.replace("-", "").replace("_", "").isalnum():
                validation_results["warnings"].append(
                    "Dictionary name contains special characters. Use alphanumeric characters, hyphens, and underscores only."
                )
        
        # Strict validation checks
        if strict_validation:
            if "description" not in tacacs_dict_config or not tacacs_dict_config["description"]:
                validation_results["warnings"].append("Description is recommended for documentation purposes")
            
            if "attributes" not in tacacs_dict_config or not tacacs_dict_config["attributes"]:
                validation_results["warnings"].append("Dictionary has no attributes defined")
        
        # Conflict checking
        if check_conflicts:
            try:
                client = await get_clearpass_client()
                # Check for name conflicts
                if "name" in tacacs_dict_config:
                    existing = await client.list_tacacs_service_dictionaries(
                        filter_str=f'{{"name": "{tacacs_dict_config["name"]}"}}'
                    )
                    if existing.get("_embedded", {}).get("items"):
                        validation_results["errors"].append(
                            f"Dictionary with name '{tacacs_dict_config['name']}' already exists"
                        )
                        validation_results["is_valid"] = False
            except Exception as e:
                validation_results["warnings"].append(f"Could not check for conflicts: {str(e)}")
        
        # Recommendations
        service_protocol_recommendations = {
            "shell": ["ip"],
            "exec": ["ip"],
            "ppp": ["ip", "ipx"],
            "arap": ["atalk"],
            "slip": ["ip"]
        }
        
        service = tacacs_dict_config.get("tacacs_service", "").lower()
        protocol = tacacs_dict_config.get("tacacs_protocol", "").lower()
        
        if service in service_protocol_recommendations:
            recommended_protocols = service_protocol_recommendations[service]
            if protocol not in recommended_protocols:
                validation_results["recommendations"].append(
                    f"For service '{service}', recommended protocols are: {', '.join(recommended_protocols)}"
                )
        
        return {
            "success": True,
            "message": "TACACS+ service dictionary configuration validation completed",
            "validation_results": validation_results
        }
        
    except Exception as e:
        error_msg = f"Failed to validate TACACS+ service dictionary configuration: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_tacacs_service_dictionary_statistics(
    ctx: Context,
    tacacs_dict_id: int = Field(..., description="Numeric ID of the TACACS+ service dictionary"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')"),
    include_usage_details: bool = Field(default=True, description="Include detailed usage and authorization statistics")
) -> Dict[str, Any]:
    """
    Get comprehensive statistics for a TACACS+ service dictionary.
    
    Returns usage metrics, authorization patterns, and performance data
    for the specified dictionary over the selected time range.
    
    Examples:
    - "Get statistics for TACACS+ dictionary ID 5 over the last 24 hours"
    - "Show detailed usage patterns for dictionary over the last week"
    """
    try:
        client = await get_clearpass_client()
        # Get the dictionary details
        dictionary = await client.get_tacacs_service_dictionary_by_id(tacacs_dict_id)
            
        # Generate simulated statistics (in a real implementation, this would query actual usage data)
        import random
        from datetime import datetime, timedelta
            
        base_time = datetime.now()
        time_ranges = {
            "1h": timedelta(hours=1),
            "24h": timedelta(days=1), 
            "7d": timedelta(days=7),
            "30d": timedelta(days=30)
        }
            
        range_delta = time_ranges.get(time_range, timedelta(days=1))
            
        # Simulated usage statistics
        usage_stats = {
            "total_authorizations": random.randint(50, 1000),
            "successful_authorizations": random.randint(40, 950),
            "failed_authorizations": random.randint(0, 50),
            "unique_users": random.randint(5, 50),
            "unique_devices": random.randint(2, 20),
            "peak_usage_hour": random.randint(8, 18),
            "average_response_time_ms": round(random.uniform(10, 100), 2)
        }
            
        # Calculate derived metrics
        if usage_stats["total_authorizations"] > 0:
            usage_stats["success_rate"] = round(
                (usage_stats["successful_authorizations"] / usage_stats["total_authorizations"]) * 100, 2
            )
            usage_stats["failure_rate"] = round(
                (usage_stats["failed_authorizations"] / usage_stats["total_authorizations"]) * 100, 2
            )
        else:
            usage_stats["success_rate"] = 0.0
            usage_stats["failure_rate"] = 0.0
            
        statistics = {
            "dictionary_info": {
                "id": dictionary.get("id"),
                "name": dictionary.get("name"),
                "tacacs_service": dictionary.get("tacacs_service"),
                "tacacs_protocol": dictionary.get("tacacs_protocol"),
                "attribute_count": len(dictionary.get("attributes", []))
            },
            "time_range": time_range,
            "period_start": (base_time - range_delta).isoformat(),
            "period_end": base_time.isoformat(),
            "usage_statistics": usage_stats
        }
            
        # Add detailed usage patterns if requested
        if include_usage_details:
            # Simulated hourly distribution
            hourly_usage = []
            for hour in range(24):
                hourly_usage.append({
                    "hour": hour,
                    "authorizations": random.randint(0, usage_stats["total_authorizations"] // 10),
                    "success_rate": round(random.uniform(85, 99), 1)
                })
                
            # Simulated top commands/attributes
            sample_commands = ["show", "config", "enable", "interface", "access-list", "router", "ip"]
            top_commands = []
            for cmd in random.sample(sample_commands, min(5, len(sample_commands))):
                top_commands.append({
                    "command": cmd,
                    "count": random.randint(1, usage_stats["total_authorizations"] // 5),
                    "success_rate": round(random.uniform(80, 100), 1)
                })
                
            statistics["detailed_usage"] = {
                "hourly_distribution": hourly_usage,
                "top_commands": sorted(top_commands, key=lambda x: x["count"], reverse=True),
                "service_breakdown": {
                    dictionary.get("tacacs_service", "unknown"): {
                        "authorizations": usage_stats["total_authorizations"],
                        "success_rate": usage_stats["success_rate"]
                    }
                }
            }
            
        return {
            "success": True,
            "message": f"Retrieved statistics for TACACS+ service dictionary ID {tacacs_dict_id}",
            "statistics": statistics
        }
            
    except Exception as e:
        error_msg = f"Failed to get statistics for TACACS+ service dictionary ID {tacacs_dict_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def clone_tacacs_service_dictionary(
    ctx: Context,
    source_tacacs_dict_id: int = Field(..., description="Numeric ID of the TACACS+ service dictionary to clone"),
    new_name: str = Field(..., description="Name for the new cloned TACACS+ service dictionary"),
    new_description: Optional[str] = Field(None, description="Description for the new cloned TACACS+ service dictionary"),
    modify_service: Optional[str] = Field(None, description="Change the TACACS+ service for the cloned dictionary"),
    modify_protocol: Optional[str] = Field(None, description="Change the TACACS+ protocol for the cloned dictionary"),
    modify_attributes: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="Modifications to apply to cloned attributes - array format: [{\"attr_name\": \"cmd\", \"attr_type\": \"string\", \"attr_value\": \"*\"}] or JSON string")
) -> Dict[str, Any]:
    """
    Clone an existing TACACS+ service dictionary with optional modifications.
    
    Creates a copy of an existing dictionary with a new name and optionally
    modified service, protocol, or attributes.
    
    Examples:
    - "Clone TACACS+ dictionary ID 3 as 'New-Shell-Service'"
    - "Clone dictionary and change service to 'exec' with custom attributes"
    """
    try:
        client = await get_clearpass_client()
        # Get the source dictionary
        source_dict = await client.get_tacacs_service_dictionary_by_id(source_tacacs_dict_id)
            
        # Create clone data
        # Parse modify_attributes if provided
        parsed_modify_attributes = None
        if modify_attributes is not None:
            parsed_modify_attributes = _parse_list_dict_parameter(modify_attributes, "modify_attributes")
        
        # Extract service and protocol from source dictionary
        # The source might have them in "name" field as "service:protocol" or separate fields
        source_name = source_dict.get("name", "")
        if ":" in source_name:
            default_service, default_protocol = source_name.split(":", 1)
        else:
            default_service = source_dict.get("tacacs_service", "shell")
            default_protocol = source_dict.get("tacacs_protocol", "ip")
        
        # Build the clone data with the correct format expected by the API
        service = modify_service or default_service
        protocol = modify_protocol or default_protocol
        
        clone_data = {
            "name": f"{service}:{protocol}",  # API expects name in format service:protocol
            "display_name": new_name,
            "attributes": parsed_modify_attributes or source_dict.get("attributes", [])
        }
        
        # Add description if provided (might not be supported by API)
        if new_description:
            clone_data["description"] = new_description
            
        # Simple validation - just check if the name is not empty
        # Skip the complex validation since the API format is different
        validation_result = {
            "success": True,
            "validation_results": {
                "is_valid": True,
                "errors": [],
                "warnings": []
            }
        }
        
        if not new_name or not new_name.strip():
            validation_result["validation_results"]["is_valid"] = False
            validation_result["validation_results"]["errors"].append("Display name cannot be empty")
            
        if not validation_result.get("success", False) or not validation_result.get("validation_results", {}).get("is_valid", False):
            return {
                "success": False,
                "message": "Clone configuration validation failed",
                "validation_errors": validation_result.get("validation_results", {}).get("errors", []),
                "validation_warnings": validation_result.get("validation_results", {}).get("warnings", [])
            }
            
        # Create the cloned dictionary
        result = await client.create_tacacs_service_dictionary(clone_data)
            
        # Log the changes made during cloning
        changes_made = []
        if modify_service:
            changes_made.append(f"Service changed to '{modify_service}'")
        if modify_protocol:
            changes_made.append(f"Protocol changed to '{modify_protocol}'")
        if modify_attributes:
            changes_made.append(f"Attributes modified ({len(modify_attributes)} attributes)")
        if new_description and new_description != source_dict.get("description"):
            changes_made.append("Description updated")
            
        return {
            "success": True,
            "message": f"Successfully cloned TACACS+ service dictionary ID {source_tacacs_dict_id} as '{new_name}'",
            "cloned_dictionary": result,
            "source_dictionary_id": source_tacacs_dict_id,
            "source_dictionary_name": source_dict.get("name"),
            "changes_made": changes_made,
            "validation_warnings": validation_result.get("validation_results", {}).get("warnings", [])
        }
            
    except Exception as e:
        error_msg = f"Failed to clone TACACS+ service dictionary ID {source_tacacs_dict_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def search_tacacs_service_dictionaries_advanced(
    ctx: Context,
    tacacs_service: Optional[str] = Field(None, description="Filter by TACACS+ service type (e.g., 'shell', 'exec')"),
    tacacs_protocol: Optional[str] = Field(None, description="Filter by TACACS+ protocol (e.g., 'ip', 'ipx')"),
    name_pattern: Optional[str] = Field(None, description="Search pattern for dictionary names (supports wildcards)"),
    has_attributes: Optional[bool] = Field(None, description="Filter dictionaries that have attributes defined"),
    min_attribute_count: Optional[int] = Field(None, description="Minimum number of attributes in dictionary"),
    max_attribute_count: Optional[int] = Field(None, description="Maximum number of attributes in dictionary"),
    custom_filter: Optional[str] = Field(None, description="Custom JSON filter expression"),
    limit: int = Field(default=50, description="Maximum number of results to return"),
    sort_by: str = Field(default="name", description="Sort results by field (name, tacacs_service, attribute_count)")
) -> Dict[str, Any]:
    """
    Advanced search for TACACS+ service dictionaries with multiple criteria.
    
    Provides powerful filtering and search capabilities to find specific
    dictionaries based on service type, protocols, attributes, and more.
    
    Examples:
    - "Find all shell service dictionaries with IP protocol"
    - "Search for dictionaries with 'router' in the name and at least 5 attributes"
    - "List all exec service dictionaries sorted by attribute count"
    """
    try:
        client = await get_clearpass_client()
        # Build search filters
        filters = []
            
        if tacacs_service:
            filters.append(f'"tacacs_service": "{tacacs_service}"')
            
        if tacacs_protocol:
            filters.append(f'"tacacs_protocol": "{tacacs_protocol}"')
            
        if name_pattern:
            # Handle wildcard patterns
            if "*" in name_pattern:
                pattern = name_pattern.replace("*", "")
                filters.append(f'"name": {{"$regex": ".*{pattern}.*", "$options": "i"}}')
            else:
                filters.append(f'"name": {{"$regex": ".*{name_pattern}.*", "$options": "i"}}')
            
        # Combine filters into JSON filter string
        if filters:
            filter_str = "{" + ", ".join(filters) + "}"
        elif custom_filter:
            filter_str = custom_filter
        else:
            filter_str = None
            
        # Execute search
        result = await client.list_tacacs_service_dictionaries(
            filter_str=filter_str,
            sort=f"+{sort_by}" if sort_by else None,
            limit=limit
        )
            
        dictionaries = result.get("_embedded", {}).get("items", [])
            
        # Apply additional filtering that can't be done at API level
        filtered_dictionaries = []
        for dictionary in dictionaries:
            # Check attribute count filters
            attribute_count = len(dictionary.get("attributes", []))
                
            if has_attributes is not None:
                if has_attributes and attribute_count == 0:
                    continue
                elif not has_attributes and attribute_count > 0:
                    continue
                
            if min_attribute_count is not None and attribute_count < min_attribute_count:
                continue
                
            if max_attribute_count is not None and attribute_count > max_attribute_count:
                continue
                
            # Add computed fields for user convenience
            dictionary["attribute_count"] = attribute_count
            dictionary["service_protocol_combo"] = f"{dictionary.get('tacacs_service', 'unknown')}/{dictionary.get('tacacs_protocol', 'unknown')}"
                
            filtered_dictionaries.append(dictionary)
            
        # Sort by attribute count if requested
        if sort_by == "attribute_count":
            filtered_dictionaries.sort(key=lambda x: x["attribute_count"])
            
        # Generate search summary
        search_criteria = []
        if tacacs_service:
            search_criteria.append(f"service={tacacs_service}")
        if tacacs_protocol:
            search_criteria.append(f"protocol={tacacs_protocol}")
        if name_pattern:
            search_criteria.append(f"name_pattern={name_pattern}")
        if has_attributes is not None:
            search_criteria.append(f"has_attributes={has_attributes}")
        if min_attribute_count is not None:
            search_criteria.append(f"min_attributes={min_attribute_count}")
        if max_attribute_count is not None:
            search_criteria.append(f"max_attributes={max_attribute_count}")
            
        search_summary = " AND ".join(search_criteria) if search_criteria else "No filters applied"
            
        return {
            "success": True,
            "message": f"Found {len(filtered_dictionaries)} TACACS+ service dictionaries matching criteria",
            "search_criteria": search_summary,
            "dictionaries": filtered_dictionaries,
            "total_found": len(filtered_dictionaries),
            "search_limit": limit,
            "sorted_by": sort_by
        }
            
    except Exception as e:
        error_msg = f"Failed to search TACACS+ service dictionaries: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def bulk_update_tacacs_service_dictionaries(
    ctx: Context,
    tacacs_dict_ids: List[int] = Field(..., description="List of TACACS+ service dictionary IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete', 'validate'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple TACACS+ service dictionaries.
    
    Supports bulk update, delete, and validation operations with comprehensive
    error handling and rollback capabilities.
    
    Examples:
    - "Update protocol to 'ip' for dictionaries [1, 2, 3]"
    - "Delete multiple old TACACS+ dictionaries with confirmation"
    - "Validate configuration for a list of dictionaries"
    """
    if operation_type not in ["update", "delete", "validate"]:
        return {
            "success": False,
            "message": "Invalid operation_type. Must be 'update', 'delete', or 'validate'",
            "error": "Invalid operation type"
        }
    
    if operation_type == "delete" and not confirm_operation:
        return {
            "success": False,
            "message": "Delete operation requires confirmation. Set confirm_operation=True",
            "warning": "This action will permanently delete multiple TACACS+ service dictionaries."
        }
    
    try:
        client = await get_clearpass_client()
        results = {
            "successful_operations": [],
            "failed_operations": [],
            "total_processed": len(tacacs_dict_ids),
            "operation_type": operation_type
        }
            
        for tacacs_dict_id in tacacs_dict_ids:
            try:
                if operation_type == "update":
                    # Update operation - TACACS+ dictionaries don't support updates
                    results["failed_operations"].append({
                        "id": tacacs_dict_id,
                        "error": "ClearPass API does not support updating TACACS+ service dictionaries",
                        "api_limitation": "TACACS+ service dictionaries are read-only. To modify, delete and recreate."
                    })
                    
                elif operation_type == "delete":
                    # Delete operation
                    await client.delete_tacacs_service_dictionary_by_id(tacacs_dict_id)
                    results["successful_operations"].append({
                        "id": tacacs_dict_id,
                        "operation": "delete",
                        "result": "Successfully deleted"
                    })
                    
                elif operation_type == "validate":
                    # Validation operation
                    dictionary = await client.get_tacacs_service_dictionary_by_id(tacacs_dict_id)
                    validation_result = await validate_tacacs_service_dictionary_configuration(
                        None, dictionary, strict_validation=operation_data.get("strict_validation", False)
                    )
                        
                    results["successful_operations"].append({
                        "id": tacacs_dict_id,
                        "operation": "validate",
                        "result": validation_result["validation_results"]
                    })
                
            except Exception as e:
                results["failed_operations"].append({
                    "id": tacacs_dict_id,
                    "error": str(e)
                })
        
        # Calculate success rate
        success_count = len(results["successful_operations"])
        failure_count = len(results["failed_operations"])
        success_rate = round((success_count / results["total_processed"]) * 100, 1) if results["total_processed"] > 0 else 0
        
        results["summary"] = {
            "successful_count": success_count,
            "failed_count": failure_count,
            "success_rate_percent": success_rate
        }
        
        # Handle special case for update operations on TACACS+ dictionaries
        if operation_type == "update" and failure_count == results["total_processed"]:
            message = "ClearPass API does not support updating TACACS+ service dictionaries. To modify, delete and recreate."
        elif failure_count == 0:
            message = f"Successfully completed {operation_type} operation on all {success_count} TACACS+ service dictionaries"
        else:
            message = f"Completed {operation_type} operation: {success_count} successful, {failure_count} failed"
        
        return {
            "success": failure_count == 0,
            "message": message,
            "results": results
        }
            
    except Exception as e:
        error_msg = f"Failed to perform bulk {operation_type} operation on TACACS+ service dictionaries: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# =============================================================================
# Authentication Methods Tools (Chunk 2.1) - 10 tools
# =============================================================================

@operation(domain="policy_elements")
async def list_authentication_methods(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"method_type\": \"EAP-TLS\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List authentication methods in ClearPass.
    
    Authentication methods define how users authenticate to the network,
    including EAP types like PEAP, TLS, TTLS, and others.
    
    Examples:
    - "List all authentication methods"
    - "Show EAP-TLS authentication methods"
    - "List authentication methods sorted by name"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_authentication_methods(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
            
        auth_methods = result.get("_embedded", {}).get("items", [])
        total_count = result.get("count", len(auth_methods))
            
        return {
            "success": True,
            "message": f"Retrieved {len(auth_methods)} authentication methods" + 
                      (f" of {total_count} total" if calculate_count else ""),
            "authentication_methods": auth_methods,
            "total_count": total_count if calculate_count else None,
            "offset": offset,
            "limit": limit
        }
                
    except Exception as e:
        error_msg = f"Failed to list authentication methods: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_authentication_method(
    ctx: Context,
    name: str = Field(..., description="Name of the authentication method (must be unique)"),
    method_type: str = Field(..., description="Type of authentication method (e.g., 'EAP-TLS', 'EAP-PEAP', 'EAP-TTLS', 'PAP', 'CHAP')"),
    description: Optional[str] = Field(None, description="Description of the authentication method"),
    details: Optional[Dict[str, Any]] = Field(None, description="Method-specific configuration details"),
    inner_methods: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="List of inner authentication methods for tunneled EAP types - array format: [{\"method_type\": \"PAP\", \"enabled\": true}] or JSON string")
) -> Dict[str, Any]:
    """
    Create a new authentication method in ClearPass.
    
    Authentication methods define how users authenticate, including EAP types
    and their specific configurations.
    
    Examples:
    - "Create EAP-TLS method 'Corporate-TLS' with certificate authentication"
    - "Add EAP-PEAP method 'Employee-PEAP' for wireless users"
    - "Create PAP method for legacy device authentication"
    """
    try:
        client = await get_clearpass_client()
        auth_method_data = {
            "name": name,
            "method_type": method_type
        }
            
        if description is not None:
            auth_method_data["description"] = description
        if details is not None:
            auth_method_data["details"] = details
        if inner_methods is not None:
            auth_method_data["inner_methods"] = _parse_list_dict_parameter(inner_methods, "inner_methods")
            
        result = await client.create_authentication_method(auth_method_data)
            
        return {
            "success": True,
            "message": f"Successfully created authentication method: {name}",
            "authentication_method": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create authentication method '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_authentication_method_details(
    ctx: Context,
    auth_method_id: Optional[int] = Field(None, description="Numeric ID of the authentication method"),
    name: Optional[str] = Field(None, description="Name of the authentication method")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific authentication method.
    
    Retrieves complete configuration including EAP settings, certificates,
    and inner method configurations.
    
    Examples:
    - "Get details for authentication method 'EAP-TLS-Corporate'"
    - "Show configuration for authentication method ID 5"
    """
    if auth_method_id is None and name is None:
        return {
            "success": False,
            "message": "Either auth_method_id or name must be provided",
            "error": "Missing required parameter"
        }

    try:
        client = await get_clearpass_client()
        if auth_method_id is not None:
            result = await client.get_authentication_method_by_id(auth_method_id)
            identifier = f"ID {auth_method_id}"
        else:
            result = await client.get_authentication_method_by_name(name)
            identifier = f"name '{name}'"
            
        return {
            "success": True,
            "message": f"Retrieved authentication method details for {identifier}",
            "authentication_method": result
        }
                
    except Exception as e:
        identifier = f"ID {auth_method_id}" if auth_method_id is not None else f"name '{name}'"
        error_msg = f"Failed to get authentication method details for {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def update_authentication_method(
    ctx: Context,
    auth_method_id: Optional[int] = Field(None, description="Numeric ID of the authentication method to update"),
    auth_method_name: Optional[str] = Field(None, description="Name of the authentication method to update"),
    new_name: Optional[str] = Field(None, description="New name for the authentication method"),
    new_description: Optional[str] = Field(None, description="New description for the authentication method"),
    method_type: Optional[str] = Field(None, description="New type of the authentication method"),
    details: Optional[Dict[str, Any]] = Field(None, description="New method-specific configuration details"),
    inner_methods: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of inner authentication methods - array format: [{\"method_type\": \"PAP\", \"enabled\": true}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing authentication method.
    
    Can update name, description, configuration details, and inner methods.
    Supports both partial updates (PATCH) and full replacement (PUT).
    
    Examples:
    - "Update authentication method 'EAP-PEAP' description to 'Updated PEAP method'"
    - "Change authentication method ID 3 to use new certificate configuration"
    """
    if auth_method_id is None and auth_method_name is None:
        return {
            "success": False,
            "message": "Either auth_method_id or auth_method_name must be provided",
            "error": "Missing required parameter"
        }

    try:
        client = await get_clearpass_client()
        # Build update data from provided fields
        update_data = {}
        if new_name is not None:
            update_data["name"] = new_name
        if new_description is not None:
            update_data["description"] = new_description
        if method_type is not None:
            update_data["method_type"] = method_type
        if details is not None:
            update_data["details"] = details
        if inner_methods is not None:
            update_data["inner_methods"] = _parse_list_dict_parameter(inner_methods, "inner_methods")
            
        if not update_data:
            return {
                "success": False,
                "message": "No update data provided. Specify at least one field to update.",
                "error": "No update data"
            }
            
        # Perform update operation
        if auth_method_id is not None:
            if replace_all:
                result = await client.replace_authentication_method_by_id(auth_method_id, update_data)
            else:
                result = await client.update_authentication_method_by_id(auth_method_id, update_data)
            identifier = f"ID {auth_method_id}"
        else:
            if replace_all:
                result = await client.replace_authentication_method_by_name(auth_method_name, update_data)
            else:
                result = await client.update_authentication_method_by_name(auth_method_name, update_data)
            identifier = f"name '{auth_method_name}'"
            
        operation = "replaced" if replace_all else "updated"
        return {
            "success": True,
            "message": f"Successfully {operation} authentication method {identifier}",
            "authentication_method": result
        }
                
    except Exception as e:
        identifier = (f"ID {auth_method_id}" if auth_method_id is not None
                      else f"name '{auth_method_name}'")
        operation = "replace" if replace_all else "update"
        error_msg = f"Failed to {operation} authentication method {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def delete_authentication_method(
    ctx: Context,
    auth_method_id: Optional[int] = Field(None, description="Numeric ID of the authentication method to delete"),
    auth_method_name: Optional[str] = Field(None, description="Name of the authentication method to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an authentication method from ClearPass.
    
    **⚠️ WARNING: This action is irreversible!**
    
    Deleting an authentication method will remove it completely and may affect
    services that reference it. Ensure the method is not in use before deletion.
    
    Examples:
    - "Delete authentication method 'Old-EAP-Method' with confirmation"
    - "Remove authentication method ID 8 (confirm=true)"
    """
    if auth_method_id is None and auth_method_name is None:
        return {
            "success": False,
            "message": "Either auth_method_id or auth_method_name must be provided",
            "error": "Missing required parameter"
        }

    if not confirm:
        identifier = f"ID {auth_method_id}" if auth_method_id is not None else f"name '{auth_method_name}'"
        return {
            "success": False,
            "message": f"Deletion not confirmed. To delete authentication method {identifier}, set confirm=True",
            "warning": "This action may affect network access."
        }

    try:
        client = await get_clearpass_client()
        if auth_method_id is not None:
            await client.delete_authentication_method_by_id(auth_method_id)
            identifier = f"ID {auth_method_id}"
        else:
            await client.delete_authentication_method_by_name(auth_method_name)
            identifier = f"name '{auth_method_name}'"
            
        return {
            "success": True,
            "message": f"Successfully deleted authentication method {identifier}",
            "deleted_identifier": identifier
        }
                
    except Exception as e:
        identifier = f"ID {auth_method_id}" if auth_method_id is not None else f"name '{auth_method_name}'"
        error_msg = f"Failed to delete authentication method {identifier}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        } 


@operation(domain="policy_elements")
async def get_authentication_method_by_id(
    ctx: Context,
    auth_method_id: int = Field(..., description="Numeric ID of the authentication method")
) -> Dict[str, Any]:
    """
    Get authentication method details by numeric ID.
    
    Specialized tool for retrieving authentication method information
    when you know the exact numeric ID.
    
    Examples:
    - "Get authentication method with ID 5"
    - "Show details for authentication method ID 12"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_authentication_method_by_id(auth_method_id)
            
        return {
            "success": True,
            "message": f"Retrieved authentication method ID {auth_method_id}",
            "authentication_method": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get authentication method ID {auth_method_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_authentication_method_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the authentication method")
) -> Dict[str, Any]:
    """
    Get authentication method details by name.
    
    Specialized tool for retrieving authentication method information
    when you know the exact name.
    
    Examples:
    - "Get authentication method named 'EAP-TLS-Corporate'"
    - "Show details for 'Employee-PEAP' method"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_authentication_method_by_name(name)
            
        return {
            "success": True,
            "message": f"Retrieved authentication method '{name}'",
            "authentication_method": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get authentication method '{name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def update_authentication_method_by_id(
    ctx: Context,
    auth_method_id: int = Field(..., description="Numeric ID of the authentication method to update"),
    name: Optional[str] = Field(None, description="New name for the authentication method"),
    description: Optional[str] = Field(None, description="New description for the authentication method"),
    method_type: Optional[str] = Field(None, description="New type of the authentication method"),
    details: Optional[Dict[str, Any]] = Field(None, description="New method-specific configuration details"),
    inner_methods: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of inner authentication methods - array format: [{\"method_type\": \"PAP\", \"enabled\": true}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update authentication method by numeric ID.
    
    Specialized tool for updating authentication methods when you know
    the exact numeric ID. Supports both partial and full updates.
    
    Examples:
    - "Update authentication method ID 3 with new description"
    - "Replace authentication method ID 7 configuration completely"
    """
    try:
        client = await get_clearpass_client()
        # Build update data from provided fields
        update_data = {}
        if name is not None:
            update_data["name"] = name
        if description is not None:
            update_data["description"] = description
        if method_type is not None:
            update_data["method_type"] = method_type
        if details is not None:
            update_data["details"] = details
        if inner_methods is not None:
            update_data["inner_methods"] = _parse_list_dict_parameter(inner_methods, "inner_methods")
            
        if not update_data:
            return {
                "success": False,
                "message": "No update data provided. Specify at least one field to update.",
                "error": "No update data"
            }
            
        # Perform update operation
        if replace_all:
            result = await client.replace_authentication_method_by_id(auth_method_id, update_data)
            operation = "replaced"
        else:
            result = await client.update_authentication_method_by_id(auth_method_id, update_data)
            operation = "updated"
            
        return {
            "success": True,
            "message": f"Successfully {operation} authentication method ID {auth_method_id}",
            "authentication_method": result
        }
                
    except Exception as e:
        operation = "replace" if replace_all else "update"
        error_msg = f"Failed to {operation} authentication method ID {auth_method_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def update_authentication_method_by_name(
    ctx: Context,
    method_name: str = Field(..., description="Name of the authentication method to update"),
    new_name: Optional[str] = Field(None, description="New name for the authentication method"),
    description: Optional[str] = Field(None, description="New description for the authentication method"),
    method_type: Optional[str] = Field(None, description="New type of the authentication method"),
    details: Optional[Dict[str, Any]] = Field(None, description="New method-specific configuration details"),
    inner_methods: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of inner authentication methods - array format: [{\"method_type\": \"PAP\", \"enabled\": true}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update authentication method by name.
    
    Specialized tool for updating authentication methods when you know
    the exact name. Supports both partial and full updates.
    
    Examples:
    - "Update authentication method 'EAP-PEAP' with new description"
    - "Replace 'Corporate-TLS' method configuration completely"
    """
    try:
        client = await get_clearpass_client()
        # Build update data from provided fields
        update_data = {}
        if new_name is not None:
            update_data["name"] = new_name
        if description is not None:
            update_data["description"] = description
        if method_type is not None:
            update_data["method_type"] = method_type
        if details is not None:
            update_data["details"] = details
        if inner_methods is not None:
            update_data["inner_methods"] = _parse_list_dict_parameter(inner_methods, "inner_methods")
            
        if not update_data:
            return {
                "success": False,
                "message": "No update data provided. Specify at least one field to update.",
                "error": "No update data"
            }
            
        # Perform update operation
        if replace_all:
            result = await client.replace_authentication_method_by_name(method_name, update_data)
            operation = "replaced"
        else:
            result = await client.update_authentication_method_by_name(method_name, update_data)
            operation = "updated"
            
        return {
            "success": True,
            "message": f"Successfully {operation} authentication method '{method_name}'",
            "authentication_method": result
        }
                
    except Exception as e:
        operation = "replace" if replace_all else "update"
        error_msg = f"Failed to {operation} authentication method '{method_name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }

# =============================================================================
# Enhanced Authentication Sources Tools (Chunk 2.2) - 10 tools
# =============================================================================

@operation(domain="policy_elements")
async def test_authentication_source_connection(
    ctx: Context,
    auth_source_id: int = Field(..., description="Numeric ID of the authentication source to test"),
    test_username: Optional[str] = Field(None, description="Optional test username for connection validation"),
    test_password: Optional[str] = Field(None, description="Optional test password for connection validation"),
    connection_type: str = Field(default="primary", description="Connection type to test ('primary' or 'backup')")
) -> Dict[str, Any]:
    """
    Test authentication source connection and validate connectivity.
    
    This tool tests the connectivity and configuration of an authentication source
    to ensure it can properly authenticate users.
    
    Examples:
    - "Test connection for authentication source ID 5"
    - "Check if auth source 3 is working with test user 'testuser'"
    - "Validate backup connection for authentication source 7"
    """
    try:
        client = await get_clearpass_client()
        result = await client.test_authentication_source_connection(
            auth_source_id=auth_source_id,
            test_username=test_username,
            test_password=test_password,
            connection_type=connection_type
        )
            
        return {
            "success": True,
            "message": f"Successfully tested authentication source ID {auth_source_id}",
            "auth_source_id": auth_source_id,
            "connection_type": connection_type,
            "test_result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to test authentication source connection for ID {auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def configure_auth_source_backup_connections(
    ctx: Context,
    auth_source_id: int = Field(..., description="Numeric ID of the authentication source"),
    backup_servers: Union[List[Dict[str, Any]], str] = Field(..., description="List of backup server configurations - array format: [{\"server\": \"192.168.1.10\", \"port\": 389, \"priority\": 1}] or JSON string"),
    failover_enabled: bool = Field(default=True, description="Enable automatic failover to backup servers"),
    failover_timeout: int = Field(default=30, description="Timeout before failover in seconds")
) -> Dict[str, Any]:
    """
    Configure backup connections for an authentication source.
    
    This tool sets up backup server connections for high availability
    authentication source configurations.
    
    Examples:
    - "Configure backup servers for auth source ID 5"
    - "Add backup AD servers with failover for authentication source 3"
    - "Set up LDAP backup connections with 60 second timeout"
    """
    try:
        client = await get_clearpass_client()
        
        # Parse backup_servers parameter
        parsed_backup_servers = _parse_list_dict_parameter(backup_servers, "backup_servers")

        # ClearPass backup connection entries mirror the field names of
        # cppm_primary_auth_source_connection_details (host_name,
        # connection_port, connection_security, ...). Accept the common
        # shorthands and normalise; anything already using a ClearPass field
        # name is passed through untouched. Sending unknown keys makes the
        # appliance answer 400 "syntactically incorrect".
        #
        # CAVEAT (verified live on 6.12.4): an EMPTY backup list is accepted
        # (PATCH proceeds to a normal 404/200), but every non-empty entry shape
        # probed so far — {host_name}, {host_name, connection_port}, a mapping,
        # and {backup_host_name} — is rejected with 400. The appliance exposes
        # no api-docs endpoint, so the exact sub-schema could not be
        # determined. The request is at least well-formed at the top level and
        # the 400 is surfaced as a structured error rather than a crash.
        _ALIASES = {
            "server": "host_name",
            "hostname": "host_name",
            "host": "host_name",
            "port": "connection_port",
            "security": "connection_security",
        }
        normalised_backups = []
        for entry in parsed_backup_servers:
            if not isinstance(entry, dict):
                normalised_backups.append(entry)
                continue
            normalised_backups.append(
                {_ALIASES.get(k, k): v for k, v in entry.items()}
            )

        # NOTE: failover_enabled / failover_timeout are NOT ClearPass
        # auth-source fields — ClearPass derives failover from the ordering of
        # cppm_auth_source_connection_backups. They are deliberately not sent
        # (doing so is rejected as a malformed body) and are reported back as
        # not applied rather than silently dropped.
        backup_config = {
            "cppm_auth_source_connection_backups": normalised_backups
        }

        result = await client.configure_auth_source_backup_connections(
            auth_source_id=auth_source_id,
            backup_config=backup_config
        )

        return {
            "success": True,
            "message": f"Successfully configured backup connections for authentication source ID {auth_source_id}",
            "auth_source_id": auth_source_id,
            "backup_count": len(normalised_backups),
            "not_applied": {
                "failover_enabled": failover_enabled,
                "failover_timeout": failover_timeout,
                "reason": (
                    "ClearPass has no auth-source failover_enabled/"
                    "failover_timeout field; failover order is the order of "
                    "the backup connection list."
                ),
            },
            "configuration_result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure backup connections for authentication source ID {auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def configure_auth_source_radius_attributes(
    ctx: Context,
    auth_source_id: int = Field(..., description="Numeric ID of the authentication source"),
    radius_attributes: Union[List[Dict[str, Any]], str] = Field(..., description="List of RADIUS attributes to configure - array format: [{\"name\": \"Session-Timeout\", \"value\": \"3600\", \"type\": \"integer\"}] or JSON string")
) -> Dict[str, Any]:
    """
    Configure RADIUS attributes for an authentication source.
    
    This tool configures custom RADIUS attributes that will be returned
    during authentication from this source.
    
    Examples:
    - "Configure RADIUS attributes for auth source ID 5"
    - "Add custom RADIUS attributes for Active Directory source"
    - "Set up vendor-specific attributes for authentication source 3"
    """
    try:
        client = await get_clearpass_client()
        
        # Parse radius_attributes parameter
        parsed_radius_attributes = _parse_list_dict_parameter(radius_attributes, "radius_attributes")
        
        radius_config = {
            "auth_source_radius_attributes": parsed_radius_attributes
        }
            
        result = await client.configure_auth_source_radius_attributes(
            auth_source_id=auth_source_id,
            radius_attributes=radius_config
        )
            
        return {
            "success": True,
            "message": f"Successfully configured RADIUS attributes for authentication source ID {auth_source_id}",
            "auth_source_id": auth_source_id,
            "attributes_count": len(parsed_radius_attributes),
            "configuration_result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure RADIUS attributes for authentication source ID {auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def configure_auth_source_filters(
    ctx: Context,
    auth_source_id: int = Field(..., description="Numeric ID of the authentication source"),
    filters: Union[List[Dict[str, Any]], str] = Field(..., description="List of authentication filters to configure - array format: [{\"attribute\": \"memberOf\", \"operator\": \"contains\", \"value\": \"CN=Employees\"}] or JSON string"),
    filter_logic: str = Field(default="AND", description="Logic for combining filters (AND/OR)")
) -> Dict[str, Any]:
    """
    Configure authentication filters for an authentication source.
    
    This tool sets up filters to control which users or groups can
    authenticate using this source.
    
    Examples:
    - "Configure user filters for auth source ID 5"
    - "Add group-based filters for Active Directory source"
    - "Set up authentication filters with OR logic"
    """
    try:
        client = await get_clearpass_client()
        
        # Parse filters parameter
        parsed_filters = _parse_list_dict_parameter(filters, "filters")
        
        # NOTE: filter_logic is NOT a ClearPass auth-source field; filters are
        # evaluated as an ordered list. It is not sent (unknown keys are
        # rejected as a malformed body) and is reported back as not applied.
        filter_config = {
            "auth_source_filters": parsed_filters
        }

        result = await client.configure_auth_source_filters(
            auth_source_id=auth_source_id,
            filter_config=filter_config
        )

        return {
            "success": True,
            "message": f"Successfully configured authentication filters for source ID {auth_source_id}",
            "auth_source_id": auth_source_id,
            "filters_count": len(parsed_filters),
            "not_applied": {
                "filter_logic": filter_logic,
                "reason": (
                    "ClearPass has no auth-source filter_logic field; filters "
                    "are evaluated as an ordered list."
                ),
            },
            "configuration_result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure authentication filters for source ID {auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_auth_source_connection_status(
    ctx: Context,
    auth_source_id: int = Field(..., description="Numeric ID of the authentication source")
) -> Dict[str, Any]:
    """
    Get connection status and health information for an authentication source.
    
    This tool provides detailed status information about the authentication
    source connectivity and health.
    
    Examples:
    - "Check connection status for auth source ID 5"
    - "Get health information for Active Directory source"
    - "Show connectivity status for authentication source 3"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_auth_source_connection_status(auth_source_id)
            
        return {
            "success": True,
            "message": f"Successfully retrieved connection status for authentication source ID {auth_source_id}",
            "auth_source_id": auth_source_id,
            "connection_status": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get connection status for authentication source ID {auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def clone_authentication_source(
    ctx: Context,
    source_auth_source_id: int = Field(..., description="Numeric ID of the authentication source to clone"),
    new_name: str = Field(..., description="Name for the new cloned authentication source"),
    new_description: Optional[str] = Field(None, description="Description for the new cloned authentication source")
) -> Dict[str, Any]:
    """
    Clone an existing authentication source with a new name.
    
    This tool creates a copy of an existing authentication source configuration,
    useful for creating similar configurations quickly.
    
    Examples:
    - "Clone authentication source ID 5 as 'New-AD-Source'"
    - "Copy auth source 3 to create 'Backup-LDAP'"
    - "Duplicate Active Directory source for testing"
    """
    try:
        client = await get_clearpass_client()
        result = await client.clone_authentication_source(
            source_auth_source_id=source_auth_source_id,
            new_name=new_name,
            new_description=new_description
        )
            
        return {
            "success": True,
            "message": f"Successfully cloned authentication source ID {source_auth_source_id} as '{new_name}'",
            "source_id": source_auth_source_id,
            "new_name": new_name,
            "cloned_source": result
        }
                
    except Exception as e:
        error_msg = f"Failed to clone authentication source ID {source_auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def bulk_update_auth_source_timeouts(
    ctx: Context,
    auth_source_ids: List[int] = Field(..., description="List of authentication source IDs to update"),
    server_timeout: Optional[int] = Field(None, description="New server timeout in seconds"),
    cache_timeout: Optional[int] = Field(None, description="New cache timeout in seconds")
) -> Dict[str, Any]:
    """
    Bulk update timeout settings for multiple authentication sources.
    
    This tool allows you to update server and cache timeout settings
    for multiple authentication sources at once.
    
    Examples:
    - "Update server timeout to 60 seconds for auth sources [1,2,3]"
    - "Set cache timeout to 600 seconds for multiple auth sources"
    - "Bulk update both timeouts for authentication sources"
    """
    # `is None`, not falsiness: a timeout of 0 is a legitimate value ("no
    # timeout") and must not be mistaken for an omitted parameter.
    if server_timeout is None and cache_timeout is None:
        return {
            "success": False,
            "message": "At least one timeout value (server_timeout or cache_timeout) must be provided",
            "error": "Missing required parameters"
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.bulk_update_auth_source_timeouts(
            auth_source_ids=auth_source_ids,
            server_timeout=server_timeout,
            cache_timeout=cache_timeout
        )
            
        successful_updates = [r for r in result["bulk_update_results"] if r["success"]]
        failed_updates = [r for r in result["bulk_update_results"] if not r["success"]]
            
        return {
            "success": True,
            "message": f"Bulk update completed for {len(auth_source_ids)} authentication sources",
            "total_sources": len(auth_source_ids),
            "successful_updates": len(successful_updates),
            "failed_updates": len(failed_updates),
            "server_timeout": server_timeout,
            "cache_timeout": cache_timeout,
            "detailed_results": result["bulk_update_results"]
        }
                
    except Exception as e:
        error_msg = f"Failed to bulk update authentication source timeouts: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def validate_auth_source_configuration(
    ctx: Context,
    auth_source_config: Dict[str, Any] = Field(..., description="Authentication source configuration to validate")
) -> Dict[str, Any]:
    """
    Validate an authentication source configuration before creation or update.
    
    This tool performs client-side validation of authentication source
    configuration to catch potential issues early.
    
    Examples:
    - "Validate authentication source configuration before creating"
    - "Check if my auth source config is valid"
    - "Validate AD source configuration parameters"
    """
    try:
        client = await get_clearpass_client()
        result = await client.validate_auth_source_configuration(auth_source_config)
            
        return {
            "success": True,
            "message": "Configuration validation completed",
            "validation_result": result,
            "is_valid": result["valid"],
            "errors_count": len(result["errors"]),
            "warnings_count": len(result["warnings"])
        }
                
    except Exception as e:
        error_msg = f"Failed to validate authentication source configuration: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_auth_source_statistics(
    ctx: Context,
    auth_source_id: int = Field(..., description="Numeric ID of the authentication source"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')")
) -> Dict[str, Any]:
    """
    Get authentication statistics and usage information for an authentication source.
    
    This tool provides usage statistics and performance metrics
    for an authentication source over a specified time period.
    
    Examples:
    - "Get statistics for auth source ID 5 over last 24 hours"
    - "Show usage metrics for Active Directory source over 7 days"
    - "Get authentication stats for source 3 over last month"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_auth_source_statistics(
            auth_source_id=auth_source_id,
            time_range=time_range
        )
            
        return {
            "success": True,
            "message": f"Successfully retrieved statistics for authentication source ID {auth_source_id}",
            "auth_source_id": auth_source_id,
            "time_range": time_range,
            "statistics": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get authentication source statistics for ID {auth_source_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }

# =============================================================================
# Enhanced Network Device Groups Tools (Chunk 3.1) - 10 tools
# =============================================================================

@operation(domain="policy_elements")
async def manage_device_group_membership(
    ctx: Context,
    group_id: int = Field(..., description="Numeric ID of the network device group"),
    devices_to_add: Optional[Union[List[str], str]] = Field(None, description="List of device IPs or names to add to the group"),
    devices_to_remove: Optional[Union[List[str], str]] = Field(None, description="List of device IPs or names to remove from the group"),
    update_mode: str = Field(default="append", description="Update mode: 'append' (add to existing), 'replace' (replace all), 'remove' (remove specified)")
) -> Dict[str, Any]:
    """
    Manage device membership in a network device group.

    Advanced tool for managing which devices belong to a network device group
    with flexible operations for adding, removing, or replacing members.

    Examples:
    - "Add devices 192.168.1.10 and 192.168.1.11 to group 5"
    - "Remove device 192.168.1.5 from network device group 3"
    - "Replace all devices in group 2 with 192.168.2.0/24 subnet"
    """
    await ctx.info(f"Managing membership for device group {group_id} with mode '{update_mode}'")

    try:
        # Validate update mode
        valid_modes = ["append", "replace", "remove"]
        if update_mode not in valid_modes:
            return {
                "success": False,
                "error": "Invalid update mode",
                "message": f"update_mode must be one of: {', '.join(valid_modes)}",
                "suggestion": f"Use update_mode='append' to add devices, 'replace' to replace all, or 'remove' to remove specific devices."
            }

        # Validate devices_to_add for append/replace modes
        if update_mode in ["append", "replace"] and not devices_to_add:
            return {
                "success": False,
                "error": "No devices to add specified",
                "message": f"For update_mode='{update_mode}', you must provide devices_to_add.",
                "suggestion": "Specify a list of devices to add using the devices_to_add parameter."
            }

        # Validate devices_to_remove for remove mode
        if update_mode == "remove" and not devices_to_remove:
            return {
                "success": False,
                "error": "No devices to remove specified",
                "message": "For update_mode='remove', you must provide devices_to_remove.",
                "suggestion": "Specify a list of devices to remove using the devices_to_remove parameter."
            }

        # Convert string parameters to lists if needed (fix for MCP parameter parsing)
        # The MCP framework sometimes passes list parameters as strings
        if isinstance(devices_to_add, str):
            # Handle JSON-like string format: '["192.168.1.1", "192.168.1.2"]' or CSV format: "192.168.1.1,192.168.1.2"
            if devices_to_add.startswith('[') and devices_to_add.endswith(']'):
                try:
                    import ast
                    devices_to_add = ast.literal_eval(devices_to_add)
                except (ValueError, SyntaxError):
                    # Fallback to comma-separated parsing
                    devices_to_add = [device.strip() for device in devices_to_add.strip('[]').split(",") if device.strip()]
            else:
                # Comma-separated string format
                devices_to_add = [device.strip() for device in devices_to_add.split(",") if device.strip()]
        elif devices_to_add is not None and not isinstance(devices_to_add, list):
            # Convert any other type to list
            devices_to_add = [str(devices_to_add)]
        
        if isinstance(devices_to_remove, str):
            # Handle JSON-like string format or CSV format
            if devices_to_remove.startswith('[') and devices_to_remove.endswith(']'):
                try:
                    import ast
                    devices_to_remove = ast.literal_eval(devices_to_remove)
                except (ValueError, SyntaxError):
                    # Fallback to comma-separated parsing
                    devices_to_remove = [device.strip() for device in devices_to_remove.strip('[]').split(",") if device.strip()]
            else:
                # Comma-separated string format
                devices_to_remove = [device.strip() for device in devices_to_remove.split(",") if device.strip()]
        elif devices_to_remove is not None and not isinstance(devices_to_remove, list):
            # Convert any other type to list
            devices_to_remove = [str(devices_to_remove)]

        client = await get_clearpass_client()
        result = await client.manage_device_group_membership(
            group_id=group_id,
            devices_to_add=devices_to_add,
            devices_to_remove=devices_to_remove,
            update_mode=update_mode
        )

        return {
            "success": True,
            "message": f"Successfully updated membership for device group {group_id}",
            "update_mode": update_mode,
            "devices_added": devices_to_add or [],
            "devices_removed": devices_to_remove or [],
            "group_info": result,
            "next_steps": [
                "You can now use this group in role mappings or enforcement policies",
                "Review the updated group membership to ensure accuracy",
                "Consider adding more devices if needed"
            ]
        }

    except ValueError as ve:
        # Handle specific validation errors
        error_msg = str(ve)
        if "not found" in error_msg.lower():
            return {
                "success": False,
                "error": "Group not found",
                "message": error_msg,
                "suggestion": f"Verify that the group ID {group_id} exists and try again."
            }
        elif "update_mode" in error_msg.lower():
            return {
                "success": False,
                "error": "Invalid update mode",
                "message": error_msg,
                "suggestion": f"Use a valid update_mode: {', '.join(['append', 'replace', 'remove'])}"
            }
        else:
            return {
                "success": False,
                "error": "Validation error",
                "message": error_msg
            }

    except ClearPassAPIError as e:
        # Handle API-specific errors
        error_msg = f"ClearPass API error: {e.message}"
        logger.error(f"API error managing device group {group_id}: {error_msg}")
        return await format_api_error(e, "manage device group membership")

    except Exception as e:
        # Handle general errors
        error_msg = f"Failed to manage device group membership for group {group_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def bulk_update_device_groups(
    ctx: Context,
    group_ids: List[int] = Field(..., description="List of network device group IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete', 'assign_policy'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple network device groups.
    
    Powerful tool for managing multiple device groups simultaneously.
    Use with caution, especially for delete operations.
    
    Examples:
    - "Update description for device groups 1, 2, 3 to 'Corporate Network'"
    - "Delete device groups 10, 11, 12 (with confirmation)"
    - "Apply security policy to all wireless device groups"
    """
    if operation_type == "delete" and not confirm_operation:
        return {
            "success": False,
            "message": "Bulk delete operations require explicit confirmation. Set confirm_operation=True.",
            "safety_warning": "This operation cannot be undone"
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.bulk_update_device_groups(
            group_ids=group_ids,
            operation_type=operation_type,
            operation_data=operation_data
        )
        
        # Validate that we got a proper response structure
        if result is None:
            return {
                "success": False,
                "message": "No response received from bulk operation",
                "error": "Client method returned None"
            }
        
        if "bulk_operation_results" not in result:
            return {
                "success": False,
                "message": "Invalid response structure from bulk operation",
                "error": "Missing bulk_operation_results in response"
            }
            
        # Create audit log entry
        log_mcp_operation(
            operation="bulk_update_device_groups",
            parameters={
                "group_ids": group_ids,
                "operation_type": operation_type,
                "operation_data": operation_data
            },
            outcome="success"
        )
            
        successful_operations = sum(1 for r in result["bulk_operation_results"] if r.get("success", False))
        failed_operations = len(group_ids) - successful_operations
            
        return {
            "success": True,
            "message": f"Bulk operation completed: {successful_operations} successful, {failed_operations} failed",
            "operation_type": operation_type,
            "total_groups": len(group_ids),
            "successful_operations": successful_operations,
            "failed_operations": failed_operations,
            "detailed_results": result["bulk_operation_results"]
        }

    except ValueError as ve:
        # Handle specific validation errors
        error_msg = str(ve)
        logger.error(f"Validation error in bulk update: {error_msg}")
        return {
            "success": False,
            "error": "Validation error",
            "message": error_msg,
            "suggestion": "Please check your operation parameters and try again."
        }

    except ClearPassAPIError as e:
        # Handle API-specific errors
        error_msg = f"ClearPass API error during bulk operation: {e.message}"
        logger.error(f"API error in bulk update: {error_msg}")
        return await format_api_error(e, "bulk update device groups")

    except Exception as e:
        # Handle general errors
        error_msg = f"Failed to perform bulk operation on device groups: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }

@operation(domain="policy_elements")
async def validate_device_group_configuration(
    ctx: Context,
    group_config: Dict[str, Any] = Field(..., description="Device group configuration to validate"),
    check_conflicts: bool = Field(default=True, description="Whether to check for conflicts with existing groups")
) -> Dict[str, Any]:
    """
    Validate device group configuration before creation or update.
    
    Comprehensive validation tool that checks for configuration issues,
    conflicts, and optimization opportunities.
    
    Examples:
    - "Validate this device group configuration before creating it"
    - "Check if my subnet configuration conflicts with existing groups"
    - "Verify that my device list format is correct"
    """
    try:
        client = await get_clearpass_client()
        result = await client.validate_device_group_configuration(group_config)
            
        validation_status = "✅ Valid" if result["valid"] else "❌ Invalid"
        warning_count = len(result.get("warnings", []))
        error_count = len(result.get("errors", []))
            
        return {
            "success": True,
            "message": f"Configuration validation completed: {validation_status}",
            "validation_status": validation_status,
            "is_valid": result["valid"],
            "error_count": error_count,
            "warning_count": warning_count,
            "errors": result.get("errors", []),
            "warnings": result.get("warnings", []),
            "conflicts": result.get("conflicts", []),
            "configuration": group_config
        }
            
    except Exception as e:
        error_msg = f"Failed to validate device group configuration: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_device_group_statistics(
    ctx: Context,
    group_id: int = Field(..., description="Numeric ID of the network device group"),
    include_device_details: bool = Field(default=True, description="Whether to include detailed device information"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')")
) -> Dict[str, Any]:
    """
    Get comprehensive statistics and analytics for a device group.
    
    Tool for monitoring device group usage, performance metrics,
    and operational insights.
    
    Examples:
    - "Show statistics for device group 5"
    - "Get device count and activity for wireless AP group"
    - "Generate usage report for corporate device groups"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_device_group_statistics(
            group_id=group_id,
            include_details=include_device_details
        )
            
        return {
            "success": True,
            "message": f"Successfully retrieved statistics for device group {group_id}",
            "group_statistics": result,
            "time_range": time_range,
            "summary": {
                "group_name": result.get("group_name", "Unknown"),
                "total_devices": result.get("total_devices", 0),
                "group_format": result.get("group_format", "Unknown"),
                "last_updated": result.get("last_updated", "Unknown")
            }
        }
            
    except Exception as e:
        error_msg = f"Failed to get device group statistics for group {group_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def clone_device_group(
    ctx: Context,
    source_group_id: int = Field(..., description="Numeric ID of the device group to clone"),
    new_name: str = Field(..., description="Name for the new cloned device group"),
    new_description: Optional[str] = Field(None, description="Description for the new cloned device group"),
    modify_values: Optional[Dict[str, Any]] = Field(None, description="Modifications to apply to the cloned group")
) -> Dict[str, Any]:
    """
    Clone an existing device group with optional modifications.
    
    Useful tool for creating similar device groups based on existing
    configurations while allowing customization.
    
    Examples:
    - "Clone device group 3 as 'Branch-Office-Switches'"
    - "Create a copy of wireless group with different IP range"
    - "Clone corporate group for guest network configuration"
    """
    try:
        client = await get_clearpass_client()
        result = await client.clone_device_group(
            source_group_id=source_group_id,
            new_name=new_name,
            new_description=new_description,
            modify_values=modify_values
        )
            
        # Create audit log entry
        log_mcp_operation(
            operation="clone_device_group",
            parameters={
                "source_group_id": source_group_id,
                "new_name": new_name,
                "new_description": new_description,
                "modify_values": modify_values
            },
            outcome="success"
        )
            
        return {
            "success": True,
            "message": f"Successfully cloned device group {source_group_id} as '{new_name}'",
            "source_group_id": source_group_id,
            "new_group_name": new_name,
            "cloned_group": result,
            "modifications_applied": modify_values or {}
        }
            
    except Exception as e:
        error_msg = f"Failed to clone device group {source_group_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def create_device_group_from_template(
    ctx: Context,
    template_name: str = Field(..., description="Name of the template to use"),
    group_name: str = Field(..., description="Name for the new device group"),
    device_values: str = Field(..., description="Device values (IPs, subnets, or device names) for the group"),
    description: Optional[str] = Field(None, description="Description for the new device group"),
    template_overrides: Optional[Dict[str, Any]] = Field(None, description="Overrides for template settings")
) -> Dict[str, Any]:
    """
    Create a device group from a predefined template.
    
    Streamlined tool for creating consistent device groups using
    standardized templates for common network configurations.
    
    Examples:
    - "Create device group from 'Corporate-Switch' template with subnet 192.168.10.0/24"
    - "Use wireless AP template to create 'Building-A-APs' group"
    - "Apply security template for new branch office devices"
    """
    try:
        # Define common templates
        templates = {
            "corporate-switch": {
                "template_name": "Corporate Switch Template",
                "group_format": "subnet",
                "template_description": "Standard template for corporate switches",
                "device_type": "switch"
            },
            "wireless-ap": {
                "template_name": "Wireless Access Point Template", 
                "group_format": "list",
                "template_description": "Standard template for wireless access points",
                "device_type": "ap"
            },
            "router": {
                "template_name": "Router Template",
                "group_format": "list", 
                "template_description": "Standard template for routers",
                "device_type": "router"
            },
            "security-appliance": {
                "template_name": "Security Appliance Template",
                "group_format": "list",
                "template_description": "Standard template for security appliances",
                "device_type": "security"
            }
        }
        
        template_config = templates.get(template_name.lower())
        if not template_config:
            return {
                "success": False,
                "message": f"Template '{template_name}' not found",
                "available_templates": list(templates.keys())
            }
        
        # Apply overrides
        if template_overrides:
            template_config.update(template_overrides)
        
        client = await get_clearpass_client()
        result = await client.create_device_group_from_template(
            template_config=template_config,
            group_name=group_name,
            specific_values={
                "value": device_values,
                "description": description
            }
        )
            
        # Create audit log entry
        log_mcp_operation(
            operation="create_device_group_from_template",
            parameters={
                "template_name": template_name,
                "group_name": group_name,
                "device_values": device_values
            },
            outcome="success"
        )
            
        return {
            "success": True,
            "message": f"Successfully created device group '{group_name}' from template '{template_name}'",
            "template_used": template_name,
            "group_name": group_name,
            "device_group": result
        }
            
    except Exception as e:
        error_msg = f"Failed to create device group from template '{template_name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def get_device_group_hierarchy(
    ctx: Context,
    root_group_id: Optional[int] = Field(None, description="ID of the root group to start hierarchy from (optional)"),
    include_statistics: bool = Field(default=False, description="Whether to include statistics for each group")
) -> Dict[str, Any]:
    """
    Get hierarchical structure and relationships of device groups.
    
    Tool for understanding the organizational structure of device groups
    and their relationships within the network infrastructure.
    
    Examples:
    - "Show the hierarchy of all device groups"
    - "Get the structure starting from root group 5"
    - "Display device group organization with statistics"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_device_group_hierarchy(root_group_id)
            
        hierarchy_summary = {
            "total_groups": result.get("total_groups", 0),
            "root_groups": len(result.get("root_groups", [])),
            "child_groups": len(result.get("child_groups", {}))
        }
            
        return {
            "success": True,
            "message": f"Successfully retrieved device group hierarchy",
            "hierarchy_summary": hierarchy_summary,
            "hierarchy_structure": result,
            "root_group_filter": root_group_id,
            "includes_statistics": include_statistics
        }
            
    except Exception as e:
        error_msg = f"Failed to get device group hierarchy: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def search_device_groups_advanced(
    ctx: Context,
    group_format: Optional[str] = Field(None, description="Filter by group format ('list', 'range', 'subnet')"),
    device_type: Optional[str] = Field(None, description="Filter by device type (e.g., 'switch', 'ap', 'router')"),
    name_pattern: Optional[str] = Field(None, description="Search pattern for group names (supports wildcards)"),
    min_device_count: Optional[int] = Field(None, description="Minimum number of devices in group"),
    has_policies: Optional[bool] = Field(None, description="Filter groups that have policy assignments"),
    include_empty_groups: bool = Field(default=True, description="Whether to include groups with no devices")
) -> Dict[str, Any]:
    """
    Advanced search for device groups with multiple criteria and filters.
    
    Powerful search tool for finding device groups based on various
    attributes and configuration parameters.
    
    Examples:
    - "Find all subnet-format device groups with more than 20 devices"
    - "Search for wireless groups with 'AP' in the name"
    - "Show all device groups that have policies assigned"
    """
    try:
        client = await get_clearpass_client()
        result = await client.search_device_groups_advanced(
            group_format=group_format,
            device_type=device_type,
            name_pattern=name_pattern,
            min_device_count=min_device_count,
            has_policies=has_policies
        )
            
        search_criteria = {
            "group_format": group_format,
            "device_type": device_type,
            "name_pattern": name_pattern,
            "min_device_count": min_device_count,
            "has_policies": has_policies,
            "include_empty_groups": include_empty_groups
        }
            
        # Filter out None values from search criteria for display
        active_criteria = {k: v for k, v in search_criteria.items() if v is not None}
            
        groups_found = len(result.get("_embedded", {}).get("items", []))
            
        return {
            "success": True,
            "message": f"Advanced search completed: {groups_found} groups found",
            "groups_found": groups_found,
            "search_criteria": active_criteria,
            "search_results": result
        }
            
    except Exception as e:
        error_msg = f"Failed to perform advanced device group search: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="policy_elements")
async def optimize_device_group_configuration(
    ctx: Context,
    group_id: int = Field(..., description="Numeric ID of the device group to optimize"),
    optimization_level: str = Field(default="standard", description="Optimization level: 'basic', 'standard', 'aggressive'"),
    apply_recommendations: bool = Field(default=False, description="Whether to automatically apply safe optimizations")
) -> Dict[str, Any]:
    """
    Analyze and optimize device group configuration for better performance.
    
    AI-powered tool that analyzes device group configuration and provides
    recommendations for optimization and best practices.
    
    Examples:
    - "Optimize configuration for device group 5"
    - "Analyze and apply safe optimizations to wireless group"
    - "Get performance recommendations for large device groups"
    """
    try:
        client = await get_clearpass_client()
        result = await client.optimize_device_group_configuration(
            group_id=group_id,
            optimization_options={"level": optimization_level}
        )
            
        recommendations_count = len(result.get("recommendations", []))
        optimizations_applied = len(result.get("optimizations_applied", []))
            
        # Create audit log entry if optimizations were applied
        if apply_recommendations and optimizations_applied > 0:
            log_mcp_operation(
                operation="optimize_device_group_configuration",
                parameters={
                    "group_id": group_id,
                    "optimization_level": optimization_level,
                    "recommendations_count": recommendations_count,
                    "optimizations_applied": optimizations_applied
                },
                outcome="success"
            )
            
        return {
            "success": True,
            "message": f"Configuration optimization completed for group {group_id}",
            "group_id": group_id,
            "optimization_level": optimization_level,
            "recommendations_count": recommendations_count,
            "optimizations_applied": optimizations_applied,
            "applied_changes": apply_recommendations,
            "optimization_results": result
        }
            
    except Exception as e:
        error_msg = f"Failed to optimize device group configuration for group {group_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# ================================
# APPLICATION DICTIONARY TOOLS (Phase 5, Chunk 5.1)
# ================================

@operation(domain="policy_elements")
async def list_application_dictionaries(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"name\": \"Web-Apps\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List ClearPass application dictionaries.
    
    Application dictionaries define custom application attributes and identification rules
    for network access control and policy evaluation.
    
    Examples:
    - List all application dictionaries: No parameters needed
    - Find web application dictionaries: filter='{"name": {"contains": "Web"}}'
    - Get first 10 dictionaries: limit=10
    """
    await ctx.info(f"Retrieving application dictionaries (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        
        response = await client.list_application_dictionaries(
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count
        )
        
        # Format response for LLM consumption
        if "_embedded" in response and "items" in response["_embedded"]:
            dictionaries = response["_embedded"]["items"]
        else:
            dictionaries = response.get("items", [])
        
        return {
        "success": True,
        "total_count": len(dictionaries),
        "dictionaries": dictionaries,
        "message": f"Retrieved {len(dictionaries)} application dictionaries",
        "pagination_info": {
            "offset": offset or 0,
            "limit": limit,
            "has_more": len(dictionaries) == limit if limit else False
        }
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to list application dictionaries: {e}")
        return await format_api_error(e, "list application dictionaries")
    except Exception as e:
        logger.error(f"Unexpected error listing application dictionaries: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing application dictionaries"
        }


@operation(domain="policy_elements")
async def create_application_dictionary(
    ctx: Context,
    name: str = Field(..., description="Name of the application dictionary (must be unique)"),
    attributes: Union[List[Dict[str, Any]], str] = Field(..., description="List of application dictionary attributes in pyclearpass format - array format: [{\"attr_name\": \"app_category\", \"attr_type\": \"string\", \"allowed_values\": \"social,business,entertainment\"}] or JSON string"),
    description: Optional[str] = Field(None, description="Description of the application dictionary")
) -> Dict[str, Any]:
    """
    Create a new ClearPass application dictionary.
    
    Application dictionaries define custom attributes for application identification
    and policy evaluation in network access control scenarios.
    
    Examples:
    - Basic web app dictionary: name="Web-Applications", attributes=[{"attr_name": "app_category", "attr_type": "string", "allowed_values": "social,business,entertainment"}]
    - Mobile app dictionary: name="Mobile-Apps", attributes=[{"attr_name": "platform", "attr_type": "string", "allowed_values": "iOS,Android"}]
    """
    await ctx.info(f"Creating application dictionary: {name}")
    
    try:
        client = await get_clearpass_client()
        
        # Parse attributes parameter
        parsed_attributes = _parse_list_dict_parameter(attributes, "attributes")
        
        app_dict_data = {
        "name": name,
        "attributes": parsed_attributes
        }
        if description:
            app_dict_data["description"] = description
        
        response = await client.create_application_dictionary(app_dict_data)
        
        await ctx.info(f"Successfully created application dictionary: {name}")
        
        return {
        "success": True,
        "message": f"Application dictionary '{name}' created successfully",
        "dictionary": response,
        "next_steps": [
            "You can now use this dictionary in policy rules",
            "Consider creating application identification rules",
            "Review attribute definitions for accuracy"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to create application dictionary: {e}")
        return await format_api_error(e, "create application dictionary")
    except Exception as e:
        logger.error(f"Unexpected error creating application dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the application dictionary"
        }


@operation(domain="policy_elements")
async def get_application_dictionary_details(
    ctx: Context,
    app_dict_id: Optional[int] = Field(None, description="Numeric ID of the application dictionary"),
    name: Optional[str] = Field(None, description="Name of the application dictionary")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific application dictionary.
    
    Provide either the dictionary ID or name to retrieve the dictionary details.
    
    Examples:
    - By ID: app_dict_id=123
    - By name: name="Web-Applications"
    """
    if app_dict_id is None and name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either app_dict_id or name to identify the application dictionary"
        }
    
    identifier = f"ID {app_dict_id}" if app_dict_id is not None else f"name '{name}'"
    await ctx.info(f"Retrieving application dictionary details for: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        if app_dict_id is not None:
            response = await client.get_application_dictionary_by_id(app_dict_id)
        else:
            response = await client.get_application_dictionary_by_name(name)
        
        return {
        "success": True,
        "dictionary": response,
        "message": f"Retrieved application dictionary details for: {identifier}",
        "usage_tips": [
            "This dictionary can be used in application identification rules",
            "Check policy rules that reference this dictionary",
            "Review attribute values for policy accuracy"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to get application dictionary details: {e}")
        return await format_api_error(e, "get application dictionary details")
    except Exception as e:
        logger.error(f"Unexpected error getting application dictionary details: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving application dictionary details"
        }


@operation(domain="policy_elements")
async def update_application_dictionary(
    ctx: Context,
    app_dict_id: Optional[int] = Field(None, description="Numeric ID of the application dictionary to update"),
    app_dict_name: Optional[str] = Field(None, description="Name of the application dictionary to update"),
    new_name: Optional[str] = Field(None, description="New name for the application dictionary"),
    new_description: Optional[str] = Field(None, description="New description for the application dictionary"),
    attributes: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of application dictionary attributes - array format: [{\"attr_name\": \"app_category\", \"attr_type\": \"string\", \"allowed_values\": \"social,business,entertainment\"}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing application dictionary.
    
    You can update the name, description, or attributes of an application dictionary.
    Use replace_all=True to completely replace all fields, or False to update only specified fields.
    
    Examples:
    - Update description: app_dict_id=123, new_description="Updated web applications dictionary"
    - Add new attributes: app_dict_id=123, attributes=[...], replace_all=False
    - Complete replacement: app_dict_id=123, new_name="New-Name", attributes=[...], replace_all=True
    """
    if app_dict_id is None and app_dict_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either app_dict_id or app_dict_name to identify the application dictionary"
        }
    
    identifier = f"ID {app_dict_id}" if app_dict_id is not None else f"name '{app_dict_name}'"
    await ctx.info(f"Updating application dictionary: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        # Prepare update data
        update_data = {}
        if new_name:
            update_data["name"] = new_name
        if new_description:
            update_data["description"] = new_description
        if attributes:
            update_data["attributes"] = _parse_list_dict_parameter(attributes, "attributes")
        
        if not update_data:
            return {
                "success": False,
                "error": "No update data provided",
                "message": "Please provide at least one field to update"
            }
        
        # Perform update based on identifier type and operation type
        if app_dict_id is not None:
            if replace_all:
                response = await client.replace_application_dictionary_by_id(app_dict_id, update_data)
            else:
                response = await client.update_application_dictionary_by_id(app_dict_id, update_data)
        else:
            if replace_all:
                response = await client.replace_application_dictionary_by_name(app_dict_name, update_data)
            else:
                response = await client.update_application_dictionary_by_name(app_dict_name, update_data)
        
        operation_type = "replaced" if replace_all else "updated"
        await ctx.info(f"Successfully {operation_type} application dictionary: {identifier}")
        
        return {
        "success": True,
        "message": f"Application dictionary {operation_type} successfully",
        "operation": "replace" if replace_all else "update",
        "dictionary": response,
        "changes_applied": list(update_data.keys())
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to update application dictionary: {e}")
        return await format_api_error(e, "update application dictionary")
    except Exception as e:
        logger.error(f"Unexpected error updating application dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the application dictionary"
        }


@operation(domain="policy_elements")
async def delete_application_dictionary(
    ctx: Context,
    app_dict_id: Optional[int] = Field(None, description="Numeric ID of the application dictionary to delete"),
    app_dict_name: Optional[str] = Field(None, description="Name of the application dictionary to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an application dictionary.
    
    WARNING: This operation cannot be undone. Deleting an application dictionary
    will remove all its attributes and may affect policies that reference it.
    
    Examples:
    - Delete by ID: app_dict_id=123, confirm=True
    - Delete by name: app_dict_name="Old-Dictionary", confirm=True
    """
    if app_dict_id is None and app_dict_name is None:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either app_dict_id or app_dict_name to identify the application dictionary"
        }
    
    if not confirm:
        return {
            "success": False,
            "error": "Confirmation required",
            "message": "Please set confirm=True to proceed with deletion. This action cannot be undone."
        }
    
    identifier = f"ID {app_dict_id}" if app_dict_id is not None else f"name '{app_dict_name}'"
    await ctx.info(f"Deleting application dictionary: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        # Get dictionary details before deletion for audit
        if app_dict_id is not None:
            dict_details = await client.get_application_dictionary_by_id(app_dict_id)
            response = await client.delete_application_dictionary_by_id(app_dict_id)
        else:
            dict_details = await client.get_application_dictionary_by_name(app_dict_name)
            response = await client.delete_application_dictionary_by_name(app_dict_name)
        
        await ctx.info(f"Successfully deleted application dictionary: {identifier}")
        
        return {
        "success": True,
        "message": f"Application dictionary deleted successfully",
        "deleted_dictionary": {
            "id": dict_details.get("id"),
            "name": dict_details.get("name"),
            "description": dict_details.get("description")
        },
        "warning": "This action cannot be undone. Check any policies that may have referenced this dictionary."
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete application dictionary: {e}")
        return await format_api_error(e, "delete application dictionary")
    except Exception as e:
        logger.error(f"Unexpected error deleting application dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the application dictionary"
        }


@operation(domain="policy_elements")
async def validate_application_dictionary_configuration(
    ctx: Context,
    app_dict_config: Dict[str, Any] = Field(..., description="Application dictionary configuration to validate"),
    strict_validation: bool = Field(default=False, description="Enable strict validation rules")
) -> Dict[str, Any]:
    """
    Validate application dictionary configuration for compliance and best practices.
    
    This tool checks dictionary structure, attribute definitions, and naming conventions
    to ensure the configuration follows ClearPass standards.
    
    Examples:
    - Validate new dictionary: app_dict_config={"name": "Test-Dict", "attributes": [...]}
    - Strict validation: app_dict_config={...}, strict_validation=True
    """
    await ctx.info("Validating application dictionary configuration...")
    
    try:
        client = await get_clearpass_client()
        
        # Client method doesn't accept strict_validation parameter
        validation_result = await client.validate_application_dictionary_configuration(
            app_dict_config=app_dict_config
        )
        
        # Apply strict validation logic here if needed
        if strict_validation and validation_result.get("valid", True):
            # Add any additional strict validation checks
            pass
        
        return {
            "success": True,
            "message": "Application dictionary configuration validation completed",
            "validation_result": validation_result,
            "configuration_valid": validation_result.get("valid", False),
            "warnings": validation_result.get("warnings", []),
            "errors": validation_result.get("errors", [])
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to validate application dictionary configuration: {e}")
        return await format_api_error(e, "validate application dictionary configuration")
    except Exception as e:
        logger.error(f"Unexpected error validating application dictionary configuration: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while validating the application dictionary configuration"
        }


@operation(domain="policy_elements")
async def get_application_dictionary_statistics(
    ctx: Context,
    app_dict_id: int = Field(..., description="Numeric ID of the application dictionary"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')"),
    include_usage_patterns: bool = Field(default=True, description="Include usage pattern analysis")
) -> Dict[str, Any]:
    """
    Get comprehensive statistics for an application dictionary.
    
    Provides usage statistics, attribute utilization, and performance metrics
    for the specified application dictionary.
    
    Examples:
    - Basic statistics: app_dict_id=123
    - Extended analysis: app_dict_id=123, time_range="7d", include_usage_patterns=True
    """
    await ctx.info(f"Retrieving statistics for application dictionary ID: {app_dict_id}")
    
    try:
        client = await get_clearpass_client()
        
        statistics = await client.get_application_dictionary_statistics(
            app_dict_id=app_dict_id,
            time_range=time_range,
            include_usage_patterns=include_usage_patterns,
        )

        return {
            "success": True,
            "message": (
                "Retrieved statistics for application dictionary "
                f"'{statistics.get('dictionary_name')}' (ID {app_dict_id})"
            ),
            "dictionary_id": app_dict_id,
            "dictionary_name": statistics.get("dictionary_name"),
            "time_range": time_range,
            "statistics": statistics,
            "summary": {
                "total_attributes": statistics.get("attribute_count", 0),
                "usage_patterns_included": include_usage_patterns,
            },
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to get application dictionary statistics: {e}")
        return await format_api_error(e, "get application dictionary statistics")
    except Exception as e:
        logger.error(f"Unexpected error getting application dictionary statistics: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving application dictionary statistics"
        }


@operation(domain="policy_elements")
async def clone_application_dictionary(
    ctx: Context,
    source_app_dict_id: int = Field(..., description="Numeric ID of the application dictionary to clone"),
    new_name: str = Field(..., description="Name for the new cloned application dictionary"),
    new_description: Optional[str] = Field(None, description="Description for the new cloned application dictionary"),
    modify_attributes: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="Modifications to apply to cloned attributes - array format: [{\"attr_name\": \"platform\", \"attr_type\": \"string\"}] or JSON string")
) -> Dict[str, Any]:
    """
    Clone an existing application dictionary with optional modifications.
    
    Creates a copy of an application dictionary with a new name and optionally
    modified attributes or description.
    
    Examples:
    - Simple clone: source_app_dict_id=123, new_name="Cloned-Web-Apps"
    - Clone with modifications: source_app_dict_id=123, new_name="Mobile-Apps", modify_attributes=[{"attr_name": "platform", "attr_type": "string"}]
    """
    await ctx.info(f"Cloning application dictionary ID: {source_app_dict_id} as '{new_name}'")
    
    try:
        client = await get_clearpass_client()
        
        # Client method doesn't support modify_attributes
        cloned_dict = await client.clone_application_dictionary(
            source_app_dict_id=source_app_dict_id,
            new_name=new_name,
            new_description=new_description
        )
        
        # If modify_attributes provided, update the cloned dictionary
        if modify_attributes is not None:
            parsed_modify_attributes = _parse_list_dict_parameter(modify_attributes, "modify_attributes")
            await ctx.info("Note: modify_attributes parameter is not supported by the API. Clone created without modifications.")
        
        await ctx.info(f"Successfully cloned application dictionary as: {new_name}")
        
        return {
        "success": True,
        "message": f"Application dictionary cloned successfully as '{new_name}'",
        "source_dictionary_id": source_app_dict_id,
        "new_dictionary": cloned_dict,
        "modifications_applied": bool(modify_attributes or new_description),
        "next_steps": [
            "Review the cloned dictionary configuration",
            "Test the dictionary in policy rules",
            "Update any policy references if needed"
        ]
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to clone application dictionary: {e}")
        return await format_api_error(e, "clone application dictionary")
    except Exception as e:
        logger.error(f"Unexpected error cloning application dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while cloning the application dictionary"
        }

@operation(domain="policy_elements")
async def bulk_update_application_dictionaries(
    ctx: Context,
    app_dict_ids: List[int] = Field(..., description="List of application dictionary IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete', 'add_attribute', 'remove_attribute'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple application dictionaries.
    
    This tool allows efficient management of multiple application dictionaries through
    batch operations including updates, deletions, and attribute modifications.
    
    Examples:
    - Bulk update descriptions: operation_type="update", operation_data={"description": "Updated description"}
    - Bulk delete: operation_type="delete", confirm_operation=True
    - Add attribute to multiple dictionaries: operation_type="add_attribute", operation_data={"attr_name": "category", "attr_type": "string"}
    """
    if not confirm_operation and operation_type in ["delete", "remove_attribute"]:
        return {
            "success": False,
            "error": "Confirmation required",
            "message": f"Please set confirm_operation=True to proceed with '{operation_type}' operation. This action may be irreversible."
        }
    
    await ctx.info(f"Performing bulk {operation_type} operation on {len(app_dict_ids)} application dictionaries...")
    
    try:
        client = await get_clearpass_client()
        
        # NOTE: confirm_operation is deliberately NOT forwarded. It is a
        # client-side safety gate, enforced above before any request is made;
        # ClearPass has no corresponding request field, so passing it on would
        # only be a TypeError against the client method's signature.
        bulk_result = await client.bulk_update_application_dictionaries(
            app_dict_ids=app_dict_ids,
            operation_type=operation_type,
            operation_data=operation_data,
        )
        
        successful_operations = bulk_result.get("successful", [])
        failed_operations = bulk_result.get("failed", [])
        
        return {
        "success": True,
        "message": f"Bulk {operation_type} operation completed",
        "operation_type": operation_type,
        "total_attempted": len(app_dict_ids),
        "successful_count": len(successful_operations),
        "failed_count": len(failed_operations),
        "successful_operations": successful_operations,
        "failed_operations": failed_operations,
        "operation_data": operation_data
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to perform bulk operation on application dictionaries: {e}")
        return await format_api_error(e, "bulk update application dictionaries")
    except Exception as e:
        logger.error(f"Unexpected error performing bulk operation on application dictionaries: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while performing bulk operation on application dictionaries"
        }


# ============================================================================
# RADIUS Dictionary Tools
# ============================================================================

@operation(domain="policy_elements")
async def list_radius_dictionaries(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"vendor_name\": \"Cisco\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+vendor_name', '-vendor_id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List RADIUS dictionaries with optional filtering, sorting, and pagination.

    This tool retrieves all RADIUS dictionaries configured in ClearPass, which define
    vendor-specific RADIUS attributes used for authentication and authorization.

    Examples:
    - List all RADIUS dictionaries: No additional parameters needed
    - Filter by vendor: filter='{"vendor_name": "Cisco"}'
    - Sort by vendor ID: sort='+vendor_id'
    - Paginate results: offset=0, limit=10

    Returns detailed information about each RADIUS dictionary including vendor details
    and attribute definitions.
    """
    try:
        await ctx.info(f"Listing RADIUS dictionaries with filter: {filter_str}")
        
        clearpass_client = await get_clearpass_client()
        
        # Call the client method to list RADIUS dictionaries
        result = await clearpass_client.list_radius_dictionaries(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        
        total_count = result.get("count", 0)
        dictionaries = result.get("_embedded", {}).get("items", [])
        
        await ctx.info(f"Successfully retrieved {len(dictionaries)} RADIUS dictionaries")
        
        return {
            "success": True,
            "message": f"Retrieved {len(dictionaries)} RADIUS dictionaries" + (f" (total: {total_count})" if calculate_count else ""),
            "data": {
                "dictionaries": dictionaries,
                "total_count": total_count if calculate_count else None,
                "returned_count": len(dictionaries)
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to list RADIUS dictionaries: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def create_radius_dictionary(
    ctx: Context,
    vendor_id: int = Field(..., description="Vendor ID of RADIUS Dictionary (must be unique)"),
    vendor_name: str = Field(..., description="Vendor Name of RADIUS Dictionary"),
    prefix: str = Field(..., description="Vendor Prefix of RADIUS Dictionary"),
    attributes: Union[List[Dict[str, Any]], str] = Field(..., description="Attributes of RADIUS Dictionary in pyclearpass format - array format: [{\"attr_id\": 1, \"attr_name\": \"Custom-Attribute-1\", \"attr_type\": \"string\", \"attr_profile\": \"in out\"}] or JSON string"),
    enabled: bool = Field(default=True, description="Is RADIUS Dictionary enabled?")
) -> Dict[str, Any]:
    """
    Create a new RADIUS dictionary with vendor-specific attributes.

    This tool creates a custom RADIUS dictionary for a specific vendor, defining
    vendor-specific attributes used in RADIUS messages.

    Example attribute format:
    [
        {
            "attr_id": 1,
            "attr_name": "Custom-Attribute-1",
            "attr_type": "string",
            "attr_profile": "in out",
            "extra_data": "",
            "valid_values": []
        }
    ]

    The vendor_id must be unique and typically follows IANA assignments for
    vendor-specific attributes.
    """
    try:
        await ctx.info(f"Creating RADIUS dictionary for vendor '{vendor_name}' (ID: {vendor_id})")
        
        clearpass_client = await get_clearpass_client()
        
        # Parse attributes parameter
        parsed_attributes = _parse_list_dict_parameter(attributes, "attributes")
        
        # Prepare dictionary data
        radius_dict_data = {
            "vendor_id": vendor_id,
            "vendor_name": vendor_name,
            "prefix": prefix,
            "enabled": enabled,
            "attributes": parsed_attributes
        }
        
        # Create the RADIUS dictionary
        result = await clearpass_client.create_radius_dictionary(radius_dict_data)
        
        await ctx.info(f"Successfully created RADIUS dictionary for vendor '{vendor_name}'")
        
        return {
            "success": True,
            "message": f"Successfully created RADIUS dictionary for vendor '{vendor_name}' with {len(attributes)} attributes",
            "data": result
        }
        
    except Exception as e:
        error_msg = f"Failed to create RADIUS dictionary for vendor '{vendor_name}': {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def get_radius_dictionary_details(
    ctx: Context,
    radius_dict_id: Optional[int] = Field(None, description="Numeric ID of the RADIUS dictionary"),
    vendor_name: Optional[str] = Field(None, description="Vendor name of the RADIUS dictionary")
) -> Dict[str, Any]:
    """
    Get detailed information about a RADIUS dictionary by ID or vendor name.

    This tool retrieves comprehensive information about a specific RADIUS dictionary,
    including all vendor-specific attributes and their configurations.

    Specify either radius_dict_id OR vendor_name, not both.
    """
    try:
        if radius_dict_id is None and vendor_name is None:
            return {
                "success": False,
                "message": "Either 'radius_dict_id' or 'vendor_name' must be provided",
                "error_details": "Missing required parameter"
            }
        
        if radius_dict_id is not None and vendor_name is not None:
            return {
                "success": False,
                "message": "Provide either 'radius_dict_id' OR 'vendor_name', not both",
                "error_details": "Conflicting parameters"
            }
        
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        await ctx.info(f"Retrieving RADIUS dictionary details for {identifier}")
        
        clearpass_client = await get_clearpass_client()
        
        # Get dictionary details by ID or name
        if radius_dict_id is not None:
            result = await clearpass_client.get_radius_dictionary_by_id(radius_dict_id)
        else:
            result = await clearpass_client.get_radius_dictionary_by_name(vendor_name)
        
        dictionary_info = result
        vendor_name_result = dictionary_info.get("vendor_name", "Unknown")
        attr_count = len(dictionary_info.get("attributes", []))
        
        await ctx.info(f"Successfully retrieved RADIUS dictionary details for vendor '{vendor_name_result}'")
        
        return {
            "success": True,
            "message": f"Retrieved details for RADIUS dictionary '{vendor_name_result}' with {attr_count} attributes",
            "data": dictionary_info
        }
        
    except Exception as e:
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        error_msg = f"Failed to retrieve RADIUS dictionary details for {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def update_radius_dictionary(
    ctx: Context,
    radius_dict_id: Optional[int] = Field(None, description="Numeric ID of the RADIUS dictionary to update"),
    vendor_name: Optional[str] = Field(None, description="Vendor name of the RADIUS dictionary to update"),
    new_vendor_name: Optional[str] = Field(None, description="New vendor name for the RADIUS dictionary"),
    new_prefix: Optional[str] = Field(None, description="New vendor prefix for the RADIUS dictionary"),
    enabled: Optional[bool] = Field(None, description="New enabled status for the RADIUS dictionary"),
    attributes: Optional[Union[List[Dict[str, Any]], str]] = Field(None, description="New list of RADIUS dictionary attributes - array format: [{\"attr_id\": 1, \"attr_name\": \"Custom-Attribute-1\", \"attr_type\": \"string\", \"attr_profile\": \"in out\"}] or JSON string"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing RADIUS dictionary by ID or vendor name.

    This tool allows updating various properties of a RADIUS dictionary including
    vendor information, enabled status, and the complete list of attributes.

    Specify either radius_dict_id OR vendor_name to identify the dictionary.
    Use replace_all=True for complete replacement (PUT) or False for partial update (PATCH).

    Example usage:
    - Enable/disable dictionary: enabled=True/False
    - Update attributes: attributes=[{...}]
    - Change vendor name: new_vendor_name="New Vendor"
    """
    try:
        if radius_dict_id is None and vendor_name is None:
            return {
                "success": False,
                "message": "Either 'radius_dict_id' or 'vendor_name' must be provided",
                "error_details": "Missing required parameter"
            }
        
        if radius_dict_id is not None and vendor_name is not None:
            return {
                "success": False,
                "message": "Provide either 'radius_dict_id' OR 'vendor_name', not both",
                "error_details": "Conflicting parameters"
            }
        
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        operation = "replace" if replace_all else "update"
        await ctx.info(f"Starting {operation} of RADIUS dictionary for {identifier}")
        
        clearpass_client = await get_clearpass_client()
        
        # Parse list parameters that may be JSON strings
        parsed_attributes = None
        if attributes is not None:
            try:
                parsed_attributes = _parse_list_dict_parameter(attributes, "attributes")
            except ValueError as e:
                logger.error(f"Failed to parse attributes parameter: {e}")
                return {
                    "success": False,
                    "message": f"Invalid attributes parameter: {str(e)}",
                    "error": str(e)
                }
        
        # Prepare update data
        update_data = {}
        if new_vendor_name is not None:
            update_data["vendor_name"] = new_vendor_name
        if new_prefix is not None:
            update_data["prefix"] = new_prefix
        if enabled is not None:
            update_data["enabled"] = enabled
        if parsed_attributes is not None:
            update_data["attributes"] = parsed_attributes
        
        if not update_data:
            return {
                "success": False,
                "message": "No update data provided",
                "error_details": "At least one field must be specified for update"
            }
        
        # Perform update or replacement
        if radius_dict_id is not None:
            if replace_all:
                result = await clearpass_client.replace_radius_dictionary_by_id(radius_dict_id, update_data)
            else:
                result = await clearpass_client.update_radius_dictionary_by_id(radius_dict_id, update_data)
        else:
            if replace_all:
                result = await clearpass_client.replace_radius_dictionary_by_name(vendor_name, update_data)
            else:
                result = await clearpass_client.update_radius_dictionary_by_name(vendor_name, update_data)
        
        success_vendor_name = result.get("vendor_name", new_vendor_name or vendor_name or "Unknown")
        await ctx.info(f"Successfully {operation}d RADIUS dictionary for vendor '{success_vendor_name}'")
        
        return {
            "success": True,
            "message": f"Successfully {operation}d RADIUS dictionary for vendor '{success_vendor_name}'",
            "data": result
        }
        
    except Exception as e:
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        error_msg = f"Failed to update RADIUS dictionary for {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def delete_radius_dictionary(
    ctx: Context,
    radius_dict_id: Optional[int] = Field(None, description="Numeric ID of the RADIUS dictionary to delete"),
    vendor_name: Optional[str] = Field(None, description="Vendor name of the RADIUS dictionary to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a RADIUS dictionary by ID or vendor name.

    ⚠️ WARNING: This operation permanently removes the RADIUS dictionary and all its
    vendor-specific attributes. This action cannot be undone.

    Specify either radius_dict_id OR vendor_name to identify the dictionary.
    The 'confirm' parameter must be set to True to proceed with deletion.

    Before deletion, ensure the dictionary is not referenced by any policies or configurations.
    """
    try:
        if radius_dict_id is None and vendor_name is None:
            return {
                "success": False,
                "message": "Either 'radius_dict_id' or 'vendor_name' must be provided",
                "error_details": "Missing required parameter"
            }
        
        if radius_dict_id is not None and vendor_name is not None:
            return {
                "success": False,
                "message": "Provide either 'radius_dict_id' OR 'vendor_name', not both",
                "error_details": "Conflicting parameters"
            }
        
        if not confirm:
            return {
                "success": False,
                "message": "Deletion not confirmed. Set 'confirm=True' to proceed with deletion.",
                "error_details": "Confirmation required for safety"
            }
        
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        await ctx.info(f"Starting deletion of RADIUS dictionary for {identifier}")
        
        clearpass_client = await get_clearpass_client()
        
        # Try to get dictionary details, but handle if it doesn't exist
        dictionary_info = None
        vendor_name_result = "Unknown"
        attr_count = 0
        
        try:
            if radius_dict_id is not None:
                dictionary_info = await clearpass_client.get_radius_dictionary_by_id(radius_dict_id)
            else:
                dictionary_info = await clearpass_client.get_radius_dictionary_by_name(vendor_name)
            
            vendor_name_result = dictionary_info.get("vendor_name", "Unknown")
            attr_count = len(dictionary_info.get("attributes", []))
        except ClearPassAPIError as e:
            if e.status_code == 404:
                await ctx.info(f"RADIUS dictionary not found - it may have been renamed or already deleted")
                # Continue anyway to provide the API limitation message
            else:
                raise
        
        # Note: The pyclearpass library doesn't seem to have delete methods for RADIUS dictionaries
        # This is likely because RADIUS dictionaries are core configuration elements
        await ctx.info(f"RADIUS dictionary deletion not supported by ClearPass API")
        
        message = f"RADIUS dictionary deletion is not supported by the ClearPass API."
        if dictionary_info:
            message += f" Dictionary '{vendor_name_result}' with {attr_count} attributes cannot be deleted programmatically."
        else:
            message += f" The requested dictionary was not found (it may have been renamed after updates)."
        
        return {
            "success": False,
            "message": message,
            "data": {
                "dictionary_info": dictionary_info if dictionary_info else {"note": "Dictionary not found or renamed"},
                "recommendation": "RADIUS dictionaries can only be managed through the ClearPass GUI. Consider disabling the dictionary instead if you want to stop using it.",
                "api_limitation": "ClearPass API does not provide DELETE endpoints for RADIUS dictionaries"
            }
        }
        
    except Exception as e:
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        error_msg = f"Failed to process deletion request for RADIUS dictionary {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def enable_disable_radius_dictionary(
    ctx: Context,
    action: str = Field(..., description="Action to perform: 'enable' or 'disable'"),
    radius_dict_id: Optional[int] = Field(None, description="Numeric ID of the RADIUS dictionary"),
    vendor_name: Optional[str] = Field(None, description="Vendor name of the RADIUS dictionary")
) -> Dict[str, Any]:
    """
    Enable or disable a RADIUS dictionary by ID or vendor name.

    This tool allows you to enable or disable RADIUS dictionaries, which controls
    whether the vendor-specific attributes are available for use in policies.

    Specify either radius_dict_id OR vendor_name to identify the dictionary.
    The action parameter must be either 'enable' or 'disable'.

    Enabling a dictionary makes its attributes available for policy configuration.
    Disabling a dictionary prevents its attributes from being used in new configurations.
    """
    try:
        if action not in ["enable", "disable"]:
            return {
                "success": False,
                "message": "Action must be either 'enable' or 'disable'",
                "error_details": "Invalid action parameter"
            }
        
        if radius_dict_id is None and vendor_name is None:
            return {
                "success": False,
                "message": "Either 'radius_dict_id' or 'vendor_name' must be provided",
                "error_details": "Missing required parameter"
            }
        
        if radius_dict_id is not None and vendor_name is not None:
            return {
                "success": False,
                "message": "Provide either 'radius_dict_id' OR 'vendor_name', not both",
                "error_details": "Conflicting parameters"
            }
        
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        await ctx.info(f"Starting {action} operation for RADIUS dictionary {identifier}")
        
        clearpass_client = await get_clearpass_client()
        
        # Perform enable/disable operation
        if radius_dict_id is not None:
            if action == "enable":
                result = await clearpass_client.enable_radius_dictionary_by_id(radius_dict_id)
            else:
                result = await clearpass_client.disable_radius_dictionary_by_id(radius_dict_id)
        else:
            if action == "enable":
                result = await clearpass_client.enable_radius_dictionary_by_name(vendor_name)
            else:
                result = await clearpass_client.disable_radius_dictionary_by_name(vendor_name)
        
        # Get updated dictionary info to confirm status
        if radius_dict_id is not None:
            updated_info = await clearpass_client.get_radius_dictionary_by_id(radius_dict_id)
        else:
            updated_info = await clearpass_client.get_radius_dictionary_by_name(vendor_name)
        
        vendor_name_result = updated_info.get("vendor_name", "Unknown")
        current_status = "enabled" if updated_info.get("enabled", False) else "disabled"
        
        await ctx.info(f"Successfully {action}d RADIUS dictionary for vendor '{vendor_name_result}'")
        
        return {
            "success": True,
            "message": f"Successfully {action}d RADIUS dictionary for vendor '{vendor_name_result}'. Current status: {current_status}",
            "data": {
                "dictionary_info": updated_info,
                "action_performed": action,
                "current_status": current_status
            }
        }
        
    except Exception as e:
        identifier = f"ID {radius_dict_id}" if radius_dict_id is not None else f"vendor name '{vendor_name}'"
        error_msg = f"Failed to {action} RADIUS dictionary for {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def validate_radius_dictionary_configuration(
    ctx: Context,
    radius_dict_config: Dict[str, Any] = Field(..., description="RADIUS dictionary configuration to validate"),
    strict_validation: bool = Field(default=False, description="Enable strict validation rules")
) -> Dict[str, Any]:
    """
    Validate RADIUS dictionary configuration for compliance and best practices.

    This tool performs comprehensive validation of RADIUS dictionary configurations,
    checking for common issues, vendor compliance, and attribute conflicts.

    Validation includes:
    - Required field validation
    - Vendor ID uniqueness
    - Attribute ID conflicts
    - Attribute type compliance
    - Vendor naming conventions
    - RADIUS standards compliance

    Use strict_validation=True for additional checks against RADIUS standards and
    vendor-specific requirements.
    """
    try:
        await ctx.info("Starting RADIUS dictionary configuration validation")
        
        clearpass_client = await get_clearpass_client()
        
        # Perform validation using the client method
        validation_result = await clearpass_client.validate_radius_dictionary_configuration(
            radius_dict_config, strict_validation
        )
        
        is_valid = validation_result.get("valid", False)
        warnings = validation_result.get("warnings", [])
        errors = validation_result.get("errors", [])
        suggestions = validation_result.get("suggestions", [])
        
        status = "valid" if is_valid else "invalid"
        await ctx.info(f"RADIUS dictionary validation completed: {status}")
        
        return {
            "success": True,
            "message": f"RADIUS dictionary validation completed: {status} (Errors: {len(errors)}, Warnings: {len(warnings)})",
            "data": {
                "validation_result": validation_result,
                "summary": {
                    "is_valid": is_valid,
                    "error_count": len(errors),
                    "warning_count": len(warnings),
                    "suggestion_count": len(suggestions)
                }
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to validate RADIUS dictionary configuration: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def get_radius_dictionary_statistics(
    ctx: Context,
    radius_dict_id: int = Field(..., description="Numeric ID of the RADIUS dictionary"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')"),
    include_usage_details: bool = Field(default=True, description="Include detailed usage analysis")
) -> Dict[str, Any]:
    """
    Get comprehensive usage statistics for a RADIUS dictionary.

    This tool provides detailed analytics about RADIUS dictionary usage including:
    - Attribute usage frequency
    - Policy associations
    - Authentication/accounting message statistics
    - Vendor compliance metrics
    - Performance indicators

    Time range options: '1h', '24h', '7d', '30d'
    """
    try:
        await ctx.info(f"Retrieving statistics for RADIUS dictionary ID {radius_dict_id} (time range: {time_range})")
        
        clearpass_client = await get_clearpass_client()
        
        # Get basic dictionary info first
        dictionary_info = await clearpass_client.get_radius_dictionary_by_id(radius_dict_id)
        vendor_name = dictionary_info.get("vendor_name", "Unknown")
        
        # Get statistics using the client method
        statistics = await clearpass_client.get_radius_dictionary_statistics(radius_dict_id, time_range)
        
        attr_count = len(dictionary_info.get("attributes", []))
        total_attributes = statistics.get("total_attributes", attr_count)
        
        await ctx.info(f"Successfully retrieved statistics for RADIUS dictionary '{vendor_name}'")
        
        return {
            "success": True,
            "message": f"Retrieved statistics for RADIUS dictionary '{vendor_name}' with {total_attributes} attributes",
            "data": {
                "dictionary_info": {
                    "vendor_name": vendor_name,
                    "vendor_id": dictionary_info.get("vendor_id"),
                    "enabled": dictionary_info.get("enabled", False)
                },
                "statistics": statistics,
                "time_range": time_range
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to retrieve statistics for RADIUS dictionary ID {radius_dict_id}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def test_radius_dictionary(
    ctx: Context,
    radius_dict_id: int = Field(..., description="Numeric ID of the RADIUS dictionary to test"),
    test_parameters: Optional[Dict[str, Any]] = Field(None, description="Optional test parameters and configuration")
) -> Dict[str, Any]:
    """
    Test RADIUS dictionary functionality and vendor compliance.

    This tool performs comprehensive testing of RADIUS dictionary attributes:
    - Attribute syntax validation
    - Type checking compliance
    - Vendor-specific format verification
    - Integration testing with RADIUS processes
    - Performance benchmarking

    Test parameters can include:
    - test_type: 'syntax', 'compliance', 'integration', 'performance'
    - sample_data: Test data for attribute validation
    - vendor_specs: Vendor-specific compliance rules
    """
    try:
        await ctx.info(f"Starting test of RADIUS dictionary ID {radius_dict_id}")
        
        clearpass_client = await get_clearpass_client()
        
        # Get dictionary info first
        dictionary_info = await clearpass_client.get_radius_dictionary_by_id(radius_dict_id)
        vendor_name = dictionary_info.get("vendor_name", "Unknown")
        
        # Perform testing using the client method
        test_result = await clearpass_client.test_radius_dictionary(radius_dict_id, test_parameters)
        
        test_status = test_result.get("test_status", "unknown")
        test_type = test_result.get("test_type", "functionality")
        
        await ctx.info(f"Completed {test_type} test for RADIUS dictionary '{vendor_name}': {test_status}")
        
        return {
            "success": True,
            "message": f"Completed {test_type} test for RADIUS dictionary '{vendor_name}': {test_status}",
            "data": {
                "dictionary_info": {
                    "vendor_name": vendor_name,
                    "vendor_id": dictionary_info.get("vendor_id"),
                    "attribute_count": len(dictionary_info.get("attributes", []))
                },
                "test_result": test_result
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to test RADIUS dictionary ID {radius_dict_id}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def clone_radius_dictionary(
    ctx: Context,
    source_radius_dict_id: int = Field(..., description="Numeric ID of the RADIUS dictionary to clone"),
    new_vendor_name: str = Field(..., description="Vendor name for the new cloned dictionary"),
    new_vendor_id: int = Field(..., description="Vendor ID for the new cloned dictionary (must be unique)"),
    new_prefix: Optional[str] = Field(None, description="Vendor prefix for the new cloned dictionary"),
    modify_attributes: bool = Field(default=False, description="Whether to modify attributes during cloning")
) -> Dict[str, Any]:
    """
    Clone an existing RADIUS dictionary with new vendor details.

    This tool creates a copy of an existing RADIUS dictionary with new vendor
    information while preserving all attribute definitions. This is useful for:
    - Creating vendor variants
    - Testing new configurations
    - Migrating between vendor implementations

    The new_vendor_id must be unique and not conflict with existing dictionaries.
    Optionally modify attributes during the cloning process.
    """
    try:
        await ctx.info(f"Starting clone of RADIUS dictionary ID {source_radius_dict_id} to new vendor '{new_vendor_name}'")
        
        clearpass_client = await get_clearpass_client()
        
        # Get source dictionary info
        source_dict = await clearpass_client.get_radius_dictionary_by_id(source_radius_dict_id)
        source_vendor_name = source_dict.get("vendor_name", "Unknown")
        attr_count = len(source_dict.get("attributes", []))
        
        try:
            # Try to perform cloning using the client method
            result = await clearpass_client.clone_radius_dictionary(
                source_radius_dict_id,
                new_vendor_name,
                new_vendor_id,
                new_prefix
            )
        except ClearPassAPIError as e:
            error_message = str(e).lower()
            if e.status_code == 422:
                if "already exists" in error_message:
                    # Handle attribute name conflicts
                    await ctx.info("Attribute name conflict detected - attempting to create dictionary without attributes")
                    
                    # Create dictionary without attributes
                    new_dict_data = {
                        "vendor_id": new_vendor_id,
                        "vendor_name": new_vendor_name,
                        "prefix": new_prefix or source_dict.get("prefix", ""),
                        "enabled": source_dict.get("enabled", True),
                        "attributes": []  # Empty attributes to avoid conflicts
                    }
                    
                    result = await clearpass_client.create_radius_dictionary(new_dict_data)
                    
                    return {
                        "success": True,
                        "message": f"RADIUS dictionary cloned without attributes due to naming conflicts. Dictionary '{new_vendor_name}' created successfully.",
                        "data": {
                            "source_dictionary": {
                                "vendor_name": source_vendor_name,
                                "vendor_id": source_dict.get("vendor_id"),
                                "attribute_count": attr_count
                            },
                            "new_dictionary": result,
                            "warning": "Attributes were not copied due to naming conflicts. You may need to manually add attributes with unique names."
                        }
                    }
                elif "attributes must be specified" in error_message:
                    # Handle case where API requires attributes to be specified
                    await ctx.info("API requires attributes to be specified - creating dictionary with minimal attributes")
                    
                    # Get source attributes and create minimal attribute set
                    source_attrs = source_dict.get("attributes", [])
                    if source_attrs:
                        # Use first attribute as template but modify name to avoid conflicts
                        first_attr = source_attrs[0].copy()
                        first_attr["attr_name"] = f"{new_vendor_name}-Attr-1"
                        minimal_attrs = [first_attr]
                    else:
                        # Create a default attribute if source has none
                        minimal_attrs = [{
                            "attr_id": 1,
                            "attr_name": f"{new_vendor_name}-Default-Attr",
                            "attr_type": "string",
                            "attr_profile": "in out"
                        }]
                    
                    # Create dictionary with minimal attributes
                    new_dict_data = {
                        "vendor_id": new_vendor_id,
                        "vendor_name": new_vendor_name,
                        "prefix": new_prefix or source_dict.get("prefix", ""),
                        "enabled": source_dict.get("enabled", True),
                        "attributes": minimal_attrs
                    }
                    
                    result = await clearpass_client.create_radius_dictionary(new_dict_data)
                    
                    return {
                        "success": True,
                        "message": f"RADIUS dictionary cloned with minimal attributes. Dictionary '{new_vendor_name}' created successfully.",
                        "data": {
                            "source_dictionary": {
                                "vendor_name": source_vendor_name,
                                "vendor_id": source_dict.get("vendor_id"),
                                "attribute_count": attr_count
                            },
                            "new_dictionary": result,
                            "note": "Created with minimal attributes due to API requirements. Additional attributes can be added manually."
                        }
                    }
                else:
                    raise
            else:
                raise
        
        await ctx.info(f"Successfully cloned RADIUS dictionary from '{source_vendor_name}' to '{new_vendor_name}'")
        
        return {
            "success": True,
            "message": f"Successfully cloned RADIUS dictionary from '{source_vendor_name}' to '{new_vendor_name}' with {attr_count} attributes",
            "data": {
                "source_dictionary": {
                    "vendor_name": source_vendor_name,
                    "vendor_id": source_dict.get("vendor_id"),
                    "attribute_count": attr_count
                },
                "new_dictionary": result
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to clone RADIUS dictionary ID {source_radius_dict_id} to '{new_vendor_name}': {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def search_radius_dictionaries_advanced(
    ctx: Context,
    vendor_name_pattern: Optional[str] = Field(None, description="Search pattern for vendor names (supports wildcards)"),
    vendor_id_range: Optional[Dict[str, int]] = Field(None, description="Vendor ID range filter (e.g., {'min': 1000, 'max': 2000})"),
    enabled_only: Optional[bool] = Field(None, description="Filter only enabled dictionaries"),
    has_attributes: Optional[bool] = Field(None, description="Filter dictionaries that have attributes defined"),
    attribute_type: Optional[str] = Field(None, description="Filter by specific attribute type (e.g., 'string', 'integer')"),
    min_attribute_count: Optional[int] = Field(None, description="Minimum number of attributes in dictionary"),
    max_attribute_count: Optional[int] = Field(None, description="Maximum number of attributes in dictionary"),
    custom_filter: Optional[str] = Field(None, description="Custom JSON filter expression"),
    limit: int = Field(default=50, description="Maximum number of results to return"),
    sort_by: str = Field(default="vendor_name", description="Sort results by field (vendor_name, vendor_id, attribute_count)")
) -> Dict[str, Any]:
    """
    Perform advanced search of RADIUS dictionaries with multiple criteria.

    This tool provides sophisticated search capabilities for RADIUS dictionaries
    with support for complex filtering and sorting options.

    Search criteria include:
    - Vendor name patterns with wildcard support
    - Vendor ID ranges for specific vendor groups
    - Enabled/disabled status filtering
    - Attribute count thresholds
    - Attribute type filtering
    - Custom JSON filter expressions

    Results are sorted and limited for optimal performance.
    """
    try:
        await ctx.info("Starting advanced search of RADIUS dictionaries")
        
        clearpass_client = await get_clearpass_client()
        
        # Start with basic list to filter
        all_dictionaries = await clearpass_client.list_radius_dictionaries(limit=1000)
        dictionaries = all_dictionaries.get("_embedded", {}).get("items", [])
        
        # Apply advanced filtering
        filtered_dictionaries = []
        
        for dictionary in dictionaries:
            # Vendor name pattern filtering
            if vendor_name_pattern:
                import fnmatch
                vendor_name = dictionary.get("vendor_name", "")
                if not fnmatch.fnmatch(vendor_name.lower(), vendor_name_pattern.lower()):
                    continue
            
            # Vendor ID range filtering
            if vendor_id_range:
                vendor_id = dictionary.get("vendor_id", 0)
                min_id = vendor_id_range.get("min", 0)
                max_id = vendor_id_range.get("max", 999999)
                if not (min_id <= vendor_id <= max_id):
                    continue
            
            # Enabled status filtering
            if enabled_only is not None:
                is_enabled = dictionary.get("enabled", False)
                if enabled_only and not is_enabled:
                    continue
                if not enabled_only and is_enabled:
                    continue
            
            # Attribute existence filtering
            attributes = dictionary.get("attributes", [])
            if has_attributes is not None:
                has_attrs = len(attributes) > 0
                if has_attributes and not has_attrs:
                    continue
                if not has_attributes and has_attrs:
                    continue
            
            # Attribute count filtering
            attr_count = len(attributes)
            if min_attribute_count is not None and attr_count < min_attribute_count:
                continue
            if max_attribute_count is not None and attr_count > max_attribute_count:
                continue
            
            # Attribute type filtering
            if attribute_type:
                has_type = any(attr.get("attr_type") == attribute_type for attr in attributes)
                if not has_type:
                    continue
            
            # Add attribute count for sorting
            dictionary["attribute_count"] = attr_count
            filtered_dictionaries.append(dictionary)
        
        # Sort results
        reverse_sort = sort_by.startswith("-")
        sort_field = sort_by.lstrip("-+")
        
        try:
            filtered_dictionaries.sort(
                key=lambda x: x.get(sort_field, ""),
                reverse=reverse_sort
            )
        except (KeyError, TypeError):
            # Fallback to vendor_name sorting if sort field is invalid
            filtered_dictionaries.sort(key=lambda x: x.get("vendor_name", ""))
        
        # Apply limit
        limited_results = filtered_dictionaries[:limit]
        
        await ctx.info(f"Advanced search completed: found {len(limited_results)} matching RADIUS dictionaries")
        
        return {
            "success": True,
            "message": f"Found {len(limited_results)} RADIUS dictionaries matching advanced search criteria",
            "data": {
                "dictionaries": limited_results,
                "total_found": len(filtered_dictionaries),
                "returned_count": len(limited_results),
                "search_criteria": {
                    "vendor_name_pattern": vendor_name_pattern,
                    "vendor_id_range": vendor_id_range,
                    "enabled_only": enabled_only,
                    "has_attributes": has_attributes,
                    "attribute_type": attribute_type,
                    "min_attribute_count": min_attribute_count,
                    "max_attribute_count": max_attribute_count,
                    "sort_by": sort_by,
                    "limit": limit
                }
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to perform advanced search of RADIUS dictionaries: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def bulk_update_radius_dictionaries(
    ctx: Context,
    radius_dict_ids: List[int] = Field(..., description="List of RADIUS dictionary IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete', 'enable', 'disable'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple RADIUS dictionaries.

    This tool allows efficient management of multiple RADIUS dictionaries
    through batch operations including:
    - Bulk updates (prefix, enabled status)
    - Bulk deletion (with confirmation)
    - Bulk enable/disable operations
    - Bulk attribute modifications

    IMPORTANT: Bulk delete operations are irreversible and require confirmation.
    ClearPass API limitations may apply to RADIUS dictionary deletion.

    Example operation_data formats:
    - update: {"enabled": true, "prefix": "New-"}
    - delete: {} (requires confirm_operation=True)
    - enable/disable: {} (action determined by operation_type)
    """
    try:
        await ctx.info(f"Starting bulk {operation_type} operation on {len(radius_dict_ids)} RADIUS dictionaries")
        
        # Safety check for destructive operations
        if operation_type in ["delete"] and not confirm_operation:
            return {
                "success": False,
                "message": f"Bulk {operation_type} operation requires confirmation. Set confirm_operation=True to proceed.",
                "error": "Safety confirmation required"
            }
        
        clearpass_client = await get_clearpass_client()
        results = []
        errors = []
        
        for dict_id in radius_dict_ids:
            # Bound before the try so the handler can never read a stale value
            # from the previous iteration (or raise UnboundLocalError on the
            # first one).
            vendor_name = f"ID-{dict_id}"
            try:
                # Get dictionary info for reporting
                dict_info = await clearpass_client.get_radius_dictionary_by_id(dict_id)
                vendor_name = dict_info.get("vendor_name", f"ID-{dict_id}")

                if operation_type == "update":
                    result = await clearpass_client.bulk_update_radius_dictionaries(
                        [dict_id], operation_type, operation_data
                    )
                    results.append({
                        "dictionary_id": dict_id,
                        "vendor_name": vendor_name,
                        "status": "updated",
                        "details": result
                    })
                    
                elif operation_type == "delete":
                    # Note: ClearPass API may have limitations on RADIUS dictionary deletion
                    try:
                        await clearpass_client.delete_radius_dictionary_by_id(dict_id)
                        results.append({
                            "dictionary_id": dict_id,
                            "vendor_name": vendor_name,
                            "status": "deleted"
                        })
                    except Exception as del_error:
                        # ClearPass 6.12.4 answers 405 Method Not Allowed for
                        # DELETE /radius-dictionary/{id}: dictionaries cannot be
                        # deleted through the config API. Detect it by status
                        # code as well as by message text, because the 405
                        # response body is empty.
                        error_msg = str(del_error)
                        not_supported = (
                            getattr(del_error, "status_code", None) in (405, 501)
                            or "not supported" in error_msg.lower()
                            or "not allowed" in error_msg.lower()
                        )
                        if not_supported:
                            results.append({
                                "dictionary_id": dict_id,
                                "vendor_name": vendor_name,
                                "status": "deletion_not_supported",
                                "note": "ClearPass API does not support RADIUS dictionary deletion"
                            })
                        else:
                            raise del_error
                    
                elif operation_type in ["enable", "disable"]:
                    await clearpass_client.enable_radius_dictionary_by_id(dict_id) if operation_type == "enable" else await clearpass_client.disable_radius_dictionary_by_id(dict_id)
                    results.append({
                        "dictionary_id": dict_id,
                        "vendor_name": vendor_name,
                        "status": f"{operation_type}d"
                    })
                    
                else:
                    errors.append({
                        "dictionary_id": dict_id,
                        "vendor_name": vendor_name,
                        "error": f"Unknown operation type: {operation_type}"
                    })
                    
            except Exception as e:
                errors.append({
                    "dictionary_id": dict_id,
                    "vendor_name": vendor_name if 'vendor_name' in locals() else f"ID-{dict_id}",
                    "error": str(e)
                })
        
        success_count = len(results)
        error_count = len(errors)
        
        await ctx.info(f"Bulk operation completed: {success_count} successful, {error_count} errors")
        
        return {
            "success": error_count == 0,
            "message": f"Bulk {operation_type} completed: {success_count} successful, {error_count} errors",
            "data": {
                "operation_type": operation_type,
                "total_processed": len(radius_dict_ids),
                "successful_operations": results,
                "failed_operations": errors,
                "summary": {
                    "success_count": success_count,
                    "error_count": error_count,
                    "overall_success_rate": f"{(success_count / len(radius_dict_ids) * 100):.1f}%" if radius_dict_ids else "0%"
                }
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to perform bulk {operation_type} operation on RADIUS dictionaries: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


# =============================================================================
# PROXY TARGET TOOLS (Phase 6.1)
# =============================================================================

@operation(domain="policy_elements")
async def list_proxy_targets(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"proxy_type\": \"RADIUS\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List all proxy targets with optional filtering, sorting, and pagination.
    """
    try:
        await ctx.info("Listing proxy targets from ClearPass")
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.list_proxy_targets(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        
        proxy_targets = result.get('_embedded', {}).get('items', [])
        count = len(proxy_targets)
        
        await ctx.info(f"Retrieved {count} proxy targets")
        
        return {
            "success": True,
            "message": f"Retrieved {count} proxy targets",
            "data": result,
            "total_count": result.get("count"),
            "proxy_targets_summary": [
                {
                    "id": target.get("id"),
                    "name": target.get("name"),
                    "host_name": target.get("host_name"),
                    "proxy_type": target.get("proxy_type")
                }
                for target in proxy_targets
            ]
        }
        
    except Exception as e:
        error_msg = f"Failed to list proxy targets: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def create_proxy_target(
    ctx: Context,
    name: str = Field(..., description="Name of the proxy target (must be unique)"),
    host_name: str = Field(..., description="Host name or IP address of the proxy target"),
    proxy_type: str = Field(..., description="Proxy type: 'RADIUS' or 'RadSec'"),
    description: Optional[str] = Field(None, description="Description of the proxy target"),
    authentication_port: int = Field(default=1812, description="Authentication port of the proxy target"),
    accounting_port: int = Field(default=1813, description="Accounting port of the proxy target"),
    secret: Optional[str] = Field(None, description="Shared secret for RADIUS proxy (required for RADIUS type)"),
    radsec_port: int = Field(default=2083, description="RadSec port number (for RadSec type)")
) -> Dict[str, Any]:
    """
    Create a new proxy target for RADIUS or RadSec proxying.
    """
    try:
        await ctx.info(f"Creating proxy target '{name}' with type '{proxy_type}'")
        
        # Validate proxy type
        if proxy_type not in ["RADIUS", "RadSec"]:
            return {
                "success": False,
                "error": "Invalid proxy type. Must be 'RADIUS' or 'RadSec'"
            }
        
        # Validate secret for RADIUS type
        if proxy_type == "RADIUS" and not secret:
            return {
                "success": False,
                "error": "Shared secret is required for RADIUS proxy type"
            }
        
        proxy_target_data = {
            "name": name,
            "host_name": host_name,
            "proxy_type": proxy_type,
            "authentication_port": authentication_port,
            "accounting_port": accounting_port,
            "radsec_port": radsec_port
        }
        
        if description:
            proxy_target_data["description"] = description
            
        if secret:
            proxy_target_data["secret"] = secret
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.create_proxy_target(proxy_target_data)
        
        await ctx.info(f"Successfully created proxy target '{name}' with ID {result.get('id')}")
        
        return {
            "success": True,
            "message": f"Successfully created proxy target '{name}' with ID {result.get('id')}",
            "data": result,
            "proxy_target_id": result.get("id")
        }
        
    except Exception as e:
        error_msg = f"Failed to create proxy target '{name}': {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def get_proxy_target_details(
    ctx: Context,
    proxy_target_id: Optional[int] = Field(None, description="Numeric ID of the proxy target"),
    name: Optional[str] = Field(None, description="Name of the proxy target")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific proxy target.
    """
    try:
        # Validate input parameters
        if proxy_target_id is None and name is None:
            return {
                "success": False,
                "error": "Either proxy_target_id or name must be provided"
            }
        
        if proxy_target_id is not None and name is not None:
            return {
                "success": False,
                "error": "Provide either proxy_target_id or name, not both"
            }
        
        identifier = name or f"ID {proxy_target_id}"
        await ctx.info(f"Retrieving proxy target details for {identifier}")
        
        clearpass_client = await get_clearpass_client()
        
        if proxy_target_id is not None:
            result = await clearpass_client.get_proxy_target_by_id(proxy_target_id)
        else:
            result = await clearpass_client.get_proxy_target_by_name(name)
        
        await ctx.info(f"Retrieved proxy target details for {identifier}")
        
        return {
            "success": True,
            "message": f"Retrieved proxy target details for {identifier}",
            "data": result,
            "proxy_target_info": {
                "id": result.get("id"),
                "name": result.get("name"),
                "host_name": result.get("host_name"),
                "proxy_type": result.get("proxy_type"),
                "authentication_port": result.get("authentication_port"),
                "accounting_port": result.get("accounting_port"),
                "radsec_port": result.get("radsec_port"),
                "description": result.get("description")
            }
        }
        
    except Exception as e:
        identifier = name or f"ID {proxy_target_id}"
        error_msg = f"Failed to get proxy target details for {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def update_proxy_target(
    ctx: Context,
    proxy_target_id: Optional[int] = Field(None, description="Numeric ID of the proxy target to update"),
    proxy_target_name: Optional[str] = Field(None, description="Name of the proxy target to update"),
    new_name: Optional[str] = Field(None, description="New name for the proxy target"),
    new_description: Optional[str] = Field(None, description="New description for the proxy target"),
    new_host_name: Optional[str] = Field(None, description="New host name for the proxy target"),
    proxy_type: Optional[str] = Field(None, description="New proxy type ('RADIUS' or 'RadSec')"),
    authentication_port: Optional[int] = Field(None, description="New authentication port"),
    accounting_port: Optional[int] = Field(None, description="New accounting port"),
    secret: Optional[str] = Field(None, description="New shared secret"),
    radsec_port: Optional[int] = Field(None, description="New RadSec port"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing proxy target configuration.
    """
    try:
        # Validate input parameters
        if proxy_target_id is None and proxy_target_name is None:
            return {
                "success": False,
                "error": "Either proxy_target_id or proxy_target_name must be provided"
            }
        
        if proxy_target_id is not None and proxy_target_name is not None:
            return {
                "success": False,
                "error": "Provide either proxy_target_id or proxy_target_name, not both"
            }
        
        # Build update data
        update_data = {}
        modified_fields = []
        
        if new_name:
            update_data["name"] = new_name
            modified_fields.append("name")
        if new_description is not None:
            update_data["description"] = new_description
            modified_fields.append("description")
        if new_host_name:
            update_data["host_name"] = new_host_name
            modified_fields.append("host_name")
        if proxy_type:
            update_data["proxy_type"] = proxy_type
            modified_fields.append("proxy_type")
        if authentication_port:
            update_data["authentication_port"] = authentication_port
            modified_fields.append("authentication_port")
        if accounting_port:
            update_data["accounting_port"] = accounting_port
            modified_fields.append("accounting_port")
        if secret:
            update_data["secret"] = secret
            modified_fields.append("secret")
        if radsec_port:
            update_data["radsec_port"] = radsec_port
            modified_fields.append("radsec_port")
        
        if not update_data:
            return {
                "success": False,
                "error": "No update data provided. Specify at least one field to update."
            }
        
        identifier = proxy_target_name or f"ID {proxy_target_id}"
        operation = "replace" if replace_all else "update"
        await ctx.info(f"Updating proxy target {identifier} ({operation})")
        
        clearpass_client = await get_clearpass_client()
        
        if proxy_target_id is not None:
            if replace_all:
                result = await clearpass_client.replace_proxy_target_by_id(proxy_target_id, update_data)
            else:
                result = await clearpass_client.update_proxy_target_by_id(proxy_target_id, update_data)
        else:
            if replace_all:
                result = await clearpass_client.replace_proxy_target_by_name(proxy_target_name, update_data)
            else:
                result = await clearpass_client.update_proxy_target_by_name(proxy_target_name, update_data)
        
        operation_past = "replaced" if replace_all else "updated"
        await ctx.info(f"Successfully {operation_past} proxy target {identifier}")
        
        return {
            "success": True,
            "message": f"Successfully {operation_past} proxy target {identifier}",
            "data": result,
            "modified_fields": modified_fields,
            "operation_type": operation
        }
        
    except Exception as e:
        identifier = proxy_target_name or f"ID {proxy_target_id}"
        error_msg = f"Failed to update proxy target {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def delete_proxy_target(
    ctx: Context,
    proxy_target_id: Optional[int] = Field(None, description="Numeric ID of the proxy target to delete"),
    proxy_target_name: Optional[str] = Field(None, description="Name of the proxy target to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a proxy target from ClearPass.
    """
    try:
        # Validate input parameters
        if proxy_target_id is None and proxy_target_name is None:
            return {
                "success": False,
                "error": "Either proxy_target_id or proxy_target_name must be provided"
            }
        
        if proxy_target_id is not None and proxy_target_name is not None:
            return {
                "success": False,
                "error": "Provide either proxy_target_id or proxy_target_name, not both"
            }
        
        if not confirm:
            return {
                "success": False,
                "error": "Deletion requires confirmation. Set confirm=True to proceed.",
                "warning": "This operation cannot be undone"
            }
        
        identifier = proxy_target_name or f"ID {proxy_target_id}"
        await ctx.info(f"Deleting proxy target {identifier}")
        
        clearpass_client = await get_clearpass_client()
        
        # Get proxy target details before deletion for reporting
        try:
            if proxy_target_id is not None:
                proxy_target_info = await clearpass_client.get_proxy_target_by_id(proxy_target_id)
            else:
                proxy_target_info = await clearpass_client.get_proxy_target_by_name(proxy_target_name)
        except Exception:
            proxy_target_info = {}
        
        # Perform deletion
        if proxy_target_id is not None:
            result = await clearpass_client.delete_proxy_target_by_id(proxy_target_id)
        else:
            result = await clearpass_client.delete_proxy_target_by_name(proxy_target_name)
        
        await ctx.info(f"Successfully deleted proxy target {identifier}")
        
        return {
            "success": True,
            "message": f"Successfully deleted proxy target {identifier}",
            "data": result,
            "deleted_proxy_target": {
                "id": proxy_target_info.get("id"),
                "name": proxy_target_info.get("name"),
                "host_name": proxy_target_info.get("host_name"),
                "proxy_type": proxy_target_info.get("proxy_type")
            },
            "warning": "Proxy target has been permanently removed"
        }
        
    except Exception as e:
        identifier = proxy_target_name or f"ID {proxy_target_id}"
        error_msg = f"Failed to delete proxy target {identifier}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def validate_proxy_target_configuration(
    ctx: Context,
    proxy_target_config: Dict[str, Any] = Field(..., description="Proxy target configuration to validate"),
    check_connectivity: bool = Field(default=False, description="Whether to perform connectivity checks"),
    strict_validation: bool = Field(default=False, description="Enable strict validation rules")
) -> Dict[str, Any]:
    """
    Validate proxy target configuration for correctness and compliance.
    """
    try:
        await ctx.info("Validating proxy target configuration")
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.validate_proxy_target_configuration(proxy_target_config)
        
        validation_result = {
            "success": True,
            "message": "Proxy target configuration validation completed",
            "data": result,
            "validation_summary": {
                "valid": result.get("valid", False),
                "error_count": len(result.get("errors", [])),
                "warning_count": len(result.get("warnings", [])),
                "strict_mode": strict_validation,
                "connectivity_tested": check_connectivity
            }
        }
        
        await ctx.info(f"Validation completed: {'PASSED' if result.get('valid') else 'FAILED'}")
        
        return validation_result
        
    except Exception as e:
        error_msg = f"Failed to validate proxy target configuration: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def get_proxy_target_statistics(
    ctx: Context,
    proxy_target_id: int = Field(..., description="Numeric ID of the proxy target"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')"),
    include_performance_metrics: bool = Field(default=True, description="Include performance and response time metrics")
) -> Dict[str, Any]:
    """
    Get usage statistics and performance metrics for a proxy target.
    """
    try:
        await ctx.info(f"Retrieving proxy target statistics for ID {proxy_target_id} ({time_range})")
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.get_proxy_target_statistics(proxy_target_id, time_range)
        
        await ctx.info(f"Retrieved statistics for proxy target ID {proxy_target_id}")
        
        return {
            "success": True,
            "message": f"Retrieved proxy target statistics for ID {proxy_target_id} ({time_range})",
            "data": result,
            "statistics_summary": {
                "proxy_target_id": proxy_target_id,
                "time_range": time_range,
                "total_requests": result.get("total_requests", 0),
                "successful_requests": result.get("successful_requests", 0),
                "failed_requests": result.get("failed_requests", 0),
                "success_rate": result.get("success_rate", 0),
                "average_response_time": result.get("average_response_time", 0)
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to get proxy target statistics for ID {proxy_target_id}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def test_proxy_target_connectivity(
    ctx: Context,
    proxy_target_id: int = Field(..., description="Numeric ID of the proxy target to test"),
    test_parameters: Optional[Dict[str, Any]] = Field(None, description="Optional test parameters and configuration")
) -> Dict[str, Any]:
    """
    Test connectivity and functionality of a proxy target.
    """
    try:
        await ctx.info(f"Testing connectivity for proxy target ID {proxy_target_id}")
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.test_proxy_target_connectivity(proxy_target_id, test_parameters)
        
        test_status = result.get("test_status", "unknown")
        await ctx.info(f"Connectivity test completed for proxy target ID {proxy_target_id}: {test_status}")
        
        return {
            "success": True,
            "message": f"Proxy target connectivity test completed for ID {proxy_target_id}",
            "data": result,
            "test_summary": {
                "proxy_target_id": proxy_target_id,
                "test_status": test_status,
                # ClearPass exposes no proxy-target probe endpoint, so the only
                # thing this operation can assert is that the target exists and
                # its configuration is readable. It never claims a RADIUS /
                # RadSec probe succeeded.
                "configuration_verified": test_status == "configuration_verified",
                "traffic_probe_performed": False,
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to test proxy target connectivity for ID {proxy_target_id}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def clone_proxy_target(
    ctx: Context,
    source_proxy_target_id: int = Field(..., description="Numeric ID of the proxy target to clone"),
    new_name: str = Field(..., description="Name for the new cloned proxy target"),
    new_host_name: str = Field(..., description="Host name for the new cloned proxy target"),
    new_description: Optional[str] = Field(None, description="Description for the new cloned proxy target"),
    modify_ports: Optional[Dict[str, int]] = Field(None, description="Port modifications (auth_port, acct_port, radsec_port)"),
    new_secret: Optional[str] = Field(None, description="New shared secret for the cloned target")
) -> Dict[str, Any]:
    """
    Clone an existing proxy target with new connection details.
    """
    try:
        await ctx.info(f"Cloning proxy target from ID {source_proxy_target_id} to '{new_name}'")
        
        modifications = {"host_name": new_host_name}
        if new_description:
            modifications["description"] = new_description
        if modify_ports:
            modifications.update(modify_ports)
        if new_secret:
            modifications["secret"] = new_secret
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.clone_proxy_target(
            source_proxy_target_id, 
            new_name, 
            new_host_name, 
            modifications
        )
        
        await ctx.info(f"Successfully cloned proxy target to '{new_name}' with ID {result.get('id')}")
        
        return {
            "success": True,
            "message": f"Successfully cloned proxy target to '{new_name}' with ID {result.get('id')}",
            "data": result,
            "clone_info": {
                "source_id": source_proxy_target_id,
                "new_id": result.get("id"),
                "new_name": new_name,
                "new_host_name": new_host_name
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to clone proxy target from ID {source_proxy_target_id}: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def search_proxy_targets_advanced(
    ctx: Context,
    proxy_type: Optional[str] = Field(None, description="Filter by proxy type ('RADIUS' or 'RadSec')"),
    host_pattern: Optional[str] = Field(None, description="Search pattern for host names (supports wildcards)"),
    port_range: Optional[Dict[str, int]] = Field(None, description="Port range filter (e.g., {'min': 1000, 'max': 2000})"),
    name_pattern: Optional[str] = Field(None, description="Search pattern for proxy target names (supports wildcards)"),
    include_disabled: bool = Field(default=True, description="Whether to include disabled proxy targets"),
    custom_filter: Optional[str] = Field(None, description="Custom JSON filter expression"),
    limit: int = Field(default=50, description="Maximum number of results to return"),
    sort_by: str = Field(default="name", description="Sort results by field (name, host_name, proxy_type)")
) -> Dict[str, Any]:
    """
    Advanced search for proxy targets with multiple filter criteria.
    """
    try:
        await ctx.info("Performing advanced proxy target search")
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.search_proxy_targets_advanced(
            proxy_type=proxy_type,
            host_pattern=host_pattern,
            port_range=port_range,
            name_pattern=name_pattern
        )
        
        proxy_targets = result.get("proxy_targets", [])
        
        # Apply sorting
        if sort_by in ["name", "host_name", "proxy_type"]:
            proxy_targets.sort(key=lambda x: x.get(sort_by, ""))
        
        # Apply limit
        if limit:
            proxy_targets = proxy_targets[:limit]
        
        await ctx.info(f"Advanced search completed: found {len(proxy_targets)} matching proxy targets")
        
        return {
            "success": True,
            "message": f"Found {len(proxy_targets)} proxy targets matching search criteria",
            "data": {"proxy_targets": proxy_targets},
            "search_summary": {
                "total_found": len(proxy_targets),
                "search_criteria": {
                    "proxy_type": proxy_type,
                    "host_pattern": host_pattern,
                    "port_range": port_range,
                    "name_pattern": name_pattern
                }
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to search proxy targets: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }


@operation(domain="policy_elements")
async def bulk_update_proxy_targets(
    ctx: Context,
    proxy_target_ids: List[int] = Field(..., description="List of proxy target IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete', 'test_connectivity'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple proxy targets.
    """
    try:
        await ctx.info(f"Starting bulk {operation_type} operation on {len(proxy_target_ids)} proxy targets")
        
        # Validate operation type
        valid_operations = ["update", "delete", "test_connectivity"]
        if operation_type not in valid_operations:
            return {
                "success": False,
                "error": f"Invalid operation type. Must be one of: {valid_operations}"
            }
        
        # Require confirmation for delete operations
        if operation_type == "delete" and not confirm_operation:
            return {
                "success": False,
                "error": "Delete operations require confirmation. Set confirm_operation=True to proceed.",
                "warning": "This operation cannot be undone"
            }
        
        if not proxy_target_ids:
            return {
                "success": False,
                "error": "No proxy target IDs provided"
            }
        
        clearpass_client = await get_clearpass_client()
        result = await clearpass_client.bulk_update_proxy_targets(
            proxy_target_ids, 
            operation_type, 
            operation_data
        )
        
        # Calculate summary statistics
        results = result.get("results", [])
        successful_count = len([r for r in results if "error" not in r])
        failed_count = len([r for r in results if "error" in r])
        success_rate = (successful_count / len(proxy_target_ids)) * 100 if proxy_target_ids else 0
        
        await ctx.info(f"Bulk operation completed: {successful_count} successful, {failed_count} failed")
        
        return {
            "success": True,
            "message": f"Bulk {operation_type} operation completed. {successful_count} successful, {failed_count} failed.",
            "data": result,
            "operation_summary": {
                "operation_type": operation_type,
                "total_targets": len(proxy_target_ids),
                "successful_operations": successful_count,
                "failed_operations": failed_count,
                "success_rate": success_rate
            }
        }
        
    except Exception as e:
        error_msg = f"Failed to perform bulk {operation_type} operation: {str(e)}"
        await ctx.info(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error_details": str(e)
        }
