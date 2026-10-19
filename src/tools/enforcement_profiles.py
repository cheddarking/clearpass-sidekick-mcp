"""
MCP tools for ClearPass Enforcement Profile operations.

This module provides focused MCP tools for the most common enforcement profile
use cases with a template-driven approach for practical networking scenarios.
"""

import json
from typing import Any, Dict, List, Optional, Union
from pydantic import Field
from fastmcp import Context

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error
from ..models.enforcement_profiles import (
    EnforcementProfile,
    CreateEnforcementProfileRequest,
    UpdateEnforcementProfileRequest,
    ProfileAttribute,
    TacacsServiceParam,
    DURConfig,
    PREDEFINED_TEMPLATES
)

import logging
logger = logging.getLogger(__name__)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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


# ============================================================================
# Phase 1.1: Basic Profile Management (5 tools)
# ============================================================================

@operation(domain="enforcement_profiles")
async def list_enforcement_profiles(
    ctx: Context,
    filter_type: Optional[str] = Field(None, description="Filter by profile type"),
    filter_action: Optional[str] = Field(None, description="Filter by profile action"),
    name_contains: Optional[str] = Field(None, description="Filter by profile name substring"),
    limit: Optional[int] = Field(100, description="Maximum number of profiles to return (1-1000)"),
    offset: Optional[int] = Field(0, description="Starting offset for pagination"),
    calculate_count: bool = Field(False, description="Whether to calculate total count")
) -> Dict[str, Any]:
    """
    List enforcement profiles with optional filtering.
    
    This tool retrieves enforcement profiles with support for filtering by type, action,
    and name patterns. Use this to browse existing profiles and understand current
    configuration before creating new profiles.
    
    Args:
        filter_type: Filter by specific profile type (e.g., "[Policy Manager Admin]")
        filter_action: Filter by specific profile action
        name_contains: Filter profiles containing this text in their name
        limit: Maximum number of profiles to return (default: 100, max: 1000)
        offset: Starting offset for pagination (default: 0)
        calculate_count: Whether to calculate and return total count
        
    Returns:
        Dictionary containing list of enforcement profiles with metadata
        
    Example:
        To list all enforcement profiles:
        list_enforcement_profiles()
        
        To find guest-related profiles:
        list_enforcement_profiles(name_contains="guest")
        
        To list specific profile type:
        list_enforcement_profiles(filter_type="[Policy Manager Admin]")
    """
    await ctx.info(f"Retrieving enforcement profiles (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        
        # Get all profiles from the API without filtering
        # We'll handle filtering in memory after retrieving the results
        # This avoids issues with the ClearPass API's filter parameter validation
        result = await client.list_enforcement_profiles(
            # Don't pass any filter parameters to the API
            limit=limit,
            offset=offset,
            calculate_count=calculate_count
        )
        
        profiles = result.get("_embedded", {}).get("items", [])
        total_count = result.get("count", len(profiles))
        
        # Apply filtering in memory if any filter parameters were specified
        if filter_type or filter_action or name_contains:
            filtered_profiles = []
            
            for profile in profiles:
                matches = True
                
                if filter_type and profile.get("type") != filter_type:
                    matches = False
                if filter_action and profile.get("action") != filter_action:
                    matches = False
                if name_contains and name_contains not in profile.get("name", ""):
                    matches = False
                    
                if matches:
                    filtered_profiles.append(profile)
            
            profiles = filtered_profiles
            filtered_count = len(profiles)
            
            # Update total count if we're calculating it
            if calculate_count:
                # This is an estimate since we're filtering after the API call
                total_count = filtered_count
        
        # Create summary for better readability
        summary = {
            "profiles": profiles,
            "count": len(profiles),
            "total_count": total_count,
            "has_more": len(profiles) == limit and total_count > (offset + limit),
            "pagination": {
                "offset": offset,
                "limit": limit,
                "next_offset": offset + limit if len(profiles) == limit else None
            }
        }
        
        return {
            "success": True,
            "message": f"Retrieved {len(profiles)} enforcement profiles",
            "total_count": total_count,
            "profiles": profiles,
            "pagination": summary["pagination"]
        }
            
    except ClearPassAPIError as e:
        logger.error(f"Failed to list enforcement profiles: {e}")
        return await format_api_error(e, "list enforcement profiles")
    except Exception as e:
        logger.error(f"Unexpected error listing enforcement profiles: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing enforcement profiles"
        }


@operation(domain="enforcement_profiles")
async def create_enforcement_profile(
    ctx: Context,
    name: str = Field(..., description="Profile name"),
    profile_type: str = Field(..., description="Profile type (use 'RADIUS' for RADIUS enforcement profiles)"),
    description: Optional[str] = Field(None, description="Profile description"),
    action: str = Field("Accept", description="Profile action (Accept, Reject, etc.) - Required for enforcement profiles"),
    agent_template: Optional[str] = Field(None, description="Agent template"),
    post_auth_template: Optional[str] = Field(None, description="Post authentication template"),
    radius_dyn_authz_template: Optional[str] = Field(None, description="RADIUS dynamic authorization template"),
    device_group_list: Optional[List[str]] = Field(None, description="List of device groups"),
    attributes: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="Profile attributes - array format: [{\"type\": \"Radius:IETF\", \"name\": \"Session-Timeout\", \"value\": \"3600\"}] or JSON string"),
    tacacs_service_params: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="TACACS+ service parameters - array format: [{\"service\": \"shell\", \"protocol\": \"ip\"}] or JSON string"),
    dur_config: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="Downloadable User Role configuration - array format: [{\"name\": \"ACL-Name\", \"value\": \"permit ip any any\"}] or JSON string")
) -> Dict[str, Any]:
    """
    Create a new enforcement profile with specified configuration.
    
    This tool creates a new enforcement profile with custom configuration. For common
    scenarios, consider using create_profile_from_template instead.
    
    Args:
        name: Unique name for the enforcement profile
        profile_type: Profile type (use "RADIUS" for RADIUS enforcement profiles)
        description: Optional description explaining the profile's purpose
        action: Profile action (Accept, Reject, etc.) - Required for enforcement profiles
        agent_template: Agent enforcement profile template
        post_auth_template: Post authentication enforcement profile template
        radius_dyn_authz_template: RADIUS dynamic authorization template
        device_group_list: List of device groups this profile applies to
        attributes: List of profile attributes (each with type, name, value)
        tacacs_service_params: TACACS+ service parameters
        dur_config: Downloadable User Role configuration
        
    Returns:
        Dictionary containing created profile details
        
    Example:
        To create a basic profile:
        create_enforcement_profile(
            name="Custom-Employee-Profile",
            profile_type="RADIUS",
            action="Accept",
            description="Custom employee access profile",
            attributes=[
                {"type": "Radius:IETF", "name": "Session-Timeout", "value": "28800"},
                {"type": "Radius:IETF", "name": "Acct-Interim-Interval", "value": "300"}
            ]
        )
    """
    await ctx.info(f"Creating enforcement profile: {name}")
    
    try:
        # Parse list parameters that may be JSON strings
        parsed_attributes = None
        parsed_tacacs_params = None
        parsed_dur_config = None
        
        try:
            parsed_attributes = _parse_list_dict_parameter(attributes, "attributes")
            parsed_tacacs_params = _parse_list_dict_parameter(tacacs_service_params, "tacacs_service_params")
            parsed_dur_config = _parse_list_dict_parameter(dur_config, "dur_config")
        except ValueError as e:
            logger.error(f"Failed to parse list parameter: {e}")
            return {
                "success": False,
                "message": f"Invalid parameter format: {str(e)}",
                "error": str(e)
            }
        
        # Local pre-check: ClearPass rejects a profile that carries no
        # enforcement parameters at all, but reports it as
        # "Invalid value specified for attribute -> type", which points at the
        # wrong field. Answer locally with something actionable instead.
        if not any([parsed_attributes, agent_template, post_auth_template,
                    radius_dyn_authz_template, device_group_list,
                    parsed_tacacs_params, parsed_dur_config]):
            msg = (
                "An enforcement profile must carry at least one enforcement "
                "parameter. Supply 'attributes' — e.g. attributes=[{\"type\": "
                "\"Radius:IETF\", \"name\": \"Session-Timeout\", \"value\": "
                "\"28800\"}] — or one of agent_template, post_auth_template, "
                "radius_dyn_authz_template, device_group_list, "
                "tacacs_service_params, dur_config. Attribute types must be "
                "namespaced (Radius:IETF for standard RADIUS attributes, "
                "Radius:Aruba for Aruba VSAs, cpass:HTTP for HTTP "
                "enforcement); a bare \"RADIUS\" is rejected by ClearPass."
            )
            logger.error(f"Refusing to create profile '{name}' with no enforcement parameters")
            return {
                "success": False,
                "error": "No enforcement parameters specified",
                "error_type": "validation_error",
                "message": msg
            }

        client = await get_clearpass_client()
        result = await client.create_enforcement_profile(
            name=name,
            profile_type=profile_type,
            description=description,
            agent_template=agent_template,
            post_auth_template=post_auth_template,
            radius_dyn_authz_template=radius_dyn_authz_template,
            action=action,
            device_group_list=device_group_list,
            attributes=parsed_attributes,
            tacacs_service_params=parsed_tacacs_params,
            dur_config=parsed_dur_config
        )
        
        profile_id = result.get("id")
        profile_name = result.get("name")
        attribute_count = len(result.get("attributes", []))
        
        await ctx.info(f"Successfully created enforcement profile: {profile_name}")
        
        return {
            "success": True,
            "message": f"Enforcement profile '{profile_name}' created successfully",
            "profile": result,
            "summary": {
                "id": profile_id,
                "name": profile_name,
                "type": profile_type,
                "description": description or "Not specified",
                "attribute_count": attribute_count,
                "device_groups": len(device_group_list or [])
            },
            "next_steps": "The profile is now available for use in policy configurations"
        }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to create enforcement profile: {e}")
        return await format_api_error(e, "create enforcement profile")
    except Exception as e:
        logger.error(f"Unexpected error creating enforcement profile: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the enforcement profile"
        }


@operation(domain="enforcement_profiles")
async def get_enforcement_profile_details(
    ctx: Context,
    profile_id: Optional[int] = Field(None, description="Profile ID"),
    profile_name: Optional[str] = Field(None, description="Profile name")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific enforcement profile.
    
    This tool retrieves comprehensive details about an enforcement profile including
    all attributes, configurations, and settings. Specify either profile_id or
    profile_name to identify the profile.
    
    Args:
        profile_id: Numeric ID of the enforcement profile (takes precedence)
        profile_name: Name of the enforcement profile
        
    Returns:
        Dictionary containing complete profile details
        
    Example:
        To get details by ID:
        get_enforcement_profile_details(profile_id=123)
        
        To get details by name:
        get_enforcement_profile_details(profile_name="Guest-Internet-Access")
    """
    if not profile_id and not profile_name:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either profile_id or profile_name to identify the profile"
        }
    
    identifier = f"ID {profile_id}" if profile_id else f"name '{profile_name}'"
    await ctx.info(f"Retrieving enforcement profile details for: {identifier}")
        
    try:
        client = await get_clearpass_client()
        result = await client.get_enforcement_profile_details(
            profile_id=profile_id,
            profile_name=profile_name
        )
        
        # Extract key information for summary
        profile_name_result = result.get("name")
        profile_id_result = result.get("id")
        profile_type = result.get("type")
        description = result.get("description")
        action = result.get("action")
        attributes = result.get("attributes", [])
        device_groups = result.get("device_group_list", [])
        tacacs_params = result.get("tacacs_service_params", [])
        dur_config = result.get("dur_config", [])
        
        return {
            "success": True,
            "profile": result,
            "summary": {
                "id": profile_id_result,
                "name": profile_name_result,
                "type": profile_type,
                "description": description or "Not specified",
                "action": action or "Not specified",
                "attribute_count": len(attributes),
                "device_group_count": len(device_groups),
                "tacacs_param_count": len(tacacs_params),
                "dur_config_count": len(dur_config)
            },
            "message": f"Retrieved enforcement profile details for: {identifier}"
        }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to get enforcement profile details: {e}")
        return await format_api_error(e, "get enforcement profile details")
    except Exception as e:
        logger.error(f"Unexpected error getting enforcement profile details: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving enforcement profile details"
        }


@operation(domain="enforcement_profiles")
async def update_enforcement_profile(
    ctx: Context,
    profile_id: Optional[int] = Field(None, description="Profile ID"),
    profile_name: Optional[str] = Field(None, description="Profile name"),
    name: Optional[str] = Field(None, description="New profile name"),
    description: Optional[str] = Field(None, description="New profile description"),
    profile_type: Optional[str] = Field(None, description="New profile type"),
    agent_template: Optional[str] = Field(None, description="Agent template"),
    post_auth_template: Optional[str] = Field(None, description="Post authentication template"),
    radius_dyn_authz_template: Optional[str] = Field(None, description="RADIUS template"),
    action: Optional[str] = Field(None, description="Profile action"),
    device_group_list: Optional[List[str]] = Field(None, description="Device groups"),
    attributes: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="Profile attributes - array format: [{\"type\": \"Radius:IETF\", \"name\": \"Session-Timeout\", \"value\": \"3600\"}] or JSON string"),
    tacacs_service_params: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="TACACS+ parameters - array format: [{\"service\": \"shell\", \"protocol\": \"ip\"}] or JSON string"),
    dur_config: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="DUR configuration - array format: [{\"name\": \"ACL-Name\", \"value\": \"permit ip any any\"}] or JSON string")
) -> Dict[str, Any]:
    """
    Update an existing enforcement profile.
    
    This tool updates specific fields of an enforcement profile. Only the fields
    you specify will be modified; other fields remain unchanged. Specify either
    profile_id or profile_name to identify the profile to update.
    
    Args:
        profile_id: ID of the profile to update (takes precedence)
        profile_name: Name of the profile to update
        name: New name for the profile
        description: New description for the profile
        profile_type: New profile type
        agent_template: Agent template
        post_auth_template: Post authentication template
        radius_dyn_authz_template: RADIUS template
        action: Profile action
        device_group_list: List of device groups
        attributes: Profile attributes (replaces existing)
        tacacs_service_params: TACACS+ service parameters
        dur_config: DUR configuration
        
    Returns:
        Dictionary containing update results
        
    Example:
        To update description and add attributes:
        update_enforcement_profile(
            profile_name="Guest-Access",
            description="Updated guest access with new time limits",
            attributes=[
                {"type": "Radius:IETF", "name": "Session-Timeout", "value": "7200"},
                {"type": "Radius:IETF", "name": "Idle-Timeout", "value": "1800"}
            ]
        )
    """
    if not profile_id and not profile_name:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either profile_id or profile_name to identify the profile"
        }
        
    # Check if at least one update field is provided
    update_fields = [name, description, profile_type, agent_template, post_auth_template,
                    radius_dyn_authz_template, action, device_group_list, attributes,
                    tacacs_service_params, dur_config]
    if not any(field is not None for field in update_fields):
        return {
            "success": False,
            "error": "No update parameters provided",
            "message": "At least one field to update must be provided"
        }

    identifier = f"ID {profile_id}" if profile_id else f"name '{profile_name}'"
    await ctx.info(f"Updating enforcement profile: {identifier}")
        
    try:
        # Parse list parameters that may be JSON strings
        parsed_attributes = None
        parsed_tacacs_params = None
        parsed_dur_config = None
        
        try:
            parsed_attributes = _parse_list_dict_parameter(attributes, "attributes")
            parsed_tacacs_params = _parse_list_dict_parameter(tacacs_service_params, "tacacs_service_params")
            parsed_dur_config = _parse_list_dict_parameter(dur_config, "dur_config")
        except ValueError as e:
            logger.error(f"Failed to parse list parameter: {e}")
            return {
                "success": False,
                "message": f"Invalid parameter format: {str(e)}",
                "error": str(e)
            }
        
        client = await get_clearpass_client()
        result = await client.update_enforcement_profile(
            profile_id=profile_id,
            profile_name=profile_name,
            name=name,
            description=description,
            profile_type=profile_type,
            agent_template=agent_template,
            post_auth_template=post_auth_template,
            radius_dyn_authz_template=radius_dyn_authz_template,
            action=action,
            device_group_list=device_group_list,
            attributes=parsed_attributes,
            tacacs_service_params=parsed_tacacs_params,
            dur_config=parsed_dur_config
        )
        
        updated_name = result.get("name")
        updated_id = result.get("id")
        
        # Summarize what was updated
        changes = []
        if name: changes.append(f"Name: {name}")
        if description: changes.append(f"Description: {description}")
        if profile_type: changes.append(f"Type: {profile_type}")
        if action: changes.append(f"Action: {action}")
        if attributes: changes.append(f"Attributes: {len(attributes)} configured")
        if device_group_list: changes.append(f"Device Groups: {len(device_group_list)}")

        await ctx.info(f"Successfully updated enforcement profile: {updated_name}")
        
        return {
            "success": True,
            "message": f"Enforcement profile '{updated_name}' updated successfully",
            "profile": result,
            "summary": {
                "id": updated_id,
                "name": updated_name,
                "changes_applied": changes
            },
            "next_steps": "The profile configuration has been updated and is ready for use"
        }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to update enforcement profile: {e}")
        return await format_api_error(e, "update enforcement profile")
    except Exception as e:
        logger.error(f"Unexpected error updating enforcement profile: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the enforcement profile"
        }


@operation(domain="enforcement_profiles")
async def delete_enforcement_profile(
    ctx: Context,
    profile_id: Optional[int] = Field(None, description="Profile ID"),
    profile_name: Optional[str] = Field(None, description="Profile name"),
    confirm_deletion: bool = Field(False, description="Confirmation flag to prevent accidental deletion")
) -> Dict[str, Any]:
    """
    Delete an enforcement profile.
    
    ⚠️ WARNING: This permanently deletes the enforcement profile and cannot be undone.
    Make sure the profile is not referenced by any active policies before deletion.
    
    Args:
        profile_id: ID of the profile to delete (takes precedence)
        profile_name: Name of the profile to delete
        confirm_deletion: Must be True to confirm the deletion
        
    Returns:
        Dictionary containing deletion results
        
    Example:
        To delete a profile:
        delete_enforcement_profile(
            profile_name="Old-Guest-Profile",
            confirm_deletion=True
        )
    """
    if not profile_id and not profile_name:
        return {
            "success": False,
            "error": "Missing required parameter",
            "message": "Please provide either profile_id or profile_name to identify the profile"
        }
        
    if not confirm_deletion:
        return {
            "success": False,
            "error": "Deletion not confirmed",
            "message": "Set confirm_deletion=True to proceed. WARNING: This will permanently delete the enforcement profile and cannot be undone. Please ensure the profile is not referenced by any active policies."
        }

    identifier = f"ID {profile_id}" if profile_id else f"name '{profile_name}'"
    await ctx.info(f"Deleting enforcement profile: {identifier}")
    
    try:
        client = await get_clearpass_client()
        
        # Get profile details first for confirmation
        profile_details = await client.get_enforcement_profile_details(
            profile_id=profile_id,
            profile_name=profile_name
        )
        
        profile_name_actual = profile_details.get("name")
        profile_id_actual = profile_details.get("id")
        
        # Perform deletion
        await client.delete_enforcement_profile(
            profile_id=profile_id,
            profile_name=profile_name
        )

        await ctx.info(f"Successfully deleted enforcement profile: {profile_name_actual}")
        
        return {
            "success": True,
            "message": f"Enforcement profile '{profile_name_actual}' deleted successfully",
            "deleted_profile": {
                "id": profile_id_actual,
                "name": profile_name_actual
            },
            "warning": "The profile has been permanently removed from the system. Please update any policies that may have referenced this profile."
        }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete enforcement profile: {e}")
        return await format_api_error(e, "delete enforcement profile")
    except Exception as e:
        logger.error(f"Unexpected error deleting enforcement profile: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the enforcement profile"
        }


# ============================================================================
# Phase 1.2: Template-Based Creation (3 tools)
# ============================================================================

@operation(domain="enforcement_profiles")
async def create_profile_from_template(
    ctx: Context,
    template_name: str = Field(..., description="Template name (corporate_employee, guest_internet, contractor_limited, iot_device, executive_access)"),
    profile_name: str = Field(..., description="Name for the new profile"),
    profile_description: Optional[str] = Field(None, description="Custom description for the profile"),
    custom_session_timeout: Optional[int] = Field(None, description="Custom session timeout in seconds"),
    custom_idle_timeout: Optional[int] = Field(None, description="Custom idle timeout in seconds"),
    additional_attributes: Optional[Union[List[Dict[str, str]], str]] = Field(None, description="Additional custom attributes - array format: [{\"type\": \"Radius:IETF\", \"name\": \"Idle-Timeout\", \"value\": \"1800\"}] or JSON string"),
    device_groups: Optional[List[str]] = Field(None, description="Device groups to apply this profile to")
) -> Dict[str, Any]:
    """
    Create an enforcement profile from a predefined template.
    
    This tool creates profiles using proven templates for common networking scenarios.
    Templates include optimized settings for typical use cases and can be customized
    with additional attributes or modified timeouts.
    
    Available Templates:
    • corporate_employee: Standard employee access (8-hour timeout, business traffic)
    • guest_internet: Guest access (4-hour timeout, internet only)
    • contractor_limited: Contractor access (VLAN assignment, restricted resources)
    • iot_device: IoT device access (24-hour timeout, device restrictions)
    • executive_access: Executive access (12-hour timeout, enhanced privileges)
    
    Args:
        template_name: Name of the predefined template to use
        profile_name: Unique name for the new profile
        profile_description: Custom description (defaults to template description)
        custom_session_timeout: Override template session timeout (seconds)
        custom_idle_timeout: Override template idle timeout (seconds)
        additional_attributes: Additional custom attributes to include
        device_groups: Device groups this profile should apply to
        
    Returns:
        Dictionary containing created profile details
        
    Example:
        To create a guest profile with custom timeout:
        create_profile_from_template(
            template_name="guest_internet",
            profile_name="Conference-Guest-Access",
            profile_description="Guest access for conference attendees",
            custom_session_timeout=7200,  # 2 hours
            device_groups=["Guest-APs"]
        )
    """
    if template_name not in PREDEFINED_TEMPLATES:
        available = ", ".join(PREDEFINED_TEMPLATES.keys())
        return {
            "success": False,
            "error": f"Unknown template '{template_name}'",
            "message": f"Available templates: {available}"
        }

    await ctx.info(f"Creating enforcement profile '{profile_name}' from template '{template_name}'")
    
    try:
        # Parse additional_attributes parameter that may be a JSON string
        parsed_additional_attributes = None
        parsed_device_groups = None
        
        try:
            parsed_additional_attributes = _parse_list_dict_parameter(additional_attributes, "additional_attributes")
            
            # device_groups is now a direct list parameter, no JSON parsing needed
            parsed_device_groups = device_groups
                    
        except ValueError as e:
            logger.error(f"Failed to parse parameter: {e}")
            return {
                "success": False,
                "message": f"Invalid parameter format: {str(e)}",
                "error": str(e)
            }
        
        client = await get_clearpass_client()
        
        # Build customizations
        customizations = {}
        
        # Handle timeout customizations
        if custom_session_timeout or custom_idle_timeout:
            custom_attrs = []
            # Session-Timeout / Idle-Timeout are standard RFC 2865 attributes,
            # so they live in the IETF dictionary. ClearPass rejects a bare
            # "RADIUS" type with 422 "Invalid value specified for attribute ->
            # type".
            if custom_session_timeout:
                custom_attrs.append({
                    "type": "Radius:IETF",
                    "name": "Session-Timeout",
                    "value": str(custom_session_timeout)
                })
            if custom_idle_timeout:
                custom_attrs.append({
                    "type": "Radius:IETF",
                    "name": "Idle-Timeout",
                    "value": str(custom_idle_timeout)
                })
            customizations["attributes"] = custom_attrs
        
        # Add additional attributes if provided
        if parsed_additional_attributes:
            if "attributes" in customizations:
                customizations["attributes"].extend(parsed_additional_attributes)
            else:
                customizations["attributes"] = parsed_additional_attributes
                
        # Add device groups if provided
        if parsed_device_groups:
            customizations["device_group_list"] = parsed_device_groups
        
        # Set custom description if provided
        if profile_description:
            customizations["description"] = profile_description
        
        result = await client.create_profile_from_template(
            template_name=template_name,
            profile_name=profile_name,
            customizations=customizations
        )
        
        template_info = PREDEFINED_TEMPLATES[template_name]
        profile_id = result.get("id")
        
        await ctx.info(f"Successfully created enforcement profile '{profile_name}' from template '{template_name}'")
        
        return {
            "success": True,
            "message": f"Enforcement profile '{profile_name}' created from template '{template_name}'",
            "profile": result,
            "template_used": {
                "name": template_name,
                "description": template_info.description,
                "category": template_info.category
            },
            "customizations_applied": len(customizations),
            "next_steps": "The profile is ready for use in policy configurations"
        }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to create profile from template: {e}")
        return await format_api_error(e, "create profile from template")
    except Exception as e:
        logger.error(f"Unexpected error creating profile from template: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the profile from template"
        }


@operation(domain="enforcement_profiles")
async def list_profile_templates(ctx: Context) -> Dict[str, Any]:
    """
    List all available predefined profile templates.
    
    This tool shows all available templates that can be used with the
    create_profile_from_template function. Each template is optimized for
    specific networking scenarios and use cases.
    
    Returns:
        Dictionary containing available templates with descriptions
        
    Example:
        To see all available templates:
        list_profile_templates()
    """
    await ctx.info("Retrieving available profile templates...")
    
    try:
        # Use try-catch to isolate where the error occurs  
        try:
            client = await get_clearpass_client()
        except Exception as get_client_error:
            import traceback
            get_client_error_details = traceback.format_exc()
            logger.error(f"Error getting client: {get_client_error}\n{get_client_error_details}")
            return {
                "success": False,
                "error": str(get_client_error),
                "error_details": get_client_error_details,
                "message": f"Error getting ClearPass client: {str(get_client_error)}"
            }
            
        try:
            # Isolate each step to find the exact error location
            try:
                from ..models.enforcement_profiles import PREDEFINED_TEMPLATES
                logger.info(f"Successfully imported PREDEFINED_TEMPLATES: {type(PREDEFINED_TEMPLATES)}")
            except Exception as import_error:
                import traceback
                import_error_details = traceback.format_exc()
                logger.error(f"Import error: {import_error}\n{import_error_details}")
                return {
                    "success": False,
                    "error": str(import_error),
                    "error_details": import_error_details,
                    "message": f"Failed to import PREDEFINED_TEMPLATES: {str(import_error)}"
                }
            
            try:
                templates = []
                template_count = 0
                for template_name, template_obj in PREDEFINED_TEMPLATES.items():
                    template_count += 1
                    logger.info(f"Processing template {template_count}: {template_name} - type: {type(template_obj)}")
                    
                    # Convert ProfileTemplate object to dict for JSON serialization
                    if hasattr(template_obj, 'display_name'):
                        # It's a ProfileTemplate object
                        template_dict = {
                            "name": template_name,
                            "display_name": template_obj.display_name,
                            "description": template_obj.description,
                            "category": template_obj.category,
                        }
                    else:
                        # It's already a dict (fallback)
                        template_dict = {
                            "name": template_name,
                            "display_name": template_obj.get("display_name", template_name),
                            "description": template_obj.get("description", ""),
                            "category": template_obj.get("category", "unknown"),
                        }
                    templates.append(template_dict)
                    
                logger.info(f"Successfully processed {template_count} templates")
            except Exception as processing_error:
                import traceback
                processing_error_details = traceback.format_exc()
                logger.error(f"Processing error: {processing_error}\n{processing_error_details}")
                return {
                    "success": False,
                    "error": str(processing_error),
                    "error_details": processing_error_details,
                    "message": f"Failed to process templates: {str(processing_error)}"
                }
            
            return {
                "success": True,
                "message": f"Retrieved {len(templates)} available profile templates",
                "templates": templates,
                "template_count": len(templates),
                "categories": ["user_access", "device_access", "guest_access"],
                "usage_tip": "Use create_profile_from_template() with any template name to create a profile"
            }
        except Exception as client_error:
            import traceback
            client_error_details = traceback.format_exc()
            logger.error(f"Error in client.list_profile_templates(): {client_error}\n{client_error_details}")
            
            # Return error details for debugging
            return {
                "success": False,
                "error": str(client_error),
                "error_details": client_error_details,
                "message": f"Error in client method: {str(client_error)}"
            }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to list profile templates: {e}")
        return await format_api_error(e, "list profile templates")
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        logger.error(f"Unexpected error listing profile templates: {e}\n{error_details}")
        return {
            "success": False,
            "error": str(e),
            "error_details": error_details,
            "message": "An unexpected error occurred while listing profile templates"
        }


@operation(domain="enforcement_profiles")
async def validate_profile_configuration(
    ctx: Context,
    profile_data: Dict[str, Any] = Field(..., description="Profile configuration to validate"),
    check_dependencies: bool = Field(True, description="Whether to check for missing dependencies")
) -> Dict[str, Any]:
    """
    Validate an enforcement profile configuration before deployment.
    
    This tool performs comprehensive validation of profile configuration
    including attribute format, dependency checks, and best practice
    recommendations.
    
    Args:
        profile_data: Profile configuration to validate
        check_dependencies: Whether to perform dependency validation
        
    Returns:
        Dictionary containing validation results and recommendations
        
    Example:
        To validate a profile configuration:
        validate_profile_configuration(
            profile_data={
                "name": "Test-Profile",
                "type": "[Policy Manager Admin]",
                "attributes": [
                    {"type": "Radius:IETF", "name": "Session-Timeout", "value": "3600"}
                ]
            },
            check_dependencies=True
        )
    """
    await ctx.info(f"Validating profile configuration for: {profile_data.get('name', 'unnamed profile')}")
    
    try:
        client = await get_clearpass_client()
        result = await client.validate_profile_configuration(
            profile_data=profile_data,
            check_dependencies=check_dependencies
        )
        
        # The client method returns ValidationResult.model_dump(), whose keys are
        # is_valid / errors / warnings / conflicts / dependencies. Read those
        # exact keys — reading "valid"/"issues" (which do not exist) made every
        # input, including {}, validate clean.
        errors = list(result.get("errors") or [])
        conflicts = list(result.get("conflicts") or [])
        warnings = list(result.get("warnings") or [])
        dependencies = list(result.get("dependencies") or [])

        # "issues" is this tool's caller-facing name for everything that makes
        # the configuration invalid.
        issues = errors + conflicts
        validation_passed = bool(result.get("is_valid", False)) and not issues

        return {
            "success": True,
            "validation_passed": validation_passed,
            "profile_name": profile_data.get("name", "unnamed"),
            "issues": issues,
            "errors": errors,
            "conflicts": conflicts,
            "warnings": warnings,
            "dependencies": dependencies,
            "message": (
                "Profile configuration validated successfully"
                if validation_passed
                else f"Profile configuration has {len(issues)} issue(s) that need attention: "
                     + "; ".join(issues)
            )
        }
               
    except ClearPassAPIError as e:
        logger.error(f"Failed to validate profile configuration: {e}")
        return await format_api_error(e, "validate profile configuration")
    except Exception as e:
        logger.error(f"Unexpected error validating profile configuration: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while validating the profile configuration"
        } 