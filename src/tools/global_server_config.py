"""
MCP tools for Global Server Configuration management.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error, format_clarification_needed
from ..models.global_server_config import (
    AdminPrivilege,
    AdminUser,
    AdminPasswordPolicy,
    ApplicationLicense,
    ClusterParameters,
    LocalUserPasswordPolicy
)

logger = logging.getLogger(__name__)


@operation(domain="global_server_config")
async def get_cluster_parameters(ctx: Context) -> Dict[str, Any]:
    """
    Get cluster parameters configuration.
    Maps to 'get_cluster_parameters' in pyclearpass.
    """
    await ctx.info("Getting cluster parameters")
    try:
        client = await get_clearpass_client()
        response = await client.get_cluster_parameters()
        
        return {
            "success": True,
            "cluster_parameters": response,
            "message": "Cluster parameters retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get cluster parameters: {e}")
        return await format_api_error(e, "get cluster parameters")
    except Exception as e:
        logger.error(f"Unexpected error getting cluster parameters: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_cluster_parameters(
    ctx: Context,
    parameters_data: Dict[str, Any] = Field(..., description="Cluster parameters data to update"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update cluster parameters configuration.
    Maps to 'update_cluster_parameters' or 'replace_cluster_parameters' in pyclearpass.
    """
    await ctx.info(f"Updating cluster parameters (Replace all: {replace_all})")
    try:
        client = await get_clearpass_client()
        response = await client.update_cluster_parameters(parameters_data, replace=replace_all)
        
        action_taken = "replaced" if replace_all else "updated"
        return {
            "success": True,
            "message": f"Cluster parameters {action_taken} successfully.",
            "updated_parameters": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update cluster parameters: {e}")
        return await format_api_error(e, "update cluster parameters")
    except Exception as e:
        logger.error(f"Unexpected error updating cluster parameters: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def list_admin_privileges(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    Get a list of admin privileges.
    Maps to 'get_admin_privilege' in pyclearpass.
    """
    await ctx.info("Listing admin privileges")
    try:
        client = await get_clearpass_client()
        params = {k: v for k, v in locals().items() if k not in ['ctx', 'client'] and v is not None}
        if 'filter_str' in params:
            params['filter_str'] = params.pop('filter_str')
        
        response = await client.list_admin_privileges(**params)
        
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "admin_privileges": items,
            "message": f"Retrieved {len(items)} admin privileges."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list admin privileges: {e}")
        return await format_api_error(e, "list admin privileges")
    except Exception as e:
        logger.error(f"Unexpected error listing admin privileges: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def create_admin_privilege(
    ctx: Context,
    name: str = Field(..., description="Name of the admin privilege"),
    cppm_privileges: Dict[str, str] = Field(..., description="Privilege list in JSON object format (e.g., {'con':'RWD', 'mon':'RW'})"),
    description: Optional[str] = Field(None, description="Description of the admin privilege"),
    access_type: Optional[str] = Field(None, description="Property to decide the access type of the user"),
    insight_privileges: Optional[Dict[str, str]] = Field(None, description="Insight privilege list (e.g., {'report': 'RWD', 'dashboard':'RW'})"),
    allow_passwords: bool = Field(default=False, description="If selected, all passwords may be displayed in the response"),
    allow_security_configs: bool = Field(default=False, description="If selected, Admin user will have access for security configuration")
) -> Dict[str, Any]:
    """
    Create a new admin privilege.
    Maps to 'new_admin_privilege' in pyclearpass.
    """
    await ctx.info(f"Creating admin privilege: {name}")
    try:
        client = await get_clearpass_client()
        privilege_data = AdminPrivilege(
            name=name,
            description=description,
            access_type=access_type,
            cppm_privileges=cppm_privileges,
            insight_privileges=insight_privileges,
            allow_passwords=allow_passwords,
            allow_security_configs=allow_security_configs
        )
        response = await client.create_admin_privilege(privilege_data.model_dump(exclude_none=True, exclude={'id'}))
        
        return {
            "success": True,
            "message": "Admin privilege created successfully.",
            "created_privilege": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create admin privilege: {e}")
        return await format_api_error(e, "create admin privilege")
    except Exception as e:
        logger.error(f"Unexpected error creating admin privilege: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_admin_privilege_details(
    ctx: Context,
    admin_privilege_id: Optional[int] = Field(None, description="Numeric ID of the admin privilege"),
    name: Optional[str] = Field(None, description="Name of the admin privilege")
) -> Dict[str, Any]:
    """
    Get an admin privilege by ID or name.
    Maps to 'get_admin_privilege_by_admin_privilege_id' or 'get_admin_privilege_name_by_name' in pyclearpass.
    """
    if admin_privilege_id is None and name is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the admin privilege.",
            question="Please provide either 'admin_privilege_id' or 'name'."
        )
    
    identifier = f"ID: {admin_privilege_id}" if admin_privilege_id is not None else f"name: {name}"
    await ctx.info(f"Getting admin privilege details for {identifier}")
    
    try:
        client = await get_clearpass_client()
        if admin_privilege_id is not None:
            response = await client.get_admin_privilege_by_id(admin_privilege_id)
        else:
            response = await client.get_admin_privilege_by_name(name)
        
        return {
            "success": True,
            "admin_privilege_details": response,
            "message": f"Admin privilege details retrieved successfully for {identifier}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get admin privilege details: {e}")
        return await format_api_error(e, f"get admin privilege details for {identifier}")
    except Exception as e:
        logger.error(f"Unexpected error getting admin privilege details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_admin_privilege(
    ctx: Context,
    admin_privilege_id: int = Field(..., description="Numeric ID of the admin privilege to update"),
    name: Optional[str] = Field(None, description="New name for the admin privilege"),
    description: Optional[str] = Field(None, description="New description for the admin privilege"),
    access_type: Optional[str] = Field(None, description="New access type for the admin privilege"),
    cppm_privileges: Optional[Dict[str, str]] = Field(None, description="New CPPM privilege list in JSON object format"),
    insight_privileges: Optional[Dict[str, str]] = Field(None, description="New Insight privilege list in JSON object format"),
    allow_passwords: Optional[bool] = Field(None, description="New setting for password display permission"),
    allow_security_configs: Optional[bool] = Field(None, description="New setting for security configuration access"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing admin privilege configuration.
    
    Updates the specified admin privilege with new values. Only provided fields will be updated
    unless replace_all is True.
    """
    try:
        client = await get_clearpass_client()
        
        privilege_data = {}
        if name is not None:
            privilege_data["name"] = name
        if description is not None:
            privilege_data["description"] = description
        if access_type is not None:
            privilege_data["access_type"] = access_type
        if cppm_privileges is not None:
            privilege_data["cppm_privileges"] = cppm_privileges
        if insight_privileges is not None:
            privilege_data["insight_privileges"] = insight_privileges
        if allow_passwords is not None:
            privilege_data["allow_passwords"] = allow_passwords
        if allow_security_configs is not None:
            privilege_data["allow_security_configs"] = allow_security_configs
            
        if not privilege_data:
            return await format_clarification_needed(
                "No update fields provided",
                "Please provide at least one field to update."
            )
        
        if replace_all:
            result = await client.replace_admin_privilege_by_id(admin_privilege_id, privilege_data)
            action = "replaced"
        else:
            result = await client.update_admin_privilege_by_id(admin_privilege_id, privilege_data)
            action = "updated"
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully {action} admin privilege ID {admin_privilege_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update admin privilege ID {admin_privilege_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating admin privilege: {str(e)}"),
            "update admin privilege"
        )


@operation(domain="global_server_config")
async def delete_admin_privilege(
    ctx: Context,
    admin_privilege_id: int = Field(..., description="Numeric ID of the admin privilege to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an admin privilege from the ClearPass system.
    
    Permanently removes the specified admin privilege. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete admin privilege ID {admin_privilege_id}? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_admin_privilege_by_id(admin_privilege_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted admin privilege ID {admin_privilege_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete admin privilege ID {admin_privilege_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting admin privilege: {str(e)}"),
            "delete admin privilege"
        )


@operation(domain="global_server_config")
async def list_application_licenses(ctx: Context) -> Dict[str, Any]:
    """
    Get application licenses.
    Maps to 'get_application_license' in pyclearpass.
    """
    await ctx.info("Listing application licenses")
    try:
        client = await get_clearpass_client()
        response = await client.list_application_licenses()
        
        # Handle response format - might be direct list or embedded
        if isinstance(response, list):
            licenses = response
        elif isinstance(response, dict) and "_embedded" in response:
            licenses = response["_embedded"].get("items", [])
        else:
            licenses = [response] if response else []
        
        return {
            "success": True,
            "application_licenses": licenses,
            "count": len(licenses),
            "message": f"Retrieved {len(licenses)} application licenses."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list application licenses: {e}")
        return await format_api_error(e, "list application licenses")
    except Exception as e:
        logger.error(f"Unexpected error listing application licenses: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def activate_application_license_online(
    ctx: Context,
    license_id: str = Field(..., description="ID of the license to activate")
) -> Dict[str, Any]:
    """
    Activate application license online.
    Maps to 'update_application_license_activate_online_by_license_id' in pyclearpass.
    """
    await ctx.info(f"Activating application license online: {license_id}")
    try:
        client = await get_clearpass_client()
        response = await client.activate_application_license_online(license_id)
        
        return {
            "success": True,
            "license_id": license_id,
            "message": "Application license activated online successfully.",
            "activation_result": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to activate application license online: {e}")
        return await format_api_error(e, "activate application license online")
    except Exception as e:
        logger.error(f"Unexpected error activating application license online: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def activate_application_license_offline(
    ctx: Context,
    license_id: str = Field(..., description="ID of the license to activate")
) -> Dict[str, Any]:
    """
    Activate application license offline.
    Maps to 'update_application_license_activate_offline_by_license_id' in pyclearpass.
    """
    await ctx.info(f"Activating application license offline: {license_id}")
    try:
        client = await get_clearpass_client()
        response = await client.activate_application_license_offline(license_id)
        
        return {
            "success": True,
            "license_id": license_id,
            "message": "Application license activated offline successfully.",
            "activation_result": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to activate application license offline: {e}")
        return await format_api_error(e, "activate application license offline")
    except Exception as e:
        logger.error(f"Unexpected error activating application license offline: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_oauth_all_privileges(
    ctx: Context,
    format_type: Optional[str] = Field(None, description="Format for the privileges output")
) -> Dict[str, Any]:
    """
    Get all OAuth privileges.
    Maps to 'get_oauth_all_privileges' in pyclearpass.
    """
    await ctx.info("Getting all OAuth privileges")
    try:
        client = await get_clearpass_client()
        response = await client.get_oauth_all_privileges(format_type)
        
        return {
            "success": True,
            "oauth_privileges": response,
            "message": "OAuth privileges retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get OAuth privileges: {e}")
        return await format_api_error(e, "get OAuth privileges")
    except Exception as e:
        logger.error(f"Unexpected error getting OAuth privileges: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def list_admin_users(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List admin users in the ClearPass system.
    
    Returns a list of admin users with their configurations, including user IDs, names,
    privilege levels, and enabled status.
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_admin_users(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved admin users list. Found {len(result.get('_embedded', {}).get('items', []))} users."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "list admin users")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error listing admin users: {str(e)}"),
            "list admin users"
        )


@operation(domain="global_server_config")
async def create_admin_user(
    ctx: Context,
    user_id: str = Field(..., description="User ID of the admin"),
    name: str = Field(..., description="Name of the admin user"),
    password: str = Field(..., description="Password for the admin user"),
    privilege_level: str = Field(..., description="Privilege level for the admin user"),
    enabled: bool = Field(default=True, description="Whether the admin user is enabled")
) -> Dict[str, Any]:
    """
    Create a new admin user in the ClearPass system.
    
    Creates a new administrative user with specified credentials and privilege level.
    """
    try:
        client = await get_clearpass_client()
        
        user_data = {
            "user_id": user_id,
            "name": name,
            "password": password,
            "privilege_level": privilege_level,
            "enabled": enabled
        }
        
        result = await client.create_admin_user(user_data)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully created admin user '{user_id}' with privilege level '{privilege_level}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create admin user")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating admin user: {str(e)}"),
            "create admin user"
        )


@operation(domain="global_server_config")
async def get_admin_user_details(
    ctx: Context,
    user_id: Optional[int] = Field(None, description="Numeric ID of the admin user"),
    user_name: Optional[str] = Field(None, description="User ID/name of the admin user")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific admin user.
    
    Provide either the numeric ID or the user_name to retrieve the admin user details.
    """
    if user_id is None and user_name is None:
        return await format_clarification_needed(
            "Admin user identifier required",
            "Please provide either user_id (numeric) or user_name to retrieve admin user details.",
            ["Specify user_id for lookup by numeric ID", "Specify user_name for lookup by user name"]
        )
    
    # Hoisted before the API call: error handlers below interpolate `identifier`,
    # so it must be bound even when the awaited call raises.
    identifier = f"ID {user_id}" if user_id is not None else f"user name '{user_name}'"

    try:
        client = await get_clearpass_client()
        
        if user_id is not None:
            result = await client.get_admin_user_by_id(user_id)
        else:
            result = await client.get_admin_user_by_user_id(user_name)
            
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved admin user details for {identifier}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"get admin user details for {identifier}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving admin user details: {str(e)}"),
            "get admin user details"
        )


@operation(domain="global_server_config")
async def update_admin_user(
    ctx: Context,
    user_id: int = Field(..., description="Numeric ID of the admin user to update"),
    name: Optional[str] = Field(None, description="New name for the admin user"),
    password: Optional[str] = Field(None, description="New password for the admin user"),
    privilege_level: Optional[str] = Field(None, description="New privilege level for the admin user"),
    enabled: Optional[bool] = Field(None, description="New enabled status for the admin user"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing admin user's configuration.
    
    Updates the specified admin user with new values. Only provided fields will be updated
    unless replace_all is True.
    """
    try:
        client = await get_clearpass_client()
        
        user_data = {}
        if name is not None:
            user_data["name"] = name
        if password is not None:
            user_data["password"] = password
        if privilege_level is not None:
            user_data["privilege_level"] = privilege_level
        if enabled is not None:
            user_data["enabled"] = enabled
            
        if not user_data:
            return await format_clarification_needed(
                "No update fields provided",
                "Please provide at least one field to update (name, password, privilege_level, or enabled)."
            )
        
        if replace_all:
            result = await client.replace_admin_user_by_id(user_id, user_data)
            action = "replaced"
        else:
            result = await client.update_admin_user_by_id(user_id, user_data)
            action = "updated"
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully {action} admin user ID {user_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update admin user ID {user_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating admin user: {str(e)}"),
            "update admin user"
        )


@operation(domain="global_server_config")
async def delete_admin_user(
    ctx: Context,
    user_id: int = Field(..., description="Numeric ID of the admin user to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an admin user from the ClearPass system.
    
    Permanently removes the specified admin user. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete admin user ID {user_id}? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_admin_user_by_id(user_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted admin user ID {user_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete admin user ID {user_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting admin user: {str(e)}"),
            "delete admin user"
        )


@operation(domain="global_server_config")
async def create_application_license(
    ctx: Context,
    license_data: Dict[str, Any] = Field(..., description="License data including license key and configuration")
) -> Dict[str, Any]:
    """
    Create/install a new application license in the ClearPass system.
    
    Installs a new application license with the provided license data.
    """
    try:
        client = await get_clearpass_client()
        result = await client.create_application_license(license_data)
        
        return {
            "success": True,
            "data": result,
            "message": "Successfully created/installed application license."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create application license")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating application license: {str(e)}"),
            "create application license"
        )


@operation(domain="global_server_config")
async def get_application_license_details(
    ctx: Context,
    license_id: str = Field(..., description="ID of the application license")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific application license.
    
    Retrieves comprehensive details about the specified application license.
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_application_license_by_id(license_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved application license details for license ID '{license_id}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"get application license details for license ID '{license_id}'")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving application license details: {str(e)}"),
            "get application license details"
        )


@operation(domain="global_server_config")
async def update_application_license(
    ctx: Context,
    license_id: str = Field(..., description="ID of the application license to update"),
    license_data: Dict[str, Any] = Field(..., description="New license configuration data")
) -> Dict[str, Any]:
    """
    Update/replace an existing application license configuration.
    
    Replaces the specified application license with new configuration data.
    """
    try:
        client = await get_clearpass_client()
        result = await client.replace_application_license_by_id(license_id, license_data)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated application license ID '{license_id}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update application license ID '{license_id}'")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating application license: {str(e)}"),
            "update application license"
        )


@operation(domain="global_server_config")
async def delete_application_license(
    ctx: Context,
    license_id: str = Field(..., description="ID of the application license to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an application license from the ClearPass system.
    
    Permanently removes the specified application license. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete application license ID '{license_id}'? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_application_license_by_id(license_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted application license ID '{license_id}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete application license ID '{license_id}'")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting application license: {str(e)}"),
            "delete application license"
        )


@operation(domain="global_server_config")
async def list_attributes(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List attributes defined in the ClearPass system.
    
    Returns a list of custom attributes with their entity associations, data types,
    and configuration details.
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_attributes(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved attributes list. Found {len(result.get('_embedded', {}).get('items', []))} attributes."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "list attributes")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error listing attributes: {str(e)}"),
            "list attributes"
        )


@operation(domain="global_server_config")
async def create_attribute(
    ctx: Context,
    entity_name: str = Field(..., description="Entity name for the attribute"),
    name: str = Field(..., description="Name of the attribute"),
    description: Optional[str] = Field(None, description="Description of the attribute"),
    data_type: Optional[str] = Field(None, description="Data type of the attribute"),
    default_value: Optional[str] = Field(None, description="Default value for the attribute"),
    mandatory: bool = Field(default=False, description="Whether the attribute is mandatory")
) -> Dict[str, Any]:
    """
    Create a new attribute in the ClearPass system.
    
    Creates a custom attribute that can be associated with various entities.
    """
    try:
        client = await get_clearpass_client()
        
        attribute_data = {
            "entity_name": entity_name,
            "name": name,
            "mandatory": mandatory
        }
        
        if description is not None:
            attribute_data["description"] = description
        if data_type is not None:
            attribute_data["data_type"] = data_type
        if default_value is not None:
            attribute_data["default_value"] = default_value
        
        result = await client.create_attribute(attribute_data)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully created attribute '{name}' for entity '{entity_name}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create attribute")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating attribute: {str(e)}"),
            "create attribute"
        )


@operation(domain="global_server_config")
async def get_attribute_details(
    ctx: Context,
    attribute_id: Optional[int] = Field(None, description="Numeric ID of the attribute"),
    entity_name: Optional[str] = Field(None, description="Entity name of the attribute"),
    name: Optional[str] = Field(None, description="Name of the attribute")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific attribute.
    
    Provide either the numeric ID or both entity_name and name to retrieve the attribute details.
    """
    if attribute_id is None and not (entity_name is not None and name is not None):
        return await format_clarification_needed(
            "Attribute identifier required",
            "Please provide either attribute_id (numeric) or both entity_name and name to retrieve attribute details.",
            ["Specify attribute_id for lookup by numeric ID", "Specify both entity_name and name for lookup by entity and name"]
        )
    
    # Hoisted before the API call: error handlers below interpolate `identifier`,
    # so it must be bound even when the awaited call raises.
    identifier = f"ID {attribute_id}" if attribute_id is not None else f"entity '{entity_name}' name '{name}'"

    try:
        client = await get_clearpass_client()
        
        if attribute_id is not None:
            result = await client.get_attribute_by_id(attribute_id)
        else:
            result = await client.get_attribute_by_entity_and_name(entity_name, name)
            
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved attribute details for {identifier}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"get attribute details for {identifier}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving attribute details: {str(e)}"),
            "get attribute details"
        )


@operation(domain="global_server_config")
async def update_attribute(
    ctx: Context,
    attribute_id: int = Field(..., description="Numeric ID of the attribute to update"),
    entity_name: Optional[str] = Field(None, description="New entity name for the attribute"),
    name: Optional[str] = Field(None, description="New name for the attribute"),
    description: Optional[str] = Field(None, description="New description for the attribute"),
    data_type: Optional[str] = Field(None, description="New data type for the attribute"),
    default_value: Optional[str] = Field(None, description="New default value for the attribute"),
    mandatory: Optional[bool] = Field(None, description="New mandatory setting for the attribute"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing attribute's configuration.
    
    Updates the specified attribute with new values. Only provided fields will be updated
    unless replace_all is True.
    """
    try:
        client = await get_clearpass_client()
        
        attribute_data = {}
        if entity_name is not None:
            attribute_data["entity_name"] = entity_name
        if name is not None:
            attribute_data["name"] = name
        if description is not None:
            attribute_data["description"] = description
        if data_type is not None:
            attribute_data["data_type"] = data_type
        if default_value is not None:
            attribute_data["default_value"] = default_value
        if mandatory is not None:
            attribute_data["mandatory"] = mandatory
            
        if not attribute_data:
            return await format_clarification_needed(
                "No update fields provided",
                "Please provide at least one field to update."
            )
        
        if replace_all:
            result = await client.replace_attribute_by_id(attribute_id, attribute_data)
            action = "replaced"
        else:
            result = await client.update_attribute_by_id(attribute_id, attribute_data)
            action = "updated"
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully {action} attribute ID {attribute_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update attribute ID {attribute_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating attribute: {str(e)}"),
            "update attribute"
        )


@operation(domain="global_server_config")
async def delete_attribute(
    ctx: Context,
    attribute_id: int = Field(..., description="Numeric ID of the attribute to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an attribute from the ClearPass system.
    
    Permanently removes the specified attribute. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete attribute ID {attribute_id}? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_attribute_by_id(attribute_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted attribute ID {attribute_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete attribute ID {attribute_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting attribute: {str(e)}"),
            "delete attribute"
        )


@operation(domain="global_server_config")
async def list_data_filters(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List data filters defined in the ClearPass system.
    
    Returns a list of data filters with their filter expressions and entity associations.
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_data_filters(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved data filters list. Found {len(result.get('_embedded', {}).get('items', []))} filters."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "list data filters")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error listing data filters: {str(e)}"),
            "list data filters"
        )


@operation(domain="global_server_config")
async def create_data_filter(
    ctx: Context,
    name: str = Field(..., description="Name of the data filter"),
    type: str = Field(..., description="Filter type: 'SESSION', 'ACCOUNTING' or 'INSIGHT'"),
    configuration_type: str = Field(..., description="How the filter is defined: 'attribute_rules' or 'custom_sql'"),
    description: Optional[str] = Field(None, description="Description of the data filter"),
    rule_eval_algo: Optional[str] = Field(None, description="Rule evaluation algorithm for attribute_rules filters, e.g. 'OR' or 'AND'"),
    rules: Optional[List[Dict[str, Any]]] = Field(None, description="Rules for an attribute_rules filter. Each rule is {'match_type': 'OR'|'AND', 'condition': [{'type': ..., 'name': ..., 'oper': ..., 'value': ...}]}"),
    custom_sql: Optional[str] = Field(None, description="Raw SQL WHERE clause for a custom_sql filter (may use the --START-TIME--/--END-TIME-- placeholders)")
) -> Dict[str, Any]:
    """
    Create a new data filter in the ClearPass system.

    The body field names match the ClearPass API exactly (verified against
    ClearPass 6.12.4). A data filter is either `configuration_type`
    ``attribute_rules`` (supply `rule_eval_algo` + `rules`) or ``custom_sql``
    (supply `custom_sql`). The earlier `filter_expression` / `entity_name`
    parameters were not API fields and were always rejected with HTTP 422.
    """
    if configuration_type == "attribute_rules" and not rules:
        return await format_clarification_needed(
            "Rules required for an attribute_rules data filter",
            "Please supply 'rules' (and normally 'rule_eval_algo') when configuration_type is 'attribute_rules'.",
            ["Example rule: {'match_type': 'OR', 'condition': [{'type': 'Common', 'name': 'Source', 'oper': 'EQUALS', 'value': 'RADIUS'}]}"]
        )
    if configuration_type == "custom_sql" and not custom_sql:
        return await format_clarification_needed(
            "SQL required for a custom_sql data filter",
            "Please supply 'custom_sql' when configuration_type is 'custom_sql'.",
            ["Example: \" WHERE T1.timestamp >= --START-TIME--\""]
        )

    try:
        client = await get_clearpass_client()

        filter_data: Dict[str, Any] = {
            "name": name,
            "type": type,
            "configuration_type": configuration_type,
        }

        optional_fields = {
            "description": description,
            "rule_eval_algo": rule_eval_algo,
            "rules": rules,
            "custom_sql": custom_sql,
        }
        filter_data.update({k: v for k, v in optional_fields.items() if v is not None})

        result = await client.create_data_filter(filter_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully created data filter '{name}' of type '{type}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create data filter")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating data filter: {str(e)}"),
            "create data filter"
        )


@operation(domain="global_server_config")
async def get_data_filter_details(
    ctx: Context,
    data_filter_id: Optional[int] = Field(None, description="Numeric ID of the data filter"),
    name: Optional[str] = Field(None, description="Name of the data filter")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific data filter.
    
    Provide either the numeric ID or name to retrieve the data filter details.
    """
    if data_filter_id is None and name is None:
        return await format_clarification_needed(
            "Data filter identifier required",
            "Please provide either data_filter_id (numeric) or name to retrieve data filter details.",
            ["Specify data_filter_id for lookup by numeric ID", "Specify name for lookup by filter name"]
        )
    
    # Hoisted before the API call: error handlers below interpolate `identifier`,
    # so it must be bound even when the awaited call raises.
    identifier = f"ID {data_filter_id}" if data_filter_id is not None else f"name '{name}'"

    try:
        client = await get_clearpass_client()
        
        if data_filter_id is not None:
            result = await client.get_data_filter_by_id(data_filter_id)
        else:
            result = await client.get_data_filter_by_name(name)
            
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved data filter details for {identifier}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"get data filter details for {identifier}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving data filter details: {str(e)}"),
            "get data filter details"
        )


@operation(domain="global_server_config")
async def update_data_filter(
    ctx: Context,
    data_filter_id: int = Field(..., description="Numeric ID of the data filter to update"),
    name: Optional[str] = Field(None, description="New name for the data filter"),
    description: Optional[str] = Field(None, description="New description for the data filter"),
    filter_expression: Optional[str] = Field(None, description="New filter expression"),
    entity_name: Optional[str] = Field(None, description="New entity name to apply the filter to"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing data filter's configuration.
    
    Updates the specified data filter with new values. Only provided fields will be updated
    unless replace_all is True.
    """
    try:
        client = await get_clearpass_client()
        
        filter_data = {}
        if name is not None:
            filter_data["name"] = name
        if description is not None:
            filter_data["description"] = description
        if filter_expression is not None:
            filter_data["filter_expression"] = filter_expression
        if entity_name is not None:
            filter_data["entity_name"] = entity_name
            
        if not filter_data:
            return await format_clarification_needed(
                "No update fields provided",
                "Please provide at least one field to update."
            )
        
        if replace_all:
            result = await client.replace_data_filter_by_id(data_filter_id, filter_data)
            action = "replaced"
        else:
            result = await client.update_data_filter_by_id(data_filter_id, filter_data)
            action = "updated"
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully {action} data filter ID {data_filter_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update data filter ID {data_filter_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating data filter: {str(e)}"),
            "update data filter"
        )


@operation(domain="global_server_config")
async def delete_data_filter(
    ctx: Context,
    data_filter_id: int = Field(..., description="Numeric ID of the data filter to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a data filter from the ClearPass system.
    
    Permanently removes the specified data filter. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete data filter ID {data_filter_id}? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_data_filter_by_id(data_filter_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted data filter ID {data_filter_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete data filter ID {data_filter_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting data filter: {str(e)}"),
            "delete data filter"
        )


@operation(domain="global_server_config")
async def list_operator_profiles(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List operator profiles defined in the ClearPass system.
    
    Returns a list of operator profiles with their privilege levels and configurations.
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_operator_profiles(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved operator profiles list. Found {len(result.get('_embedded', {}).get('items', []))} profiles."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "list operator profiles")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error listing operator profiles: {str(e)}"),
            "list operator profiles"
        )


@operation(domain="global_server_config")
async def create_operator_profile(
    ctx: Context,
    name: str = Field(..., description="Name of the operator profile"),
    description: Optional[str] = Field(None, description="Description of the operator profile"),
    privilege_level: Optional[str] = Field(None, description="Privilege level for the operator"),
    sponsor_privileges: Optional[Dict[str, Any]] = Field(None, description="Sponsor privileges configuration"),
    guest_account_restrictions: Optional[Dict[str, Any]] = Field(None, description="Guest account restrictions")
) -> Dict[str, Any]:
    """
    Create a new operator profile in the ClearPass system.
    
    Creates an operator profile that defines privileges and restrictions for operators.
    """
    try:
        client = await get_clearpass_client()
        
        profile_data = {
            "name": name
        }
        
        if description is not None:
            profile_data["description"] = description
        if privilege_level is not None:
            profile_data["privilege_level"] = privilege_level
        if sponsor_privileges is not None:
            profile_data["sponsor_privileges"] = sponsor_privileges
        if guest_account_restrictions is not None:
            profile_data["guest_account_restrictions"] = guest_account_restrictions
        
        result = await client.create_operator_profile(profile_data)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully created operator profile '{name}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create operator profile")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating operator profile: {str(e)}"),
            "create operator profile"
        )


@operation(domain="global_server_config")
async def get_operator_profile_details(
    ctx: Context,
    profile_id: Optional[int] = Field(None, description="Numeric ID of the operator profile"),
    name: Optional[str] = Field(None, description="Name of the operator profile")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific operator profile.
    
    Provide either the numeric ID or name to retrieve the operator profile details.
    """
    if profile_id is None and name is None:
        return await format_clarification_needed(
            "Operator profile identifier required",
            "Please provide either profile_id (numeric) or name to retrieve operator profile details.",
            ["Specify profile_id for lookup by numeric ID", "Specify name for lookup by profile name"]
        )
    
    # Hoisted before the API call: error handlers below interpolate `identifier`,
    # so it must be bound even when the awaited call raises.
    identifier = f"ID {profile_id}" if profile_id is not None else f"name '{name}'"

    try:
        client = await get_clearpass_client()
        
        if profile_id is not None:
            result = await client.get_operator_profile_by_id(profile_id)
        else:
            result = await client.get_operator_profile_by_name(name)
            
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved operator profile details for {identifier}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"get operator profile details for {identifier}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving operator profile details: {str(e)}"),
            "get operator profile details"
        )


@operation(domain="global_server_config")
async def update_operator_profile(
    ctx: Context,
    profile_id: int = Field(..., description="Numeric ID of the operator profile to update"),
    name: Optional[str] = Field(None, description="New name for the operator profile"),
    description: Optional[str] = Field(None, description="New description for the operator profile"),
    privilege_level: Optional[str] = Field(None, description="New privilege level for the operator"),
    sponsor_privileges: Optional[Dict[str, Any]] = Field(None, description="New sponsor privileges configuration"),
    guest_account_restrictions: Optional[Dict[str, Any]] = Field(None, description="New guest account restrictions"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing operator profile's configuration.
    
    Updates the specified operator profile with new values. Only provided fields will be updated
    unless replace_all is True.
    """
    try:
        client = await get_clearpass_client()
        
        profile_data = {}
        if name is not None:
            profile_data["name"] = name
        if description is not None:
            profile_data["description"] = description
        if privilege_level is not None:
            profile_data["privilege_level"] = privilege_level
        if sponsor_privileges is not None:
            profile_data["sponsor_privileges"] = sponsor_privileges
        if guest_account_restrictions is not None:
            profile_data["guest_account_restrictions"] = guest_account_restrictions
            
        if not profile_data:
            return await format_clarification_needed(
                "No update fields provided",
                "Please provide at least one field to update."
            )
        
        if replace_all:
            result = await client.replace_operator_profile_by_id(profile_id, profile_data)
            action = "replaced"
        else:
            result = await client.update_operator_profile_by_id(profile_id, profile_data)
            action = "updated"
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully {action} operator profile ID {profile_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update operator profile ID {profile_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating operator profile: {str(e)}"),
            "update operator profile"
        )


@operation(domain="global_server_config")
async def delete_operator_profile(
    ctx: Context,
    profile_id: int = Field(..., description="Numeric ID of the operator profile to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an operator profile from the ClearPass system.
    
    Permanently removes the specified operator profile. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete operator profile ID {profile_id}? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_operator_profile_by_id(profile_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted operator profile ID {profile_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete operator profile ID {profile_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting operator profile: {str(e)}"),
            "delete operator profile"
        )


@operation(domain="global_server_config")
async def list_snmp_trap_receivers(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List SNMP trap receivers defined in the ClearPass system.
    
    Returns a list of SNMP trap receivers with their host addresses, ports, and configurations.
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_snmp_trap_receivers(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved SNMP trap receivers list. Found {len(result.get('_embedded', {}).get('items', []))} receivers."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "list SNMP trap receivers")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error listing SNMP trap receivers: {str(e)}"),
            "list SNMP trap receivers"
        )


@operation(domain="global_server_config")
async def create_snmp_trap_receiver(
    ctx: Context,
    host_address: str = Field(..., description="Host address of the trap receiver. This is also the receiver's unique name for the by-name operations."),
    snmp_version: str = Field(default="V2C", description="SNMP version: 'V1', 'V2C' or 'V3' (upper case)"),
    server_port: int = Field(default=162, description="UDP port the trap receiver listens on"),
    description: Optional[str] = Field(None, description="Description of the SNMP trap receiver"),
    community_string: Optional[str] = Field(None, description="SNMP community string. Required for V1/V2C."),
    type: Optional[str] = Field(None, description="Notification type: 'Trap' or 'Inform' (V3 only; defaults to 'Inform')"),
    user: Optional[str] = Field(None, description="SNMPv3 username (V3 only)"),
    security_level: Optional[str] = Field(None, description="SNMPv3 security level: 'NOAUTH_NOPRIV', 'AUTH_NOPRIV' or 'AUTH_PRIV' (V3 only)"),
    auth_protocol: Optional[str] = Field(None, description="SNMPv3 authentication protocol, e.g. 'MD5' or 'SHA' (V3 only)"),
    auth_key: Optional[str] = Field(None, description="SNMPv3 authentication key (V3 only)"),
    priv_protocol: Optional[str] = Field(None, description="SNMPv3 privacy protocol: 'AES_128' or 'DES_CBC' (V3 only)"),
    priv_key: Optional[str] = Field(None, description="SNMPv3 privacy key (V3 only)")
) -> Dict[str, Any]:
    """
    Create a new SNMP trap receiver in the ClearPass system.

    Creates an SNMP trap receiver that will receive SNMP trap notifications.

    The body field names match the ClearPass API exactly (verified against
    ClearPass 6.12.4): `snmp_version` (not `version`), `community_string`
    (not `community`), `server_port` (not `port`), and the SNMPv3 fields
    `priv_protocol` / `priv_key` (not `privacy_*`). The resource has no
    `name` or `enabled` field — `host_address` is the identity.
    """
    try:
        client = await get_clearpass_client()

        receiver_data: Dict[str, Any] = {
            "host_address": host_address,
            "snmp_version": snmp_version,
            "server_port": server_port,
        }

        optional_fields = {
            "description": description,
            "community_string": community_string,
            "type": type,
            "user": user,
            "security_level": security_level,
            "auth_protocol": auth_protocol,
            "auth_key": auth_key,
            "priv_protocol": priv_protocol,
            "priv_key": priv_key,
        }
        receiver_data.update({k: v for k, v in optional_fields.items() if v is not None})

        result = await client.create_snmp_trap_receiver(receiver_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully created SNMP trap receiver at {host_address}:{server_port}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create SNMP trap receiver")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating SNMP trap receiver: {str(e)}"),
            "create SNMP trap receiver"
        )


@operation(domain="global_server_config")
async def get_snmp_trap_receiver_details(
    ctx: Context,
    snmp_trap_receiver_id: Optional[int] = Field(None, description="Numeric ID of the SNMP trap receiver"),
    name: Optional[str] = Field(None, description="Name of the SNMP trap receiver")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific SNMP trap receiver.
    
    Provide either the numeric ID or name to retrieve the SNMP trap receiver details.
    """
    if snmp_trap_receiver_id is None and name is None:
        return await format_clarification_needed(
            "SNMP trap receiver identifier required",
            "Please provide either snmp_trap_receiver_id (numeric) or name to retrieve SNMP trap receiver details.",
            ["Specify snmp_trap_receiver_id for lookup by numeric ID", "Specify name for lookup by receiver name"]
        )
    
    # Hoisted before the API call: error handlers below interpolate `identifier`,
    # so it must be bound even when the awaited call raises.
    identifier = f"ID {snmp_trap_receiver_id}" if snmp_trap_receiver_id is not None else f"name '{name}'"

    try:
        client = await get_clearpass_client()
        
        if snmp_trap_receiver_id is not None:
            result = await client.get_snmp_trap_receiver_by_id(snmp_trap_receiver_id)
        else:
            result = await client.get_snmp_trap_receiver_by_name(name)
            
        return {
            "success": True,
            "data": result,
            "message": f"Successfully retrieved SNMP trap receiver details for {identifier}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"get SNMP trap receiver details for {identifier}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving SNMP trap receiver details: {str(e)}"),
            "get SNMP trap receiver details"
        )


@operation(domain="global_server_config")
async def update_snmp_trap_receiver(
    ctx: Context,
    snmp_trap_receiver_id: int = Field(..., description="Numeric ID of the SNMP trap receiver to update"),
    name: Optional[str] = Field(None, description="New name for the SNMP trap receiver"),
    host_address: Optional[str] = Field(None, description="New host address for the trap receiver"),
    port: Optional[int] = Field(None, description="New port for SNMP traps"),
    version: Optional[str] = Field(None, description="New SNMP version (v1, v2c, v3)"),
    community: Optional[str] = Field(None, description="New SNMP community string"),
    enabled: Optional[bool] = Field(None, description="New enabled status for the trap receiver"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing SNMP trap receiver's configuration.
    
    Updates the specified SNMP trap receiver with new values. Only provided fields will be updated
    unless replace_all is True.
    """
    try:
        client = await get_clearpass_client()
        
        receiver_data = {}
        if name is not None:
            receiver_data["name"] = name
        if host_address is not None:
            receiver_data["host_address"] = host_address
        if port is not None:
            receiver_data["port"] = port
        if version is not None:
            receiver_data["version"] = version
        if community is not None:
            receiver_data["community"] = community
        if enabled is not None:
            receiver_data["enabled"] = enabled
            
        if not receiver_data:
            return await format_clarification_needed(
                "No update fields provided",
                "Please provide at least one field to update."
            )
        
        if replace_all:
            result = await client.replace_snmp_trap_receiver_by_id(snmp_trap_receiver_id, receiver_data)
            action = "replaced"
        else:
            result = await client.update_snmp_trap_receiver_by_id(snmp_trap_receiver_id, receiver_data)
            action = "updated"
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully {action} SNMP trap receiver ID {snmp_trap_receiver_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"update SNMP trap receiver ID {snmp_trap_receiver_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error updating SNMP trap receiver: {str(e)}"),
            "update SNMP trap receiver"
        )


@operation(domain="global_server_config")
async def delete_snmp_trap_receiver(
    ctx: Context,
    snmp_trap_receiver_id: int = Field(..., description="Numeric ID of the SNMP trap receiver to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an SNMP trap receiver from the ClearPass system.
    
    Permanently removes the specified SNMP trap receiver. This action cannot be undone.
    """
    if not confirm:
        return await format_clarification_needed(
            "Deletion confirmation required",
            f"Are you sure you want to delete SNMP trap receiver ID {snmp_trap_receiver_id}? This action cannot be undone.",
            ["Set confirm=True to proceed with deletion"]
        )
    
    try:
        client = await get_clearpass_client()
        result = await client.delete_snmp_trap_receiver_by_id(snmp_trap_receiver_id)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted SNMP trap receiver ID {snmp_trap_receiver_id}."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, f"delete SNMP trap receiver ID {snmp_trap_receiver_id}")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error deleting SNMP trap receiver: {str(e)}"),
            "delete SNMP trap receiver"
        )


@operation(domain="global_server_config")
async def get_messaging_setup(ctx: Context) -> Dict[str, Any]:
    """
    Get the current messaging setup configuration.
    
    Retrieves the current SMTP and messaging configuration for the ClearPass system.
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_messaging_setup()
        
        return {
            "success": True,
            "data": result,
            "message": "Successfully retrieved messaging setup configuration."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "get messaging setup")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error retrieving messaging setup: {str(e)}"),
            "get messaging setup"
        )


@operation(domain="global_server_config")
async def create_messaging_setup(
    ctx: Context,
    smtp_server: str = Field(..., description="SMTP server for email notifications"),
    sender_email: str = Field(..., description="Sender email address"),
    smtp_port: int = Field(default=25, description="SMTP server port"),
    smtp_username: Optional[str] = Field(None, description="SMTP username"),
    smtp_password: Optional[str] = Field(None, description="SMTP password"),
    enable_tls: bool = Field(default=False, description="Enable TLS for SMTP")
) -> Dict[str, Any]:
    """
    Create/configure messaging setup in the ClearPass system.
    
    Configures SMTP settings for email notifications and messaging.
    """
    try:
        client = await get_clearpass_client()
        
        messaging_data = {
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "enable_tls": enable_tls,
            "sender_email": sender_email
        }
        
        if smtp_username is not None:
            messaging_data["smtp_username"] = smtp_username
        if smtp_password is not None:
            messaging_data["smtp_password"] = smtp_password
        
        result = await client.create_messaging_setup(messaging_data)
        
        return {
            "success": True,
            "data": result,
            "message": f"Successfully configured messaging setup with SMTP server '{smtp_server}'."
        }
    except ClearPassAPIError as e:
        return await format_api_error(e, "create messaging setup")
    except Exception as e:
        return await format_api_error(
            ClearPassAPIError(f"Unexpected error creating messaging setup: {str(e)}"),
            "create messaging setup"
        )


@operation(domain="global_server_config")
async def delete_messaging_setup(
    ctx: Context,
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete messaging setup configuration.
    Maps to 'delete_messaging_setup' in pyclearpass.
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question="Are you sure you want to delete the messaging setup configuration? Set 'confirm' to True to proceed."
        )

    await ctx.info("Deleting messaging setup configuration")
    try:
        client = await get_clearpass_client()
        await client.delete_messaging_setup()
        
        return {
            "success": True,
            "message": "Messaging setup configuration deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete messaging setup: {e}")
        return await format_api_error(e, "delete messaging setup")
    except Exception as e:
        logger.error(f"Unexpected error deleting messaging setup: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# File Backup Server Management
@operation(domain="global_server_config")
async def list_file_backup_servers(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    Get a list of file backup servers configured in ClearPass.
    Maps to 'get_file_backup_server' in pyclearpass.
    """
    await ctx.info("Listing file backup servers")
    try:
        client = await get_clearpass_client()
        params = {
            "filter_str": filter_str,
            "sort": sort,
            "offset": offset,
            "limit": limit,
            "calculate_count": calculate_count
        }
        active_params = {k: v for k, v in params.items() if v is not None}
        response = await client.list_file_backup_servers(**active_params)
        
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "file_backup_servers": items,
            "message": f"Retrieved {len(items)} file backup servers."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list file backup servers: {e}")
        return await format_api_error(e, "list file backup servers")
    except Exception as e:
        logger.error(f"Unexpected error listing file backup servers: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def create_file_backup_server(
    ctx: Context,
    host_address: str = Field(..., description="Host address of the backup server"),
    protocol: str = Field(..., description="Protocol for backup (FTP, SFTP, SCP, etc.)"),
    username: str = Field(..., description="Username for backup server authentication"),
    password: str = Field(..., description="Password for backup server authentication"),
    backup_path: Optional[str] = Field(None, description="Path for backup files on the server"),
    port: Optional[int] = Field(None, description="Port number for the backup server connection"),
    description: Optional[str] = Field(None, description="Description of the backup server")
) -> Dict[str, Any]:
    """
    Create a new file backup server configuration.
    Maps to 'new_file_backup_server' in pyclearpass.
    """
    await ctx.info(f"Creating file backup server: {host_address}")
    try:
        client = await get_clearpass_client()
        server_data = {
            "host_address": host_address,
            "protocol": protocol,
            "username": username,
            "password": password
        }
        
        if backup_path is not None:
            server_data["backup_path"] = backup_path
        if port is not None:
            server_data["port"] = port
        if description is not None:
            server_data["description"] = description
            
        response = await client.create_file_backup_server(server_data)
        
        return {
            "success": True,
            "message": "File backup server created successfully.",
            "created_server": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create file backup server: {e}")
        return await format_api_error(e, "create file backup server")
    except Exception as e:
        logger.error(f"Unexpected error creating file backup server: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_file_backup_server_details(
    ctx: Context,
    file_backup_server_id: Optional[int] = Field(None, description="Numeric ID of the file backup server"),
    host_address: Optional[str] = Field(None, description="Host address of the file backup server")
) -> Dict[str, Any]:
    """
    Get details for a specific file backup server by ID or host address.
    Maps to 'get_file_backup_server_by_file_backup_server_id' or 'get_file_backup_server_host_address_by_host_address' in pyclearpass.
    """
    if file_backup_server_id is None and host_address is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the file backup server.",
            question="Please provide either 'file_backup_server_id' or 'host_address'."
        )
    
    log_identifier = f"ID: {file_backup_server_id}" if file_backup_server_id is not None else f"host: {host_address}"
    await ctx.info(f"Getting file backup server details for {log_identifier}")
    try:
        client = await get_clearpass_client()
        if file_backup_server_id is not None:
            response = await client.get_file_backup_server_by_id(file_backup_server_id)
        else:  # host_address must be present
            response = await client.get_file_backup_server_by_host_address(host_address)
        
        return {
            "success": True,
            "file_backup_server_details": response,
            "message": f"File backup server details retrieved successfully for {log_identifier}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get file backup server details: {e}")
        return await format_api_error(e, f"get file backup server details for {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error retrieving file backup server details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_file_backup_server(
    ctx: Context,
    file_backup_server_id: Optional[int] = Field(None, description="Numeric ID of the file backup server to update"),
    host_address: Optional[str] = Field(None, description="Host address of the file backup server to update (if not using ID)"),
    new_host_address: Optional[str] = Field(None, description="New host address for the backup server"),
    protocol: Optional[str] = Field(None, description="New protocol for backup"),
    username: Optional[str] = Field(None, description="New username for backup server"),
    password: Optional[str] = Field(None, description="New password for backup server"),
    backup_path: Optional[str] = Field(None, description="New path for backup files"),
    port: Optional[int] = Field(None, description="New port number for the backup server"),
    description: Optional[str] = Field(None, description="New description of the backup server"),
    replace_all: bool = Field(default=False, description="Set to True to perform a full replacement (PUT), False for partial update (PATCH)")
) -> Dict[str, Any]:
    """
    Update an existing file backup server configuration by ID or host address.
    Supports partial (PATCH) or full (PUT) update.
    Maps to 'update_file_backup_server_by_file_backup_server_id' or 'replace_file_backup_server_by_file_backup_server_id' in pyclearpass.
    """
    if file_backup_server_id is None and host_address is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the file backup server.",
            question="Please provide either 'file_backup_server_id' or 'host_address'."
        )
    
    log_identifier = f"ID: {file_backup_server_id}" if file_backup_server_id is not None else f"host: {host_address}"
    await ctx.info(f"Updating file backup server {log_identifier} (Replace all: {replace_all})")
    
    update_data = {
        k: v for k, v in {
            "host_address": new_host_address,
            "protocol": protocol,
            "username": username,
            "password": password,
            "backup_path": backup_path,
            "port": port,
            "description": description
        }.items() if v is not None
    }

    if not update_data:
        return {"success": False, "error": "No update parameters provided.", "message": "Please provide at least one field to update."}

    try:
        client = await get_clearpass_client()
        if file_backup_server_id is not None:
            if replace_all:
                response = await client.replace_file_backup_server_by_id(file_backup_server_id, update_data)
            else:
                response = await client.update_file_backup_server_by_id(file_backup_server_id, update_data)
        else:  # host_address must be present
            if replace_all:
                response = await client.replace_file_backup_server_by_host_address(host_address, update_data)
            else:
                response = await client.update_file_backup_server_by_host_address(host_address, update_data)
        
        action_taken = "replaced" if replace_all else "updated"
        return {
            "success": True,
            "message": f"File backup server {action_taken} successfully.",
            "updated_server": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update file backup server: {e}")
        return await format_api_error(e, f"update file backup server {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error updating file backup server: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_file_backup_server(
    ctx: Context,
    file_backup_server_id: Optional[int] = Field(None, description="Numeric ID of the file backup server to delete"),
    host_address: Optional[str] = Field(None, description="Host address of the file backup server to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a file backup server configuration by ID or host address.
    Maps to 'delete_file_backup_server_by_file_backup_server_id' or 'delete_file_backup_server_host_address_by_host_address' in pyclearpass.
    """
    if file_backup_server_id is None and host_address is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the file backup server.",
            question="Please provide either 'file_backup_server_id' or 'host_address'."
        )

    if not confirm:
        log_identifier = f"ID: {file_backup_server_id}" if file_backup_server_id is not None else f"host: {host_address}"
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete file backup server {log_identifier}? Set 'confirm' to True to proceed."
        )

    log_identifier = f"ID: {file_backup_server_id}" if file_backup_server_id is not None else f"host: {host_address}"
    await ctx.info(f"Deleting file backup server {log_identifier}")
    try:
        client = await get_clearpass_client()
        if file_backup_server_id is not None:
            await client.delete_file_backup_server_by_id(file_backup_server_id)
        else:  # host_address must be present
            await client.delete_file_backup_server_by_host_address(host_address)
        
        return {
            "success": True,
            "message": f"File backup server {log_identifier} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete file backup server: {e}")
        return await format_api_error(e, f"delete file backup server {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error deleting file backup server: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# Server Policy Manager Zones Management
@operation(domain="global_server_config")
async def list_server_policy_manager_zones(ctx: Context) -> Dict[str, Any]:
    """
    Get a list of server policy manager zones configured in ClearPass.
    Maps to 'get_server_policy_manager_zones' in pyclearpass.
    """
    await ctx.info("Listing server policy manager zones")
    try:
        client = await get_clearpass_client()
        response = await client.list_server_policy_manager_zones()
        
        # The response might be a direct list or a dict with _embedded items
        if isinstance(response, list):
            zones = response
            count = len(zones)
        elif isinstance(response, dict) and "_embedded" in response:
            zones = response["_embedded"].get("items", [])
            count = len(zones)
        elif isinstance(response, dict):
            zones = [response]  # Wrap single object in list
            count = 1
        else:
            zones = []
            count = 0
        
        return {
            "success": True,
            "count": count,
            "server_policy_manager_zones": zones,
            "message": f"Retrieved {count} server policy manager zones."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list server policy manager zones: {e}")
        return await format_api_error(e, "list server policy manager zones")
    except Exception as e:
        logger.error(f"Unexpected error listing server policy manager zones: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def create_server_policy_manager_zone(
    ctx: Context,
    name: str = Field(..., description="Name of the policy manager zone"),
    zone_id: Optional[Union[int, str]] = Field(None, description="Zone ID (numeric; if not provided, will be auto-generated)"),
    description: Optional[str] = Field(None, description="Description of the zone"),
    template: Optional[str] = Field(None, description="Zone template"),
    cluster_role: Optional[str] = Field(None, description="Cluster role for the zone")
) -> Dict[str, Any]:
    """
    Create a new server policy manager zone.
    Maps to 'new_server_policy_manager_zones' in pyclearpass.
    """
    await ctx.info(f"Creating server policy manager zone: {name}")
    try:
        client = await get_clearpass_client()
        zone_data = {"name": name}
        
        if zone_id is not None:
            zone_data["zone_id"] = zone_id
        if description is not None:
            zone_data["description"] = description
        if template is not None:
            zone_data["template"] = template
        if cluster_role is not None:
            zone_data["cluster_role"] = cluster_role
            
        response = await client.create_server_policy_manager_zone(zone_data)
        
        return {
            "success": True,
            "message": "Server policy manager zone created successfully.",
            "created_zone": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create server policy manager zone: {e}")
        return await format_api_error(e, "create server policy manager zone")
    except Exception as e:
        logger.error(f"Unexpected error creating server policy manager zone: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_server_policy_manager_zone_details(
    ctx: Context,
    zone_id: Optional[Union[int, str]] = Field(None, description="Zone ID of the policy manager zone (numeric -- the API returns an int; zone 0 is 'default')"),
    name: Optional[str] = Field(None, description="Name of the policy manager zone")
) -> Dict[str, Any]:
    """
    Get details for a specific server policy manager zone by zone ID or name.
    Maps to 'get_server_policy_manager_zones_by_zone_id' or 'get_server_policy_manager_zones_name_by_name' in pyclearpass.
    """
    if zone_id is None and name is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the server policy manager zone.",
            question="Please provide either 'zone_id' or 'name'."
        )
    
    log_identifier = f"zone ID: {zone_id}" if zone_id is not None else f"name: {name}"
    await ctx.info(f"Getting server policy manager zone details for {log_identifier}")
    try:
        client = await get_clearpass_client()
        if zone_id is not None:
            response = await client.get_server_policy_manager_zone_by_zone_id(zone_id)
        else:  # name must be present
            response = await client.get_server_policy_manager_zone_by_name(name)
        
        return {
            "success": True,
            "server_policy_manager_zone_details": response,
            "message": f"Server policy manager zone details retrieved successfully for {log_identifier}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server policy manager zone details: {e}")
        return await format_api_error(e, f"get server policy manager zone details for {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error retrieving server policy manager zone details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_server_policy_manager_zone(
    ctx: Context,
    zone_id: Optional[Union[int, str]] = Field(None, description="Zone ID of the policy manager zone to update (numeric -- the API returns an int; zone 0 is 'default')"),
    name: Optional[str] = Field(None, description="Name of the policy manager zone to update (if not using zone_id)"),
    new_name: Optional[str] = Field(None, description="New name for the policy manager zone"),
    new_zone_id: Optional[Union[int, str]] = Field(None, description="New zone ID (numeric)"),
    description: Optional[str] = Field(None, description="New description for the zone"),
    template: Optional[str] = Field(None, description="New zone template"),
    cluster_role: Optional[str] = Field(None, description="New cluster role for the zone")
) -> Dict[str, Any]:
    """
    Update an existing server policy manager zone by zone ID or name.
    Note: Only full replacement (PUT) is supported by the ClearPass API for policy manager zones.
    Maps to 'replace_server_policy_manager_zones_by_zone_id' or 'replace_server_policy_manager_zones_name_by_name' in pyclearpass.
    """
    if zone_id is None and name is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the server policy manager zone.",
            question="Please provide either 'zone_id' or 'name'."
        )
    
    log_identifier = f"zone ID: {zone_id}" if zone_id is not None else f"name: {name}"
    await ctx.info(f"Updating server policy manager zone {log_identifier}")
    
    update_data = {
        k: v for k, v in {
            "name": new_name,
            "zone_id": new_zone_id,
            "description": description,
            "template": template,
            "cluster_role": cluster_role
        }.items() if v is not None
    }

    if not update_data:
        return {"success": False, "error": "No update parameters provided.", "message": "Please provide at least one field to update."}

    try:
        client = await get_clearpass_client()
        if zone_id is not None:
            response = await client.replace_server_policy_manager_zone_by_zone_id(zone_id, update_data)
        else:  # name must be present
            response = await client.replace_server_policy_manager_zone_by_name(name, update_data)
        
        return {
            "success": True,
            "message": "Server policy manager zone updated successfully.",
            "updated_zone": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update server policy manager zone: {e}")
        return await format_api_error(e, f"update server policy manager zone {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error updating server policy manager zone: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_server_policy_manager_zone(
    ctx: Context,
    zone_id: Optional[Union[int, str]] = Field(None, description="Zone ID of the policy manager zone to delete (numeric -- the API returns an int; zone 0 is 'default')"),
    name: Optional[str] = Field(None, description="Name of the policy manager zone to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a server policy manager zone by zone ID or name.
    Maps to 'delete_server_policy_manager_zones_by_zone_id' or 'delete_server_policy_manager_zones_name_by_name' in pyclearpass.
    """
    if zone_id is None and name is None:
        return await format_clarification_needed(
            message="Insufficient parameters to identify the server policy manager zone.",
            question="Please provide either 'zone_id' or 'name'."
        )

    if not confirm:
        log_identifier = f"zone ID: {zone_id}" if zone_id is not None else f"name: {name}"
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete server policy manager zone {log_identifier}? Set 'confirm' to True to proceed."
        )

    log_identifier = f"zone ID: {zone_id}" if zone_id is not None else f"name: {name}"
    await ctx.info(f"Deleting server policy manager zone {log_identifier}")
    try:
        client = await get_clearpass_client()
        if zone_id is not None:
            await client.delete_server_policy_manager_zone_by_zone_id(zone_id)
        else:  # name must be present
            await client.delete_server_policy_manager_zone_by_name(name)
        
        return {
            "success": True,
            "message": f"Server policy manager zone {log_identifier} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete server policy manager zone: {e}")
        return await format_api_error(e, f"delete server policy manager zone {log_identifier}")
    except Exception as e:
        logger.error(f"Unexpected error deleting server policy manager zone: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."} 



@operation(domain="global_server_config")
async def update_admin_privilege_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the admin privilege"),
    privilege_data: Dict[str, Any] = Field(..., description="Admin privilege fields to update (e.g., description, access_type, cppm_privileges, insight_privileges, allow_passwords, allow_security_configs)")
) -> Dict[str, Any]:
    """
    Update some fields of an admin privilege by name.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_admin_privilege_name_by_name' in pyclearpass (PATCH /admin-privilege/name/{name}).
    """
    await ctx.info(f"Updating admin privilege by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.update_admin_privilege_by_name(name, privilege_data)

        return {
            "success": True,
            "admin_privilege": response,
            "message": f"Admin privilege '{name}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update admin privilege by name: {e}")
        return await format_api_error(e, f"update admin privilege by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error updating admin privilege by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_admin_privilege_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the admin privilege"),
    privilege_data: Dict[str, Any] = Field(..., description="Full admin privilege definition. Required keys: 'name', 'cppm_privileges'")
) -> Dict[str, Any]:
    """
    Replace an admin privilege by name.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_admin_privilege_name_by_name' in pyclearpass (PUT /admin-privilege/name/{name}).
    """
    await ctx.info(f"Replacing admin privilege by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.replace_admin_privilege_by_name(name, privilege_data)

        return {
            "success": True,
            "admin_privilege": response,
            "message": f"Admin privilege '{name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace admin privilege by name: {e}")
        return await format_api_error(e, f"replace admin privilege by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing admin privilege by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_admin_privilege_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the admin privilege to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an admin privilege by name.

    Permanently removes the specified admin privilege. This action cannot be undone.

    Maps to 'delete_admin_privilege_name_by_name' in pyclearpass (DELETE /admin-privilege/name/{name}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete admin privilege '{name}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting admin privilege by name: {name}")
    try:
        client = await get_clearpass_client()
        await client.delete_admin_privilege_by_name(name)

        return {
            "success": True,
            "message": f"Admin privilege '{name}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete admin privilege by name: {e}")
        return await format_api_error(e, f"delete admin privilege by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting admin privilege by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_admin_user_password_policy(ctx: Context) -> Dict[str, Any]:
    """
    Get the admin user password policies.

    Maps to 'get_admin_user_password_policy' in pyclearpass (GET /admin-user/password-policy).
    """
    await ctx.info("Getting admin user password policy")
    try:
        client = await get_clearpass_client()
        response = await client.get_admin_user_password_policy()

        return {
            "success": True,
            "admin_user_password_policy": response,
            "message": "Admin user password policy retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get admin user password policy: {e}")
        return await format_api_error(e, "get admin user password policy")
    except Exception as e:
        logger.error(f"Unexpected error getting admin user password policy: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_admin_user_password_policy(
    ctx: Context,
    policy_data: Dict[str, Any] = Field(..., description="Admin user password policy fields to update (e.g., password_minimum_length, password_complexity, password_expiry_days, disable_after_failed_attempts)")
) -> Dict[str, Any]:
    """
    Patch the admin user password policies.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_admin_user_password_policy' in pyclearpass (PATCH /admin-user/password-policy).
    """
    await ctx.info("Updating admin user password policy")
    try:
        client = await get_clearpass_client()
        response = await client.update_admin_user_password_policy(policy_data)

        return {
            "success": True,
            "admin_user_password_policy": response,
            "message": "Admin user password policy updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update admin user password policy: {e}")
        return await format_api_error(e, "update admin user password policy")
    except Exception as e:
        logger.error(f"Unexpected error updating admin user password policy: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_admin_user_password_policy(
    ctx: Context,
    policy_data: Dict[str, Any] = Field(..., description="Full admin user password policy definition. Required keys: 'password_minimum_length', 'password_complexity'")
) -> Dict[str, Any]:
    """
    Put the admin user password policies.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_admin_user_password_policy' in pyclearpass (PUT /admin-user/password-policy).
    """
    await ctx.info("Replacing admin user password policy")
    try:
        client = await get_clearpass_client()
        response = await client.replace_admin_user_password_policy(policy_data)

        return {
            "success": True,
            "admin_user_password_policy": response,
            "message": "Admin user password policy replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace admin user password policy: {e}")
        return await format_api_error(e, "replace admin user password policy")
    except Exception as e:
        logger.error(f"Unexpected error replacing admin user password policy: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_admin_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="Unique user_id of the admin user"),
    user_data: Dict[str, Any] = Field(..., description="Admin user fields to update (e.g., name, user_id, enabled, password, privilege_level)")
) -> Dict[str, Any]:
    """
    Update some fields of an admin user by user_id.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_admin_user_user_id_by_user_id' in pyclearpass (PATCH /admin-user/user-id/{user_id}).
    """
    await ctx.info(f"Updating admin user by user_id: {user_id}")
    try:
        client = await get_clearpass_client()
        response = await client.update_admin_user_by_user_id(user_id, user_data)

        return {
            "success": True,
            "admin_user": response,
            "message": f"Admin user '{user_id}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update admin user by user_id: {e}")
        return await format_api_error(e, f"update admin user by user_id '{user_id}'")
    except Exception as e:
        logger.error(f"Unexpected error updating admin user by user_id: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_admin_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="Unique user_id of the admin user"),
    user_data: Dict[str, Any] = Field(..., description="Full admin user definition. Required keys: 'name', 'user_id', 'password', 'privilege_level'")
) -> Dict[str, Any]:
    """
    Replace an admin user by user_id.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_admin_user_user_id_by_user_id' in pyclearpass (PUT /admin-user/user-id/{user_id}).
    """
    await ctx.info(f"Replacing admin user by user_id: {user_id}")
    try:
        client = await get_clearpass_client()
        response = await client.replace_admin_user_by_user_id(user_id, user_data)

        return {
            "success": True,
            "admin_user": response,
            "message": f"Admin user '{user_id}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace admin user by user_id: {e}")
        return await format_api_error(e, f"replace admin user by user_id '{user_id}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing admin user by user_id: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_admin_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="Unique user_id of the admin user to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an admin user by user_id.

    Permanently removes the specified admin user. This action cannot be undone and can
    cause administrative lockout if the last remaining admin account is removed.

    Maps to 'delete_admin_user_user_id_by_user_id' in pyclearpass (DELETE /admin-user/user-id/{user_id}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete admin user '{user_id}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting admin user by user_id: {user_id}")
    try:
        client = await get_clearpass_client()
        await client.delete_admin_user_by_user_id(user_id)

        return {
            "success": True,
            "message": f"Admin user '{user_id}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete admin user by user_id: {e}")
        return await format_api_error(e, f"delete admin user by user_id '{user_id}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting admin user by user_id: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_application_license_summary_detail(ctx: Context) -> Dict[str, Any]:
    """
    Get application license summary.

    Reads the summary from the '/application-license/summary' resource path.

    Maps to 'get_application_license_summary' in pyclearpass (GET /application-license/summary).
    """
    await ctx.info("Getting application license summary")
    try:
        client = await get_clearpass_client()
        response = await client.get_application_license_summary_detail()

        return {
            "success": True,
            "license_summary": response,
            "message": "Application license summary retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get application license summary: {e}")
        return await format_api_error(e, "get application license summary")
    except Exception as e:
        logger.error(f"Unexpected error getting application license summary: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_attribute_by_entity_and_name(
    ctx: Context,
    entity_name: str = Field(..., description="Entity name of the attribute (e.g., Device, Endpoint, GuestUser)"),
    name: str = Field(..., description="Unique name of the attribute"),
    attribute_data: Dict[str, Any] = Field(..., description="Attribute fields to update (e.g., name, entity_name, data_type, mandatory, default_value, allow_multiple, allowed_value)")
) -> Dict[str, Any]:
    """
    Update some fields of an attribute by name.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_attribute_by_entity_name_name_name' in pyclearpass (PATCH /attribute/{entity_name}/name/{name}).
    """
    await ctx.info(f"Updating attribute '{name}' for entity '{entity_name}'")
    try:
        client = await get_clearpass_client()
        response = await client.update_attribute_by_entity_and_name(entity_name, name, attribute_data)

        return {
            "success": True,
            "attribute": response,
            "message": f"Attribute '{name}' for entity '{entity_name}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update attribute by entity and name: {e}")
        return await format_api_error(e, f"update attribute '{name}' for entity '{entity_name}'")
    except Exception as e:
        logger.error(f"Unexpected error updating attribute by entity and name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_attribute_by_entity_and_name(
    ctx: Context,
    entity_name: str = Field(..., description="Entity name of the attribute (e.g., Device, Endpoint, GuestUser)"),
    name: str = Field(..., description="Unique name of the attribute"),
    attribute_data: Dict[str, Any] = Field(..., description="Full attribute definition. Required keys: 'name', 'entity_name', 'data_type'")
) -> Dict[str, Any]:
    """
    Replace an attribute by name.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_attribute_by_entity_name_name_name' in pyclearpass (PUT /attribute/{entity_name}/name/{name}).
    """
    await ctx.info(f"Replacing attribute '{name}' for entity '{entity_name}'")
    try:
        client = await get_clearpass_client()
        response = await client.replace_attribute_by_entity_and_name(entity_name, name, attribute_data)

        return {
            "success": True,
            "attribute": response,
            "message": f"Attribute '{name}' for entity '{entity_name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace attribute by entity and name: {e}")
        return await format_api_error(e, f"replace attribute '{name}' for entity '{entity_name}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing attribute by entity and name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_attribute_by_entity_and_name(
    ctx: Context,
    entity_name: str = Field(..., description="Entity name of the attribute (e.g., Device, Endpoint, GuestUser)"),
    name: str = Field(..., description="Unique name of the attribute to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an attribute by name.

    Permanently removes the specified attribute. This action cannot be undone.

    Maps to 'delete_attribute_by_entity_name_name_name' in pyclearpass (DELETE /attribute/{entity_name}/name/{name}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete attribute '{name}' for entity '{entity_name}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting attribute '{name}' for entity '{entity_name}'")
    try:
        client = await get_clearpass_client()
        await client.delete_attribute_by_entity_and_name(entity_name, name)

        return {
            "success": True,
            "message": f"Attribute '{name}' for entity '{entity_name}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete attribute by entity and name: {e}")
        return await format_api_error(e, f"delete attribute '{name}' for entity '{entity_name}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting attribute by entity and name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_clearpass_portal(ctx: Context) -> Dict[str, Any]:
    """
    Get the ClearPass Portal configuration.

    Returns the default landing page settings (title, header, footer, copyright) and the
    redirect target (application login page or guest portal).

    Maps to 'get_clearpass_portal' in pyclearpass (GET /clearpass-portal).
    """
    await ctx.info("Getting ClearPass Portal configuration")
    try:
        client = await get_clearpass_client()
        response = await client.get_clearpass_portal()

        return {
            "success": True,
            "clearpass_portal": response,
            "message": "ClearPass Portal configuration retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get ClearPass Portal configuration: {e}")
        return await format_api_error(e, "get ClearPass Portal configuration")
    except Exception as e:
        logger.error(f"Unexpected error getting ClearPass Portal configuration: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def create_clearpass_portal(
    ctx: Context,
    portal_data: Dict[str, Any] = Field(..., description="ClearPass Portal configuration (e.g., title, header, footer, copyright, app_name, guest_portal, url)")
) -> Dict[str, Any]:
    """
    Change the ClearPass Portal configuration.

    Maps to 'new_clearpass_portal' in pyclearpass (POST /clearpass-portal).
    """
    await ctx.info("Changing ClearPass Portal configuration")
    try:
        client = await get_clearpass_client()
        response = await client.create_clearpass_portal(portal_data)

        return {
            "success": True,
            "clearpass_portal": response,
            "message": "ClearPass Portal configuration changed successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to change ClearPass Portal configuration: {e}")
        return await format_api_error(e, "change ClearPass Portal configuration")
    except Exception as e:
        logger.error(f"Unexpected error changing ClearPass Portal configuration: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def sync_cluster_database(
    ctx: Context,
    timeout: Optional[str] = Field(None, description="Maximum time in seconds to wait for the database sync operation"),
    confirm: bool = Field(default=False, description="Confirm the synchronization (required for safety)")
) -> Dict[str, Any]:
    """
    Synchronize a subscriber with the publisher.

    Triggers a cluster database synchronization. This is a disruptive cluster-wide
    operation and requires explicit confirmation.

    Maps to 'new_cluster_db_sync' in pyclearpass (POST /cluster/db-sync).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Cluster database synchronization requires confirmation as it is a disruptive operation.",
            question="Are you sure you want to synchronize the subscriber with the publisher? Set 'confirm' to True to proceed."
        )

    await ctx.info("Synchronizing cluster database (subscriber with publisher)")
    try:
        client = await get_clearpass_client()
        sync_data: Dict[str, Any] = {}
        if timeout is not None:
            sync_data["timeout"] = timeout

        response = await client.sync_cluster_database(sync_data)

        return {
            "success": True,
            "db_sync": response,
            "message": "Cluster database synchronization requested successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to synchronize cluster database: {e}")
        return await format_api_error(e, "synchronize cluster database")
    except Exception as e:
        logger.error(f"Unexpected error synchronizing cluster database: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_data_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the data filter"),
    filter_data: Dict[str, Any] = Field(..., description="Data filter fields to update (e.g., name, description, type, attr_type, configuration_type, template, custom_sql, rule_eval_algo, rules)")
) -> Dict[str, Any]:
    """
    Update a data filter by name.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_data_filter_name_by_name' in pyclearpass (PATCH /data-filter/name/{name}).
    """
    await ctx.info(f"Updating data filter by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.update_data_filter_by_name(name, filter_data)

        return {
            "success": True,
            "data_filter": response,
            "message": f"Data filter '{name}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update data filter by name: {e}")
        return await format_api_error(e, f"update data filter by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error updating data filter by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_data_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the data filter"),
    filter_data: Dict[str, Any] = Field(..., description="Full data filter definition. Required keys: 'name', 'type', 'configuration_type'")
) -> Dict[str, Any]:
    """
    Replace a data filter by name.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_data_filter_name_by_name' in pyclearpass (PUT /data-filter/name/{name}).
    """
    await ctx.info(f"Replacing data filter by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.replace_data_filter_by_name(name, filter_data)

        return {
            "success": True,
            "data_filter": response,
            "message": f"Data filter '{name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace data filter by name: {e}")
        return await format_api_error(e, f"replace data filter by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing data filter by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_data_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the data filter to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a data filter by name.

    Permanently removes the specified data filter. This action cannot be undone.

    Maps to 'delete_data_filter_name_by_name' in pyclearpass (DELETE /data-filter/name/{name}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete data filter '{name}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting data filter by name: {name}")
    try:
        client = await get_clearpass_client()
        await client.delete_data_filter_by_name(name)

        return {
            "success": True,
            "message": f"Data filter '{name}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete data filter by name: {e}")
        return await format_api_error(e, f"delete data filter by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting data filter by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def get_local_user_password_policy_settings(ctx: Context) -> Dict[str, Any]:
    """
    Get the local user password policy.

    Reads the policy from the '/local-user/password-policy' resource path.

    Maps to 'get_local_user_password_policy' in pyclearpass (GET /local-user/password-policy).
    """
    await ctx.info("Getting local user password policy settings")
    try:
        client = await get_clearpass_client()
        response = await client.get_local_user_password_policy_settings()

        return {
            "success": True,
            "local_user_password_policy": response,
            "message": "Local user password policy retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get local user password policy settings: {e}")
        return await format_api_error(e, "get local user password policy settings")
    except Exception as e:
        logger.error(f"Unexpected error getting local user password policy settings: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_local_user_password_policy_settings(
    ctx: Context,
    policy_data: Dict[str, Any] = Field(..., description="Local user password policy fields to update (e.g., password_minimum_length, password_complexity, password_expiry_days, disable_after_days, reminder_days)")
) -> Dict[str, Any]:
    """
    Patch the local user password policy.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_local_user_password_policy' in pyclearpass (PATCH /local-user/password-policy).
    """
    await ctx.info("Updating local user password policy settings")
    try:
        client = await get_clearpass_client()
        response = await client.update_local_user_password_policy_settings(policy_data)

        return {
            "success": True,
            "local_user_password_policy": response,
            "message": "Local user password policy updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update local user password policy settings: {e}")
        return await format_api_error(e, "update local user password policy settings")
    except Exception as e:
        logger.error(f"Unexpected error updating local user password policy settings: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_local_user_password_policy_settings(
    ctx: Context,
    policy_data: Dict[str, Any] = Field(..., description="Full local user password policy definition. Required keys: 'password_minimum_length', 'password_complexity'")
) -> Dict[str, Any]:
    """
    Put the local user password policy.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_local_user_password_policy' in pyclearpass (PUT /local-user/password-policy).
    """
    await ctx.info("Replacing local user password policy settings")
    try:
        client = await get_clearpass_client()
        response = await client.replace_local_user_password_policy_settings(policy_data)

        return {
            "success": True,
            "local_user_password_policy": response,
            "message": "Local user password policy replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace local user password policy settings: {e}")
        return await format_api_error(e, "replace local user password policy settings")
    except Exception as e:
        logger.error(f"Unexpected error replacing local user password policy settings: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_operator_profile_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the operator profile"),
    profile_data: Dict[str, Any] = Field(..., description="Operator profile fields to update. Required keys: 'name', 'sponsor_filter'")
) -> Dict[str, Any]:
    """
    Update an operator profile by name.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_operator_profile_name_by_name' in pyclearpass (PATCH /operator-profile/name/{name}).
    """
    await ctx.info(f"Updating operator profile by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.update_operator_profile_by_name(name, profile_data)

        return {
            "success": True,
            "operator_profile": response,
            "message": f"Operator profile '{name}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update operator profile by name: {e}")
        return await format_api_error(e, f"update operator profile by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error updating operator profile by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_operator_profile_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the operator profile"),
    profile_data: Dict[str, Any] = Field(..., description="Full operator profile definition. Required keys: 'name', 'sponsor_filter'")
) -> Dict[str, Any]:
    """
    Replace an operator profile by name.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_operator_profile_name_by_name' in pyclearpass (PUT /operator-profile/name/{name}).
    """
    await ctx.info(f"Replacing operator profile by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.replace_operator_profile_by_name(name, profile_data)

        return {
            "success": True,
            "operator_profile": response,
            "message": f"Operator profile '{name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace operator profile by name: {e}")
        return await format_api_error(e, f"replace operator profile by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing operator profile by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_operator_profile_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the operator profile to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an operator profile by name.

    Permanently removes the specified operator profile. This action cannot be undone.

    Maps to 'delete_operator_profile_name_by_name' in pyclearpass (DELETE /operator-profile/name/{name}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete operator profile '{name}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting operator profile by name: {name}")
    try:
        client = await get_clearpass_client()
        await client.delete_operator_profile_by_name(name)

        return {
            "success": True,
            "message": f"Operator profile '{name}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete operator profile by name: {e}")
        return await format_api_error(e, f"delete operator profile by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting operator profile by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def update_snmp_trap_receiver_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name (host address) of the SNMP trap receiver"),
    receiver_data: Dict[str, Any] = Field(..., description="SNMP trap receiver fields to update (e.g., host_address, description, snmp_version, community_string, server_port, user, type, auth_key, priv_key, priv_protocol, auth_protocol, security_level)")
) -> Dict[str, Any]:
    """
    Update some fields of an SNMP trap receiver by name.

    Performs a partial update (PATCH); only the supplied fields are modified.

    Maps to 'update_snmp_trap_receiver_name_by_name' in pyclearpass (PATCH /snmp-trap-receiver/name/{name}).
    """
    await ctx.info(f"Updating SNMP trap receiver by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.update_snmp_trap_receiver_by_name(name, receiver_data)

        return {
            "success": True,
            "snmp_trap_receiver": response,
            "message": f"SNMP trap receiver '{name}' updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update SNMP trap receiver by name: {e}")
        return await format_api_error(e, f"update SNMP trap receiver by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error updating SNMP trap receiver by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def replace_snmp_trap_receiver_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name (host address) of the SNMP trap receiver"),
    receiver_data: Dict[str, Any] = Field(..., description="Full SNMP trap receiver definition. Required keys: 'host_address', 'snmp_version'")
) -> Dict[str, Any]:
    """
    Replace an SNMP trap receiver by name.

    Performs a full replacement (PUT); any field omitted from the body is reset.

    Maps to 'replace_snmp_trap_receiver_name_by_name' in pyclearpass (PUT /snmp-trap-receiver/name/{name}).
    """
    await ctx.info(f"Replacing SNMP trap receiver by name: {name}")
    try:
        client = await get_clearpass_client()
        response = await client.replace_snmp_trap_receiver_by_name(name, receiver_data)

        return {
            "success": True,
            "snmp_trap_receiver": response,
            "message": f"SNMP trap receiver '{name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace SNMP trap receiver by name: {e}")
        return await format_api_error(e, f"replace SNMP trap receiver by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error replacing SNMP trap receiver by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="global_server_config")
async def delete_snmp_trap_receiver_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name (host address) of the SNMP trap receiver to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an SNMP trap receiver by name.

    Permanently removes the specified SNMP trap receiver. This action cannot be undone.

    Maps to 'delete_snmp_trap_receiver_name_by_name' in pyclearpass (DELETE /snmp-trap-receiver/name/{name}).
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete SNMP trap receiver '{name}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting SNMP trap receiver by name: {name}")
    try:
        client = await get_clearpass_client()
        await client.delete_snmp_trap_receiver_by_name(name)

        return {
            "success": True,
            "message": f"SNMP trap receiver '{name}' deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete SNMP trap receiver by name: {e}")
        return await format_api_error(e, f"delete SNMP trap receiver by name '{name}'")
    except Exception as e:
        logger.error(f"Unexpected error deleting SNMP trap receiver by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}
