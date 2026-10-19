"""
MCP tools for Guest User management.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


def _is_numeric_guest_id(user_id: Union[int, str]) -> bool:
    """True when ``user_id`` is a guest account ID rather than a username.

    This is the single branch rule shared by get / update / delete: ClearPass
    exposes ``guest/<id>`` and ``guest/username/<name>`` as separate resources
    and rejects a username sent to the id route with
    ``422 ID '<name>' is invalid``.
    """
    return isinstance(user_id, int) or (
        isinstance(user_id, str) and user_id.isdigit()
    )


@operation(domain="guest_users")
async def list_guest_users(
    ctx: Context,
    filter_enabled: Optional[bool] = None,
    role_filter: Optional[str] = None,
    limit: int = Field(default=50, description="Maximum number of results")
) -> Dict[str, Any]:
    """List ClearPass guest users with optional filtering."""
    await ctx.info(f"Retrieving guest users (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        response = await client.list_guest_users(
            filter_enabled=filter_enabled,
            role_filter=role_filter,
            limit=limit
        )
        
        if "_embedded" in response and "items" in response["_embedded"]:
            users = response["_embedded"]["items"]
        else:
            users = response.get("items", [])
            
        return {
            "success": True,
            "total_count": len(users),
            "users": users,
            "message": f"Retrieved {len(users)} guest users"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list guest users: {e}")
        return await format_api_error(e, "list guest users")
    except Exception as e:
        logger.error(f"Unexpected error listing guest users: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing guest users"
        }


@operation(domain="guest_users")
async def get_guest_user(
    ctx: Context,
    user_id: Union[int, str] = Field(..., description="Guest user ID (numeric) or username (string)")
) -> Dict[str, Any]:
    """Get details of a specific ClearPass guest user by ID or username."""
    await ctx.info(f"Retrieving guest user: {user_id}")
    
    try:
        client = await get_clearpass_client()
        
        # Try to determine if this is a numeric ID or username
        if _is_numeric_guest_id(user_id):
            # Numeric ID - use standard endpoint
            response = await client.get_guest_user(user_id)
        else:
            # String username - use username endpoint
            response = await client.get_guest_user_by_username(user_id)
        
        return {
            "success": True,
            "user": response,
            "message": f"Retrieved guest user details for: {user_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get guest user: {e}")
        return await format_api_error(e, "get guest user")
    except Exception as e:
        logger.error(f"Unexpected error getting guest user: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving the guest user"
        }


@operation(domain="guest_users")
async def create_guest_user(
    ctx: Context,
    username: str = Field(..., description="Guest username"),
    password: str = Field(..., description="Guest password"),
    role_name: str = Field(default="[Guest]", description="Guest Manager role name, e.g. '[Guest]', '[Contractor]', '[Employee]' (resolved to the guest role_id)"),
    role_id: Optional[int] = Field(None, description="Guest Manager role ID (takes precedence over role_name). NOT a Policy Manager role id"),
    expire_time: Optional[str] = Field(None, description="Account expiration time (ISO 8601 format)"),
    sponsor_profile: Optional[str] = Field(None, description="Sponsor profile"),
    enabled: bool = Field(default=True, description="Whether account is enabled")
) -> Dict[str, Any]:
    """Create a new ClearPass guest user. Either role_name or role_id must be provided.

    Roles are resolved against the Guest Manager role namespace (the namespace a
    guest account's role_id belongs to), NOT the Policy Manager /role namespace.
    The built-in guest roles are '[Contractor]', '[Guest]' and '[Employee]'.
    """
    await ctx.info(f"Creating guest user: {username}")
    
    try:
        client = await get_clearpass_client()
        user_data = {
            "username": username,
            "password": password,
            "enabled": enabled
        }
        
        # Use role_id if provided, otherwise use role_name
        if role_id is not None:
            user_data["role_id"] = role_id
        else:
            user_data["role_name"] = role_name
            
        if expire_time:
            user_data["expire_time"] = expire_time
        if sponsor_profile:
            user_data["sponsor_profile"] = sponsor_profile
            
        response = await client.create_guest_user(user_data)
        
        await ctx.info(f"Successfully created guest user: {username}")
        
        return {
            "success": True,
            "message": f"Guest user '{username}' created successfully",
            "user": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create guest user: {e}")
        return await format_api_error(e, "create guest user")
    except ValueError as e:
        logger.error(f"Role validation error: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "Role validation failed"
        }
    except Exception as e:
        logger.error(f"Unexpected error creating guest user: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the guest user"
        }


@operation(domain="guest_users")
async def update_guest_user(
    ctx: Context,
    user_id: Union[int, str] = Field(..., description="Guest user ID or username to update"),
    username: Optional[str] = Field(None, description="New guest username"),
    password: Optional[str] = Field(None, description="New guest password"),
    role_name: Optional[str] = Field(None, description="New Guest Manager role name, e.g. '[Guest]' (resolved to the guest role_id)"),
    role_id: Optional[int] = Field(None, description="New Guest Manager role ID (takes precedence over role_name). NOT a Policy Manager role id"),
    expire_time: Optional[str] = Field(None, description="New account expiration time (ISO 8601 format)"),
    sponsor_profile: Optional[str] = Field(None, description="New sponsor profile"),
    enabled: Optional[bool] = Field(None, description="New account enabled status")
) -> Dict[str, Any]:
    """Update an existing ClearPass guest user."""
    await ctx.info(f"Updating guest user: {user_id}")
    
    update_data = {}
    if username is not None and isinstance(username, str):
        update_data["username"] = username
    if password is not None and isinstance(password, str):
        update_data["password"] = password
    
    # Handle role_id vs role_name
    if role_id is not None:
        update_data["role_id"] = role_id
    elif role_name is not None and isinstance(role_name, str):
        update_data["role_name"] = role_name
        
    if expire_time is not None and isinstance(expire_time, str):
        update_data["expire_time"] = expire_time
    if sponsor_profile is not None and isinstance(sponsor_profile, str):
        update_data["sponsor_profile"] = sponsor_profile
    if enabled is not None and isinstance(enabled, bool):
        update_data["enabled"] = enabled
        
    if not update_data:
        return {
            "success": False,
            "error": "No update parameters provided. Please provide at least one parameter to update.",
            "message": "No changes requested."
        }
        
    try:
        client = await get_clearpass_client()

        # Same branch rule as get_guest_user: ClearPass rejects a username sent
        # to the by-id route with 422 "ID '<name>' is invalid".
        if _is_numeric_guest_id(user_id):
            response = await client.update_guest_user(user_id, update_data)
        else:
            response = await client.update_guest_user_by_username(user_id, update_data)

        return {
            "success": True,
            "message": f"Guest user '{user_id}' updated successfully",
            "user": response,
            "updated_fields": list(update_data.keys())
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update guest user: {e}")
        return await format_api_error(e, "update guest user")
    except ValueError as e:
        logger.error(f"Role validation error: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "Role validation failed"
        }
    except Exception as e:
        logger.error(f"Unexpected error updating guest user: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the guest user"
        }


@operation(domain="guest_users")
async def delete_guest_user(
    ctx: Context,
    user_id: Union[int, str] = Field(..., description="Guest user ID or username to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a ClearPass guest user."""
    await ctx.info(f"Deleting guest user: {user_id}")
    
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a guest user will remove their account from ClearPass."
        }
        
    try:
        client = await get_clearpass_client()

        # Same branch rule as get_guest_user.
        if _is_numeric_guest_id(user_id):
            await client.delete_guest_user(user_id)
        else:
            await client.delete_guest_user_by_username(user_id)


        return {
            "success": True,
            "message": f"Guest user '{user_id}' deleted successfully",
            "warning": "The guest user account has been removed from ClearPass."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete guest user: {e}")
        return await format_api_error(e, "delete guest user")
    except Exception as e:
        logger.error(f"Unexpected error deleting guest user: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the guest user"
        }