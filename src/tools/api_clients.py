"""
MCP tools for API Client management.
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


@operation(domain="api_clients")
async def list_api_clients(
    ctx: Context,
    filter_enabled: Optional[bool] = None,
    limit: int = Field(default=50, description="Maximum number of results")
) -> Dict[str, Any]:
    """List ClearPass API clients with optional filtering."""
    await ctx.info(f"Retrieving API clients (limit: {limit})...")
    
    try:
        # Get ClearPass client instance
        client = await get_clearpass_client()
        
        # Make API call
        response = await client.list_api_clients(filter_enabled=filter_enabled, limit=limit)
        
        # Format response for LLM consumption
        if "_embedded" in response and "items" in response["_embedded"]:
            clients = response["_embedded"]["items"]
        else:
            clients = response.get("items", [])
        
        return {
            "success": True,
            "total_count": len(clients),
            "clients": clients,
            "message": f"Retrieved {len(clients)} API clients"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to list API clients: {e}")
        return await format_api_error(e, "list API clients")
    except Exception as e:
        logger.error(f"Unexpected error listing API clients: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing API clients"
        }


@operation(domain="api_clients")
async def create_api_client(
    ctx: Context,
    client_id: str = Field(..., description="Unique client identifier"),
    description: str = Field(..., description="Description of the API client"),
    scope: str = Field(default="read", description="API access scope (read, write, read write)"),
    enabled: bool = Field(default=True, description="Whether the client should be enabled")
) -> Dict[str, Any]:
    """Create a new ClearPass API client."""
    await ctx.info(f"Creating API client: {client_id}")
    
    # Validate scope
    valid_scopes = ["read", "write", "read write"]
    if scope not in valid_scopes:
        return {
            "success": False,
            "error": f"Invalid scope '{scope}'. Must be one of: {', '.join(valid_scopes)}",
            "message": "Please provide a valid scope and try again."
        }
    
    try:
        # Get ClearPass client instance
        client = await get_clearpass_client()
        
        # Prepare client data
        client_data = {
            "client_id": client_id,
            "client_description": description,  # Fixed: Use correct API field name
            "enabled": enabled,
            # Note: scope is not supported by ClearPass API according to documentation
            # "scope": scope,  # Removed as it's not supported
            "grant_types": "client_credentials",  # Fixed: Should be string not array according to API docs
            # Required fields for API client creation
            # "id": client_id,  # Removed: Causes 404 error on POST
            "access_token_lifetime": "365",  # Default 365 days
            "access_token_lifetime_units": "days",  # Fixed: Must be lowercase
            "refresh_token_lifetime": "14", # Default 14 days  
            "refresh_token_lifetime_units": "days",  # Fixed: Must be lowercase
            "profile_id": "1"  # Default to Super Administrator profile (must be string)
        }
        
        # Make API call
        response = await client.create_api_client(client_data)
        
        await ctx.info(f"Successfully created API client: {client_id}")
        
        return {
            "success": True,
            "message": f"API client '{client_id}' created successfully",
            "client": response,
            "important_note": "Please save the client_secret as it won't be displayed again"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to create API client: {e}")
        return await format_api_error(e, "create API client")
    except Exception as e:
        logger.error(f"Unexpected error creating API client: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the API client"
        }


@operation(domain="api_clients")
async def get_api_client(
    ctx: Context,
    client_id: Union[int, str] = Field(..., description="API client ID or client_id")
) -> Dict[str, Any]:
    """Get details of a specific ClearPass API client."""
    await ctx.info(f"Retrieving API client: {client_id}")
    
    try:
        # Get ClearPass client instance
        client = await get_clearpass_client()
        
        # Make API call
        response = await client.get_api_client(client_id)
        
        return {
            "success": True,
            "client": response,
            "message": f"Retrieved API client details for: {client_id}"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to get API client: {e}")
        return await format_api_error(e, "get API client")
    except Exception as e:
        logger.error(f"Unexpected error getting API client: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving the API client"
        }


@operation(domain="api_clients")
async def update_api_client(
    ctx: Context,
    client_id: Union[int, str] = Field(..., description="API client ID or client_id to update"),
    description: Optional[str] = Field(None, description="New description"),
    enabled: Optional[bool] = Field(None, description="Enable/disable the client"),
    scope: Optional[str] = Field(None, description="New API access scope")
) -> Dict[str, Any]:
    """Update an existing ClearPass API client."""
    await ctx.info(f"Updating API client: {client_id}")
    
    update_data = {}
    if description is not None and isinstance(description, str):
        update_data["client_description"] = description  # Fixed: Use correct API field name
    if enabled is not None and isinstance(enabled, bool):
        update_data["enabled"] = enabled
    if scope is not None and isinstance(scope, str): # Ensure scope is a string before validation
        # Note: ClearPass API documentation shows scope as "Not supported at this time"
        # This parameter is kept for backward compatibility but may not work
        valid_scopes = ["read", "write", "read write"]
        if scope not in valid_scopes:
            return {
                "success": False,
                "error": f"Invalid scope '{scope}'. Must be one of: {', '.join(valid_scopes)}",
                "message": "Please provide a valid scope and try again."
            }
        update_data["scope"] = scope
    elif scope is not None and not isinstance(scope, str):
        # This case handles the FastMCP/Pydantic issue where Field object is passed
        # Treat it as if no scope was provided, or return an error if strict
        # For now, we'll just ignore it, as it means the user didn't explicitly set it.
        pass
    
    if not update_data:
        return {
            "success": False,
            "error": "No update parameters provided. Please provide at least one parameter to update (description, enabled, or scope).",
            "message": "No changes requested."
        }

    try:
        # Get ClearPass client instance
        client = await get_clearpass_client()
        
        # Make API call
        response = await client.update_api_client(client_id, update_data)
        
        return {
            "success": True,
            "message": f"API client '{client_id}' updated successfully",
            "client": response,
            "updated_fields": list(update_data.keys())
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to update API client: {e}")
        return await format_api_error(e, "update API client")
    except Exception as e:
        logger.error(f"Unexpected error updating API client: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the API client"
        }


@operation(domain="api_clients")
async def delete_api_client(
    ctx: Context,
    client_id: Union[int, str] = Field(..., description="API client ID or client_id to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a ClearPass API client."""
    await ctx.info(f"Deleting API client: {client_id}")
    
    # Safety check - require confirmation
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting an API client will immediately revoke access for any applications using it."
        }
    
    try:
        # Get ClearPass client instance
        client = await get_clearpass_client()
        
        # Make API call
        await client.delete_api_client(client_id)
        
        return {
            "success": True,
            "message": f"API client '{client_id}' deleted successfully",
            "warning": "Any applications using this client will no longer be able to authenticate"
        }
        
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete API client: {e}")
        return await format_api_error(e, "delete API client")
    except Exception as e:
        logger.error(f"Unexpected error deleting API client: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the API client"
        }