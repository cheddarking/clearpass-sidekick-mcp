"""
MCP tools for server utility functions.
"""

import logging
from typing import Dict, List, Optional, Any
from fastmcp import Context
from pydantic import Field

from ..app_config import mcp, get_clearpass_client, CLEARPASS_CONFIG, credentials_manager
from ..exceptions import ClearPassAPIError
from ..utils import format_api_error
from ..credentials import CredentialsManager, CredentialsError

logger = logging.getLogger(__name__)


@mcp.tool()
async def get_server_info(ctx: Context) -> Dict[str, Any]:
    """Get ClearPass Sidekick server information and configuration status."""
    await ctx.info("Retrieving server information...")
    
    # Determine authentication method
    auth_method = "none"
    auth_configured = False
    
    if CLEARPASS_CONFIG.get("api_token"):
        auth_method = "api_token"
        auth_configured = True
    elif CLEARPASS_CONFIG.get("client_id") and CLEARPASS_CONFIG.get("client_secret"):
        auth_method = "client_credentials"
        auth_configured = True
    
    config_status = {
        "host_configured": bool(CLEARPASS_CONFIG.get("host") or CLEARPASS_CONFIG.get("server")),
        "authentication_method": auth_method,
        "credentials_configured": auth_configured,
        "api_version": CLEARPASS_CONFIG["api_version"],
        "ssl_verification": CLEARPASS_CONFIG["verify_ssl"],
        "credentials_source": "credentials_manager" if "clearpass_credentials" in locals() else "environment_variables"
    }
    
    return {
        "server_name": "ClearPass Sidekick MCP Server",
        "version": "1.0.0",
        "description": "Natural language automation for Aruba ClearPass",
        "configuration_status": config_status,
        "available_operations": [
            "API Client Management",
            "Network Device Management", 
            "Guest User Management",
            "Certificate Operations",
            "Audit Log Queries"
        ]
    }


@mcp.tool()
async def _test_clearpass_connection_tool(ctx: Context) -> Dict[str, Any]:
    """Test the connection to ClearPass and display configuration status."""
    await ctx.info("Testing ClearPass connection...")
    
    try:
        # Try to get and authenticate client
        client = await get_clearpass_client()
        
        # Test with a simple API call
        health_response = await client.get_system_health()
        
        return {
            "success": True,
            "message": "Successfully connected to ClearPass",
            "connection_details": {
                "host": CLEARPASS_CONFIG.get("host"),
                "api_version": CLEARPASS_CONFIG.get("api_version"),
                "authentication_method": "client_credentials" if CLEARPASS_CONFIG.get("client_id") else "api_token",
                "ssl_verification": CLEARPASS_CONFIG.get("verify_ssl")
            },
            "health_status": health_response
        }
        
    except ClearPassAPIError as e:
        logger.error(f"ClearPass connection test failed: {e}")
        return await format_api_error(e, "test connection")
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return {
            "success": False,
            "error": str(e),
            "configuration_status": {
                "host_configured": bool(CLEARPASS_CONFIG.get("host")),
                "credentials_configured": bool(CLEARPASS_CONFIG.get("client_id") and CLEARPASS_CONFIG.get("client_secret")),
                "suggestions": [
                    "Verify ClearPass host configuration",
                    "Check client credentials",
                    "Ensure network connectivity to ClearPass server"
                ]
            }
        }
    except Exception as e:
        logger.error(f"Unexpected error testing connection: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while testing the connection"
        }


@mcp.tool()
async def manage_credentials(
    ctx: Context,
    action: str = Field(..., description="Action to perform: 'status', 'validate', 'create_template'"),
    config_path: Optional[str] = Field(None, description="Custom path for credentials file")
) -> Dict[str, Any]:
    """Manage ClearPass credentials configuration."""
    await ctx.info(f"Managing credentials: {action}")
    
    # Use custom path if provided, otherwise use default
    manager = CredentialsManager(config_path=config_path) if config_path else credentials_manager
    
    try:
        if action == "status":
            # Check current credential status
            try:
                creds = manager.load_credentials()
                masked_creds = manager.mask_sensitive_data(creds)
                return {
                    "success": True,
                    "status": "configured",
                    "credentials": masked_creds,
                    "message": "Credentials are properly configured"
                }
            except CredentialsError as e:
                return {
                    "success": False,
                    "status": "not_configured",
                    "error": str(e),
                    "message": "No valid credentials found"
                }
        
        elif action == "validate":
            # Validate current credentials
            try:
                creds = manager.load_credentials()
                is_valid = manager.validate_credentials(creds)
                
                # Try to create a ClearPass login to test connectivity
                try:
                    login_client = manager.get_clearpass_login()
                    return {
                        "success": True,
                        "valid": True,
                        "message": "Credentials are valid and ClearPass connection successful",
                        "authentication_method": "api_token" if creds.get("api_token") else "client_credentials"
                    }
                except Exception as e:
                    return {
                        "success": True,
                        "valid": False,
                        "message": f"Credentials format is valid but connection failed: {str(e)}",
                        "authentication_method": "api_token" if creds.get("api_token") else "client_credentials"
                    }
                    
            except CredentialsError as e:
                return {
                    "success": False,
                    "valid": False,
                    "error": str(e),
                    "message": "Invalid or missing credentials"
                }
        
        elif action == "create_template":
            # Create a template configuration file
            template_path = manager.create_config_template()
            return {
                "success": True,
                "message": f"Configuration template created at: {template_path}",
                "template_path": str(template_path),
                "instructions": "Edit the template file with your ClearPass server details and credentials"
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown action: {action}",
                "valid_actions": ["status", "validate", "create_template"]
            }
            
    except Exception as e:
        logger.error(f"Error managing credentials: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while managing credentials"
        }


async def _list_available_tools_impl(
    ctx: Context,
    search_term: Optional[str] = None
) -> Dict[str, Any]:
    """
    Implementation of list_available_tools function.
    
    This function provides tool discovery by listing all registered MCP tools
    with their names and descriptions. Optionally filter results by search term.
    
    Args:
        search_term: Optional string to filter tools by name or description (case-insensitive)
    
    Returns:
        Dictionary containing success status, total tool count, and list of tools
    """
    search_filter_text = f" with filter: {search_term}" if search_term else ""
    await ctx.info(f"Listing available tools{search_filter_text}...")
    
    try:
        # Get all tools from FastMCP registry
        tools_registry = await mcp.get_tools()
        
        # Convert to list of tool information
        tools_list = []
        for tool_name, tool_obj in tools_registry.items():
            tool_info = {
                "name": tool_name,
                "description": tool_obj.description or "No description available"
            }
            
            # Apply search filter if provided
            if search_term:
                search_lower = search_term.lower()
                if (search_lower in tool_name.lower() or 
                    search_lower in tool_info["description"].lower()):
                    tools_list.append(tool_info)
            else:
                tools_list.append(tool_info)
        
        # Sort tools by name for consistent output
        tools_list.sort(key=lambda x: x["name"])
        
        return {
            "success": True,
            "total_tools": len(tools_list),
            "filtered": bool(search_term),
            "search_term": search_term,
            "tools": tools_list,
            "message": f"Found {len(tools_list)} tool{'s' if len(tools_list) != 1 else ''}"
        }
        
    except Exception as e:
        logger.error(f"Failed to list tools: {e}")
        return {
            "success": False,
            "error": f"Failed to list tools: {str(e)}",
            "message": "An error occurred while retrieving the tool list"
        }


@mcp.tool()
async def list_available_tools(
    ctx: Context,
    search_term: Optional[str] = Field(None, description="Optional search term to filter tools by name or description")
) -> Dict[str, Any]:
    """
    List all available ClearPass Sidekick tools with their descriptions.
    
    This function provides tool discovery by listing all registered MCP tools
    with their names and descriptions. Optionally filter results by search term.
    
    Args:
        search_term: Optional string to filter tools by name or description (case-insensitive)
    
    Returns:
        Dictionary containing success status, total tool count, and list of tools
    """
    return await _list_available_tools_impl(ctx, search_term)