"""
MCP tools for ClearPass third-party integration operations.

This module exposes the ClearPass integration surface as registry operations:
endpoint context servers and their context server actions, Device Insight,
ingress event sources and event dictionaries, ClearPass Extensions (instance
lifecycle, configuration, logs, upgrades and the extension store), and syslog
export filters/targets.
"""

import logging
from typing import Any, Dict, Optional

from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation
from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


# ============================================================================
# CONTEXT SERVER ACTIONS
# ============================================================================


@operation(domain="integrations")
async def list_context_server_actions(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List context server actions configured on ClearPass.

    Context server actions are the HTTP calls ClearPass makes out to an endpoint context server (for example Palo Alto, Aruba Central or a generic HTTP server).

    Maps to 'get_context_server_action' in pyclearpass (GET /context-server-action).
    """
    await ctx.info("Retrieving context server actions...")

    try:
        client = await get_clearpass_client()
        result = await client.list_context_server_actions(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} context server actions."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list context server actions: {e}")
        return await format_api_error(e, "list context server actions")
    except Exception as e:
        logger.error(f"Unexpected error trying to list context server actions: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list context server actions."
        }


@operation(domain="integrations")
async def create_context_server_action(
    ctx: Context,
    action_data: Dict[str, Any] = Field(..., description="Context server action definition (server_type, server_name, action_name, action_type, description, http_method, auth_method, url, content_type, content, headers, attributes)")
) -> Dict[str, Any]:
    """
    Create a new context server action.

    Required body fields: server_type, action_name, http_method, url.

    Maps to 'new_context_server_action' in pyclearpass (POST /context-server-action).
    """
    await ctx.info("Creating context server action...")

    try:
        client = await get_clearpass_client()
        result = await client.create_context_server_action(action_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully created the context server action."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create context server action: {e}")
        return await format_api_error(e, "create context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to create context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create context server action."
        }


@operation(domain="integrations")
async def get_context_server_action_by_id(
    ctx: Context,
    context_server_action_id: int = Field(..., description="Numeric ID of the context server action")
) -> Dict[str, Any]:
    """
    Get a context server action by numeric ID.

    Returns the full configuration of a single context server action.

    Maps to 'get_context_server_action_by_context_server_action_id' in pyclearpass (GET /context-server-action/{context_server_action_id}).
    """
    await ctx.info(f"Retrieving context server action {context_server_action_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_context_server_action_by_id(context_server_action_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved context server action {context_server_action_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get context server action: {e}")
        return await format_api_error(e, "get context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to get context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get context server action."
        }


@operation(domain="integrations")
async def update_context_server_action_by_id(
    ctx: Context,
    context_server_action_id: int = Field(..., description="Numeric ID of the context server action"),
    action_data: Dict[str, Any] = Field(..., description="Context server action definition (server_type, server_name, action_name, action_type, description, http_method, auth_method, url, content_type, content, headers, attributes)")
) -> Dict[str, Any]:
    """
    Update selected fields of a context server action by numeric ID.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_context_server_action_by_context_server_action_id' in pyclearpass (PATCH /context-server-action/{context_server_action_id}).
    """
    await ctx.info(f"Updating context server action {context_server_action_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_context_server_action_by_id(context_server_action_id, action_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated context server action {context_server_action_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update context server action: {e}")
        return await format_api_error(e, "update context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to update context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update context server action."
        }


@operation(domain="integrations")
async def replace_context_server_action_by_id(
    ctx: Context,
    context_server_action_id: int = Field(..., description="Numeric ID of the context server action"),
    action_data: Dict[str, Any] = Field(..., description="Context server action definition (server_type, server_name, action_name, action_type, description, http_method, auth_method, url, content_type, content, headers, attributes)")
) -> Dict[str, Any]:
    """
    Replace a context server action by numeric ID.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: server_type, action_name, http_method, url.

    Maps to 'replace_context_server_action_by_context_server_action_id' in pyclearpass (PUT /context-server-action/{context_server_action_id}).
    """
    await ctx.info(f"Replacing context server action {context_server_action_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_context_server_action_by_id(context_server_action_id, action_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced context server action {context_server_action_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace context server action: {e}")
        return await format_api_error(e, "replace context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace context server action."
        }


@operation(domain="integrations")
async def delete_context_server_action_by_id(
    ctx: Context,
    context_server_action_id: int = Field(..., description="Numeric ID of the context server action")
) -> Dict[str, Any]:
    """
    Delete a context server action by numeric ID.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_context_server_action_by_context_server_action_id' in pyclearpass (DELETE /context-server-action/{context_server_action_id}).
    """
    await ctx.info(f"Deleting context server action {context_server_action_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_context_server_action_by_id(context_server_action_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted context server action {context_server_action_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete context server action: {e}")
        return await format_api_error(e, "delete context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete context server action."
        }


@operation(domain="integrations")
async def get_context_server_action_by_name(
    ctx: Context,
    server_type: str = Field(..., description="Server type of the context server action"),
    action_name: str = Field(..., description="Unique action name of the context server action")
) -> Dict[str, Any]:
    """
    Get a context server action by server type and action name.

    Returns the full configuration of a single context server action.

    Maps to 'get_context_server_action_by_server_type_action_name_action_name' in pyclearpass (GET /context-server-action/{server_type}/action-name/{action_name}).
    """
    await ctx.info(f"Retrieving context server action '{action_name}' ({server_type})...")

    try:
        client = await get_clearpass_client()
        result = await client.get_context_server_action_by_name(server_type, action_name)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved context server action '{action_name}' ({server_type})."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get context server action: {e}")
        return await format_api_error(e, "get context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to get context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get context server action."
        }


@operation(domain="integrations")
async def update_context_server_action_by_name(
    ctx: Context,
    server_type: str = Field(..., description="Server type of the context server action"),
    action_name: str = Field(..., description="Unique action name of the context server action"),
    action_data: Dict[str, Any] = Field(..., description="Context server action definition (server_type, server_name, action_name, action_type, description, http_method, auth_method, url, content_type, content, headers, attributes)")
) -> Dict[str, Any]:
    """
    Update selected fields of a context server action by server type and action name.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_context_server_action_by_server_type_action_name_action_name' in pyclearpass (PATCH /context-server-action/{server_type}/action-name/{action_name}).
    """
    await ctx.info(f"Updating context server action '{action_name}' ({server_type})...")

    try:
        client = await get_clearpass_client()
        result = await client.update_context_server_action_by_name(server_type, action_name, action_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated context server action '{action_name}' ({server_type})."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update context server action: {e}")
        return await format_api_error(e, "update context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to update context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update context server action."
        }


@operation(domain="integrations")
async def replace_context_server_action_by_name(
    ctx: Context,
    server_type: str = Field(..., description="Server type of the context server action"),
    action_name: str = Field(..., description="Unique action name of the context server action"),
    action_data: Dict[str, Any] = Field(..., description="Context server action definition (server_type, server_name, action_name, action_type, description, http_method, auth_method, url, content_type, content, headers, attributes)")
) -> Dict[str, Any]:
    """
    Replace a context server action by server type and action name.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: server_type, action_name, http_method, url.

    Maps to 'replace_context_server_action_by_server_type_action_name_action_name' in pyclearpass (PUT /context-server-action/{server_type}/action-name/{action_name}).
    """
    await ctx.info(f"Replacing context server action '{action_name}' ({server_type})...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_context_server_action_by_name(server_type, action_name, action_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced context server action '{action_name}' ({server_type})."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace context server action: {e}")
        return await format_api_error(e, "replace context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace context server action."
        }


@operation(domain="integrations")
async def delete_context_server_action_by_name(
    ctx: Context,
    server_type: str = Field(..., description="Server type of the context server action"),
    action_name: str = Field(..., description="Unique action name of the context server action")
) -> Dict[str, Any]:
    """
    Delete a context server action by server type and action name.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_context_server_action_by_server_type_action_name_action_name' in pyclearpass (DELETE /context-server-action/{server_type}/action-name/{action_name}).
    """
    await ctx.info(f"Deleting context server action '{action_name}' ({server_type})...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_context_server_action_by_name(server_type, action_name)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted context server action '{action_name}' ({server_type})."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete context server action: {e}")
        return await format_api_error(e, "delete context server action")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete context server action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete context server action."
        }


# ============================================================================
# DEVICE INSIGHT INTEGRATION
# ============================================================================


@operation(domain="integrations")
async def get_device_insight_config(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get the Device Insight integration configuration.

    Returns activation status, polling interval, collector ID and CoA behaviour for the Aruba Device Insight integration.

    Maps to 'get_device_insight' in pyclearpass (GET /device-insight).
    """
    await ctx.info("Retrieving Device Insight integration configuration...")

    try:
        client = await get_clearpass_client()
        result = await client.get_device_insight_config()

        return {
            "success": True,
            "data": result,
            "message": "Retrieved the Device Insight integration configuration."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Device Insight configuration: {e}")
        return await format_api_error(e, "get Device Insight configuration")
    except Exception as e:
        logger.error(f"Unexpected error trying to get Device Insight configuration: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get Device Insight configuration."
        }


@operation(domain="integrations")
async def update_device_insight_config(
    ctx: Context,
    device_insight_data: Dict[str, Any] = Field(..., description="Device Insight settings (enable_device_insight, activation_token, primary_clearpass_server_uuid, standby_clearpass_server_uuid, bypass_proxy, polling_interval, sync_time, tag_update_action, tags_for_disconnect, radius_coa_action)")
) -> Dict[str, Any]:
    """
    Update the Device Insight integration configuration.

    Enables/disables the integration and updates the activation token, polling behaviour and CoA/tag actions.

    Maps to 'new_device_insight' in pyclearpass (POST /device-insight).
    """
    await ctx.info("Updating Device Insight integration configuration...")

    try:
        client = await get_clearpass_client()
        result = await client.update_device_insight_config(device_insight_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully updated the Device Insight integration configuration."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update Device Insight configuration: {e}")
        return await format_api_error(e, "update Device Insight configuration")
    except Exception as e:
        logger.error(f"Unexpected error trying to update Device Insight configuration: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update Device Insight configuration."
        }


# ============================================================================
# ENDPOINT CONTEXT SERVERS
# ============================================================================


@operation(domain="integrations")
async def list_endpoint_context_servers(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List endpoint context servers configured on ClearPass.

    Endpoint context servers are the external systems (MDM/EMM, firewalls, Aruba Central, etc.) ClearPass exchanges endpoint context with.

    Maps to 'get_endpoint_context_server' in pyclearpass (GET /endpoint-context-server).
    """
    await ctx.info("Retrieving endpoint context servers...")

    try:
        client = await get_clearpass_client()
        result = await client.list_endpoint_context_servers(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} endpoint context servers."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list endpoint context servers: {e}")
        return await format_api_error(e, "list endpoint context servers")
    except Exception as e:
        logger.error(f"Unexpected error trying to list endpoint context servers: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list endpoint context servers."
        }


@operation(domain="integrations")
async def create_endpoint_context_server(
    ctx: Context,
    server_data: Dict[str, Any] = Field(..., description="Endpoint context server definition (server_type, server_name, server_base_url, auth_method, username, password, oauth2_client_id, oauth2_client_secret, oauth2_access_token_url, vendor_attrs, validate_server, status, ip_version, bypass_proxy)")
) -> Dict[str, Any]:
    """
    Create a new endpoint context server.

    Required body fields: server_type, server_name, server_base_url, auth_method, validate_server, status, bypass_proxy.

    Maps to 'new_endpoint_context_server' in pyclearpass (POST /endpoint-context-server).
    """
    await ctx.info("Creating endpoint context server...")

    try:
        client = await get_clearpass_client()
        result = await client.create_endpoint_context_server(server_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully created the endpoint context server."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create endpoint context server: {e}")
        return await format_api_error(e, "create endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to create endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create endpoint context server."
        }


@operation(domain="integrations")
async def get_endpoint_context_server_by_name(
    ctx: Context,
    server_name: str = Field(..., description="Unique name of the endpoint context server")
) -> Dict[str, Any]:
    """
    Get a endpoint context server by server name.

    Returns the full configuration of a single endpoint context server.

    Maps to 'get_endpoint_context_server_server_name_by_server_name' in pyclearpass (GET /endpoint-context-server/server-name/{server_name}).
    """
    await ctx.info(f"Retrieving endpoint context server '{server_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.get_endpoint_context_server_by_name(server_name)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved endpoint context server '{server_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get endpoint context server: {e}")
        return await format_api_error(e, "get endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to get endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get endpoint context server."
        }


@operation(domain="integrations")
async def update_endpoint_context_server_by_name(
    ctx: Context,
    server_name: str = Field(..., description="Unique name of the endpoint context server"),
    server_data: Dict[str, Any] = Field(..., description="Endpoint context server definition (server_type, server_name, server_base_url, auth_method, username, password, oauth2_client_id, oauth2_client_secret, oauth2_access_token_url, vendor_attrs, validate_server, status, ip_version, bypass_proxy)")
) -> Dict[str, Any]:
    """
    Update selected fields of a endpoint context server by server name.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_endpoint_context_server_server_name_by_server_name' in pyclearpass (PATCH /endpoint-context-server/server-name/{server_name}).
    """
    await ctx.info(f"Updating endpoint context server '{server_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.update_endpoint_context_server_by_name(server_name, server_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated endpoint context server '{server_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update endpoint context server: {e}")
        return await format_api_error(e, "update endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to update endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update endpoint context server."
        }


@operation(domain="integrations")
async def replace_endpoint_context_server_by_name(
    ctx: Context,
    server_name: str = Field(..., description="Unique name of the endpoint context server"),
    server_data: Dict[str, Any] = Field(..., description="Endpoint context server definition (server_type, server_name, server_base_url, auth_method, username, password, oauth2_client_id, oauth2_client_secret, oauth2_access_token_url, vendor_attrs, validate_server, status, ip_version, bypass_proxy)")
) -> Dict[str, Any]:
    """
    Replace a endpoint context server by server name.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: server_type, server_name, server_base_url, auth_method, validate_server, status, bypass_proxy.

    Maps to 'replace_endpoint_context_server_server_name_by_server_name' in pyclearpass (PUT /endpoint-context-server/server-name/{server_name}).
    """
    await ctx.info(f"Replacing endpoint context server '{server_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_endpoint_context_server_by_name(server_name, server_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced endpoint context server '{server_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace endpoint context server: {e}")
        return await format_api_error(e, "replace endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace endpoint context server."
        }


@operation(domain="integrations")
async def delete_endpoint_context_server_by_name(
    ctx: Context,
    server_name: str = Field(..., description="Unique name of the endpoint context server")
) -> Dict[str, Any]:
    """
    Delete a endpoint context server by server name.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_endpoint_context_server_server_name_by_server_name' in pyclearpass (DELETE /endpoint-context-server/server-name/{server_name}).
    """
    await ctx.info(f"Deleting endpoint context server '{server_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_endpoint_context_server_by_name(server_name)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted endpoint context server '{server_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete endpoint context server: {e}")
        return await format_api_error(e, "delete endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete endpoint context server."
        }


@operation(domain="integrations")
async def get_endpoint_context_server_by_id(
    ctx: Context,
    endpoint_context_server_id: int = Field(..., description="Numeric ID of the endpoint context server")
) -> Dict[str, Any]:
    """
    Get a endpoint context server by numeric ID.

    Returns the full configuration of a single endpoint context server.

    Maps to 'get_endpoint_context_server_by_endpoint_context_server_id' in pyclearpass (GET /endpoint-context-server/{endpoint_context_server_id}).
    """
    await ctx.info(f"Retrieving endpoint context server {endpoint_context_server_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_endpoint_context_server_by_id(endpoint_context_server_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved endpoint context server {endpoint_context_server_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get endpoint context server: {e}")
        return await format_api_error(e, "get endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to get endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get endpoint context server."
        }


@operation(domain="integrations")
async def update_endpoint_context_server_by_id(
    ctx: Context,
    endpoint_context_server_id: int = Field(..., description="Numeric ID of the endpoint context server"),
    server_data: Dict[str, Any] = Field(..., description="Endpoint context server definition (server_type, server_name, server_base_url, auth_method, username, password, oauth2_client_id, oauth2_client_secret, oauth2_access_token_url, vendor_attrs, validate_server, status, ip_version, bypass_proxy)")
) -> Dict[str, Any]:
    """
    Update selected fields of a endpoint context server by numeric ID.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_endpoint_context_server_by_endpoint_context_server_id' in pyclearpass (PATCH /endpoint-context-server/{endpoint_context_server_id}).
    """
    await ctx.info(f"Updating endpoint context server {endpoint_context_server_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_endpoint_context_server_by_id(endpoint_context_server_id, server_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated endpoint context server {endpoint_context_server_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update endpoint context server: {e}")
        return await format_api_error(e, "update endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to update endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update endpoint context server."
        }


@operation(domain="integrations")
async def replace_endpoint_context_server_by_id(
    ctx: Context,
    endpoint_context_server_id: int = Field(..., description="Numeric ID of the endpoint context server"),
    server_data: Dict[str, Any] = Field(..., description="Endpoint context server definition (server_type, server_name, server_base_url, auth_method, username, password, oauth2_client_id, oauth2_client_secret, oauth2_access_token_url, vendor_attrs, validate_server, status, ip_version, bypass_proxy)")
) -> Dict[str, Any]:
    """
    Replace a endpoint context server by numeric ID.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: server_type, server_name, server_base_url, auth_method, validate_server, status, bypass_proxy.

    Maps to 'replace_endpoint_context_server_by_endpoint_context_server_id' in pyclearpass (PUT /endpoint-context-server/{endpoint_context_server_id}).
    """
    await ctx.info(f"Replacing endpoint context server {endpoint_context_server_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_endpoint_context_server_by_id(endpoint_context_server_id, server_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced endpoint context server {endpoint_context_server_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace endpoint context server: {e}")
        return await format_api_error(e, "replace endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace endpoint context server."
        }


@operation(domain="integrations")
async def delete_endpoint_context_server_by_id(
    ctx: Context,
    endpoint_context_server_id: int = Field(..., description="Numeric ID of the endpoint context server")
) -> Dict[str, Any]:
    """
    Delete a endpoint context server by numeric ID.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_endpoint_context_server_by_endpoint_context_server_id' in pyclearpass (DELETE /endpoint-context-server/{endpoint_context_server_id}).
    """
    await ctx.info(f"Deleting endpoint context server {endpoint_context_server_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_endpoint_context_server_by_id(endpoint_context_server_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted endpoint context server {endpoint_context_server_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete endpoint context server: {e}")
        return await format_api_error(e, "delete endpoint context server")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete endpoint context server: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete endpoint context server."
        }


@operation(domain="integrations")
async def trigger_endpoint_context_server_poll_by_name(
    ctx: Context,
    server_name: str = Field(..., description="Unique name of the endpoint context server")
) -> Dict[str, Any]:
    """
    Trigger an immediate poll of an endpoint context server by server name.

    Forces ClearPass to fetch endpoint context from the server now instead of waiting for the next scheduled poll.

    Maps to 'update_endpoint_context_server_server_name_by_server_name_trigger_poll' in pyclearpass (PATCH /endpoint-context-server/server-name/{server_name}/trigger-poll).
    """
    await ctx.info(f"Triggering poll for endpoint context server '{server_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.trigger_endpoint_context_server_poll_by_name(server_name)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully triggered polling for endpoint context server '{server_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to trigger endpoint context server poll: {e}")
        return await format_api_error(e, "trigger endpoint context server poll")
    except Exception as e:
        logger.error(f"Unexpected error trying to trigger endpoint context server poll: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to trigger endpoint context server poll."
        }


@operation(domain="integrations")
async def trigger_endpoint_context_server_poll_by_id(
    ctx: Context,
    endpoint_context_server_id: int = Field(..., description="Numeric ID of the endpoint context server")
) -> Dict[str, Any]:
    """
    Trigger an immediate poll of an endpoint context server by numeric ID.

    Forces ClearPass to fetch endpoint context from the server now instead of waiting for the next scheduled poll.

    Maps to 'update_endpoint_context_server_by_endpoint_context_server_id_trigger_poll' in pyclearpass (PATCH /endpoint-context-server/{endpoint_context_server_id}/trigger-poll).
    """
    await ctx.info(f"Triggering poll for endpoint context server {endpoint_context_server_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.trigger_endpoint_context_server_poll_by_id(endpoint_context_server_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully triggered polling for endpoint context server {endpoint_context_server_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to trigger endpoint context server poll: {e}")
        return await format_api_error(e, "trigger endpoint context server poll")
    except Exception as e:
        logger.error(f"Unexpected error trying to trigger endpoint context server poll: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to trigger endpoint context server poll."
        }


# ============================================================================
# EVENT SOURCES
# ============================================================================


@operation(domain="integrations")
async def list_event_sources(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List event sources configured on ClearPass.

    Event sources are the external systems permitted to send ingress events (syslog) to ClearPass for context-based enforcement.

    Maps to 'get_event_sources' in pyclearpass (GET /event-sources).
    """
    await ctx.info("Retrieving event sources...")

    try:
        client = await get_clearpass_client()
        result = await client.list_event_sources(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} event sources."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list event sources: {e}")
        return await format_api_error(e, "list event sources")
    except Exception as e:
        logger.error(f"Unexpected error trying to list event sources: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list event sources."
        }


@operation(domain="integrations")
async def create_event_source(
    ctx: Context,
    event_source_data: Dict[str, Any] = Field(..., description="Event source definition (name, description, ipaddress, vendor, type, enable)")
) -> Dict[str, Any]:
    """
    Create a new event source.

    Required body fields: name, ipaddress, vendor, type.

    Maps to 'new_event_sources' in pyclearpass (POST /event-sources).
    """
    await ctx.info("Creating event source...")

    try:
        client = await get_clearpass_client()
        result = await client.create_event_source(event_source_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully created the event source."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create event source: {e}")
        return await format_api_error(e, "create event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to create event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create event source."
        }


@operation(domain="integrations")
async def get_event_source_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the event source")
) -> Dict[str, Any]:
    """
    Get a event source by name.

    Returns the full configuration of a single event source.

    Maps to 'get_event_sources_name_by_name' in pyclearpass (GET /event-sources/name/{name}).
    """
    await ctx.info(f"Retrieving event source '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.get_event_source_by_name(name)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved event source '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get event source: {e}")
        return await format_api_error(e, "get event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to get event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get event source."
        }


@operation(domain="integrations")
async def update_event_source_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the event source"),
    event_source_data: Dict[str, Any] = Field(..., description="Event source definition (name, description, ipaddress, vendor, type, enable)")
) -> Dict[str, Any]:
    """
    Update selected fields of a event source by name.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_event_sources_name_by_name' in pyclearpass (PATCH /event-sources/name/{name}).
    """
    await ctx.info(f"Updating event source '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.update_event_source_by_name(name, event_source_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated event source '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update event source: {e}")
        return await format_api_error(e, "update event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to update event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update event source."
        }


@operation(domain="integrations")
async def replace_event_source_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the event source"),
    event_source_data: Dict[str, Any] = Field(..., description="Event source definition (name, description, ipaddress, vendor, type, enable)")
) -> Dict[str, Any]:
    """
    Replace a event source by name.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: name, ipaddress, vendor, type.

    Maps to 'replace_event_sources_name_by_name' in pyclearpass (PUT /event-sources/name/{name}).
    """
    await ctx.info(f"Replacing event source '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_event_source_by_name(name, event_source_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced event source '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace event source: {e}")
        return await format_api_error(e, "replace event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace event source."
        }


@operation(domain="integrations")
async def delete_event_source_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the event source")
) -> Dict[str, Any]:
    """
    Delete a event source by name.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_event_sources_name_by_name' in pyclearpass (DELETE /event-sources/name/{name}).
    """
    await ctx.info(f"Deleting event source '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_event_source_by_name(name)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted event source '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete event source: {e}")
        return await format_api_error(e, "delete event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete event source."
        }


@operation(domain="integrations")
async def get_event_source_by_id(
    ctx: Context,
    event_sources_id: int = Field(..., description="Unique numeric ID of the event source")
) -> Dict[str, Any]:
    """
    Get a event source by numeric ID.

    Returns the full configuration of a single event source.

    Maps to 'get_event_sources_by_event_sources_id' in pyclearpass (GET /event-sources/{event_sources_id}).
    """
    await ctx.info(f"Retrieving event source {event_sources_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_event_source_by_id(event_sources_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved event source {event_sources_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get event source: {e}")
        return await format_api_error(e, "get event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to get event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get event source."
        }


@operation(domain="integrations")
async def update_event_source_by_id(
    ctx: Context,
    event_sources_id: int = Field(..., description="Unique numeric ID of the event source"),
    event_source_data: Dict[str, Any] = Field(..., description="Event source definition (name, description, ipaddress, vendor, type, enable)")
) -> Dict[str, Any]:
    """
    Update selected fields of a event source by numeric ID.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_event_sources_by_event_sources_id' in pyclearpass (PATCH /event-sources/{event_sources_id}).
    """
    await ctx.info(f"Updating event source {event_sources_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_event_source_by_id(event_sources_id, event_source_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated event source {event_sources_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update event source: {e}")
        return await format_api_error(e, "update event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to update event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update event source."
        }


@operation(domain="integrations")
async def replace_event_source_by_id(
    ctx: Context,
    event_sources_id: int = Field(..., description="Unique numeric ID of the event source"),
    event_source_data: Dict[str, Any] = Field(..., description="Event source definition (name, description, ipaddress, vendor, type, enable)")
) -> Dict[str, Any]:
    """
    Replace a event source by numeric ID.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: name, ipaddress, vendor, type.

    Maps to 'replace_event_sources_by_event_sources_id' in pyclearpass (PUT /event-sources/{event_sources_id}).
    """
    await ctx.info(f"Replacing event source {event_sources_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_event_source_by_id(event_sources_id, event_source_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced event source {event_sources_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace event source: {e}")
        return await format_api_error(e, "replace event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace event source."
        }


@operation(domain="integrations")
async def delete_event_source_by_id(
    ctx: Context,
    event_sources_id: int = Field(..., description="Unique numeric ID of the event source")
) -> Dict[str, Any]:
    """
    Delete a event source by numeric ID.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_event_sources_by_event_sources_id' in pyclearpass (DELETE /event-sources/{event_sources_id}).
    """
    await ctx.info(f"Deleting event source {event_sources_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_event_source_by_id(event_sources_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted event source {event_sources_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete event source: {e}")
        return await format_api_error(e, "delete event source")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete event source: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete event source."
        }


# ============================================================================
# EXTENSION INSTANCES
# ============================================================================


@operation(domain="integrations")
async def list_extension_instances(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List installed extensions configured on ClearPass.

    ClearPass Extensions are containerised add-ons (for example the Aruba Central or Kafka extensions) installed on the appliance.

    Maps to 'get_extension_instance' in pyclearpass (GET /extension/instance).
    """
    await ctx.info("Retrieving installed extensions...")

    try:
        client = await get_clearpass_client()
        result = await client.list_extension_instances(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} installed extensions."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list installed extensions: {e}")
        return await format_api_error(e, "list installed extensions")
    except Exception as e:
        logger.error(f"Unexpected error trying to list installed extensions: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list installed extensions."
        }


@operation(domain="integrations")
async def install_extension_instance(
    ctx: Context,
    extension_data: Dict[str, Any] = Field(..., description="Extension install request (store_id [required], state, files, ip_address, note)")
) -> Dict[str, Any]:
    """
    Install a ClearPass Extension from the extension store.

    Required body field: store_id - the ID of the store entry (see list_extension_store).

    Maps to 'new_extension_instance' in pyclearpass (POST /extension/instance).
    """
    await ctx.info("Installing extension...")

    try:
        client = await get_clearpass_client()
        result = await client.install_extension_instance(extension_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully submitted the extension install request."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to install extension: {e}")
        return await format_api_error(e, "install extension")
    except Exception as e:
        logger.error(f"Unexpected error trying to install extension: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to install extension."
        }


@operation(domain="integrations")
async def get_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance")
) -> Dict[str, Any]:
    """
    Get an installed extension by instance ID.

    Returns the extension's state, store metadata, allocated IP address and note.

    Maps to 'get_extension_instance_by_id' in pyclearpass (GET /extension/instance/{id}).
    """
    await ctx.info(f"Retrieving extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_extension_instance(extension_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get extension instance: {e}")
        return await format_api_error(e, "get extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to get extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get extension instance."
        }


@operation(domain="integrations")
async def update_extension_instance_state(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance"),
    extension_data: Dict[str, Any] = Field(..., description="Fields to change (state, note)")
) -> Dict[str, Any]:
    """
    Change the state or note of an installed extension.

    Use the dedicated start/stop/restart operations for simple lifecycle changes; this operation also updates the displayed note.

    Maps to 'update_extension_instance_by_id' in pyclearpass (PATCH /extension/instance/{id}).
    """
    await ctx.info(f"Updating extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_extension_instance_state(extension_id, extension_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update extension instance: {e}")
        return await format_api_error(e, "update extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to update extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update extension instance."
        }


@operation(domain="integrations")
async def uninstall_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance"),
    force: Optional[bool] = Field(None, description="True to send a kill signal to the extension before deleting")
) -> Dict[str, Any]:
    """
    Uninstall an installed extension.

    Set force=True to kill a running extension before removing it.

    Maps to 'delete_extension_instance_by_id' in pyclearpass (DELETE /extension/instance/{id}).
    """
    await ctx.info(f"Uninstalling extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.uninstall_extension_instance(extension_id, force=force)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully uninstalled extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to uninstall extension instance: {e}")
        return await format_api_error(e, "uninstall extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to uninstall extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to uninstall extension instance."
        }


@operation(domain="integrations")
async def get_extension_instance_config(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance")
) -> Dict[str, Any]:
    """
    Get the configuration of an installed extension.

    The configuration schema is extension specific.

    Maps to 'get_extension_instance_by_id_config' in pyclearpass (GET /extension/instance/{id}/config).
    """
    await ctx.info(f"Retrieving configuration for extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_extension_instance_config(extension_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved configuration for extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get extension configuration: {e}")
        return await format_api_error(e, "get extension configuration")
    except Exception as e:
        logger.error(f"Unexpected error trying to get extension configuration: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get extension configuration."
        }


@operation(domain="integrations")
async def replace_extension_instance_config(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance"),
    config_data: Dict[str, Any] = Field(..., description="Complete extension configuration document (schema is extension specific)")
) -> Dict[str, Any]:
    """
    Set the configuration of an installed extension.

    This replaces the entire configuration document; fetch the current config first if you only intend to change part of it.

    Maps to 'replace_extension_instance_by_id_config' in pyclearpass (PUT /extension/instance/{id}/config).
    """
    await ctx.info(f"Setting configuration for extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_extension_instance_config(extension_id, config_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully set configuration for extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to set extension configuration: {e}")
        return await format_api_error(e, "set extension configuration")
    except Exception as e:
        logger.error(f"Unexpected error trying to set extension configuration: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to set extension configuration."
        }


@operation(domain="integrations")
async def get_extension_instance_log(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance"),
    stdout: Optional[bool] = Field(None, description="Include the extension's standard-output messages"),
    stderr: Optional[bool] = Field(None, description="Include the extension's standard-error messages"),
    since: Optional[int] = Field(None, description="UNIX timestamp - only return log entries since that time"),
    timestamps: Optional[bool] = Field(None, description="Prefix every log line with its UTC timestamp"),
    tail: Optional[str] = Field(None, description="Number of lines to return from the end of the logs, or \"all\" for everything")
) -> Dict[str, Any]:
    """
    Get the log output from an installed extension.

    Useful for troubleshooting an extension that fails to start or is not delivering data.

    Maps to 'get_extension_instance_by_id_log' in pyclearpass (GET /extension/instance/{id}/log).
    """
    await ctx.info(f"Retrieving logs for extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_extension_instance_log(
            extension_id,
            stdout=stdout,
            stderr=stderr,
            since=since,
            timestamps=timestamps,
            tail=tail
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved logs for extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get extension logs: {e}")
        return await format_api_error(e, "get extension logs")
    except Exception as e:
        logger.error(f"Unexpected error trying to get extension logs: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get extension logs."
        }


@operation(domain="integrations")
async def reinstall_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance"),
    reinstall_data: Optional[Dict[str, Any]] = Field(None, description="Optional reinstall options (state, files, ip_address)")
) -> Dict[str, Any]:
    """
    Reinstall an extension in place.

    Recreates the extension container while keeping its instance ID; optionally supply a new state, file mapping or IP address.

    Maps to 'new_extension_instance_by_id_reinstall' in pyclearpass (POST /extension/instance/{id}/reinstall).
    """
    await ctx.info(f"Reinstalling extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.reinstall_extension_instance(extension_id, reinstall_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully submitted the reinstall request for extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to reinstall extension instance: {e}")
        return await format_api_error(e, "reinstall extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to reinstall extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to reinstall extension instance."
        }


@operation(domain="integrations")
async def restart_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance")
) -> Dict[str, Any]:
    """
    Restart an installed extension.

    Stops and then starts the extension container.

    Maps to 'new_extension_instance_by_id_restart' in pyclearpass (POST /extension/instance/{id}/restart).
    """
    await ctx.info(f"Restarting extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.restart_extension_instance(extension_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully restarted extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to restart extension instance: {e}")
        return await format_api_error(e, "restart extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to restart extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to restart extension instance."
        }


@operation(domain="integrations")
async def start_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance")
) -> Dict[str, Any]:
    """
    Start an installed extension.

    Brings a stopped extension back into the running state.

    Maps to 'new_extension_instance_by_id_start' in pyclearpass (POST /extension/instance/{id}/start).
    """
    await ctx.info(f"Starting extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.start_extension_instance(extension_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully started extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to start extension instance: {e}")
        return await format_api_error(e, "start extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to start extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to start extension instance."
        }


@operation(domain="integrations")
async def stop_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance")
) -> Dict[str, Any]:
    """
    Stop an installed extension.

    Halts the extension container without uninstalling it.

    Maps to 'new_extension_instance_by_id_stop' in pyclearpass (POST /extension/instance/{id}/stop).
    """
    await ctx.info(f"Stopping extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.stop_extension_instance(extension_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully stopped extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to stop extension instance: {e}")
        return await format_api_error(e, "stop extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to stop extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to stop extension instance."
        }


@operation(domain="integrations")
async def get_extension_upgrade_info(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance")
) -> Dict[str, Any]:
    """
    Get information on an extension's available upgrade.

    Reports whether a newer version exists in the store and whether it is a major upgrade.

    Maps to 'get_extension_instance_by_id_upgrade' in pyclearpass (GET /extension/instance/{id}/upgrade).
    """
    await ctx.info(f"Checking available upgrade for extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_extension_upgrade_info(extension_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved upgrade information for extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get extension upgrade information: {e}")
        return await format_api_error(e, "get extension upgrade information")
    except Exception as e:
        logger.error(f"Unexpected error trying to get extension upgrade information: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get extension upgrade information."
        }


@operation(domain="integrations")
async def upgrade_extension_instance(
    ctx: Context,
    extension_id: str = Field(..., description="ID of the extension instance"),
    upgrade_data: Optional[Dict[str, Any]] = Field(None, description="Optional upgrade options (major, state, files, ip_address)")
) -> Dict[str, Any]:
    """
    Upgrade an installed extension to a newer store version.

    Set major=True in the body to accept major-version upgrades (minor upgrades only by default).

    Maps to 'new_extension_instance_by_id_upgrade' in pyclearpass (POST /extension/instance/{id}/upgrade).
    """
    await ctx.info(f"Upgrading extension instance {extension_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.upgrade_extension_instance(extension_id, upgrade_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully submitted the upgrade request for extension instance {extension_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to upgrade extension instance: {e}")
        return await format_api_error(e, "upgrade extension instance")
    except Exception as e:
        logger.error(f"Unexpected error trying to upgrade extension instance: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to upgrade extension instance."
        }


# ============================================================================
# EXTENSION STORE
# ============================================================================


@operation(domain="integrations")
async def list_extension_store(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List extension store entries configured on ClearPass.

    Use this to find the store_id required by install_extension_instance.

    Maps to 'get_extension_store' in pyclearpass (GET /extension/store).
    """
    await ctx.info("Retrieving extension store entries...")

    try:
        client = await get_clearpass_client()
        result = await client.list_extension_store(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} extension store entries."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list extension store entries: {e}")
        return await format_api_error(e, "list extension store entries")
    except Exception as e:
        logger.error(f"Unexpected error trying to list extension store entries: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list extension store entries."
        }


@operation(domain="integrations")
async def get_extension_store_item(
    ctx: Context,
    store_id: str = Field(..., description="ID of the extension store entry")
) -> Dict[str, Any]:
    """
    Get a single extension store entry by store ID.

    Returns the store metadata for one available extension, including its version and description.

    Maps to 'get_extension_store_by_id' in pyclearpass (GET /extension/store/{id}).
    """
    await ctx.info(f"Retrieving extension store entry {store_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_extension_store_item(store_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved extension store entry {store_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get extension store entry: {e}")
        return await format_api_error(e, "get extension store entry")
    except Exception as e:
        logger.error(f"Unexpected error trying to get extension store entry: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get extension store entry."
        }


# ============================================================================
# INGRESS EVENT DICTIONARIES
# ============================================================================


@operation(domain="integrations")
async def list_ingress_event_dictionaries(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List ingress event dictionaries configured on ClearPass.

    Ingress event dictionaries tell ClearPass how to parse syslog events received from a given vendor and format.

    Maps to 'get_ingress_event_dictionary' in pyclearpass (GET /ingress-event-dictionary).
    """
    await ctx.info("Retrieving ingress event dictionaries...")

    try:
        client = await get_clearpass_client()
        result = await client.list_ingress_event_dictionaries(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} ingress event dictionaries."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list ingress event dictionaries: {e}")
        return await format_api_error(e, "list ingress event dictionaries")
    except Exception as e:
        logger.error(f"Unexpected error trying to list ingress event dictionaries: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list ingress event dictionaries."
        }


@operation(domain="integrations")
async def create_ingress_event_dictionary(
    ctx: Context,
    dictionary_data: Dict[str, Any] = Field(..., description="Ingress event dictionary definition (vendor, format_name, prefix, status, description, format, sample, filter, fields, generic_fields)")
) -> Dict[str, Any]:
    """
    Create a new ingress event dictionary.

    Required body fields: vendor, format_name, prefix, filter, fields, generic_fields.

    Maps to 'new_ingress_event_dictionary' in pyclearpass (POST /ingress-event-dictionary).
    """
    await ctx.info("Creating ingress event dictionary...")

    try:
        client = await get_clearpass_client()
        result = await client.create_ingress_event_dictionary(dictionary_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully created the ingress event dictionary."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create ingress event dictionary: {e}")
        return await format_api_error(e, "create ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to create ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create ingress event dictionary."
        }


@operation(domain="integrations")
async def get_ingress_event_dictionary_by_format_name(
    ctx: Context,
    format_name: str = Field(..., description="Unique format name of the ingress event dictionary")
) -> Dict[str, Any]:
    """
    Get a ingress event dictionary by format name.

    Returns the full configuration of a single ingress event dictionary.

    Maps to 'get_ingress_event_dictionary_format_name_by_format_name' in pyclearpass (GET /ingress-event-dictionary/format_name/{format_name}).
    """
    await ctx.info(f"Retrieving ingress event dictionary '{format_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.get_ingress_event_dictionary_by_format_name(format_name)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved ingress event dictionary '{format_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get ingress event dictionary: {e}")
        return await format_api_error(e, "get ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to get ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get ingress event dictionary."
        }


@operation(domain="integrations")
async def update_ingress_event_dictionary_by_format_name(
    ctx: Context,
    format_name: str = Field(..., description="Unique format name of the ingress event dictionary"),
    dictionary_data: Dict[str, Any] = Field(..., description="Ingress event dictionary definition (vendor, format_name, prefix, status, description, format, sample, filter, fields, generic_fields)")
) -> Dict[str, Any]:
    """
    Update selected fields of a ingress event dictionary by format name.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_ingress_event_dictionary_format_name_by_format_name' in pyclearpass (PATCH /ingress-event-dictionary/format_name/{format_name}).
    """
    await ctx.info(f"Updating ingress event dictionary '{format_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.update_ingress_event_dictionary_by_format_name(format_name, dictionary_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated ingress event dictionary '{format_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update ingress event dictionary: {e}")
        return await format_api_error(e, "update ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to update ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update ingress event dictionary."
        }


@operation(domain="integrations")
async def replace_ingress_event_dictionary_by_format_name(
    ctx: Context,
    format_name: str = Field(..., description="Unique format name of the ingress event dictionary"),
    dictionary_data: Dict[str, Any] = Field(..., description="Ingress event dictionary definition (vendor, format_name, prefix, status, description, format, sample, filter, fields, generic_fields)")
) -> Dict[str, Any]:
    """
    Replace a ingress event dictionary by format name.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: vendor, format_name, prefix, filter, fields, generic_fields.

    Maps to 'replace_ingress_event_dictionary_format_name_by_format_name' in pyclearpass (PUT /ingress-event-dictionary/format_name/{format_name}).
    """
    await ctx.info(f"Replacing ingress event dictionary '{format_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_ingress_event_dictionary_by_format_name(format_name, dictionary_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced ingress event dictionary '{format_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace ingress event dictionary: {e}")
        return await format_api_error(e, "replace ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace ingress event dictionary."
        }


@operation(domain="integrations")
async def delete_ingress_event_dictionary_by_format_name(
    ctx: Context,
    format_name: str = Field(..., description="Unique format name of the ingress event dictionary")
) -> Dict[str, Any]:
    """
    Delete a ingress event dictionary by format name.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_ingress_event_dictionary_format_name_by_format_name' in pyclearpass (DELETE /ingress-event-dictionary/format_name/{format_name}).
    """
    await ctx.info(f"Deleting ingress event dictionary '{format_name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_ingress_event_dictionary_by_format_name(format_name)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted ingress event dictionary '{format_name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete ingress event dictionary: {e}")
        return await format_api_error(e, "delete ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete ingress event dictionary."
        }


@operation(domain="integrations")
async def get_ingress_event_dictionary_by_id(
    ctx: Context,
    ingress_event_dictionary_id: int = Field(..., description="Numeric ID of the ingress event dictionary")
) -> Dict[str, Any]:
    """
    Get a ingress event dictionary by numeric ID.

    Returns the full configuration of a single ingress event dictionary.

    Maps to 'get_ingress_event_dictionary_by_ingress_event_dictionary_id' in pyclearpass (GET /ingress-event-dictionary/{ingress_event_dictionary_id}).
    """
    await ctx.info(f"Retrieving ingress event dictionary {ingress_event_dictionary_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_ingress_event_dictionary_by_id(ingress_event_dictionary_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved ingress event dictionary {ingress_event_dictionary_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get ingress event dictionary: {e}")
        return await format_api_error(e, "get ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to get ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get ingress event dictionary."
        }


@operation(domain="integrations")
async def update_ingress_event_dictionary_by_id(
    ctx: Context,
    ingress_event_dictionary_id: int = Field(..., description="Numeric ID of the ingress event dictionary"),
    dictionary_data: Dict[str, Any] = Field(..., description="Ingress event dictionary definition (vendor, format_name, prefix, status, description, format, sample, filter, fields, generic_fields)")
) -> Dict[str, Any]:
    """
    Update selected fields of a ingress event dictionary by numeric ID.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_ingress_event_dictionary_by_ingress_event_dictionary_id' in pyclearpass (PATCH /ingress-event-dictionary/{ingress_event_dictionary_id}).
    """
    await ctx.info(f"Updating ingress event dictionary {ingress_event_dictionary_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_ingress_event_dictionary_by_id(ingress_event_dictionary_id, dictionary_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated ingress event dictionary {ingress_event_dictionary_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update ingress event dictionary: {e}")
        return await format_api_error(e, "update ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to update ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update ingress event dictionary."
        }


@operation(domain="integrations")
async def replace_ingress_event_dictionary_by_id(
    ctx: Context,
    ingress_event_dictionary_id: int = Field(..., description="Numeric ID of the ingress event dictionary"),
    dictionary_data: Dict[str, Any] = Field(..., description="Ingress event dictionary definition (vendor, format_name, prefix, status, description, format, sample, filter, fields, generic_fields)")
) -> Dict[str, Any]:
    """
    Replace a ingress event dictionary by numeric ID.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: vendor, format_name, prefix, filter, fields, generic_fields.

    Maps to 'replace_ingress_event_dictionary_by_ingress_event_dictionary_id' in pyclearpass (PUT /ingress-event-dictionary/{ingress_event_dictionary_id}).
    """
    await ctx.info(f"Replacing ingress event dictionary {ingress_event_dictionary_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_ingress_event_dictionary_by_id(ingress_event_dictionary_id, dictionary_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced ingress event dictionary {ingress_event_dictionary_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace ingress event dictionary: {e}")
        return await format_api_error(e, "replace ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace ingress event dictionary."
        }


@operation(domain="integrations")
async def delete_ingress_event_dictionary_by_id(
    ctx: Context,
    ingress_event_dictionary_id: int = Field(..., description="Numeric ID of the ingress event dictionary")
) -> Dict[str, Any]:
    """
    Delete a ingress event dictionary by numeric ID.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_ingress_event_dictionary_by_ingress_event_dictionary_id' in pyclearpass (DELETE /ingress-event-dictionary/{ingress_event_dictionary_id}).
    """
    await ctx.info(f"Deleting ingress event dictionary {ingress_event_dictionary_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_ingress_event_dictionary_by_id(ingress_event_dictionary_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted ingress event dictionary {ingress_event_dictionary_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete ingress event dictionary: {e}")
        return await format_api_error(e, "delete ingress event dictionary")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete ingress event dictionary: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete ingress event dictionary."
        }


# ============================================================================
# SYSLOG EXPORT FILTERS
# ============================================================================


@operation(domain="integrations")
async def list_syslog_export_filters(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List syslog export filters configured on ClearPass.

    Syslog export filters select which ClearPass data (sessions, audit records, system events) is streamed to which syslog targets.

    Maps to 'get_syslog_export_filter' in pyclearpass (GET /syslog-export-filter).
    """
    await ctx.info("Retrieving syslog export filters...")

    try:
        client = await get_clearpass_client()
        result = await client.list_syslog_export_filters(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} syslog export filters."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list syslog export filters: {e}")
        return await format_api_error(e, "list syslog export filters")
    except Exception as e:
        logger.error(f"Unexpected error trying to list syslog export filters: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list syslog export filters."
        }


@operation(domain="integrations")
async def create_syslog_export_filter(
    ctx: Context,
    filter_data: Dict[str, Any] = Field(..., description="Syslog export filter definition (name, description, export_template, export_event_format_type, local_facility_level, syslog_servers, cluster_servers, enabled, data_filter, selected_columns, field_group_name, custom_sql, include_audit_data)")
) -> Dict[str, Any]:
    """
    Create a new syslog export filter.

    Required body fields: name, export_template, export_event_format_type, syslog_servers.

    Maps to 'new_syslog_export_filter' in pyclearpass (POST /syslog-export-filter).
    """
    await ctx.info("Creating syslog export filter...")

    try:
        client = await get_clearpass_client()
        result = await client.create_syslog_export_filter(filter_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully created the syslog export filter."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create syslog export filter: {e}")
        return await format_api_error(e, "create syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to create syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create syslog export filter."
        }


@operation(domain="integrations")
async def get_syslog_export_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the syslog export filter")
) -> Dict[str, Any]:
    """
    Get a syslog export filter by name.

    Returns the full configuration of a single syslog export filter.

    Maps to 'get_syslog_export_filter_name_by_name' in pyclearpass (GET /syslog-export-filter/name/{name}).
    """
    await ctx.info(f"Retrieving syslog export filter '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.get_syslog_export_filter_by_name(name)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved syslog export filter '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get syslog export filter: {e}")
        return await format_api_error(e, "get syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to get syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get syslog export filter."
        }


@operation(domain="integrations")
async def update_syslog_export_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the syslog export filter"),
    filter_data: Dict[str, Any] = Field(..., description="Syslog export filter definition (name, description, export_template, export_event_format_type, local_facility_level, syslog_servers, cluster_servers, enabled, data_filter, selected_columns, field_group_name, custom_sql, include_audit_data)")
) -> Dict[str, Any]:
    """
    Update selected fields of a syslog export filter by name.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_syslog_export_filter_name_by_name' in pyclearpass (PATCH /syslog-export-filter/name/{name}).
    """
    await ctx.info(f"Updating syslog export filter '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.update_syslog_export_filter_by_name(name, filter_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated syslog export filter '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update syslog export filter: {e}")
        return await format_api_error(e, "update syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to update syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update syslog export filter."
        }


@operation(domain="integrations")
async def replace_syslog_export_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the syslog export filter"),
    filter_data: Dict[str, Any] = Field(..., description="Syslog export filter definition (name, description, export_template, export_event_format_type, local_facility_level, syslog_servers, cluster_servers, enabled, data_filter, selected_columns, field_group_name, custom_sql, include_audit_data)")
) -> Dict[str, Any]:
    """
    Replace a syslog export filter by name.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: name, export_template, export_event_format_type, syslog_servers.

    Maps to 'replace_syslog_export_filter_name_by_name' in pyclearpass (PUT /syslog-export-filter/name/{name}).
    """
    await ctx.info(f"Replacing syslog export filter '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_syslog_export_filter_by_name(name, filter_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced syslog export filter '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace syslog export filter: {e}")
        return await format_api_error(e, "replace syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace syslog export filter."
        }


@operation(domain="integrations")
async def delete_syslog_export_filter_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the syslog export filter")
) -> Dict[str, Any]:
    """
    Delete a syslog export filter by name.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_syslog_export_filter_name_by_name' in pyclearpass (DELETE /syslog-export-filter/name/{name}).
    """
    await ctx.info(f"Deleting syslog export filter '{name}'...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_syslog_export_filter_by_name(name)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted syslog export filter '{name}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete syslog export filter: {e}")
        return await format_api_error(e, "delete syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete syslog export filter."
        }


@operation(domain="integrations")
async def get_syslog_export_filter_by_id(
    ctx: Context,
    syslog_export_filter_id: int = Field(..., description="Numeric ID of the syslog export filter")
) -> Dict[str, Any]:
    """
    Get a syslog export filter by numeric ID.

    Returns the full configuration of a single syslog export filter.

    Maps to 'get_syslog_export_filter_by_syslog_export_filter_id' in pyclearpass (GET /syslog-export-filter/{syslog_export_filter_id}).
    """
    await ctx.info(f"Retrieving syslog export filter {syslog_export_filter_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_syslog_export_filter_by_id(syslog_export_filter_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved syslog export filter {syslog_export_filter_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get syslog export filter: {e}")
        return await format_api_error(e, "get syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to get syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get syslog export filter."
        }


@operation(domain="integrations")
async def update_syslog_export_filter_by_id(
    ctx: Context,
    syslog_export_filter_id: int = Field(..., description="Numeric ID of the syslog export filter"),
    filter_data: Dict[str, Any] = Field(..., description="Syslog export filter definition (name, description, export_template, export_event_format_type, local_facility_level, syslog_servers, cluster_servers, enabled, data_filter, selected_columns, field_group_name, custom_sql, include_audit_data)")
) -> Dict[str, Any]:
    """
    Update selected fields of a syslog export filter by numeric ID.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_syslog_export_filter_by_syslog_export_filter_id' in pyclearpass (PATCH /syslog-export-filter/{syslog_export_filter_id}).
    """
    await ctx.info(f"Updating syslog export filter {syslog_export_filter_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_syslog_export_filter_by_id(syslog_export_filter_id, filter_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated syslog export filter {syslog_export_filter_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update syslog export filter: {e}")
        return await format_api_error(e, "update syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to update syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update syslog export filter."
        }


@operation(domain="integrations")
async def replace_syslog_export_filter_by_id(
    ctx: Context,
    syslog_export_filter_id: int = Field(..., description="Numeric ID of the syslog export filter"),
    filter_data: Dict[str, Any] = Field(..., description="Syslog export filter definition (name, description, export_template, export_event_format_type, local_facility_level, syslog_servers, cluster_servers, enabled, data_filter, selected_columns, field_group_name, custom_sql, include_audit_data)")
) -> Dict[str, Any]:
    """
    Replace a syslog export filter by numeric ID.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: name, export_template, export_event_format_type, syslog_servers.

    Maps to 'replace_syslog_export_filter_by_syslog_export_filter_id' in pyclearpass (PUT /syslog-export-filter/{syslog_export_filter_id}).
    """
    await ctx.info(f"Replacing syslog export filter {syslog_export_filter_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_syslog_export_filter_by_id(syslog_export_filter_id, filter_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced syslog export filter {syslog_export_filter_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace syslog export filter: {e}")
        return await format_api_error(e, "replace syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace syslog export filter."
        }


@operation(domain="integrations")
async def delete_syslog_export_filter_by_id(
    ctx: Context,
    syslog_export_filter_id: int = Field(..., description="Numeric ID of the syslog export filter")
) -> Dict[str, Any]:
    """
    Delete a syslog export filter by numeric ID.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_syslog_export_filter_by_syslog_export_filter_id' in pyclearpass (DELETE /syslog-export-filter/{syslog_export_filter_id}).
    """
    await ctx.info(f"Deleting syslog export filter {syslog_export_filter_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_syslog_export_filter_by_id(syslog_export_filter_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted syslog export filter {syslog_export_filter_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete syslog export filter: {e}")
        return await format_api_error(e, "delete syslog export filter")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete syslog export filter: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete syslog export filter."
        }


# ============================================================================
# SYSLOG TARGETS
# ============================================================================


@operation(domain="integrations")
async def list_syslog_targets(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return (1-1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List syslog targets configured on ClearPass.

    Syslog targets are the remote collectors that syslog export filters send ClearPass data to.

    Maps to 'get_syslog_target' in pyclearpass (GET /syslog-target).
    """
    await ctx.info("Retrieving syslog targets...")

    try:
        client = await get_clearpass_client()
        result = await client.list_syslog_targets(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved {len(result.get('_embedded', {}).get('items', []))} syslog targets."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list syslog targets: {e}")
        return await format_api_error(e, "list syslog targets")
    except Exception as e:
        logger.error(f"Unexpected error trying to list syslog targets: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list syslog targets."
        }


@operation(domain="integrations")
async def create_syslog_target(
    ctx: Context,
    target_data: Dict[str, Any] = Field(..., description="Syslog target definition (host_address, description, server_port, protocol)")
) -> Dict[str, Any]:
    """
    Create a new syslog target.

    Required body fields: host_address, protocol, server_port.

    Maps to 'new_syslog_target' in pyclearpass (POST /syslog-target).
    """
    await ctx.info("Creating syslog target...")

    try:
        client = await get_clearpass_client()
        result = await client.create_syslog_target(target_data)

        return {
            "success": True,
            "data": result,
            "message": "Successfully created the syslog target."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create syslog target: {e}")
        return await format_api_error(e, "create syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to create syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create syslog target."
        }


@operation(domain="integrations")
async def get_syslog_target_by_host_address(
    ctx: Context,
    host_address: str = Field(..., description="Server host address of the syslog target")
) -> Dict[str, Any]:
    """
    Get a syslog target by host address.

    Returns the full configuration of a single syslog target.

    Maps to 'get_syslog_target_host_address_by_host_address' in pyclearpass (GET /syslog-target/host-address/{host_address}).
    """
    await ctx.info(f"Retrieving syslog target '{host_address}'...")

    try:
        client = await get_clearpass_client()
        result = await client.get_syslog_target_by_host_address(host_address)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved syslog target '{host_address}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get syslog target: {e}")
        return await format_api_error(e, "get syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to get syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get syslog target."
        }


@operation(domain="integrations")
async def update_syslog_target_by_host_address(
    ctx: Context,
    host_address: str = Field(..., description="Server host address of the syslog target"),
    target_data: Dict[str, Any] = Field(..., description="Syslog target definition (host_address, description, server_port, protocol)")
) -> Dict[str, Any]:
    """
    Update selected fields of a syslog target by host address.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_syslog_target_host_address_by_host_address' in pyclearpass (PATCH /syslog-target/host-address/{host_address}).
    """
    await ctx.info(f"Updating syslog target '{host_address}'...")

    try:
        client = await get_clearpass_client()
        result = await client.update_syslog_target_by_host_address(host_address, target_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated syslog target '{host_address}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update syslog target: {e}")
        return await format_api_error(e, "update syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to update syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update syslog target."
        }


@operation(domain="integrations")
async def replace_syslog_target_by_host_address(
    ctx: Context,
    host_address: str = Field(..., description="Server host address of the syslog target"),
    target_data: Dict[str, Any] = Field(..., description="Syslog target definition (host_address, description, server_port, protocol)")
) -> Dict[str, Any]:
    """
    Replace a syslog target by host address.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: host_address, protocol, server_port.

    Maps to 'replace_syslog_target_host_address_by_host_address' in pyclearpass (PUT /syslog-target/host-address/{host_address}).
    """
    await ctx.info(f"Replacing syslog target '{host_address}'...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_syslog_target_by_host_address(host_address, target_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced syslog target '{host_address}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace syslog target: {e}")
        return await format_api_error(e, "replace syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace syslog target."
        }


@operation(domain="integrations")
async def delete_syslog_target_by_host_address(
    ctx: Context,
    host_address: str = Field(..., description="Server host address of the syslog target")
) -> Dict[str, Any]:
    """
    Delete a syslog target by host address.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_syslog_target_host_address_by_host_address' in pyclearpass (DELETE /syslog-target/host-address/{host_address}).
    """
    await ctx.info(f"Deleting syslog target '{host_address}'...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_syslog_target_by_host_address(host_address)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted syslog target '{host_address}'."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete syslog target: {e}")
        return await format_api_error(e, "delete syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete syslog target."
        }


@operation(domain="integrations")
async def get_syslog_target_by_id(
    ctx: Context,
    syslog_target_id: int = Field(..., description="Numeric ID of the syslog target")
) -> Dict[str, Any]:
    """
    Get a syslog target by numeric ID.

    Returns the full configuration of a single syslog target.

    Maps to 'get_syslog_target_by_syslog_target_id' in pyclearpass (GET /syslog-target/{syslog_target_id}).
    """
    await ctx.info(f"Retrieving syslog target {syslog_target_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.get_syslog_target_by_id(syslog_target_id)

        return {
            "success": True,
            "data": result,
            "message": f"Retrieved syslog target {syslog_target_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get syslog target: {e}")
        return await format_api_error(e, "get syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to get syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get syslog target."
        }


@operation(domain="integrations")
async def update_syslog_target_by_id(
    ctx: Context,
    syslog_target_id: int = Field(..., description="Numeric ID of the syslog target"),
    target_data: Dict[str, Any] = Field(..., description="Syslog target definition (host_address, description, server_port, protocol)")
) -> Dict[str, Any]:
    """
    Update selected fields of a syslog target by numeric ID.

    Only the fields present in the body are modified (PATCH semantics).

    Maps to 'update_syslog_target_by_syslog_target_id' in pyclearpass (PATCH /syslog-target/{syslog_target_id}).
    """
    await ctx.info(f"Updating syslog target {syslog_target_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.update_syslog_target_by_id(syslog_target_id, target_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully updated syslog target {syslog_target_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update syslog target: {e}")
        return await format_api_error(e, "update syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to update syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update syslog target."
        }


@operation(domain="integrations")
async def replace_syslog_target_by_id(
    ctx: Context,
    syslog_target_id: int = Field(..., description="Numeric ID of the syslog target"),
    target_data: Dict[str, Any] = Field(..., description="Syslog target definition (host_address, description, server_port, protocol)")
) -> Dict[str, Any]:
    """
    Replace a syslog target by numeric ID.

    Full replacement (PUT semantics) - supply the complete definition. Required body fields: host_address, protocol, server_port.

    Maps to 'replace_syslog_target_by_syslog_target_id' in pyclearpass (PUT /syslog-target/{syslog_target_id}).
    """
    await ctx.info(f"Replacing syslog target {syslog_target_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.replace_syslog_target_by_id(syslog_target_id, target_data)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully replaced syslog target {syslog_target_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace syslog target: {e}")
        return await format_api_error(e, "replace syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to replace syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace syslog target."
        }


@operation(domain="integrations")
async def delete_syslog_target_by_id(
    ctx: Context,
    syslog_target_id: int = Field(..., description="Numeric ID of the syslog target")
) -> Dict[str, Any]:
    """
    Delete a syslog target by numeric ID.

    This permanently removes the configuration from ClearPass.

    Maps to 'delete_syslog_target_by_syslog_target_id' in pyclearpass (DELETE /syslog-target/{syslog_target_id}).
    """
    await ctx.info(f"Deleting syslog target {syslog_target_id}...")

    try:
        client = await get_clearpass_client()
        result = await client.delete_syslog_target_by_id(syslog_target_id)

        return {
            "success": True,
            "data": result,
            "message": f"Successfully deleted syslog target {syslog_target_id}."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete syslog target: {e}")
        return await format_api_error(e, "delete syslog target")
    except Exception as e:
        logger.error(f"Unexpected error trying to delete syslog target: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete syslog target."
        }
