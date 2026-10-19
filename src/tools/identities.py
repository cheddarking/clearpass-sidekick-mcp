"""
MCP tools for ClearPass identity operations.

Covers the ClearPass identity resources: endpoints, device accounts, local
users, static host lists, deny-listed users and external accounts, plus the
replace (PUT) variants of guest accounts and API clients that the guest and
api-client modules do not provide.

Every resource is reachable both by its numeric id and by its natural key
(MAC address, user_id, username or name) -- these are distinct ClearPass
endpoints, so both variants are exposed as separate operations.
"""

import logging
from typing import Any, Dict, List, Optional

from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation
from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


def _extract_items(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull the collection out of a ClearPass HAL list response."""
    if isinstance(response, dict):
        embedded = response.get("_embedded")
        if isinstance(embedded, dict) and "items" in embedded:
            return embedded["items"] or []
        if "items" in response:
            return response["items"] or []
    return []


@operation(domain="identities")
async def list_endpoints(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description='JSON filter expression, e.g. {"name": {"$contains": "lab"}}'),
    sort: Optional[str] = Field(None, description="Sort ordering, e.g. '+id' or '-name'"),
    offset: Optional[int] = Field(None, description="Zero-based index of the first item to return"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count"),
    profile_details: Optional[bool] = Field(None, description="Include full endpoint profiling details in the response")
) -> Dict[str, Any]:
    """
    List endpoints.

    Retrieves endpoints configured in ClearPass, with optional
    filtering, sorting and pagination.

    Maps to 'get_endpoint' in pyclearpass (GET /endpoint).
    """
    await ctx.info(f"Retrieving endpoints (limit: {limit})...")

    try:
        client = await get_clearpass_client()
        response = await client.list_endpoints(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
            profile_details=profile_details
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": response.get("count", len(items)),
            "endpoints": items,
            "message": f"Retrieved {len(items)} endpoints",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list endpoints: {e}")
        return await format_api_error(e, "list endpoints")


@operation(domain="identities")
async def create_endpoint(
    ctx: Context,
    endpoint_data: Dict[str, Any] = Field(..., description="Endpoint attributes to create. Required body fields: mac_address, status.")
) -> Dict[str, Any]:
    """
    Create a new endpoint.

    Creates an endpoint in ClearPass from the supplied attribute
    dictionary.
    Required body fields: mac_address, status.

    Maps to 'new_endpoint' in pyclearpass (POST /endpoint).
    """
    await ctx.info("Creating endpoint...")

    try:
        client = await get_clearpass_client()
        response = await client.create_endpoint(endpoint_data)

        return {
            "success": True,
            "endpoint": response,
            "message": "Endpoint created successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create endpoint: {e}")
        return await format_api_error(e, "create endpoint")


@operation(domain="identities")
async def get_endpoint_by_id(
    ctx: Context,
    endpoint_id: int = Field(..., description="Numeric ClearPass id of the endpoint"),
    profile_details: Optional[bool] = Field(None, description="Include full endpoint profiling details in the response")
) -> Dict[str, Any]:
    """
    Get an endpoint by its numeric id.

    Retrieves a single endpoint using its ClearPass id.

    Maps to 'get_endpoint_by_endpoint_id' in pyclearpass (GET /endpoint/{endpoint_id}).
    """
    await ctx.info(f"Retrieving endpoint {endpoint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_endpoint_by_id(endpoint_id, profile_details=profile_details)

        return {
            "success": True,
            "endpoint": response,
            "message": f"Retrieved endpoint {endpoint_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get endpoint by id: {e}")
        return await format_api_error(e, "get endpoint by id")


@operation(domain="identities")
async def update_endpoint_by_id(
    ctx: Context,
    endpoint_id: int = Field(..., description="Numeric ClearPass id of the endpoint"),
    endpoint_data: Dict[str, Any] = Field(..., description="Fields to apply to the endpoint.")
) -> Dict[str, Any]:
    """
    Update some fields of an endpoint by id.

    Partially updates an endpoint (PATCH semantics) -- only the keys
    present in the supplied dictionary are modified.

    Maps to 'update_endpoint_by_endpoint_id' in pyclearpass (PATCH /endpoint/{endpoint_id}).
    """
    await ctx.info(f"Updating endpoint {endpoint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_endpoint_by_id(endpoint_id, endpoint_data)

        return {
            "success": True,
            "endpoint": response,
            "message": f"Endpoint {endpoint_id} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update endpoint by id: {e}")
        return await format_api_error(e, "update endpoint by id")


@operation(domain="identities")
async def replace_endpoint_by_id(
    ctx: Context,
    endpoint_id: int = Field(..., description="Numeric ClearPass id of the endpoint"),
    endpoint_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the endpoint. Required body fields: mac_address, status.")
) -> Dict[str, Any]:
    """
    Replace an endpoint by id.

    Replaces the entire endpoint record (PUT semantics) -- any field
    omitted from the body is reset.
    Required body fields: mac_address, status.

    Maps to 'replace_endpoint_by_endpoint_id' in pyclearpass (PUT /endpoint/{endpoint_id}).
    """
    await ctx.info(f"Replacing endpoint {endpoint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_endpoint_by_id(endpoint_id, endpoint_data)

        return {
            "success": True,
            "endpoint": response,
            "message": f"Endpoint {endpoint_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace endpoint by id: {e}")
        return await format_api_error(e, "replace endpoint by id")


@operation(domain="identities")
async def delete_endpoint_by_id(
    ctx: Context,
    endpoint_id: int = Field(..., description="Numeric ClearPass id of the endpoint")
) -> Dict[str, Any]:
    """
    Delete an endpoint by id.

    Permanently removes the endpoint identified by its ClearPass id.

    Maps to 'delete_endpoint_by_endpoint_id' in pyclearpass (DELETE /endpoint/{endpoint_id}).
    """
    await ctx.info(f"Deleting endpoint {endpoint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_endpoint_by_id(endpoint_id)

        return {
            "success": True,
            "result": response,
            "message": f"Endpoint {endpoint_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete endpoint by id: {e}")
        return await format_api_error(e, "delete endpoint by id")


@operation(domain="identities")
async def get_endpoint_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address of the endpoint (e.g. '00:11:22:33:44:55')"),
    profile_details: Optional[bool] = Field(None, description="Include full endpoint profiling details in the response")
) -> Dict[str, Any]:
    """
    Get an endpoint by MAC address.

    Retrieves a single endpoint using its MAC address instead of
    the numeric id.

    Maps to 'get_endpoint_mac_address_by_mac_address' in pyclearpass (GET /endpoint/mac-address/{mac_address}).
    """
    await ctx.info(f"Retrieving endpoint {mac_address}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_endpoint_by_mac(mac_address, profile_details=profile_details)

        return {
            "success": True,
            "endpoint": response,
            "message": f"Retrieved endpoint {mac_address}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get endpoint by MAC address: {e}")
        return await format_api_error(e, "get endpoint by MAC address")


@operation(domain="identities")
async def update_endpoint_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address of the endpoint (e.g. '00:11:22:33:44:55')"),
    endpoint_data: Dict[str, Any] = Field(..., description="Fields to apply to the endpoint.")
) -> Dict[str, Any]:
    """
    Update some fields of an endpoint by MAC address.

    Partially updates the endpoint addressed by MAC address
    (PATCH semantics).

    Maps to 'update_endpoint_mac_address_by_mac_address' in pyclearpass (PATCH /endpoint/mac-address/{mac_address}).
    """
    await ctx.info(f"Updating endpoint {mac_address}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_endpoint_by_mac(mac_address, endpoint_data)

        return {
            "success": True,
            "endpoint": response,
            "message": f"Endpoint {mac_address} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update endpoint by MAC address: {e}")
        return await format_api_error(e, "update endpoint by MAC address")


@operation(domain="identities")
async def replace_endpoint_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address of the endpoint (e.g. '00:11:22:33:44:55')"),
    endpoint_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the endpoint. Required body fields: mac_address, status.")
) -> Dict[str, Any]:
    """
    Replace an endpoint by MAC address.

    Replaces the entire endpoint record addressed by MAC address
    (PUT semantics).
    Required body fields: mac_address, status.

    Maps to 'replace_endpoint_mac_address_by_mac_address' in pyclearpass (PUT /endpoint/mac-address/{mac_address}).
    """
    await ctx.info(f"Replacing endpoint {mac_address}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_endpoint_by_mac(mac_address, endpoint_data)

        return {
            "success": True,
            "endpoint": response,
            "message": f"Endpoint {mac_address} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace endpoint by MAC address: {e}")
        return await format_api_error(e, "replace endpoint by MAC address")


@operation(domain="identities")
async def delete_endpoint_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address of the endpoint (e.g. '00:11:22:33:44:55')")
) -> Dict[str, Any]:
    """
    Delete an endpoint by MAC address.

    Permanently removes the endpoint addressed by MAC address.

    Maps to 'delete_endpoint_mac_address_by_mac_address' in pyclearpass (DELETE /endpoint/mac-address/{mac_address}).
    """
    await ctx.info(f"Deleting endpoint {mac_address}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_endpoint_by_mac(mac_address)

        return {
            "success": True,
            "result": response,
            "message": f"Endpoint {mac_address} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete endpoint by MAC address: {e}")
        return await format_api_error(e, "delete endpoint by MAC address")


@operation(domain="identities")
async def list_devices(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description='JSON filter expression, e.g. {"name": {"$contains": "lab"}}'),
    sort: Optional[str] = Field(None, description="Sort ordering, e.g. '+id' or '-name'"),
    offset: Optional[int] = Field(None, description="Zero-based index of the first item to return"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List devices.

    Retrieves devices configured in ClearPass, with optional
    filtering, sorting and pagination.

    Maps to 'get_device' in pyclearpass (GET /device).
    """
    await ctx.info(f"Retrieving devices (limit: {limit})...")

    try:
        client = await get_clearpass_client()
        response = await client.list_devices(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": response.get("count", len(items)),
            "devices": items,
            "message": f"Retrieved {len(items)} devices",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list devices: {e}")
        return await format_api_error(e, "list devices")


@operation(domain="identities")
async def create_device(
    ctx: Context,
    device_data: Dict[str, Any] = Field(..., description="Device attributes to create. Required body fields: mac, role_id."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Create a new device.

    Creates a device in ClearPass from the supplied attribute
    dictionary.
    Required body fields: mac, role_id.

    Maps to 'new_device' in pyclearpass (POST /device).
    """
    await ctx.info("Creating device...")

    try:
        client = await get_clearpass_client()
        response = await client.create_device(device_data, change_of_authorization=change_of_authorization)

        return {
            "success": True,
            "device": response,
            "message": "Device created successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create device: {e}")
        return await format_api_error(e, "create device")


@operation(domain="identities")
async def get_device_by_id(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ClearPass id of the device account")
) -> Dict[str, Any]:
    """
    Get a device by its numeric id.

    Retrieves a single device using its ClearPass id.

    Maps to 'get_device_by_device_id' in pyclearpass (GET /device/{device_id}).
    """
    await ctx.info(f"Retrieving device {device_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_device_by_id(device_id)

        return {
            "success": True,
            "device": response,
            "message": f"Retrieved device {device_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get device by id: {e}")
        return await format_api_error(e, "get device by id")


@operation(domain="identities")
async def update_device_by_id(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ClearPass id of the device account"),
    device_data: Dict[str, Any] = Field(..., description="Fields to apply to the device."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Update some fields of a device by id.

    Partially updates a device (PATCH semantics) -- only the keys
    present in the supplied dictionary are modified.

    Maps to 'update_device_by_device_id' in pyclearpass (PATCH /device/{device_id}).
    """
    await ctx.info(f"Updating device {device_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_device_by_id(
            device_id,
            device_data,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "device": response,
            "message": f"Device {device_id} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update device by id: {e}")
        return await format_api_error(e, "update device by id")


@operation(domain="identities")
async def replace_device_by_id(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ClearPass id of the device account"),
    device_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the device. Required body fields: mac, role_id."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Replace a device by id.

    Replaces the entire device record (PUT semantics) -- any field
    omitted from the body is reset.
    Required body fields: mac, role_id.

    Maps to 'replace_device_by_device_id' in pyclearpass (PUT /device/{device_id}).
    """
    await ctx.info(f"Replacing device {device_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_device_by_id(
            device_id,
            device_data,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "device": response,
            "message": f"Device {device_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace device by id: {e}")
        return await format_api_error(e, "replace device by id")


@operation(domain="identities")
async def delete_device_by_id(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ClearPass id of the device account"),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Delete a device by id.

    Permanently removes the device identified by its ClearPass id.

    Maps to 'delete_device_by_device_id' in pyclearpass (DELETE /device/{device_id}).
    """
    await ctx.info(f"Deleting device {device_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_device_by_id(
            device_id,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "result": response,
            "message": f"Device {device_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete device by id: {e}")
        return await format_api_error(e, "delete device by id")


@operation(domain="identities")
async def get_device_by_mac(
    ctx: Context,
    macaddr: str = Field(..., description="MAC address of the device account (e.g. '00:11:22:33:44:55')")
) -> Dict[str, Any]:
    """
    Get a device by MAC address.

    Retrieves a single device using its MAC address instead of
    the numeric id.

    Maps to 'get_device_mac_by_macaddr' in pyclearpass (GET /device/mac/{macaddr}).
    """
    await ctx.info(f"Retrieving device {macaddr}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_device_by_mac(macaddr)

        return {
            "success": True,
            "device": response,
            "message": f"Retrieved device {macaddr}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get device by MAC address: {e}")
        return await format_api_error(e, "get device by MAC address")


@operation(domain="identities")
async def update_device_by_mac(
    ctx: Context,
    macaddr: str = Field(..., description="MAC address of the device account (e.g. '00:11:22:33:44:55')"),
    device_data: Dict[str, Any] = Field(..., description="Fields to apply to the device."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Update some fields of a device by MAC address.

    Partially updates the device addressed by MAC address
    (PATCH semantics).

    Maps to 'update_device_mac_by_macaddr' in pyclearpass (PATCH /device/mac/{macaddr}).
    """
    await ctx.info(f"Updating device {macaddr}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_device_by_mac(
            macaddr,
            device_data,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "device": response,
            "message": f"Device {macaddr} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update device by MAC address: {e}")
        return await format_api_error(e, "update device by MAC address")


@operation(domain="identities")
async def replace_device_by_mac(
    ctx: Context,
    macaddr: str = Field(..., description="MAC address of the device account (e.g. '00:11:22:33:44:55')"),
    device_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the device. Required body fields: mac, role_id."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Replace a device by MAC address.

    Replaces the entire device record addressed by MAC address
    (PUT semantics).
    Required body fields: mac, role_id.

    Maps to 'replace_device_mac_by_macaddr' in pyclearpass (PUT /device/mac/{macaddr}).
    """
    await ctx.info(f"Replacing device {macaddr}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_device_by_mac(
            macaddr,
            device_data,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "device": response,
            "message": f"Device {macaddr} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace device by MAC address: {e}")
        return await format_api_error(e, "replace device by MAC address")


@operation(domain="identities")
async def delete_device_by_mac(
    ctx: Context,
    macaddr: str = Field(..., description="MAC address of the device account (e.g. '00:11:22:33:44:55')"),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for affected sessions")
) -> Dict[str, Any]:
    """
    Delete a device by MAC address.

    Permanently removes the device addressed by MAC address.

    Maps to 'delete_device_mac_by_macaddr' in pyclearpass (DELETE /device/mac/{macaddr}).
    """
    await ctx.info(f"Deleting device {macaddr}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_device_by_mac(macaddr, change_of_authorization=change_of_authorization)

        return {
            "success": True,
            "result": response,
            "message": f"Device {macaddr} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete device by MAC address: {e}")
        return await format_api_error(e, "delete device by MAC address")


@operation(domain="identities")
async def list_local_users(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description='JSON filter expression, e.g. {"name": {"$contains": "lab"}}'),
    sort: Optional[str] = Field(None, description="Sort ordering, e.g. '+id' or '-name'"),
    offset: Optional[int] = Field(None, description="Zero-based index of the first item to return"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List local users.

    Retrieves local users configured in ClearPass, with optional
    filtering, sorting and pagination.

    Maps to 'get_local_user' in pyclearpass (GET /local-user).
    """
    await ctx.info(f"Retrieving local users (limit: {limit})...")

    try:
        client = await get_clearpass_client()
        response = await client.list_local_users(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": response.get("count", len(items)),
            "local_users": items,
            "message": f"Retrieved {len(items)} local users",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list local users: {e}")
        return await format_api_error(e, "list local users")


@operation(domain="identities")
async def create_local_user(
    ctx: Context,
    local_user_data: Dict[str, Any] = Field(..., description="Local user attributes to create. Required body fields: user_id, password, username, role_name.")
) -> Dict[str, Any]:
    """
    Create a new local user.

    Creates a local user in ClearPass from the supplied attribute
    dictionary.
    Required body fields: user_id, password, username, role_name.

    Maps to 'new_local_user' in pyclearpass (POST /local-user).
    """
    await ctx.info("Creating local user...")

    try:
        client = await get_clearpass_client()
        response = await client.create_local_user(local_user_data)

        return {
            "success": True,
            "local_user": response,
            "message": "Local user created successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create local user: {e}")
        return await format_api_error(e, "create local user")


@operation(domain="identities")
async def get_local_user_by_id(
    ctx: Context,
    local_user_id: int = Field(..., description="Numeric ClearPass id of the local user")
) -> Dict[str, Any]:
    """
    Get a local user by its numeric id.

    Retrieves a single local user using its ClearPass id.

    Maps to 'get_local_user_by_local_user_id' in pyclearpass (GET /local-user/{local_user_id}).
    """
    await ctx.info(f"Retrieving local user {local_user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_local_user_by_id(local_user_id)

        return {
            "success": True,
            "local_user": response,
            "message": f"Retrieved local user {local_user_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get local user by id: {e}")
        return await format_api_error(e, "get local user by id")


@operation(domain="identities")
async def update_local_user_by_id(
    ctx: Context,
    local_user_id: int = Field(..., description="Numeric ClearPass id of the local user"),
    local_user_data: Dict[str, Any] = Field(..., description="Fields to apply to the local user.")
) -> Dict[str, Any]:
    """
    Update some fields of a local user by id.

    Partially updates a local user (PATCH semantics) -- only the keys
    present in the supplied dictionary are modified.

    Maps to 'update_local_user_by_local_user_id' in pyclearpass (PATCH /local-user/{local_user_id}).
    """
    await ctx.info(f"Updating local user {local_user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_local_user_by_id(local_user_id, local_user_data)

        return {
            "success": True,
            "local_user": response,
            "message": f"Local user {local_user_id} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update local user by id: {e}")
        return await format_api_error(e, "update local user by id")


@operation(domain="identities")
async def replace_local_user_by_id(
    ctx: Context,
    local_user_id: int = Field(..., description="Numeric ClearPass id of the local user"),
    local_user_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the local user. Required body fields: user_id, password, username, role_name.")
) -> Dict[str, Any]:
    """
    Replace a local user by id.

    Replaces the entire local user record (PUT semantics) -- any field
    omitted from the body is reset.
    Required body fields: user_id, password, username, role_name.

    Maps to 'replace_local_user_by_local_user_id' in pyclearpass (PUT /local-user/{local_user_id}).
    """
    await ctx.info(f"Replacing local user {local_user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_local_user_by_id(local_user_id, local_user_data)

        return {
            "success": True,
            "local_user": response,
            "message": f"Local user {local_user_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace local user by id: {e}")
        return await format_api_error(e, "replace local user by id")


@operation(domain="identities")
async def delete_local_user_by_id(
    ctx: Context,
    local_user_id: int = Field(..., description="Numeric ClearPass id of the local user")
) -> Dict[str, Any]:
    """
    Delete a local user by id.

    Permanently removes the local user identified by its ClearPass id.

    Maps to 'delete_local_user_by_local_user_id' in pyclearpass (DELETE /local-user/{local_user_id}).
    """
    await ctx.info(f"Deleting local user {local_user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_local_user_by_id(local_user_id)

        return {
            "success": True,
            "result": response,
            "message": f"Local user {local_user_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete local user by id: {e}")
        return await format_api_error(e, "delete local user by id")


@operation(domain="identities")
async def get_local_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="user_id (login name) of the local user")
) -> Dict[str, Any]:
    """
    Get a local user by user_id.

    Retrieves a single local user using its user_id instead of
    the numeric id.

    Maps to 'get_local_user_user_id_by_user_id' in pyclearpass (GET /local-user/user-id/{user_id}).
    """
    await ctx.info(f"Retrieving local user {user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_local_user_by_user_id(user_id)

        return {
            "success": True,
            "local_user": response,
            "message": f"Retrieved local user {user_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get local user by user_id: {e}")
        return await format_api_error(e, "get local user by user_id")


@operation(domain="identities")
async def update_local_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="user_id (login name) of the local user"),
    local_user_data: Dict[str, Any] = Field(..., description="Fields to apply to the local user.")
) -> Dict[str, Any]:
    """
    Update some fields of a local user by user_id.

    Partially updates the local user addressed by user_id
    (PATCH semantics).

    Maps to 'update_local_user_user_id_by_user_id' in pyclearpass (PATCH /local-user/user-id/{user_id}).
    """
    await ctx.info(f"Updating local user {user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_local_user_by_user_id(user_id, local_user_data)

        return {
            "success": True,
            "local_user": response,
            "message": f"Local user {user_id} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update local user by user_id: {e}")
        return await format_api_error(e, "update local user by user_id")


@operation(domain="identities")
async def replace_local_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="user_id (login name) of the local user"),
    local_user_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the local user. Required body fields: user_id, password, username, role_name.")
) -> Dict[str, Any]:
    """
    Replace a local user by user_id.

    Replaces the entire local user record addressed by user_id
    (PUT semantics).
    Required body fields: user_id, password, username, role_name.

    Maps to 'replace_local_user_user_id_by_user_id' in pyclearpass (PUT /local-user/user-id/{user_id}).
    """
    await ctx.info(f"Replacing local user {user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_local_user_by_user_id(user_id, local_user_data)

        return {
            "success": True,
            "local_user": response,
            "message": f"Local user {user_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace local user by user_id: {e}")
        return await format_api_error(e, "replace local user by user_id")


@operation(domain="identities")
async def delete_local_user_by_user_id(
    ctx: Context,
    user_id: str = Field(..., description="user_id (login name) of the local user")
) -> Dict[str, Any]:
    """
    Delete a local user by user_id.

    Permanently removes the local user addressed by user_id.

    Maps to 'delete_local_user_user_id_by_user_id' in pyclearpass (DELETE /local-user/user-id/{user_id}).
    """
    await ctx.info(f"Deleting local user {user_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_local_user_by_user_id(user_id)

        return {
            "success": True,
            "result": response,
            "message": f"Local user {user_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete local user by user_id: {e}")
        return await format_api_error(e, "delete local user by user_id")


@operation(domain="identities")
async def list_static_host_lists(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description='JSON filter expression, e.g. {"name": {"$contains": "lab"}}'),
    sort: Optional[str] = Field(None, description="Sort ordering, e.g. '+id' or '-name'"),
    offset: Optional[int] = Field(None, description="Zero-based index of the first item to return"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List static host lists.

    Retrieves static host lists configured in ClearPass, with optional
    filtering, sorting and pagination.

    Maps to 'get_static_host_list' in pyclearpass (GET /static-host-list).
    """
    await ctx.info(f"Retrieving static host lists (limit: {limit})...")

    try:
        client = await get_clearpass_client()
        response = await client.list_static_host_lists(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": response.get("count", len(items)),
            "static_host_lists": items,
            "message": f"Retrieved {len(items)} static host lists",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list static host lists: {e}")
        return await format_api_error(e, "list static host lists")


@operation(domain="identities")
async def create_static_host_list(
    ctx: Context,
    static_host_list_data: Dict[str, Any] = Field(..., description="Static host list attributes to create. Required body fields: name, host_format, host_type.")
) -> Dict[str, Any]:
    """
    Create a new static host list.

    Creates a static host list in ClearPass from the supplied attribute
    dictionary.
    Required body fields: name, host_format, host_type.

    Maps to 'new_static_host_list' in pyclearpass (POST /static-host-list).
    """
    await ctx.info("Creating static host list...")

    try:
        client = await get_clearpass_client()
        response = await client.create_static_host_list(static_host_list_data)

        return {
            "success": True,
            "static_host_list": response,
            "message": "Static host list created successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create static host list: {e}")
        return await format_api_error(e, "create static host list")


@operation(domain="identities")
async def get_static_host_list_by_id(
    ctx: Context,
    static_host_list_id: int = Field(..., description="Numeric ClearPass id of the static host list")
) -> Dict[str, Any]:
    """
    Get a static host list by its numeric id.

    Retrieves a single static host list using its ClearPass id.

    Maps to 'get_static_host_list_by_static_host_list_id' in pyclearpass (GET /static-host-list/{static_host_list_id}).
    """
    await ctx.info(f"Retrieving static host list {static_host_list_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_static_host_list_by_id(static_host_list_id)

        return {
            "success": True,
            "static_host_list": response,
            "message": f"Retrieved static host list {static_host_list_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get static host list by id: {e}")
        return await format_api_error(e, "get static host list by id")


@operation(domain="identities")
async def update_static_host_list_by_id(
    ctx: Context,
    static_host_list_id: int = Field(..., description="Numeric ClearPass id of the static host list"),
    static_host_list_data: Dict[str, Any] = Field(..., description="Fields to apply to the static host list.")
) -> Dict[str, Any]:
    """
    Update some fields of a static host list by id.

    Partially updates a static host list (PATCH semantics) -- only the keys
    present in the supplied dictionary are modified.

    Maps to 'update_static_host_list_by_static_host_list_id' in pyclearpass (PATCH /static-host-list/{static_host_list_id}).
    """
    await ctx.info(f"Updating static host list {static_host_list_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_static_host_list_by_id(static_host_list_id, static_host_list_data)

        return {
            "success": True,
            "static_host_list": response,
            "message": f"Static host list {static_host_list_id} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update static host list by id: {e}")
        return await format_api_error(e, "update static host list by id")


@operation(domain="identities")
async def replace_static_host_list_by_id(
    ctx: Context,
    static_host_list_id: int = Field(..., description="Numeric ClearPass id of the static host list"),
    static_host_list_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the static host list. Required body fields: name, host_format, host_type.")
) -> Dict[str, Any]:
    """
    Replace a static host list by id.

    Replaces the entire static host list record (PUT semantics) -- any field
    omitted from the body is reset.
    Required body fields: name, host_format, host_type.

    Maps to 'replace_static_host_list_by_static_host_list_id' in pyclearpass (PUT /static-host-list/{static_host_list_id}).
    """
    await ctx.info(f"Replacing static host list {static_host_list_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_static_host_list_by_id(static_host_list_id, static_host_list_data)

        return {
            "success": True,
            "static_host_list": response,
            "message": f"Static host list {static_host_list_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace static host list by id: {e}")
        return await format_api_error(e, "replace static host list by id")


@operation(domain="identities")
async def delete_static_host_list_by_id(
    ctx: Context,
    static_host_list_id: int = Field(..., description="Numeric ClearPass id of the static host list")
) -> Dict[str, Any]:
    """
    Delete a static host list by id.

    Permanently removes the static host list identified by its ClearPass id.

    Maps to 'delete_static_host_list_by_static_host_list_id' in pyclearpass (DELETE /static-host-list/{static_host_list_id}).
    """
    await ctx.info(f"Deleting static host list {static_host_list_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_static_host_list_by_id(static_host_list_id)

        return {
            "success": True,
            "result": response,
            "message": f"Static host list {static_host_list_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete static host list by id: {e}")
        return await format_api_error(e, "delete static host list by id")


@operation(domain="identities")
async def get_static_host_list_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the static host list")
) -> Dict[str, Any]:
    """
    Get a static host list by name.

    Retrieves a single static host list using its name instead of
    the numeric id.

    Maps to 'get_static_host_list_name_by_name' in pyclearpass (GET /static-host-list/name/{name}).
    """
    await ctx.info(f"Retrieving static host list {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_static_host_list_by_name(name)

        return {
            "success": True,
            "static_host_list": response,
            "message": f"Retrieved static host list {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get static host list by name: {e}")
        return await format_api_error(e, "get static host list by name")


@operation(domain="identities")
async def update_static_host_list_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the static host list"),
    static_host_list_data: Dict[str, Any] = Field(..., description="Fields to apply to the static host list.")
) -> Dict[str, Any]:
    """
    Update some fields of a static host list by name.

    Partially updates the static host list addressed by name
    (PATCH semantics).

    Maps to 'update_static_host_list_name_by_name' in pyclearpass (PATCH /static-host-list/name/{name}).
    """
    await ctx.info(f"Updating static host list {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_static_host_list_by_name(name, static_host_list_data)

        return {
            "success": True,
            "static_host_list": response,
            "message": f"Static host list {name} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update static host list by name: {e}")
        return await format_api_error(e, "update static host list by name")


@operation(domain="identities")
async def replace_static_host_list_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the static host list"),
    static_host_list_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the static host list. Required body fields: name, host_format, host_type.")
) -> Dict[str, Any]:
    """
    Replace a static host list by name.

    Replaces the entire static host list record addressed by name
    (PUT semantics).
    Required body fields: name, host_format, host_type.

    Maps to 'replace_static_host_list_name_by_name' in pyclearpass (PUT /static-host-list/name/{name}).
    """
    await ctx.info(f"Replacing static host list {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_static_host_list_by_name(name, static_host_list_data)

        return {
            "success": True,
            "static_host_list": response,
            "message": f"Static host list {name} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace static host list by name: {e}")
        return await format_api_error(e, "replace static host list by name")


@operation(domain="identities")
async def delete_static_host_list_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the static host list")
) -> Dict[str, Any]:
    """
    Delete a static host list by name.

    Permanently removes the static host list addressed by name.

    Maps to 'delete_static_host_list_name_by_name' in pyclearpass (DELETE /static-host-list/name/{name}).
    """
    await ctx.info(f"Deleting static host list {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_static_host_list_by_name(name)

        return {
            "success": True,
            "result": response,
            "message": f"Static host list {name} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete static host list by name: {e}")
        return await format_api_error(e, "delete static host list by name")


@operation(domain="identities")
async def list_external_accounts(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description='JSON filter expression, e.g. {"name": {"$contains": "lab"}}'),
    sort: Optional[str] = Field(None, description="Sort ordering, e.g. '+id' or '-name'"),
    offset: Optional[int] = Field(None, description="Zero-based index of the first item to return"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List external accounts.

    Retrieves external accounts configured in ClearPass, with optional
    filtering, sorting and pagination.

    Maps to 'get_external_account' in pyclearpass (GET /external-account).
    """
    await ctx.info(f"Retrieving external accounts (limit: {limit})...")

    try:
        client = await get_clearpass_client()
        response = await client.list_external_accounts(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": response.get("count", len(items)),
            "external_accounts": items,
            "message": f"Retrieved {len(items)} external accounts",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list external accounts: {e}")
        return await format_api_error(e, "list external accounts")


@operation(domain="identities")
async def create_external_account(
    ctx: Context,
    external_account_data: Dict[str, Any] = Field(..., description="External account attributes to create. Required body fields: name, type.")
) -> Dict[str, Any]:
    """
    Create a new external account.

    Creates an external account in ClearPass from the supplied attribute
    dictionary.
    Required body fields: name, type.

    Maps to 'new_external_account' in pyclearpass (POST /external-account).
    """
    await ctx.info("Creating external account...")

    try:
        client = await get_clearpass_client()
        response = await client.create_external_account(external_account_data)

        return {
            "success": True,
            "external_account": response,
            "message": "External account created successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create external account: {e}")
        return await format_api_error(e, "create external account")


@operation(domain="identities")
async def get_external_account_by_id(
    ctx: Context,
    external_account_id: int = Field(..., description="Numeric ClearPass id of the external account")
) -> Dict[str, Any]:
    """
    Get an external account by its numeric id.

    Retrieves a single external account using its ClearPass id.

    Maps to 'get_external_account_by_external_account_id' in pyclearpass (GET /external-account/{external_account_id}).
    """
    await ctx.info(f"Retrieving external account {external_account_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_external_account_by_id(external_account_id)

        return {
            "success": True,
            "external_account": response,
            "message": f"Retrieved external account {external_account_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get external account by id: {e}")
        return await format_api_error(e, "get external account by id")


@operation(domain="identities")
async def update_external_account_by_id(
    ctx: Context,
    external_account_id: int = Field(..., description="Numeric ClearPass id of the external account"),
    external_account_data: Dict[str, Any] = Field(..., description="Fields to apply to the external account.")
) -> Dict[str, Any]:
    """
    Update some fields of an external account by id.

    Partially updates an external account (PATCH semantics) -- only the keys
    present in the supplied dictionary are modified.

    Maps to 'update_external_account_by_external_account_id' in pyclearpass (PATCH /external-account/{external_account_id}).
    """
    await ctx.info(f"Updating external account {external_account_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_external_account_by_id(external_account_id, external_account_data)

        return {
            "success": True,
            "external_account": response,
            "message": f"External account {external_account_id} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update external account by id: {e}")
        return await format_api_error(e, "update external account by id")


@operation(domain="identities")
async def replace_external_account_by_id(
    ctx: Context,
    external_account_id: int = Field(..., description="Numeric ClearPass id of the external account"),
    external_account_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the external account. Required body fields: name, type.")
) -> Dict[str, Any]:
    """
    Replace an external account by id.

    Replaces the entire external account record (PUT semantics) -- any field
    omitted from the body is reset.
    Required body fields: name, type.

    Maps to 'replace_external_account_by_external_account_id' in pyclearpass (PUT /external-account/{external_account_id}).
    """
    await ctx.info(f"Replacing external account {external_account_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_external_account_by_id(external_account_id, external_account_data)

        return {
            "success": True,
            "external_account": response,
            "message": f"External account {external_account_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace external account by id: {e}")
        return await format_api_error(e, "replace external account by id")


@operation(domain="identities")
async def delete_external_account_by_id(
    ctx: Context,
    external_account_id: int = Field(..., description="Numeric ClearPass id of the external account")
) -> Dict[str, Any]:
    """
    Delete an external account by id.

    Permanently removes the external account identified by its ClearPass id.

    Maps to 'delete_external_account_by_external_account_id' in pyclearpass (DELETE /external-account/{external_account_id}).
    """
    await ctx.info(f"Deleting external account {external_account_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_external_account_by_id(external_account_id)

        return {
            "success": True,
            "result": response,
            "message": f"External account {external_account_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete external account by id: {e}")
        return await format_api_error(e, "delete external account by id")


@operation(domain="identities")
async def get_external_account_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the external account")
) -> Dict[str, Any]:
    """
    Get an external account by name.

    Retrieves a single external account using its name instead of
    the numeric id.

    Maps to 'get_external_account_name_by_name' in pyclearpass (GET /external-account/name/{name}).
    """
    await ctx.info(f"Retrieving external account {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_external_account_by_name(name)

        return {
            "success": True,
            "external_account": response,
            "message": f"Retrieved external account {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get external account by name: {e}")
        return await format_api_error(e, "get external account by name")


@operation(domain="identities")
async def update_external_account_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the external account"),
    external_account_data: Dict[str, Any] = Field(..., description="Fields to apply to the external account.")
) -> Dict[str, Any]:
    """
    Update some fields of an external account by name.

    Partially updates the external account addressed by name
    (PATCH semantics).

    Maps to 'update_external_account_name_by_name' in pyclearpass (PATCH /external-account/name/{name}).
    """
    await ctx.info(f"Updating external account {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_external_account_by_name(name, external_account_data)

        return {
            "success": True,
            "external_account": response,
            "message": f"External account {name} updated successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update external account by name: {e}")
        return await format_api_error(e, "update external account by name")


@operation(domain="identities")
async def replace_external_account_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the external account"),
    external_account_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the external account. Required body fields: name, type.")
) -> Dict[str, Any]:
    """
    Replace an external account by name.

    Replaces the entire external account record addressed by name
    (PUT semantics).
    Required body fields: name, type.

    Maps to 'replace_external_account_name_by_name' in pyclearpass (PUT /external-account/name/{name}).
    """
    await ctx.info(f"Replacing external account {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_external_account_by_name(name, external_account_data)

        return {
            "success": True,
            "external_account": response,
            "message": f"External account {name} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace external account by name: {e}")
        return await format_api_error(e, "replace external account by name")


@operation(domain="identities")
async def delete_external_account_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the external account")
) -> Dict[str, Any]:
    """
    Delete an external account by name.

    Permanently removes the external account addressed by name.

    Maps to 'delete_external_account_name_by_name' in pyclearpass (DELETE /external-account/name/{name}).
    """
    await ctx.info(f"Deleting external account {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_external_account_by_name(name)

        return {
            "success": True,
            "result": response,
            "message": f"External account {name} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete external account by name: {e}")
        return await format_api_error(e, "delete external account by name")


@operation(domain="identities")
async def list_deny_listed_users(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description='JSON filter expression, e.g. {"name": {"$contains": "lab"}}'),
    sort: Optional[str] = Field(None, description="Sort ordering, e.g. '+id' or '-name'"),
    offset: Optional[int] = Field(None, description="Zero-based index of the first item to return"),
    limit: Optional[int] = Field(None, description="Maximum number of items to return"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List deny listed users.

    Retrieves the ClearPass deny list -- user/MAC pairs that have been
    blocked, typically by bandwidth or session-count enforcement.

    Maps to 'get_deny_listed_users' in pyclearpass (GET /deny-listed-users).
    """
    await ctx.info(f"Retrieving deny listed users (limit: {limit})...")

    try:
        client = await get_clearpass_client()
        response = await client.list_deny_listed_users(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": response.get("count", len(items)),
            "deny_listed_users": items,
            "message": f"Retrieved {len(items)} deny listed users",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list deny listed users: {e}")
        return await format_api_error(e, "list deny listed users")


@operation(domain="identities")
async def get_deny_listed_user_by_id(
    ctx: Context,
    deny_listed_users_id: int = Field(..., description="Numeric ClearPass id of the deny-list entry")
) -> Dict[str, Any]:
    """
    Get a deny listed user by id.

    Retrieves a single deny-list entry using its numeric ClearPass id.

    Maps to 'get_deny_listed_users_by_deny_listed_users_id' in pyclearpass (GET /deny-listed-users/{deny_listed_users_id}).
    """
    await ctx.info(f"Retrieving deny listed user {deny_listed_users_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_deny_listed_user_by_id(deny_listed_users_id)

        return {
            "success": True,
            "deny_listed_user": response,
            "message": f"Retrieved deny listed user {deny_listed_users_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get deny listed user by id: {e}")
        return await format_api_error(e, "get deny listed user by id")


@operation(domain="identities")
async def delete_deny_listed_user_by_id(
    ctx: Context,
    deny_listed_users_id: int = Field(..., description="Numeric ClearPass id of the deny-list entry")
) -> Dict[str, Any]:
    """
    Delete a deny listed user by id.

    Removes a deny-list entry by id, restoring network access for that
    user/MAC pair.

    Maps to 'delete_deny_listed_users_by_deny_listed_users_id' in pyclearpass (DELETE /deny-listed-users/{deny_listed_users_id}).
    """
    await ctx.info(f"Deleting deny listed user {deny_listed_users_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_deny_listed_user_by_id(deny_listed_users_id)

        return {
            "success": True,
            "result": response,
            "message": f"Deny listed user {deny_listed_users_id} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete deny listed user by id: {e}")
        return await format_api_error(e, "delete deny listed user by id")


@operation(domain="identities")
async def get_deny_listed_user_by_user_and_mac(
    ctx: Context,
    user_id: str = Field(..., description="Username of the deny listed user"),
    mac_address: str = Field(..., description="MAC address of the deny listed device")
) -> Dict[str, Any]:
    """
    Get a deny listed user by username and MAC address.

    Retrieves a deny-list entry using the natural key -- the username and
    the MAC address of the device that was denied.

    Maps to 'get_deny_listed_users_user_id_by_user_id_mac_address_mac_address' in pyclearpass (GET /deny-listed-users/user_id/{user_id}/mac_address/{mac_address}).
    """
    await ctx.info(f"Retrieving deny listed user {user_id}/{mac_address}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_deny_listed_user_by_user_and_mac(user_id, mac_address)

        return {
            "success": True,
            "deny_listed_user": response,
            "message": f"Retrieved deny listed user {user_id}/{mac_address}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get deny listed user by username and MAC address: {e}")
        return await format_api_error(e, "get deny listed user by username and MAC address")


@operation(domain="identities")
async def delete_deny_listed_user_by_user_and_mac(
    ctx: Context,
    user_id: str = Field(..., description="Username of the deny listed user"),
    mac_address: str = Field(..., description="MAC address of the deny listed device")
) -> Dict[str, Any]:
    """
    Delete a deny listed user by username and MAC address.

    Removes a deny-list entry addressed by username and MAC address,
    restoring network access for that pair.

    Maps to 'delete_deny_listed_users_user_id_by_user_id_mac_address_mac_address' in pyclearpass (DELETE /deny-listed-users/user_id/{user_id}/mac_address/{mac_address}).
    """
    await ctx.info(f"Deleting deny listed user {user_id}/{mac_address}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_deny_listed_user_by_user_and_mac(user_id, mac_address)

        return {
            "success": True,
            "result": response,
            "message": f"Deny listed user {user_id}/{mac_address} deleted successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete deny listed user by username and MAC address: {e}")
        return await format_api_error(e, "delete deny listed user by username and MAC address")


@operation(domain="identities")
async def replace_guest_by_id(
    ctx: Context,
    guest_id: int = Field(..., description="Numeric ClearPass id of the guest account"),
    guest_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the guest account. Required: username, password, role_id."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for the guest's sessions")
) -> Dict[str, Any]:
    """
    Replace a guest account by id.

    Replaces the entire guest account record (PUT semantics) -- any field
    omitted from the body is reset. Prefer update_guest_user for partial
    edits.
    Required body fields: username, password, role_id.
    NOTE: role_id belongs to the Guest Manager role namespace, which is
    NOT the Policy Manager role namespace returned by GET /role.

    Maps to 'replace_guest_by_guest_id' in pyclearpass (PUT /guest/{guest_id}).
    """
    await ctx.info(f"Replacing guest account {guest_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_guest_by_id(
            guest_id,
            guest_data,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "guest": response,
            "message": f"Guest account {guest_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace guest account by id: {e}")
        return await format_api_error(e, "replace guest account by id")


@operation(domain="identities")
async def replace_guest_by_username(
    ctx: Context,
    username: str = Field(..., description="Username of the guest account"),
    guest_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the guest account. Required: username, password, role_id."),
    change_of_authorization: Optional[bool] = Field(None, description="Whether to trigger a RADIUS Change of Authorization for the guest's sessions")
) -> Dict[str, Any]:
    """
    Replace a guest account by username.

    Replaces the entire guest account record addressed by username
    (PUT semantics) -- any field omitted from the body is reset.
    Required body fields: username, password, role_id.
    NOTE: role_id belongs to the Guest Manager role namespace, which is
    NOT the Policy Manager role namespace returned by GET /role.

    Maps to 'replace_guest_username_by_username' in pyclearpass (PUT /guest/username/{username}).
    """
    await ctx.info(f"Replacing guest account {username}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_guest_by_username(
            username,
            guest_data,
            change_of_authorization=change_of_authorization
        )

        return {
            "success": True,
            "guest": response,
            "message": f"Guest account {username} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace guest account by username: {e}")
        return await format_api_error(e, "replace guest account by username")


@operation(domain="identities")
async def replace_api_client(
    ctx: Context,
    client_id: str = Field(..., description="The unique string identifying the API client"),
    api_client_data: Dict[str, Any] = Field(..., description="Full replacement attributes for the API client.")
) -> Dict[str, Any]:
    """
    Replace an API client by client_id.

    Replaces the entire OAuth2 API client record (PUT semantics) -- any
    field omitted from the body is reset. Prefer update_api_client for
    partial edits.
    Required body fields: access_token_lifetime,
    access_token_lifetime_units, client_id, id, refresh_token_lifetime,
    refresh_token_lifetime_units.

    Maps to 'replace_api_client_by_client_id' in pyclearpass (PUT /api-client/{client_id}).
    """
    await ctx.info(f"Replacing API client {client_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_api_client(client_id, api_client_data)

        return {
            "success": True,
            "api_client": response,
            "message": f"API client {client_id} replaced successfully",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace API client: {e}")
        return await format_api_error(e, "replace API client")
