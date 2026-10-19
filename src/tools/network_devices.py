"""
MCP tools for Network Device management.
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


def _extract_device_list(result: Any) -> List[Dict[str, Any]]:
    """Normalise a ClearPass device-search response into a list of device dicts.

    A search that legitimately matches nothing returns
    ``{"_embedded": {"items": []}, "total": 0}``. That empty list is *falsy*, so
    a naive ``if not devices:`` fallback chain cannot tell "zero matches" from
    "unrecognised envelope"; it used to fall through to ``result["_embedded"]``
    -- the truthy dict ``{"items": []}`` -- and callers then iterated its *keys*
    and called ``.get()`` on the string ``"items"``, raising
    ``'str' object has no attribute 'get'``.

    Presence and type of the key decide here, never truthiness of its value, so
    an empty result set is returned faithfully as ``[]``.
    """
    if isinstance(result, list):
        return [d for d in result if isinstance(d, dict)]
    if not isinstance(result, dict):
        return []

    embedded = result.get("_embedded")
    if isinstance(embedded, dict):
        items = embedded.get("items")
        if isinstance(items, list):
            return [d for d in items if isinstance(d, dict)]
    elif isinstance(embedded, list):
        return [d for d in embedded if isinstance(d, dict)]

    for key in ("items", "devices"):
        value = result.get(key)
        if isinstance(value, list):
            return [d for d in value if isinstance(d, dict)]

    return []


@operation(domain="network_devices")
async def list_network_devices(
    ctx: Context,
    filter_coa_capable: Optional[bool] = None,
    vendor_filter: Optional[str] = None,
    limit: int = Field(default=50, description="Maximum number of results")
) -> Dict[str, Any]:
    """List ClearPass network devices with optional filtering."""
    await ctx.info(f"Retrieving network devices (limit: {limit})...")
    
    try:
        client = await get_clearpass_client()
        response = await client.list_network_devices(
            filter_coa_capable=filter_coa_capable,
            vendor_filter=vendor_filter,
            limit=limit
        )
        
        if "_embedded" in response and "items" in response["_embedded"]:
            devices = response["_embedded"]["items"]
            count = len(devices)
            total_count = response.get("count", count)
        else:
            devices = response.get("items", [])
            count = len(devices)
            total_count = response.get("count", count)
            
        await ctx.info(f"Successfully retrieved {count} of {total_count} network devices.")
            
        return {
            "success": True,
            "total_count": total_count,
            "retrieved_count": count,
            "devices": devices,
            "message": f"Retrieved {count} of {total_count} network devices"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list network devices: {e}")
        return await format_api_error(e, "list network devices")
    except Exception as e:
        logger.error(f"Unexpected error listing network devices: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while listing network devices"
        }


@operation(domain="network_devices")
async def get_network_device(
    ctx: Context,
    device_id: Union[int, str] = Field(..., description="Network device ID (numeric) or device name (string)")
) -> Dict[str, Any]:
    """Get details of a specific ClearPass network device by numeric ID or by name."""
    await ctx.info(f"Retrieving network device: {device_id}")

    try:
        client = await get_clearpass_client()

        # `network-device/<id>` only accepts a numeric ID -- a name there returns
        # `422 ID '<name>' is invalid`. Branch on the shape of the value, the same
        # way get_guest_user does.
        if isinstance(device_id, int) or (isinstance(device_id, str) and device_id.isdigit()):
            response = await client.get_network_device(device_id)
        else:
            response = await client.get_network_device_name(str(device_id))

        return {
            "success": True,
            "device": response,
            "message": f"Retrieved network device details for: {device_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get network device: {e}")
        return await format_api_error(e, "get network device")
    except Exception as e:
        logger.error(f"Unexpected error getting network device: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving the network device"
        }


@operation(domain="network_devices")
async def create_network_device(
    ctx: Context,
    name: str = Field(..., description="Device name"),
    ip_address: str = Field(..., description="Device IP address"),
    radius_secret: str = Field(..., description="RADIUS shared secret"),
    tacacs_secret: Optional[str] = Field(None, description="TACACS+ shared secret"),
    vendor_name: str = Field(default="Aruba", description="Device vendor"),
    coa_capable: bool = Field(default=True, description="Change of Authorization capability"),
    coa_port: Optional[int] = Field(None, description="CoA port number"),
    radsec_enabled: Optional[bool] = Field(None, description="Enable RadSec for this device"),
    description: Optional[str] = Field(None, description="Device description")
) -> Dict[str, Any]:
    """Create a new network device to ClearPass."""
    await ctx.info(f"Creating network device: {name} ({ip_address})")
    
    try:
        client = await get_clearpass_client()
        device_data = {
            "name": name,
            "ip_address": ip_address,
            "radius_secret": radius_secret,
            "tacacs_secret": tacacs_secret,
            "vendor_name": vendor_name,
            "coa_capable": coa_capable,
            "coa_port": coa_port,
            "radsec_enabled": radsec_enabled,
            "description": description
        }
        
        # Filter out None values so they aren't passed to the API
        device_data = {k: v for k, v in device_data.items() if v is not None}

        response = await client.create_network_device(device_data)
        
        await ctx.info(f"Successfully created network device: {name}")
        
        return {
            "success": True,
            "message": f"Network device '{name}' created successfully",
            "device": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create network device: {e}")
        return await format_api_error(e, "create network device")
    except Exception as e:
        logger.error(f"Unexpected error creating network device: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while creating the network device"
        }


@operation(domain="network_devices")
async def update_network_device(
    ctx: Context,
    device_id: Union[int, str] = Field(..., description="Network device ID or name to update"),
    name: Optional[str] = Field(None, description="New device name"),
    ip_address: Optional[str] = Field(None, description="New device IP address"),
    radius_secret: Optional[str] = Field(None, description="New RADIUS shared secret"),
    tacacs_secret: Optional[str] = Field(None, description="New TACACS+ shared secret"),
    vendor_name: Optional[str] = Field(None, description="New device vendor"),
    coa_capable: Optional[bool] = Field(None, description="New Change of Authorization capability"),
    coa_port: Optional[int] = Field(None, description="New CoA port number"),
    radsec_enabled: Optional[bool] = Field(None, description="New RadSec enabled status"),
    radsec_config: Optional[Dict[str, Any]] = Field(None, description="New RadSec settings"),
    description: Optional[str] = Field(None, description="New device description")
) -> Dict[str, Any]:
    """Update an existing ClearPass network device."""
    await ctx.info(f"Updating network device: {device_id}")
    
    update_data = {}
    if name is not None:
        update_data['name'] = name
    if ip_address is not None:
        update_data['ip_address'] = ip_address
    if radius_secret is not None:
        update_data['radius_secret'] = radius_secret
    if tacacs_secret is not None:
        update_data['tacacs_secret'] = tacacs_secret
    if vendor_name is not None:
        update_data['vendor_name'] = vendor_name
    if coa_capable is not None:
        update_data['coa_capable'] = coa_capable
    if coa_port is not None:
        update_data['coa_port'] = coa_port
    if radsec_enabled is not None:
        update_data['radsec_enabled'] = radsec_enabled
    if radsec_config is not None:
        update_data['radsec_config'] = radsec_config
    if description is not None:
        update_data['description'] = description
        
    if not update_data:
        await ctx.error("No update parameters provided.")
        return {
            "success": False,
            "message": "No update parameters provided. Please provide at least one field to update.",
        }
        
    try:
        client = await get_clearpass_client()
        response = await client.update_network_device(device_id, update_data)
        
        await ctx.info(f"Successfully updated network device '{device_id}'.")
        
        return {
            "success": True,
            "message": f"Network device '{device_id}' updated successfully",
            "device": response,
            "updated_fields": list(update_data.keys())
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update network device: {e}")
        return await format_api_error(e, "update network device")
    except Exception as e:
        logger.error(f"Unexpected error updating network device: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the network device"
        }


@operation(domain="network_devices")
async def delete_network_device(
    ctx: Context,
    device_id: Union[int, str] = Field(..., description="Network device ID or name to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """Delete a ClearPass network device."""
    await ctx.info(f"Deleting network device: {device_id}")
    
    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a network device will remove it from ClearPass."
        }
        
    try:
        client = await get_clearpass_client()
        await client.delete_network_device(device_id)
        
        return {
            "success": True,
            "message": f"Network device '{device_id}' deleted successfully",
            "warning": "The network device has been removed from ClearPass."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete network device: {e}")
        return await format_api_error(e, "delete network device")
    except Exception as e:
        logger.error(f"Unexpected error deleting network device: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the network device"
        }


# ================================
# BY-NAME ROUTE OPERATIONS
#
# These address the `network-device/name/<name>` route family directly. The
# `get_network_device` tool above also uses this family whenever it is handed a
# non-numeric device_id, so both paths now resolve names through the same native
# route (it previously used a client-side filtered-list scan, which existed only
# to route around the retired `/api/v1` mount).
# ================================


@operation(domain="network_devices")
async def get_network_device_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the network device")
) -> Dict[str, Any]:
    """
    Get a network device by its unique name.

    Maps to 'get_network_device_name_by_name' in pyclearpass (GET /network-device/name/{name}).
    """
    await ctx.info(f"Retrieving network device by name: {name}")

    try:
        client = await get_clearpass_client()
        response = await client.get_network_device_name(name)

        return {
            "success": True,
            "device": response,
            "message": f"Retrieved network device details for name: {name}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get network device by name: {e}")
        return await format_api_error(e, "get network device by name")
    except Exception as e:
        logger.error(f"Unexpected error getting network device by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while retrieving the network device by name"
        }


@operation(domain="network_devices")
async def update_network_device_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the network device to update"),
    device_data: Dict[str, Any] = Field(..., description="Fields to update, e.g. {'description': '...', 'ip_address': '10.0.0.1', 'radius_secret': '...', 'vendor_name': 'Aruba', 'coa_capable': true, 'coa_port': 3799, 'radsec_enabled': false, 'snmp_read': {...}, 'snmp_write': {...}, 'radsec_config': {...}, 'cli_config': {...}, 'onConnect_enforcement': {...}, 'attributes': {...}}")
) -> Dict[str, Any]:
    """
    Update some fields of a network device by name (partial update).

    Only the supplied fields are changed; everything else is left as-is. Use
    replace_network_device_by_name for a full replacement.

    Maps to 'update_network_device_name_by_name' in pyclearpass (PATCH /network-device/name/{name}).
    """
    await ctx.info(f"Updating network device by name: {name}")

    if not device_data:
        await ctx.error("No update parameters provided.")
        return {
            "success": False,
            "message": "No update parameters provided. Please provide at least one field to update.",
        }

    try:
        client = await get_clearpass_client()
        response = await client.update_network_device_name(name, device_data)

        return {
            "success": True,
            "message": f"Network device '{name}' updated successfully",
            "device": response,
            "updated_fields": list(device_data.keys())
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update network device by name: {e}")
        return await format_api_error(e, "update network device by name")
    except Exception as e:
        logger.error(f"Unexpected error updating network device by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while updating the network device by name"
        }


@operation(domain="network_devices")
async def replace_network_device_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the network device to replace"),
    device_data: Dict[str, Any] = Field(..., description="Complete device definition. 'name' and 'ip_address' are required; other fields (description, radius_secret, tacacs_secret, vendor_name, vendor_id, coa_capable, coa_port, radsec_enabled, snmp_read, snmp_write, radsec_config, cli_config, onConnect_enforcement, attributes) are optional and any omitted field is reset.")
) -> Dict[str, Any]:
    """
    Replace a network device by name (full replacement).

    Every field is overwritten by device_data, so it must carry the complete
    device definition — omitted fields are not preserved. Requires 'name' and
    'ip_address' in the body.

    Maps to 'replace_network_device_name_by_name' in pyclearpass (PUT /network-device/name/{name}).
    """
    await ctx.info(f"Replacing network device by name: {name}")

    missing = [field for field in ("name", "ip_address") if not device_data.get(field)]
    if missing:
        return {
            "success": False,
            "error": f"Missing required body fields: {', '.join(missing)}",
            "message": "A full replacement (PUT) requires 'name' and 'ip_address' in device_data."
        }

    try:
        client = await get_clearpass_client()
        response = await client.replace_network_device_name(name, device_data)

        return {
            "success": True,
            "message": f"Network device '{name}' replaced successfully",
            "device": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace network device by name: {e}")
        return await format_api_error(e, "replace network device by name")
    except Exception as e:
        logger.error(f"Unexpected error replacing network device by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while replacing the network device by name"
        }


@operation(domain="network_devices")
async def delete_network_device_by_name(
    ctx: Context,
    name: str = Field(..., description="Unique name of the network device to delete"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete a network device by its unique name.

    Maps to 'delete_network_device_name_by_name' in pyclearpass (DELETE /network-device/name/{name}).
    """
    await ctx.info(f"Deleting network device by name: {name}")

    if not confirm:
        return {
            "success": False,
            "error": "Deletion requires confirmation",
            "message": "This is a destructive operation. Please set confirm=True to proceed with deletion.",
            "warning": "Deleting a network device will remove it from ClearPass."
        }

    try:
        client = await get_clearpass_client()
        await client.delete_network_device_name(name)

        return {
            "success": True,
            "message": f"Network device '{name}' deleted successfully",
            "warning": "The network device has been removed from ClearPass."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete network device by name: {e}")
        return await format_api_error(e, "delete network device by name")
    except Exception as e:
        logger.error(f"Unexpected error deleting network device by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while deleting the network device by name"
        }


@operation(domain="network_devices")
async def replace_network_device(
    ctx: Context,
    device_id: Union[int, str] = Field(..., description="Numeric ID of the network device to replace"),
    device_data: Dict[str, Any] = Field(..., description="Complete device definition. 'name' and 'ip_address' are required; other fields (description, radius_secret, tacacs_secret, vendor_name, vendor_id, coa_capable, coa_port, radsec_enabled, snmp_read, snmp_write, radsec_config, cli_config, onConnect_enforcement, attributes) are optional and any omitted field is reset.")
) -> Dict[str, Any]:
    """
    Replace a network device by numeric ID (full replacement).

    Every field is overwritten by device_data, so it must carry the complete
    device definition — omitted fields are not preserved. Use
    update_network_device for a partial (PATCH) update instead.

    Maps to 'replace_network_device_by_network_device_id' in pyclearpass (PUT /network-device/{network_device_id}).
    """
    await ctx.info(f"Replacing network device: {device_id}")

    missing = [field for field in ("name", "ip_address") if not device_data.get(field)]
    if missing:
        return {
            "success": False,
            "error": f"Missing required body fields: {', '.join(missing)}",
            "message": "A full replacement (PUT) requires 'name' and 'ip_address' in device_data."
        }

    try:
        client = await get_clearpass_client()
        response = await client.replace_network_device(device_id, device_data)

        return {
            "success": True,
            "message": f"Network device '{device_id}' replaced successfully",
            "device": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace network device: {e}")
        return await format_api_error(e, "replace network device")
    except Exception as e:
        logger.error(f"Unexpected error replacing network device: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while replacing the network device"
        }


@operation(domain="network_devices")
async def bulk_update_network_devices(
    ctx: Context,
    device_ids: List[int] = Field(..., description="List of network device IDs to update"),
    operation_type: str = Field(..., description="Type of bulk operation: 'update', 'delete', 'configure_snmp', 'configure_radsec'"),
    operation_data: Dict[str, Any] = Field(..., description="Data for the bulk operation (format depends on operation type)"),
    confirm_operation: bool = Field(default=False, description="Confirm bulk operation (required for safety, especially for delete operations)")
) -> Dict[str, Any]:
    """
    Perform bulk operations on multiple network devices.
    
    This tool enables efficient management of multiple devices simultaneously,
    supporting updates, deletions, and configuration changes.
    
    Examples:
    - "Update RADIUS secret for devices [1,2,3] with confirm_operation=true"
    - "Configure SNMP on multiple switches with community string 'private'"
    - "Bulk delete test devices [10,11,12] with confirmation"
    """
    if operation_type == "delete" and not confirm_operation:
        return {
            "success": False,
            "message": "Bulk delete operations require confirm_operation=true for safety",
            "error": "Confirmation required"
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.bulk_update_network_devices(
            device_ids=device_ids,
            operation_type=operation_type,
            operation_data=operation_data
        )
            
        # Analyze results
        total_devices = len(device_ids)
        successful_operations = sum(1 for r in result["bulk_operation_results"] if r["success"])
        failed_operations = total_devices - successful_operations
        
        return {
            "success": failed_operations == 0,
            "message": f"Bulk {operation_type} operation completed: {successful_operations}/{total_devices} successful",
            "total_devices": total_devices,
            "successful_operations": successful_operations,
            "failed_operations": failed_operations,
            "operation_details": result["bulk_operation_results"]
        }
                
    except Exception as e:
        error_msg = f"Failed to perform bulk {operation_type} operation: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def clone_network_device(
    ctx: Context,
    source_device_id: int = Field(..., description="Numeric ID of the device to clone"),
    new_device_name: str = Field(..., description="Name for the new cloned device"),
    new_device_ip: str = Field(..., description="IP address for the new cloned device"),
    modify_radius_secret: Optional[str] = Field(None, description="New RADIUS secret for the cloned device"),
    modify_description: Optional[str] = Field(None, description="New description for the cloned device"),
    copy_advanced_settings: bool = Field(default=True, description="Copy SNMP, RadSec, and CLI settings")
) -> Dict[str, Any]:
    """
    Clone an existing network device with modifications.
    
    This tool creates a new device based on an existing device configuration,
    allowing for quick deployment of similar devices with minor modifications.
    
    Examples:
    - "Clone device 123 as 'new-switch-01' with IP 192.168.1.50"
    - "Clone device configuration but change RADIUS secret"
    - "Clone device without advanced settings for simple deployment"
    """
    try:
        client = await get_clearpass_client()
        # Prepare modifications
        modifications = {}
        if modify_radius_secret:
            modifications["radius_secret"] = modify_radius_secret
        if modify_description:
            modifications["description"] = modify_description
        if not copy_advanced_settings:
            modifications.update({
                "snmp_read": None,
                "snmp_write": None,
                "radsec_enabled": False,
                "cli_config": None
            })
        
        result = await client.clone_network_device(
            source_device_id=source_device_id,
            new_name=new_device_name,
            new_ip_address=new_device_ip,
            modifications=modifications
        )
            
        return {
            "success": True,
            "message": f"Successfully cloned device ID {source_device_id} as '{new_device_name}'",
            "source_device_id": source_device_id,
            "new_device_name": new_device_name,
            "new_device_ip": new_device_ip,
            "new_device_id": result.get("id"),
            "copied_advanced_settings": copy_advanced_settings,
            "cloned_device": result
        }
                
    except Exception as e:
        error_msg = f"Failed to clone device ID {source_device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def test_device_connectivity(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the network device"),
    test_types: Optional[List[str]] = Field(default=["radius", "snmp"], description="Types of connectivity tests to perform"),
    timeout_seconds: int = Field(default=30, description="Timeout for connectivity tests in seconds")
) -> Dict[str, Any]:
    """
    Test connectivity to a network device using various protocols.
    
    This tool performs comprehensive connectivity tests to verify device
    accessibility and protocol support.
    
    Examples:
    - "Test RADIUS and SNMP connectivity to device 456"
    - "Perform full connectivity test including CLI access"
    - "Quick RADIUS connectivity check with 10 second timeout"
    """
    try:
        client = await get_clearpass_client()
        result = await client.test_device_connectivity(
            device_id=device_id,
            test_types=test_types
        )
            
        # Analyze connectivity test results
        total_tests = len(test_types)
        successful_tests = sum(1 for test in result["connectivity_tests"].values() if test["status"] == "success")
        failed_tests = total_tests - successful_tests
        
        overall_status = "healthy" if failed_tests == 0 else "degraded" if successful_tests > 0 else "unreachable"
        
        return {
            "success": True,
            "message": f"Connectivity test completed for device ID {device_id}",
            "device_name": result["device_info"].get("name", "Unknown"),
            "overall_status": overall_status,
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "failed_tests": failed_tests,
            "test_results": result["connectivity_tests"],
            "device_info": result["device_info"]
        }
                
    except Exception as e:
        error_msg = f"Failed to test connectivity for device ID {device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def validate_device_configuration(
    ctx: Context,
    device_config: Dict[str, Any] = Field(..., description="Device configuration to validate"),
    check_connectivity: bool = Field(default=False, description="Whether to perform connectivity checks"),
    strict_validation: bool = Field(default=False, description="Enable strict validation rules")
) -> Dict[str, Any]:
    """
    Validate network device configuration for compliance and best practices.
    
    This tool performs comprehensive validation of device configurations
    to identify potential issues before deployment.
    
    Examples:
    - "Validate device configuration before creating new device"
    - "Check device config with strict validation enabled"
    - "Validate configuration and test connectivity"
    """
    try:
        client = await get_clearpass_client()
        result = await client.validate_device_configuration(device_config)
            
        # Add additional validation for strict mode
        if strict_validation:
            # Check for security best practices
            if not device_config.get("radius_secret"):
                result["warnings"].append("RADIUS secret not configured - authentication will fail")
            
            if device_config.get("snmp_read", {}).get("community") == "public":
                result["warnings"].append("Using default 'public' SNMP community - security risk")
            
            if not device_config.get("coa_capable", False):
                result["warnings"].append("CoA not enabled - dynamic policy changes not supported")
        
        validation_status = "valid" if result["valid"] and not result["errors"] else "invalid"
        if result["warnings"] and not result["errors"]:
            validation_status = "valid_with_warnings"
        
        return {
            "success": True,
            "message": f"Device configuration validation completed: {validation_status}",
            "validation_status": validation_status,
            "is_valid": result["valid"],
            "error_count": len(result["errors"]),
            "warning_count": len(result["warnings"]),
            "errors": result["errors"],
            "warnings": result["warnings"],
            "recommended_actions": result.get("recommendations", [])
        }
                
    except Exception as e:
        error_msg = f"Failed to validate device configuration: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def get_device_statistics(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the network device"),
    include_detailed_stats: bool = Field(default=True, description="Include detailed statistics"),
    time_range: str = Field(default="24h", description="Time range for statistics (e.g., '1h', '24h', '7d', '30d')")
) -> Dict[str, Any]:
    """
    Get comprehensive statistics and monitoring data for a network device.
    
    This tool provides detailed analytics including authentication, accounting,
    and CoA statistics for device performance monitoring.
    
    Examples:
    - "Get 24-hour statistics for device 123"
    - "Show detailed authentication stats for the past week"
    - "Get quick device performance overview"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_device_statistics(
            device_id=device_id,
            include_details=include_detailed_stats
        )
            
        return {
            "success": True,
            "message": f"Successfully retrieved statistics for device ID {device_id}",
            "device_name": result["device_name"],
            "time_range": time_range,
            "authentication_summary": {
                "total_attempts": result["authentication_stats"]["total_authentications"],
                "success_rate": result["authentication_stats"]["success_rate"],
                "recent_failures": result["authentication_stats"]["failed_authentications"]
            },
            "session_summary": {
                "total_sessions": result["accounting_stats"]["total_sessions"],
                "active_sessions": result["accounting_stats"]["active_sessions"],
                "avg_duration": result["accounting_stats"]["average_session_duration"]
            },
            "device_health": "healthy" if result["authentication_stats"]["successful_authentications"] > 0 else "inactive",
            "detailed_statistics": result if include_detailed_stats else None,
            "last_activity": result["last_activity"]
        }
                
    except Exception as e:
        error_msg = f"Failed to get statistics for device ID {device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def create_device_from_template(
    ctx: Context,
    template_name: str = Field(..., description="Name of the template to use"),
    device_name: str = Field(..., description="Name for the new device"),
    device_ip: str = Field(..., description="IP address for the new device"),
    radius_secret: str = Field(..., description="RADIUS secret for the new device"),
    description: Optional[str] = Field(None, description="Description for the new device"),
    custom_attributes: Optional[Dict[str, Any]] = Field(None, description="Custom device attributes"),
    override_template_settings: Optional[Dict[str, Any]] = Field(None, description="Override specific template settings")
) -> Dict[str, Any]:
    """
    Create a network device from a predefined template.
    
    This tool uses device templates to quickly create standardized devices
    with consistent configurations for different device types.
    
    Available templates: 'aruba-switch', 'aruba-ap', 'cisco-router', 'generic-device'
    
    Examples:
    - "Create Aruba switch from template with IP 192.168.1.100"
    - "Deploy access point using aruba-ap template"
    - "Create device from template with custom SNMP settings override"
    """
    try:
        client = await get_clearpass_client()
        # Define predefined templates
        templates = {
            "aruba-switch": {
                "template_name": "aruba-switch",
                "template_description": "Standard Aruba switch configuration",
                "vendor_name": "Aruba",
                "device_type": "switch",
                "default_settings": {
                    "coa_capable": True,
                    "coa_port": 3799,
                    "vendor_id": 25506
                }
            },
            "aruba-ap": {
                "template_name": "aruba-ap",
                "template_description": "Standard Aruba access point configuration",
                "vendor_name": "Aruba",
                "device_type": "ap",
                "default_settings": {
                    "coa_capable": True,
                    "coa_port": 3799,
                    "vendor_id": 25506
                }
            },
            "cisco-router": {
                "template_name": "cisco-router",
                "template_description": "Standard Cisco router configuration",
                "vendor_name": "Cisco",
                "device_type": "router",
                "default_settings": {
                    "coa_capable": False,
                    "vendor_id": 9
                }
            },
            "generic-device": {
                "template_name": "generic-device",
                "template_description": "Generic network device configuration",
                "vendor_name": "Generic",
                "device_type": "device",
                "default_settings": {
                    "coa_capable": False
                }
            }
        }
        
        template_config = templates.get(template_name)
        if not template_config:
            return {
                "success": False,
                "message": f"Template '{template_name}' not found",
                "available_templates": list(templates.keys()),
                "error": "Invalid template"
            }
        
        # Prepare specific configuration
        specific_config = {
            "radius_secret": radius_secret
        }
        if description:
            specific_config["description"] = description
        if custom_attributes:
            specific_config["attributes"] = custom_attributes
        if override_template_settings:
            specific_config.update(override_template_settings)
        
        result = await client.create_device_from_template(
            template_config=template_config,
            device_name=device_name,
            device_ip=device_ip,
            specific_config=specific_config
        )
        
        return {
            "success": True,
            "message": f"Successfully created device '{device_name}' from template '{template_name}'",
            "device_name": device_name,
            "device_ip": device_ip,
            "template_used": template_name,
            "device_type": template_config["device_type"],
            "vendor_name": template_config["vendor_name"],
            "new_device_id": result.get("id"),
            "device_details": result
        }
                
    except Exception as e:
        error_msg = f"Failed to create device from template '{template_name}': {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def search_devices_advanced(
    ctx: Context,
    vendor_name: Optional[str] = Field(None, description="Filter by vendor name (e.g., 'Aruba', 'Cisco')"),
    device_type: Optional[str] = Field(None, description="Filter by device type (e.g., 'switch', 'ap', 'router')"),
    coa_capable: Optional[bool] = Field(None, description="Filter by CoA capability"),
    radsec_enabled: Optional[bool] = Field(None, description="Filter by RadSec enabled status"),
    has_snmp_configured: Optional[bool] = Field(None, description="Filter by SNMP configuration presence"),
    ip_subnet: Optional[str] = Field(None, description="Filter by IP subnet (e.g., '192.168.1.0/24')"),
    custom_filter: Optional[str] = Field(None, description="Custom JSON filter expression"),
    limit: int = Field(default=50, description="Maximum number of results to return"),
    sort_by: str = Field(default="name", description="Sort results by field (name, ip_address, vendor_name)")
) -> Dict[str, Any]:
    """
    Advanced search for network devices with multiple criteria and filtering options.
    
    This tool provides sophisticated search capabilities for finding network devices
    based on various criteria including vendor, type, capabilities, and configuration.
    
    Examples:
    - "Search for Aruba switches with CoA enabled"
    - "Find all devices in subnet 192.168.1.0/24 with SNMP configured"
    - "Search for RadSec-enabled access points sorted by name"
    """
    try:
        client = await get_clearpass_client()
        result = await client.search_devices_by_criteria(
                vendor_name=vendor_name,
                device_type=device_type,
                coa_capable=coa_capable,
                radsec_enabled=radsec_enabled,
                has_snmp=has_snmp_configured
            )
        
        # DEBUG: Log the raw result to understand the format    
        logger.debug("Raw search result type: %s", type(result))
        
        # Handle string response (likely an error)
        if isinstance(result, str):
            logger.error(f"Search API returned string response: {result}")
            return {
                "success": False,
                "message": f"Search API error: {result}",
                "error": "API returned string instead of dictionary"
            }
        
        # Handle non-dictionary response
        if not isinstance(result, dict):
            logger.error(f"Search API returned unexpected type: {type(result)}")
            return {
                "success": False,
                "message": f"Search API returned unexpected response type: {type(result)}",
                "error": "Invalid response format"
            }
            
        # Normalises every known envelope shape and returns [] for a genuine
        # zero-match search (see _extract_device_list).
        devices = _extract_device_list(result)

        logger.debug("Advanced search normalised to %d device(s)", len(devices))
        
        # Apply IP subnet filtering if specified
        if ip_subnet and devices:
            try:
                from ipaddress import ip_network, ip_address
                subnet = ip_network(ip_subnet, strict=False)
                filtered_devices = []
                for device in devices:
                    try:
                        device_ip = ip_address(device.get("ip_address", ""))
                        if device_ip in subnet:
                            filtered_devices.append(device)
                    except ValueError:
                        # Skip devices with invalid IP addresses
                        continue
                devices = filtered_devices
            except ValueError:
                return {
                    "success": False,
                    "message": f"Invalid IP subnet format: {ip_subnet}",
                    "error": "Invalid subnet"
                }
        
        # Apply custom filter if specified
        if custom_filter and devices:
            try:
                import json
                filter_criteria = json.loads(custom_filter)
                filtered_devices = []
                for device in devices:
                    match = True
                    for key, value in filter_criteria.items():
                        if device.get(key) != value:
                            match = False
                            break
                    if match:
                        filtered_devices.append(device)
                devices = filtered_devices
            except (json.JSONDecodeError, TypeError):
                return {
                    "success": False,
                    "message": f"Invalid JSON filter format: {custom_filter}",
                    "error": "Invalid filter"
                }
        
        # Sort results
        if sort_by and devices:
            try:
                devices.sort(key=lambda x: str(x.get(sort_by, "")))
            except Exception:
                # If sorting fails, continue without sorting
                pass
        
        # Apply limit
        if limit and len(devices) > limit:
            devices = devices[:limit]
            limited = True
        else:
            limited = False
        
        # Analyze results
        device_summary = {}
        for device in devices:
            vendor = device.get("vendor_name", "Unknown")
            device_summary[vendor] = device_summary.get(vendor, 0) + 1
        
        return {
            "success": True,
            "message": f"Advanced search completed, found {len(devices)} devices",
            "total_found": len(devices),
            "results_limited": limited,
            "search_criteria": {
                "vendor_name": vendor_name,
                "device_type": device_type,
                "coa_capable": coa_capable,
                "radsec_enabled": radsec_enabled,
                "has_snmp_configured": has_snmp_configured,
                "ip_subnet": ip_subnet,
                "custom_filter": custom_filter
            },
            "vendor_summary": device_summary,
            "devices": devices,
            "sorting": {
                "sort_by": sort_by,
                "limit_applied": limit if limited else None
            }
        }
                
    except Exception as e:
        error_msg = f"Failed to perform advanced device search: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def configure_device_snmp_settings(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the network device"),
    snmp_read_enabled: Optional[bool] = Field(None, description="Enable SNMP read access"),
    snmp_read_community: Optional[str] = Field(None, description="SNMP read community string"),
    snmp_read_version: Optional[str] = Field(None, description="SNMP version for read (v1, v2c, v3)"),
    snmp_write_enabled: Optional[bool] = Field(None, description="Enable SNMP write access"),
    snmp_write_community: Optional[str] = Field(None, description="SNMP write community string"),
    snmp_write_version: Optional[str] = Field(None, description="SNMP version for write (v1, v2c, v3)"),
    snmpv3_security_name: Optional[str] = Field(None, description="SNMPv3 security name"),
    snmpv3_auth_protocol: Optional[str] = Field(None, description="SNMPv3 authentication protocol (MD5, SHA)"),
    snmpv3_auth_key: Optional[str] = Field(None, description="SNMPv3 authentication key"),
    snmpv3_privacy_protocol: Optional[str] = Field(None, description="SNMPv3 privacy protocol (DES, AES)"),
    snmpv3_privacy_key: Optional[str] = Field(None, description="SNMPv3 privacy key")
) -> Dict[str, Any]:
    """
    Configure SNMP settings for a network device.
    
    This tool configures SNMP read and write access for a network device,
    supporting SNMPv1, v2c, and v3 with various security options.
    
    Examples:
    - "Configure SNMP read access for device 123 with community 'public'"
    - "Set up SNMPv3 with authentication for device management"
    - "Enable SNMP write access with secure community string"
    """
    try:
        client = await get_clearpass_client()
        # Build SNMP configuration
        snmp_read_settings = None
        snmp_write_settings = None
        
        if any([snmp_read_enabled, snmp_read_community, snmp_read_version]):
            snmp_read_settings = {}
            if snmp_read_enabled is not None:
                snmp_read_settings["enabled"] = snmp_read_enabled
            if snmp_read_community is not None:
                snmp_read_settings["community_string"] = snmp_read_community
            if snmp_read_version is not None:
                # Map version strings to what ClearPass expects
                version_map = {
                    "v1": 1,
                    "v2c": 2,
                    "2c": 2,
                    "v3": 3
                }
                snmp_read_settings["version"] = version_map.get(snmp_read_version, snmp_read_version)
            if snmp_read_version == "v3":
                snmp_read_settings.update({
                    "security_name": snmpv3_security_name,
                    "auth_protocol": snmpv3_auth_protocol,
                    "auth_key": snmpv3_auth_key,
                    "privacy_protocol": snmpv3_privacy_protocol,
                    "privacy_key": snmpv3_privacy_key
                })
        
        if any([snmp_write_enabled, snmp_write_community, snmp_write_version]):
            snmp_write_settings = {}
            if snmp_write_enabled is not None:
                snmp_write_settings["enabled"] = snmp_write_enabled
            if snmp_write_community is not None:
                snmp_write_settings["community_string"] = snmp_write_community
            if snmp_write_version is not None:
                # Map version strings to what ClearPass expects
                version_map = {
                    "v1": 1,
                    "v2c": 2,
                    "2c": 2,
                    "v3": 3
                }
                snmp_write_settings["version"] = version_map.get(snmp_write_version, snmp_write_version)
            if snmp_write_version == "v3":
                snmp_write_settings.update({
                    "security_name": snmpv3_security_name,
                    "auth_protocol": snmpv3_auth_protocol,
                    "auth_key": snmpv3_auth_key,
                    "privacy_protocol": snmpv3_privacy_protocol,
                    "privacy_key": snmpv3_privacy_key
                })
        
        result = await client.configure_device_snmp_settings(
            device_id=device_id,
            snmp_read_settings=snmp_read_settings,
            snmp_write_settings=snmp_write_settings
        )
        
        return {
            "success": True,
            "message": f"Successfully configured SNMP settings for device ID {device_id}",
            "device_config": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure SNMP settings for device ID {device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def configure_device_radsec_settings(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the network device"),
    radsec_enabled: bool = Field(..., description="Enable RadSec (RADIUS over TLS)"),
    radsec_port: Optional[int] = Field(2083, description="RadSec port number (default: 2083)"),
    certificate_path: Optional[str] = Field(None, description="Path to RadSec certificate"),
    private_key_path: Optional[str] = Field(None, description="Path to RadSec private key"),
    ca_certificate_path: Optional[str] = Field(None, description="Path to CA certificate"),
    verify_certificate: bool = Field(True, description="Verify peer certificate")
) -> Dict[str, Any]:
    """
    Configure RadSec (RADIUS over TLS) settings for a network device.
    
    This tool configures secure RADIUS communication using TLS encryption
    for enhanced security in RADIUS transactions.
    
    Examples:
    - "Enable RadSec on device 456 with default port"
    - "Configure RadSec with custom certificates for secure RADIUS"
    - "Set up RadSec with certificate verification disabled for testing"
    """
    try:
        client = await get_clearpass_client()
        # Build RadSec configuration
        radsec_config = {
            "enabled": radsec_enabled,
            "port": radsec_port,
            "verify_certificate": verify_certificate
        }
        
        if certificate_path:
            radsec_config["certificate"] = certificate_path
        if private_key_path:
            radsec_config["private_key"] = private_key_path
        if ca_certificate_path:
            radsec_config["ca_certificate"] = ca_certificate_path
        
        result = await client.configure_device_radsec_settings(
            device_id=device_id,
            radsec_config=radsec_config
        )
        
        return {
            "success": True,
            "message": f"Successfully configured RadSec settings for device ID {device_id}",
            "radsec_enabled": radsec_enabled,
            "device_config": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure RadSec settings for device ID {device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def configure_device_cli_settings(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the network device"),
    cli_enabled: bool = Field(..., description="Enable CLI access"),
    cli_protocol: str = Field(default="SSH", description="CLI protocol (SSH, Telnet)"),
    cli_port: Optional[int] = Field(None, description="CLI port number (default: 22 for SSH, 23 for Telnet)"),
    cli_username: Optional[str] = Field(None, description="CLI username"),
    cli_password: Optional[str] = Field(None, description="CLI password"),
    enable_password: Optional[str] = Field(None, description="CLI enable password"),
    connection_timeout: int = Field(default=30, description="CLI connection timeout in seconds")
) -> Dict[str, Any]:
    """
    Configure CLI access settings for a network device.
    
    This tool configures command-line interface access for device management,
    supporting SSH and Telnet protocols with authentication.
    
    Examples:
    - "Enable SSH CLI access for device 789 with credentials"
    - "Configure Telnet access with custom port and timeout"
    - "Set up CLI access with enable password for privileged mode"
    """
    try:
        client = await get_clearpass_client()
        # Set default ports based on protocol
        if cli_port is None:
            cli_port = 22 if cli_protocol.upper() == "SSH" else 23
        
        # Build CLI configuration
        cli_config = {
            "enabled": cli_enabled,
            "protocol": cli_protocol.upper(),
            "port": cli_port,
            "timeout": connection_timeout
        }
        
        if cli_username:
            cli_config["username"] = cli_username
        if cli_password:
            cli_config["password"] = cli_password
        if enable_password:
            cli_config["enable_password"] = enable_password
        
        result = await client.configure_device_cli_settings(
            device_id=device_id,
            cli_config=cli_config
        )
        
        return {
            "success": True,
            "message": f"Successfully configured CLI settings for device ID {device_id}",
            "cli_protocol": cli_protocol,
            "cli_port": cli_port,
            "device_config": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure CLI settings for device ID {device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="network_devices")
async def configure_device_onconnect_enforcement(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the network device"),
    onconnect_enabled: bool = Field(..., description="Enable OnConnect enforcement"),
    enforcement_action: Optional[str] = Field(None, description="Enforcement action (quarantine, redirect, allow)"),
    enforcement_vlan: Optional[int] = Field(None, description="VLAN ID for enforcement"),
    enforcement_role: Optional[str] = Field(None, description="User role for enforcement"),
    additional_attributes: Optional[Dict[str, Any]] = Field(None, description="Additional enforcement attributes")
) -> Dict[str, Any]:
    """
    Configure OnConnect enforcement settings for a network device.
    
    This tool configures automatic enforcement actions when devices connect
    to the network, supporting quarantine, redirection, and role-based access.
    
    Examples:
    - "Enable OnConnect quarantine for device 101 with VLAN 100"
    - "Configure OnConnect enforcement with guest role assignment"
    - "Set up automatic redirection for non-compliant devices"
    """
    try:
        client = await get_clearpass_client()
        # Build OnConnect enforcement configuration
        onconnect_config = {
            "enabled": onconnect_enabled
        }
        
        if enforcement_action:
            onconnect_config["action"] = enforcement_action
        if enforcement_vlan:
            onconnect_config["vlan_id"] = enforcement_vlan
        if enforcement_role:
            onconnect_config["user_role"] = enforcement_role
        if additional_attributes:
            onconnect_config["attributes"] = additional_attributes
        
        result = await client.configure_device_onconnect_enforcement(
            device_id=device_id,
            onconnect_config=onconnect_config
        )
        
        return {
            "success": True,
            "message": f"Successfully configured OnConnect enforcement for device ID {device_id}",
            "enforcement_enabled": onconnect_enabled,
            "enforcement_action": enforcement_action,
            "device_config": result
        }
                
    except Exception as e:
        error_msg = f"Failed to configure OnConnect enforcement for device ID {device_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }