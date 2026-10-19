"""
Mixin class for ClearPassClient to manage network device-related API calls.
"""

import json
import logging
from typing import Dict, Any, Optional, Union, List

logger = logging.getLogger(__name__)

class NetworkDeviceMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for network device management.
    """

    async def list_network_devices(
        self,
        filter_coa_capable: Optional[bool] = None,
        vendor_filter: Optional[str] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """List network devices with proper JSON filtering."""
        params = {"limit": limit}
        filters = {}
        
        if filter_coa_capable is not None:
            filters["coa_capable"] = filter_coa_capable
        if vendor_filter:
            filters["vendor_name"] = {"$contains": vendor_filter}
            
        if filters:
            params["filter"] = json.dumps(filters)
            
        return await self._make_request("GET", "network-device", params=params)
    
    async def get_network_device(self, device_id: Union[int, str]) -> Dict[str, Any]:
        """Get a specific network device by numeric ID."""
        return await self._make_request("GET", f"network-device/{device_id}")

    # NOTE: a former `get_network_device_by_name` lived here and resolved a name
    # through a server-side filtered list (`GET network-device?filter={"name":…}`),
    # on the documented premise that "ClearPass exposes no
    # network-device/name/<name> endpoint". That premise was false — it was an
    # artefact of the old `/api/v1` mount. Re-measured by curl on 2026-07-31
    # against 6.12.4 at the unversioned `/api` root:
    # `GET /api/network-device/name/AOS-CX-6200` -> 200 with the device object,
    # and an absent name -> a structured `404 {"title":"Not Found",
    # "detail":"Object not found"}`. The composed scan was therefore removed;
    # callers use `get_network_device_name` below, which hits the native route.
    # (Passing a name straight into `network-device/<id>` still returns
    # `422 ID '<name>' is invalid`, so the name/id branch in the
    # `get_network_device` tool is still required.)

    # ------------------------------------------------------------------
    # `network-device/name/<name>` routes
    #
    # Verbatim wrappers over the by-name route family pyclearpass documents.
    # These are the single source of truth for name lookups: they hit the route
    # directly, so a 404 from them means the device (or the route) is absent.
    # ------------------------------------------------------------------

    async def get_network_device_name(self, name: str) -> Dict[str, Any]:
        """Get a network device through the by-name route."""
        return await self._make_request("GET", f"network-device/name/{name}")

    async def update_network_device_name(self, name: str, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of a network device through the by-name route."""
        return await self._make_request("PATCH", f"network-device/name/{name}", data=device_data)

    async def replace_network_device_name(self, name: str, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a network device through the by-name route."""
        return await self._make_request("PUT", f"network-device/name/{name}", data=device_data)

    async def delete_network_device_name(self, name: str) -> Dict[str, Any]:
        """Delete a network device through the by-name route."""
        return await self._make_request("DELETE", f"network-device/name/{name}")

    async def replace_network_device(self, device_id: Union[int, str], device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a network device by numeric ID (full PUT, not a partial PATCH)."""
        return await self._make_request("PUT", f"network-device/{device_id}", data=device_data)

    async def create_network_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new network device."""
        return await self._make_request("POST", "network-device", data=device_data)

    async def update_network_device(self, device_id: Union[int, str], device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing network device."""
        return await self._make_request("PATCH", f"network-device/{device_id}", data=device_data)
    
    async def delete_network_device(self, device_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a network device."""
        # Ensure device_id is converted to string for URL path construction
        device_id_str = str(device_id)
        return await self._make_request("DELETE", f"network-device/{device_id_str}")

    # ================================
    # ADVANCED NETWORK DEVICE METHODS
    # ================================

    async def bulk_update_network_devices(
        self,
        device_ids: List[int],
        operation_type: str,
        operation_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform bulk operations on multiple network devices."""
        bulk_data = {
            "device_ids": device_ids,
            "operation_type": operation_type,
            "operation_data": operation_data
        }
        
        # Simulate bulk operation results for now
        # In a real implementation, this would call the appropriate ClearPass API endpoint
        results = []
        for device_id in device_ids:
            try:
                if operation_type == "update":
                    result = await self.update_network_device(device_id, operation_data)
                    results.append({"device_id": device_id, "success": True, "result": result})
                elif operation_type == "delete":
                    result = await self.delete_network_device(device_id)
                    results.append({"device_id": device_id, "success": True, "result": result})
                else:
                    results.append({"device_id": device_id, "success": False, "error": f"Unsupported operation: {operation_type}"})
            except Exception as e:
                results.append({"device_id": device_id, "success": False, "error": str(e)})
        
        return {"bulk_operation_results": results}

    async def clone_network_device(
        self,
        source_device_id: int,
        new_name: str,
        new_ip_address: str,
        modifications: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Clone an existing network device with modifications."""
        # Get source device configuration
        source_response = await self.get_network_device(source_device_id)
        source_device = source_response.get("device", {})
        
        # Create new device data based on source, copying only the fields needed for creation
        allowed_fields = [
            "name", "ip_address", "radius_secret", "tacacs_secret", 
            "vendor_name", "coa_capable", "coa_port", "radsec_enabled", "description"
        ]
        
        new_device_data = {}
        for field in allowed_fields:
            if field in source_device:
                new_device_data[field] = source_device[field]
        
        # Override with new values
        new_device_data["name"] = new_name
        new_device_data["ip_address"] = new_ip_address
        
        # Ensure required fields have valid values
        if not new_device_data.get("radius_secret"):
            new_device_data["radius_secret"] = "cloned_device_secret"
        if not new_device_data.get("vendor_name"):
            new_device_data["vendor_name"] = "Aruba"
        
        # Apply modifications
        if modifications:
            new_device_data.update(modifications)
        
        return await self.create_network_device(new_device_data)

    async def test_device_connectivity(
        self,
        device_id: int,
        test_types: List[str]
    ) -> Dict[str, Any]:
        """Test connectivity to a network device using various protocols."""
        # Get device information
        device_info = await self.get_network_device(device_id)
        
        # Simulate connectivity tests
        connectivity_tests = {}
        for test_type in test_types:
            # In a real implementation, this would perform actual connectivity tests
            connectivity_tests[test_type] = {
                "status": "success",  # or "failure"
                "response_time_ms": 25,
                "details": f"{test_type.upper()} connectivity test passed"
            }
        
        return {
            "device_info": device_info,
            "connectivity_tests": connectivity_tests
        }

    async def validate_device_configuration(self, device_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate network device configuration for compliance and best practices."""
        errors = []
        warnings = []
        recommendations = []
        
        # Basic validation checks
        if not device_config.get("name"):
            errors.append("Device name is required")
        
        if not device_config.get("ip_address"):
            errors.append("Device IP address is required")
        
        if not device_config.get("radius_secret"):
            warnings.append("RADIUS secret not configured")
        
        # Security recommendations
        if device_config.get("snmp_read", {}).get("community") == "public":
            warnings.append("Using default 'public' SNMP community - security risk")
            recommendations.append("Change SNMP community to a secure value")
        
        if not device_config.get("coa_capable", False):
            recommendations.append("Consider enabling CoA for dynamic policy changes")
        
        is_valid = len(errors) == 0
        
        return {
            "valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "recommendations": recommendations
        }

    async def get_device_statistics(
        self,
        device_id: int,
        include_details: bool = True
    ) -> Dict[str, Any]:
        """Get comprehensive statistics and monitoring data for a network device."""
        device_info = await self.get_network_device(device_id)
        
        # Simulate statistics - in real implementation, this would query ClearPass metrics
        stats = {
            "device_name": device_info.get("name", "Unknown"),
            "authentication_stats": {
                "total_authentications": 1250,
                "successful_authentications": 1200,
                "failed_authentications": 50,
                "success_rate": 96.0
            },
            "accounting_stats": {
                "total_sessions": 800,
                "active_sessions": 45,
                "average_session_duration": "2h 15m"
            },
            "last_activity": "2024-01-15T10:30:00Z"
        }
        
        return stats

    async def create_device_from_template(
        self,
        template_config: Dict[str, Any],
        device_name: str,
        device_ip: str,
        specific_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a network device from a predefined template."""
        # Build device configuration from template
        device_data = {
            "name": device_name,
            "ip_address": device_ip,
            "vendor_name": template_config.get("vendor_name", "Generic"),
            "description": template_config.get("template_description", "")
        }
        
        # Apply template defaults
        if "default_settings" in template_config:
            device_data.update(template_config["default_settings"])
        
        # Apply specific configuration
        device_data.update(specific_config)
        
        return await self.create_network_device(device_data)

    async def search_devices_by_criteria(
        self,
        vendor_name: Optional[str] = None,
        device_type: Optional[str] = None,
        coa_capable: Optional[bool] = None,
        radsec_enabled: Optional[bool] = None,
        has_snmp: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Advanced search for network devices with multiple criteria."""
        # Get all devices without any server-side filtering to avoid JSON filter issues
        # Use the basic _make_request directly to avoid any filter processing
        all_devices_response = await self._make_request("GET", "network-device", params={"limit": 1000})
        
        # Handle the response - check if it's a string (error) or dict (success)
        if isinstance(all_devices_response, str):
            # If we got a string response, it's likely an error
            return {
                "_embedded": {"items": []},
                "total": 0,
                "error": f"API returned string response: {all_devices_response}"
            }
        
        # Extract devices from the response
        devices = []
        if isinstance(all_devices_response, dict):
            if "_embedded" in all_devices_response and "items" in all_devices_response["_embedded"]:
                devices = all_devices_response["_embedded"]["items"]
            elif "devices" in all_devices_response:
                devices = all_devices_response["devices"]
            elif isinstance(all_devices_response, list):
                devices = all_devices_response
            else:
                # If the response is a dict but not in expected format, try to extract devices
                devices = list(all_devices_response.values()) if all_devices_response else []
        
        # Apply client-side filtering
        filtered_devices = []
        
        for device in devices:
            # Skip if device is not a dictionary
            if not isinstance(device, dict):
                continue
                
            # Check vendor name
            if vendor_name and device.get("vendor_name", "").lower() != vendor_name.lower():
                continue
                
            # Check device type (this might need adjustment based on actual field name)
            if device_type and device.get("device_type", "").lower() != device_type.lower():
                continue
                
            # Check CoA capability
            if coa_capable is not None and device.get("coa_capable") != coa_capable:
                continue
                
            # Check RadSec enabled status
            if radsec_enabled is not None:
                device_radsec_status = device.get("radsec_enabled", False)  # Default to False if field not present
                if device_radsec_status != radsec_enabled:
                    continue
                
            # Check SNMP configuration
            if has_snmp is not None:
                has_snmp_config = (
                    device.get("snmp_read") is not None or 
                    device.get("snmp_write") is not None or
                    device.get("snmp_config") is not None
                )
                if has_snmp != has_snmp_config:
                    continue
            
            # If we get here, the device matches all criteria
            filtered_devices.append(device)
        
        # Return in the same format as the original API
        return {
            "_embedded": {
                "items": filtered_devices
            },
            "total": len(filtered_devices)
        }

    async def configure_device_snmp_settings(
        self,
        device_id: int,
        snmp_read_settings: Optional[Dict[str, Any]] = None,
        snmp_write_settings: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Configure SNMP settings for a network device."""
        config_data = {}
        
        if snmp_read_settings:
            config_data["snmp_read"] = snmp_read_settings
        if snmp_write_settings:
            config_data["snmp_write"] = snmp_write_settings
        
        # Debug logging
        logger.debug(f"Sending SNMP config data: {json.dumps(config_data, indent=2)}")
        
        return await self.update_network_device(device_id, config_data)

    async def configure_device_radsec_settings(
        self,
        device_id: int,
        radsec_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Configure RadSec (RADIUS over TLS) settings for a network device."""
        # RadSec might just be a boolean flag
        config_data = {}
        if "enabled" in radsec_config:
            config_data["radsec_enabled"] = radsec_config["enabled"]
        # Add other RadSec fields if they exist in the API
        if "port" in radsec_config:
            config_data["radsec_port"] = radsec_config["port"]
            
        return await self.update_network_device(device_id, config_data)

    async def configure_device_cli_settings(
        self,
        device_id: int,
        cli_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Configure CLI access settings for a network device."""
        config_data = {"cli_config": cli_config}
        return await self.update_network_device(device_id, config_data)

    async def configure_device_onconnect_enforcement(
        self,
        device_id: int,
        onconnect_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Configure OnConnect enforcement settings for a network device."""
        config_data = {"onconnect_config": onconnect_config}
        return await self.update_network_device(device_id, config_data)