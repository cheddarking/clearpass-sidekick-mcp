"""
Mixin class for ClearPassClient covering Endpoint Visibility API calls.

Wraps the ClearPass Endpoint Visibility surface: Agentless OnGuard settings and
subnet mappings, network-scan configuration, device profiler fingerprints, the
fingerprint dictionary, OnGuard activity / custom scripts / settings, OnGuard
Policy Manager zones, profiler subnet mappings and the Windows hotfix database.
"""

from typing import Dict, Any, Optional, Union


def _list_params(
    filter_str: Optional[str] = None,
    sort: Optional[str] = None,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    calculate_count: Optional[bool] = None,
) -> Dict[str, Any]:
    """Build the standard ClearPass list query-string parameters."""
    params: Dict[str, Any] = {}
    if filter_str is not None:
        params["filter"] = filter_str
    if sort is not None:
        params["sort"] = sort
    if offset is not None:
        params["offset"] = offset
    if limit is not None:
        params["limit"] = limit
    if calculate_count is not None:
        params["calculate_count"] = calculate_count
    return params


class EndpointVisibilityMethodsMixin:
    """
    Mixin class for ClearPassClient providing Endpoint Visibility methods.
    """

    # ================================
    # AGENTLESS ONGUARD SETTINGS
    # ================================

    async def list_agentless_onguard_settings(self) -> Dict[str, Any]:
        """Get a list of Agentless OnGuard Settings."""
        return await self._make_request("GET", "agentless-onguard/settings")

    async def create_agentless_onguard_settings(self, settings_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an Agentless OnGuard Setting."""
        return await self._make_request("POST", "agentless-onguard/settings", data=settings_data)

    async def delete_agentless_onguard_settings_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an Agentless OnGuard Setting by name."""
        return await self._make_request("DELETE", f"agentless-onguard/settings/name/{name}")

    async def get_agentless_onguard_settings_by_name(self, name: str) -> Dict[str, Any]:
        """Get an Agentless OnGuard Setting by name."""
        return await self._make_request("GET", f"agentless-onguard/settings/name/{name}")

    async def update_agentless_onguard_settings_by_name(
        self,
        name: str,
        settings_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of an Agentless OnGuard Setting by name."""
        return await self._make_request("PATCH", f"agentless-onguard/settings/name/{name}", data=settings_data)

    async def replace_agentless_onguard_settings_by_name(
        self,
        name: str,
        settings_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace an Agentless OnGuard Setting by name."""
        return await self._make_request("PUT", f"agentless-onguard/settings/name/{name}", data=settings_data)

    async def delete_agentless_onguard_settings_by_id(self, settings_id: Union[int, str]) -> Dict[str, Any]:
        """Delete an Agentless OnGuard Setting."""
        return await self._make_request("DELETE", f"agentless-onguard/settings/{settings_id}")

    async def get_agentless_onguard_settings_by_id(self, settings_id: Union[int, str]) -> Dict[str, Any]:
        """Get an Agentless OnGuard Setting."""
        return await self._make_request("GET", f"agentless-onguard/settings/{settings_id}")

    async def update_agentless_onguard_settings_by_id(
        self,
        settings_id: Union[int, str],
        settings_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of an Agentless OnGuard Setting."""
        return await self._make_request("PATCH", f"agentless-onguard/settings/{settings_id}", data=settings_data)

    async def replace_agentless_onguard_settings_by_id(
        self,
        settings_id: Union[int, str],
        settings_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace an Agentless OnGuard Setting."""
        return await self._make_request("PUT", f"agentless-onguard/settings/{settings_id}", data=settings_data)

    # ================================
    # AGENTLESS ONGUARD SUBNET MAPPINGS
    # ================================

    async def list_agentless_onguard_subnet_mappings(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of subnet mappings."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "agentless-onguard/subnet-mapping", params=params)

    async def create_agentless_onguard_subnet_mapping(self, mapping_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a subnet mapping."""
        return await self._make_request("POST", "agentless-onguard/subnet-mapping", data=mapping_data)

    async def delete_agentless_onguard_subnet_mapping_by_name(self, name: str) -> Dict[str, Any]:
        """Delete a subnet mapping by name."""
        return await self._make_request("DELETE", f"agentless-onguard/subnet-mapping/name/{name}")

    async def get_agentless_onguard_subnet_mapping_by_name(self, name: str) -> Dict[str, Any]:
        """Get a subnet mapping by name."""
        return await self._make_request("GET", f"agentless-onguard/subnet-mapping/name/{name}")

    async def update_agentless_onguard_subnet_mapping_by_name(
        self,
        name: str,
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a subnet mapping by name."""
        return await self._make_request("PATCH", f"agentless-onguard/subnet-mapping/name/{name}", data=mapping_data)

    async def replace_agentless_onguard_subnet_mapping_by_name(
        self,
        name: str,
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a subnet mapping by name."""
        return await self._make_request("PUT", f"agentless-onguard/subnet-mapping/name/{name}", data=mapping_data)

    async def disable_agentless_onguard_subnet_mapping_by_name(self, name: str) -> Dict[str, Any]:
        """Disable Agentless OnGuard Settings on client subnets by subnet mapping name."""
        # `data={}` (not None) is required: the shared httpx client always sends
        # Content-Type: application/json, so a body-less PATCH makes ClearPass
        # reject the request with 400 "malformed JSON" before it resolves the
        # name in the path. Same reason as run_insight_report_by_id in audit_logs.
        return await self._make_request("PATCH", f"agentless-onguard/subnet-mapping/name/{name}/disable", data={})

    async def enable_agentless_onguard_subnet_mapping_by_name(self, name: str) -> Dict[str, Any]:
        """Enable Agentless OnGuard Settings on client subnets by subnet mapping name."""
        # data={} -- see disable_agentless_onguard_subnet_mapping_by_name above.
        return await self._make_request("PATCH", f"agentless-onguard/subnet-mapping/name/{name}/enable", data={})

    async def delete_agentless_onguard_subnet_mapping_by_id(
        self,
        subnet_mapping_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Delete a subnet mapping."""
        return await self._make_request("DELETE", f"agentless-onguard/subnet-mapping/{subnet_mapping_id}")

    async def get_agentless_onguard_subnet_mapping_by_id(
        self,
        subnet_mapping_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Get a subnet mapping."""
        return await self._make_request("GET", f"agentless-onguard/subnet-mapping/{subnet_mapping_id}")

    async def update_agentless_onguard_subnet_mapping_by_id(
        self,
        subnet_mapping_id: Union[int, str],
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a subnet mapping."""
        return await self._make_request("PATCH", f"agentless-onguard/subnet-mapping/{subnet_mapping_id}", data=mapping_data)

    async def replace_agentless_onguard_subnet_mapping_by_id(
        self,
        subnet_mapping_id: Union[int, str],
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a subnet mapping."""
        return await self._make_request("PUT", f"agentless-onguard/subnet-mapping/{subnet_mapping_id}", data=mapping_data)

    async def disable_agentless_onguard_subnet_mapping_by_id(
        self,
        subnet_mapping_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Disable Agentless OnGuard Settings on client subnets."""
        # data={} -- see disable_agentless_onguard_subnet_mapping_by_name above.
        return await self._make_request("PATCH", f"agentless-onguard/subnet-mapping/{subnet_mapping_id}/disable", data={})

    async def enable_agentless_onguard_subnet_mapping_by_id(
        self,
        subnet_mapping_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Enable Agentless OnGuard Settings on client subnets."""
        # data={} -- see disable_agentless_onguard_subnet_mapping_by_name above.
        return await self._make_request("PATCH", f"agentless-onguard/subnet-mapping/{subnet_mapping_id}/enable", data={})

    # ================================
    # NETWORK SCAN CONFIGURATION
    # ================================

    async def list_network_scans(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of NetworkScan."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "config/network-scan", params=params)

    async def create_network_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a NetworkScan."""
        return await self._make_request("POST", "config/network-scan", data=scan_data)

    async def delete_network_scan_by_id(self, scan_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a NetworkScan."""
        return await self._make_request("DELETE", f"config/network-scan/{scan_id}")

    async def get_network_scan_by_id(self, scan_id: Union[int, str]) -> Dict[str, Any]:
        """Get a NetworkScan."""
        return await self._make_request("GET", f"config/network-scan/{scan_id}")

    async def update_network_scan_by_id(
        self,
        scan_id: Union[int, str],
        scan_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a NetworkScan."""
        return await self._make_request("PATCH", f"config/network-scan/{scan_id}", data=scan_data)

    async def replace_network_scan_by_id(
        self,
        scan_id: Union[int, str],
        scan_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update all fields of a NetworkScan."""
        return await self._make_request("PUT", f"config/network-scan/{scan_id}", data=scan_data)

    async def disable_network_scan_by_id(self, scan_id: Union[int, str]) -> Dict[str, Any]:
        """Update some fields of a NetworkScan."""
        # data={} -- see disable_agentless_onguard_subnet_mapping_by_name above.
        return await self._make_request("PATCH", f"config/network-scan/{scan_id}/disable", data={})

    async def enable_network_scan_by_id(self, scan_id: Union[int, str]) -> Dict[str, Any]:
        """Update some fields of a NetworkScan."""
        # data={} -- see disable_agentless_onguard_subnet_mapping_by_name above.
        return await self._make_request("PATCH", f"config/network-scan/{scan_id}/enable", data={})

    # ================================
    # DEVICE PROFILER FINGERPRINTS
    # ================================

    async def create_device_fingerprint(self, fingerprint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Post device fingerprint attributes for profiling."""
        return await self._make_request("POST", "device-profiler/device-fingerprint", data=fingerprint_data)

    async def delete_device_fingerprint(self, mac_or_ip: str) -> Dict[str, Any]:
        """Delete fingerprint of profiled device."""
        return await self._make_request("DELETE", f"device-profiler/device-fingerprint/{mac_or_ip}")

    async def get_device_fingerprint(self, mac_or_ip: str) -> Dict[str, Any]:
        """Get profiled device."""
        return await self._make_request("GET", f"device-profiler/device-fingerprint/{mac_or_ip}")

    # ================================
    # FINGERPRINT DICTIONARY
    # ================================

    async def list_fingerprints(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of Fingerprints."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "fingerprint", params=params)

    async def create_fingerprint(self, fingerprint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new Fingerprint."""
        return await self._make_request("POST", "fingerprint", data=fingerprint_data)

    async def delete_fingerprint_by_name(self, category: str, family: str, name: str) -> Dict[str, Any]:
        """Delete a Fingerprint by name."""
        return await self._make_request("DELETE", f"fingerprint/name/{category}/{family}/{name}")

    async def get_fingerprint_by_name(self, category: str, family: str, name: str) -> Dict[str, Any]:
        """Get a Fingerprint by name."""
        return await self._make_request("GET", f"fingerprint/name/{category}/{family}/{name}")

    async def update_fingerprint_by_name(
        self,
        category: str,
        family: str,
        name: str,
        fingerprint_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a Fingerprint by name."""
        return await self._make_request("PATCH", f"fingerprint/name/{category}/{family}/{name}", data=fingerprint_data)

    async def replace_fingerprint_by_name(
        self,
        category: str,
        family: str,
        name: str,
        fingerprint_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a Fingerprint by name."""
        return await self._make_request("PUT", f"fingerprint/name/{category}/{family}/{name}", data=fingerprint_data)

    async def delete_fingerprint_by_id(self, fingerprint_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a Fingerprint."""
        return await self._make_request("DELETE", f"fingerprint/{fingerprint_id}")

    async def get_fingerprint_by_id(self, fingerprint_id: Union[int, str]) -> Dict[str, Any]:
        """Get a Fingerprint."""
        return await self._make_request("GET", f"fingerprint/{fingerprint_id}")

    async def update_fingerprint_by_id(
        self,
        fingerprint_id: Union[int, str],
        fingerprint_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a Fingerprint."""
        return await self._make_request("PATCH", f"fingerprint/{fingerprint_id}", data=fingerprint_data)

    async def replace_fingerprint_by_id(
        self,
        fingerprint_id: Union[int, str],
        fingerprint_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a Fingerprint."""
        return await self._make_request("PUT", f"fingerprint/{fingerprint_id}", data=fingerprint_data)

    # ================================
    # ONGUARD ACTIVITY
    # ================================

    async def list_onguard_activity(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of Clearpass OnGuard Endpoints."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "onguard-activity", params=params)

    async def get_onguard_activity_by_host_mac(self, host_mac: str) -> Dict[str, Any]:
        """Get a Clearpass OnGuard Endpoint Details by host_mac."""
        return await self._make_request("GET", f"onguard-activity/host_mac/{host_mac}")

    async def send_onguard_activity_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send/Broadcast Message."""
        return await self._make_request("POST", "onguard-activity/message", data=message_data)

    async def send_onguard_activity_notification(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send/Broadcast Notification."""
        return await self._make_request("POST", "onguard-activity/notification", data=message_data)

    async def get_onguard_activity_by_id(self, onguard_activity_id: Union[int, str]) -> Dict[str, Any]:
        """Get a Clearpass OnGuard Endpoint Details."""
        return await self._make_request("GET", f"onguard-activity/{onguard_activity_id}")

    # ================================
    # ONGUARD CUSTOM SCRIPTS
    # ================================

    async def list_onguard_custom_scripts(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of OnGuard Custom Scripts."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "onguard-custom-script", params=params)

    async def create_onguard_custom_script(self, script_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new OnGuard Custom Script."""
        return await self._make_request("POST", "onguard-custom-script", data=script_data)

    async def delete_onguard_custom_script_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an OnGuard Custom Script by name."""
        return await self._make_request("DELETE", f"onguard-custom-script/name/{name}")

    async def get_onguard_custom_script_by_name(self, name: str) -> Dict[str, Any]:
        """Get an OnGuard Custom Script by name."""
        return await self._make_request("GET", f"onguard-custom-script/name/{name}")

    async def update_onguard_custom_script_by_name(
        self,
        name: str,
        script_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of an OnGuard Custom Script by name."""
        return await self._make_request("PATCH", f"onguard-custom-script/name/{name}", data=script_data)

    async def replace_onguard_custom_script_by_name(
        self,
        name: str,
        script_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace an OnGuard Custom Script by name."""
        return await self._make_request("PUT", f"onguard-custom-script/name/{name}", data=script_data)

    async def delete_onguard_custom_script_by_id(
        self,
        onguard_custom_script_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Delete an OnGuard Custom Script."""
        return await self._make_request("DELETE", f"onguard-custom-script/{onguard_custom_script_id}")

    async def get_onguard_custom_script_by_id(
        self,
        onguard_custom_script_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Get an OnGuard Custom Script."""
        return await self._make_request("GET", f"onguard-custom-script/{onguard_custom_script_id}")

    async def update_onguard_custom_script_by_id(
        self,
        onguard_custom_script_id: Union[int, str],
        script_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of an OnGuard Custom Script."""
        return await self._make_request("PATCH", f"onguard-custom-script/{onguard_custom_script_id}", data=script_data)

    async def replace_onguard_custom_script_by_id(
        self,
        onguard_custom_script_id: Union[int, str],
        script_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace an OnGuard Custom Script."""
        return await self._make_request("PUT", f"onguard-custom-script/{onguard_custom_script_id}", data=script_data)

    # ================================
    # ONGUARD GLOBAL SETTINGS
    # ================================

    async def onguard_list_global_settings(self) -> Dict[str, Any]:
        """Get OnGuard global settings."""
        return await self._make_request("GET", "onguard/global-settings")

    async def onguard_update_global_settings(self, settings_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update OnGuard global settings."""
        return await self._make_request("POST", "onguard/global-settings", data=settings_data)

    # ================================
    # ONGUARD POLICY MANAGER ZONES
    # ================================

    async def onguard_list_policy_manager_zones(self) -> Dict[str, Any]:
        """Get Policy Manager Zones with associated authentication server IP addresses(Client Subnets and Server IPs)."""
        return await self._make_request("GET", "onguard/policy-manager-zones")

    async def onguard_create_policy_manager_zone(self, zone_data: Dict[str, Any]) -> Dict[str, Any]:
        """Post Policy Manager Zones with associated authentication server IP addresses."""
        return await self._make_request("POST", "onguard/policy-manager-zones", data=zone_data)

    async def onguard_delete_policy_manager_zone_by_name(self, name: str) -> Dict[str, Any]:
        """Delete authentication server IP addresses for Policy Manager Zone by name."""
        return await self._make_request("DELETE", f"onguard/policy-manager-zones/name/{name}")

    async def onguard_get_policy_manager_zone_by_name(self, name: str) -> Dict[str, Any]:
        """Get Client Subnets and Server IPs for Policy Manager Zone by name."""
        return await self._make_request("GET", f"onguard/policy-manager-zones/name/{name}")

    async def onguard_update_policy_manager_zone_by_name(
        self,
        name: str,
        zone_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update authentication server IP addresses for Policy Manager Zone by name."""
        return await self._make_request("PATCH", f"onguard/policy-manager-zones/name/{name}", data=zone_data)

    async def onguard_replace_policy_manager_zone_by_name(
        self,
        name: str,
        zone_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Post Client Subnets and Server IPs for Policy Manager Zone by name."""
        return await self._make_request("PUT", f"onguard/policy-manager-zones/name/{name}", data=zone_data)

    async def onguard_delete_policy_manager_zone_by_id(
        self,
        policy_manager_zones_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Delete authentication server IP addresses for Policy Manager Zone."""
        return await self._make_request("DELETE", f"onguard/policy-manager-zones/{policy_manager_zones_id}")

    async def onguard_get_policy_manager_zone_by_id(
        self,
        policy_manager_zones_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Get Client Subnets and Server IPs for Policy Manager Zone."""
        return await self._make_request("GET", f"onguard/policy-manager-zones/{policy_manager_zones_id}")

    async def onguard_update_policy_manager_zone_by_id(
        self,
        policy_manager_zones_id: Union[int, str],
        zone_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update authentication server IP addresses for Policy Manager Zone."""
        return await self._make_request("PATCH", f"onguard/policy-manager-zones/{policy_manager_zones_id}", data=zone_data)

    async def onguard_replace_policy_manager_zone_by_id(
        self,
        policy_manager_zones_id: Union[int, str],
        zone_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Post Client Subnets and Server IPs for Policy Manager Zone."""
        return await self._make_request("PUT", f"onguard/policy-manager-zones/{policy_manager_zones_id}", data=zone_data)

    # ================================
    # ONGUARD SETTINGS
    # ================================

    async def onguard_list_settings(self) -> Dict[str, Any]:
        """Get OnGuard settings."""
        return await self._make_request("GET", "onguard/settings")

    async def onguard_update_settings(self, settings_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update OnGuard settings."""
        return await self._make_request("POST", "onguard/settings", data=settings_data)

    # ================================
    # PROFILER SUBNET MAPPINGS
    # ================================

    async def profiler_list_subnet_mappings(self) -> Dict[str, Any]:
        """Get a list of profiler subnet mappings."""
        return await self._make_request("GET", "profiler-subnet-mapping")

    async def profiler_create_subnet_mapping(self, mapping_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a profiler subnet mapping."""
        return await self._make_request("POST", "profiler-subnet-mapping", data=mapping_data)

    async def profiler_delete_subnet_mapping_by_network(self, scan_type: str, network: str) -> Dict[str, Any]:
        """Delete a profiler subnet mapping."""
        return await self._make_request("DELETE", f"profiler-subnet-mapping/{scan_type}/network/{network}")

    async def profiler_get_subnet_mapping_by_network(self, scan_type: str, network: str) -> Dict[str, Any]:
        """Get a profiler subnet mapping."""
        return await self._make_request("GET", f"profiler-subnet-mapping/{scan_type}/network/{network}")

    async def profiler_update_subnet_mapping_by_network(
        self,
        scan_type: str,
        network: str,
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a profiler subnet mapping."""
        return await self._make_request("PATCH", f"profiler-subnet-mapping/{scan_type}/network/{network}", data=mapping_data)

    async def profiler_replace_subnet_mapping_by_network(
        self,
        scan_type: str,
        network: str,
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a profiler subnet mapping."""
        return await self._make_request("PUT", f"profiler-subnet-mapping/{scan_type}/network/{network}", data=mapping_data)

    async def profiler_delete_subnet_mapping_by_id(
        self,
        scan_type: str,
        profiler_subnet_mapping_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Delete a profiler subnet mapping."""
        return await self._make_request("DELETE", f"profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}")

    async def profiler_get_subnet_mapping_by_id(
        self,
        scan_type: str,
        profiler_subnet_mapping_id: Union[int, str],
    ) -> Dict[str, Any]:
        """Get a profiler subnet mapping."""
        return await self._make_request("GET", f"profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}")

    async def profiler_update_subnet_mapping_by_id(
        self,
        scan_type: str,
        profiler_subnet_mapping_id: Union[int, str],
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a profiler subnet mapping."""
        return await self._make_request("PATCH", f"profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}", data=mapping_data)

    async def profiler_replace_subnet_mapping_by_id(
        self,
        scan_type: str,
        profiler_subnet_mapping_id: Union[int, str],
        mapping_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a profiler subnet mapping."""
        return await self._make_request("PUT", f"profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}", data=mapping_data)

    # ================================
    # WINDOWS HOTFIXES
    # ================================

    async def list_windows_hotfixes(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of Windows Hotfixes."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "windows-hotfix", params=params)

    async def create_windows_hotfix(self, hotfix_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a Windows Hotfix."""
        return await self._make_request("POST", "windows-hotfix", data=hotfix_data)

    async def delete_windows_hotfix_by_kbid(self, kbid: str, operating_system: str) -> Dict[str, Any]:
        """Delete a windows hotfix by kbid and os."""
        return await self._make_request("DELETE", f"windows-hotfix/kbid/{kbid}/operating_system/{operating_system}")

    async def get_windows_hotfix_by_kbid(self, kbid: str, operating_system: str) -> Dict[str, Any]:
        """Get a windows hotfix by kbid and os."""
        return await self._make_request("GET", f"windows-hotfix/kbid/{kbid}/operating_system/{operating_system}")

    async def update_windows_hotfix_by_kbid(
        self,
        kbid: str,
        operating_system: str,
        hotfix_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a windows hotfix by kbid and os."""
        return await self._make_request("PATCH", f"windows-hotfix/kbid/{kbid}/operating_system/{operating_system}", data=hotfix_data)

    async def replace_windows_hotfix_by_kbid(
        self,
        kbid: str,
        operating_system: str,
        hotfix_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a windows hotfix by kbid and os."""
        return await self._make_request("PUT", f"windows-hotfix/kbid/{kbid}/operating_system/{operating_system}", data=hotfix_data)

    async def delete_windows_hotfix_by_id(self, windows_hotfix_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a windows hotfix."""
        return await self._make_request("DELETE", f"windows-hotfix/{windows_hotfix_id}")

    async def get_windows_hotfix_by_id(self, windows_hotfix_id: Union[int, str]) -> Dict[str, Any]:
        """Get a windows hotfix."""
        return await self._make_request("GET", f"windows-hotfix/{windows_hotfix_id}")

    async def update_windows_hotfix_by_id(
        self,
        windows_hotfix_id: Union[int, str],
        hotfix_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Update some fields of a windows hotfix."""
        return await self._make_request("PATCH", f"windows-hotfix/{windows_hotfix_id}", data=hotfix_data)

    async def replace_windows_hotfix_by_id(
        self,
        windows_hotfix_id: Union[int, str],
        hotfix_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Replace a windows hotfix."""
        return await self._make_request("PUT", f"windows-hotfix/{windows_hotfix_id}", data=hotfix_data)
