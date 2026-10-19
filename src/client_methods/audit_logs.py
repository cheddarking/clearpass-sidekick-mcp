"""
Mixin class for ClearPassClient to manage audit, logs, and insight-related API calls.
"""

from typing import Dict, Any, Optional, Union

class AuditLogsMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for audit, logs, and insight management.
    """

    async def get_audit_records(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Get audit records."""
        params = {"limit": limit}
        filters = []
        
        if start_time:
            filters.append(f"timestamp ge '{start_time}'")
        if end_time:
            filters.append(f"timestamp le '{end_time}'")
            
        if filters:
            params["filter"] = " and ".join(filters)
            
        return await self._make_request("GET", "audit-record", params=params)
    
    async def get_system_health(self) -> Dict[str, Any]:
        """Get system health status."""
        return await self._make_request("GET", "cppm-version")
    
    async def get_server_configuration(self) -> Dict[str, Any]:
        """Get server configuration information."""
        return await self._make_request("GET", "server-configuration")
    
    async def get_cluster_servers(self) -> Dict[str, Any]:
        """Get cluster server information."""
        return await self._make_request("GET", "cluster/server")

    async def get_admin_login_audit(self, username: str) -> Dict[str, Any]:
        """Get previous login details for a specific admin user."""
        return await self._make_request("GET", f"login-audit/{username}")

    async def list_system_events(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of system events."""
        params = {}
        if filter_str is not None: params["filter"] = filter_str
        if sort is not None: params["sort"] = sort
        if offset is not None: params["offset"] = offset
        if limit is not None: params["limit"] = limit
        if calculate_count is not None: params["calculate_count"] = calculate_count
        return await self._make_request("GET", "system-event", params=params)

    async def create_system_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new system event."""
        return await self._make_request("POST", "system-event", data=event_data)

    async def list_insight_alerts(
        self,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get all Insight alert configurations."""
        params = {}
        if offset is not None: params["offset"] = offset
        if limit is not None: params["limit"] = limit
        if calculate_count is not None: params["calculate_count"] = calculate_count
        return await self._make_request("GET", "alert", params=params)

    async def create_insight_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an Insight alert configuration."""
        return await self._make_request("POST", "alert", data=alert_data)

    async def get_insight_alert_by_id(self, alert_id: int) -> Dict[str, Any]:
        """Get an Insight alert configuration by ID."""
        return await self._make_request("GET", f"alert/{alert_id}")

    async def get_insight_alert_by_name(self, alert_name: str) -> Dict[str, Any]:
        """Get an Insight alert configuration by name."""
        return await self._make_request("GET", f"alert/{alert_name}")

    async def update_insight_alert_by_id(self, alert_id: int, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Partially update an Insight alert configuration by ID."""
        return await self._make_request("PATCH", f"alert/{alert_id}", data=alert_data)

    async def replace_insight_alert_by_id(self, alert_id: int, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Completely update an Insight alert configuration by ID."""
        return await self._make_request("PUT", f"alert/{alert_id}", data=alert_data)

    async def delete_insight_alert_by_id(self, alert_id: int) -> Dict[str, Any]:
        """Delete an Insight alert configuration by ID."""
        return await self._make_request("DELETE", f"alert/{alert_id}")
    
    async def list_insight_reports(
        self,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get all Insight report configurations."""
        params = {}
        if offset is not None: params["offset"] = offset
        if limit is not None: params["limit"] = limit
        if calculate_count is not None: params["calculate_count"] = calculate_count
        return await self._make_request("GET", "report", params=params)

    async def create_insight_report(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an Insight report configuration."""
        return await self._make_request("POST", "report", data=report_data)

    async def get_insight_report_by_id(self, report_id: int) -> Dict[str, Any]:
        """Get an Insight report configuration by ID."""
        return await self._make_request("GET", f"report/{report_id}")

    async def run_insight_report_by_id(self, report_id: int) -> Dict[str, Any]:
        """Run an Insight report by ID."""
        # `data={}` (not None) is required: the httpx client sets a global
        # Content-Type: application/json, so an omitted body makes ClearPass
        # reject the request with 400 "malformed JSON" before it resolves the id.
        return await self._make_request("POST", f"report/{report_id}/run", data={})

    # ------------------------------------------------------------------
    # Insight alert state transitions (by name)
    #
    # Every one of these is a body-less PATCH. `data={}` (not None) is passed
    # for the same reason as run_insight_report_by_id above: the shared httpx
    # client always sends Content-Type: application/json, and ClearPass rejects
    # a JSON-typed request with no body as 400 "malformed JSON" before it ever
    # resolves the name in the path.
    # ------------------------------------------------------------------

    async def enable_insight_alert_by_name(self, alert_name: str) -> Dict[str, Any]:
        """Enable an Insight alert configuration by name."""
        return await self._make_request("PATCH", f"alert/{alert_name}/enable", data={})

    async def disable_insight_alert_by_name(self, alert_name: str) -> Dict[str, Any]:
        """Disable an Insight alert configuration by name."""
        return await self._make_request("PATCH", f"alert/{alert_name}/disable", data={})

    async def mute_insight_alert_by_name(self, alert_name: str) -> Dict[str, Any]:
        """Mute an Insight alert configuration by name."""
        return await self._make_request("PATCH", f"alert/{alert_name}/mute", data={})

    async def unmute_insight_alert_by_name(self, alert_name: str) -> Dict[str, Any]:
        """Unmute an Insight alert configuration by name."""
        return await self._make_request("PATCH", f"alert/{alert_name}/unmute", data={})

    # ------------------------------------------------------------------
    # Insight report operations (by name)
    # ------------------------------------------------------------------

    async def update_insight_report_by_name(self, report_name: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Partially update an Insight report configuration by name."""
        return await self._make_request("PATCH", f"report/{report_name}", data=report_data)

    async def replace_insight_report_by_name(self, report_name: str, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Completely update an Insight report configuration by name."""
        return await self._make_request("PUT", f"report/{report_name}", data=report_data)

    async def delete_insight_report_by_name(self, report_name: str) -> Dict[str, Any]:
        """Delete an Insight report configuration by name."""
        return await self._make_request("DELETE", f"report/{report_name}")

    async def enable_insight_report_by_name(self, report_name: str) -> Dict[str, Any]:
        """Enable an Insight report configuration by name."""
        return await self._make_request("PATCH", f"report/{report_name}/enable", data={})

    async def disable_insight_report_by_name(self, report_name: str) -> Dict[str, Any]:
        """Disable an Insight report configuration by name."""
        return await self._make_request("PATCH", f"report/{report_name}/disable", data={})

    # ------------------------------------------------------------------
    # Insight endpoint lookups
    # ------------------------------------------------------------------

    async def get_insight_endpoint_by_ip(self, ip: str) -> Dict[str, Any]:
        """Look up endpoints by IPv4/IPv6 address."""
        return await self._make_request("GET", f"insight/endpoint/ip/{ip}")

    async def get_insight_endpoints_by_ip_range(self, ip_range: str) -> Dict[str, Any]:
        """Look up endpoints by IPv4/IPv6 address range."""
        return await self._make_request("GET", f"insight/endpoint/ip-range/{ip_range}")

    async def get_insight_endpoint_by_mac(self, mac: str) -> Dict[str, Any]:
        """Get a single endpoint by MAC address."""
        return await self._make_request("GET", f"insight/endpoint/mac/{mac}")

    async def get_insight_endpoints_by_time_range(self, from_time: str, to_time: str) -> Dict[str, Any]:
        """Look up endpoints seen between two UNIX timestamps."""
        return await self._make_request(
            "GET", f"insight/endpoint/time-range/{from_time}/{to_time}"
        )