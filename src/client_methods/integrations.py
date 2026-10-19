"""
Mixin class for ClearPassClient to manage third-party integration API calls.

This module contains client methods for the ClearPass integration surface:
endpoint context servers (and their context server actions), Device Insight,
ingress event sources and event dictionaries, ClearPass Extensions (instance
lifecycle, configuration, logs and upgrades) and syslog export filters/targets.
"""

from typing import Dict, Any, Optional


def _list_params(
    filter_str: Optional[str] = None,
    sort: Optional[str] = None,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    calculate_count: Optional[bool] = None
) -> Dict[str, Any]:
    """Build the standard ClearPass list query parameters, omitting unset values."""
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


class IntegrationsMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for third-party integrations.
    """

    # ================================
    # CONTEXT SERVER ACTIONS
    # ================================

    async def list_context_server_actions(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of context server actions."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "context-server-action", params=params)

    async def create_context_server_action(self, action_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new context server action."""
        return await self._make_request("POST", "context-server-action", data=action_data)

    async def get_context_server_action_by_id(self, context_server_action_id: int) -> Dict[str, Any]:
        """Get a context server action by numeric ID."""
        return await self._make_request("GET", f"context-server-action/{context_server_action_id}")

    async def update_context_server_action_by_id(
        self,
        context_server_action_id: int,
        action_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a context server action by numeric ID."""
        return await self._make_request(
            "PATCH", f"context-server-action/{context_server_action_id}", data=action_data
        )

    async def replace_context_server_action_by_id(
        self,
        context_server_action_id: int,
        action_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a context server action by numeric ID."""
        return await self._make_request(
            "PUT", f"context-server-action/{context_server_action_id}", data=action_data
        )

    async def delete_context_server_action_by_id(self, context_server_action_id: int) -> Dict[str, Any]:
        """Delete a context server action by numeric ID."""
        return await self._make_request("DELETE", f"context-server-action/{context_server_action_id}")

    async def get_context_server_action_by_name(self, server_type: str, action_name: str) -> Dict[str, Any]:
        """Get a context server action by server type and action name."""
        return await self._make_request(
            "GET", f"context-server-action/{server_type}/action-name/{action_name}"
        )

    async def update_context_server_action_by_name(
        self,
        server_type: str,
        action_name: str,
        action_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a context server action by server type and action name."""
        return await self._make_request(
            "PATCH", f"context-server-action/{server_type}/action-name/{action_name}", data=action_data
        )

    async def replace_context_server_action_by_name(
        self,
        server_type: str,
        action_name: str,
        action_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a context server action by server type and action name."""
        return await self._make_request(
            "PUT", f"context-server-action/{server_type}/action-name/{action_name}", data=action_data
        )

    async def delete_context_server_action_by_name(self, server_type: str, action_name: str) -> Dict[str, Any]:
        """Delete a context server action by server type and action name."""
        return await self._make_request(
            "DELETE", f"context-server-action/{server_type}/action-name/{action_name}"
        )

    # ================================
    # DEVICE INSIGHT INTEGRATION
    # ================================

    async def get_device_insight_config(self) -> Dict[str, Any]:
        """Get Device Insight integration details."""
        return await self._make_request("GET", "device-insight")

    async def update_device_insight_config(self, device_insight_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update Device Insight integration values."""
        return await self._make_request("POST", "device-insight", data=device_insight_data)

    # ================================
    # ENDPOINT CONTEXT SERVERS
    # ================================

    async def list_endpoint_context_servers(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of endpoint context servers."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "endpoint-context-server", params=params)

    async def create_endpoint_context_server(self, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new endpoint context server."""
        return await self._make_request("POST", "endpoint-context-server", data=server_data)

    async def get_endpoint_context_server_by_name(self, server_name: str) -> Dict[str, Any]:
        """Get an endpoint context server by server name."""
        return await self._make_request("GET", f"endpoint-context-server/server-name/{server_name}")

    async def update_endpoint_context_server_by_name(
        self,
        server_name: str,
        server_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an endpoint context server by server name."""
        return await self._make_request(
            "PATCH", f"endpoint-context-server/server-name/{server_name}", data=server_data
        )

    async def replace_endpoint_context_server_by_name(
        self,
        server_name: str,
        server_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an endpoint context server by server name."""
        return await self._make_request(
            "PUT", f"endpoint-context-server/server-name/{server_name}", data=server_data
        )

    async def delete_endpoint_context_server_by_name(self, server_name: str) -> Dict[str, Any]:
        """Delete an endpoint context server by server name."""
        return await self._make_request("DELETE", f"endpoint-context-server/server-name/{server_name}")

    async def trigger_endpoint_context_server_poll_by_name(self, server_name: str) -> Dict[str, Any]:
        """Trigger polling for an endpoint context server by server name."""
        # The shared httpx client always sends Content-Type: application/json, so a
        # body-less PATCH would put an empty entity on the wire and the appliance
        # answers 400 "JSON decoding error: malformed JSON". An explicit empty
        # object is the smallest well-formed body this endpoint accepts.
        return await self._make_request(
            "PATCH", f"endpoint-context-server/server-name/{server_name}/trigger-poll",
            data={}
        )

    async def get_endpoint_context_server_by_id(self, endpoint_context_server_id: int) -> Dict[str, Any]:
        """Get an endpoint context server by numeric ID."""
        return await self._make_request("GET", f"endpoint-context-server/{endpoint_context_server_id}")

    async def update_endpoint_context_server_by_id(
        self,
        endpoint_context_server_id: int,
        server_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an endpoint context server by numeric ID."""
        return await self._make_request(
            "PATCH", f"endpoint-context-server/{endpoint_context_server_id}", data=server_data
        )

    async def replace_endpoint_context_server_by_id(
        self,
        endpoint_context_server_id: int,
        server_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an endpoint context server by numeric ID."""
        return await self._make_request(
            "PUT", f"endpoint-context-server/{endpoint_context_server_id}", data=server_data
        )

    async def delete_endpoint_context_server_by_id(self, endpoint_context_server_id: int) -> Dict[str, Any]:
        """Delete an endpoint context server by numeric ID."""
        return await self._make_request("DELETE", f"endpoint-context-server/{endpoint_context_server_id}")

    async def trigger_endpoint_context_server_poll_by_id(self, endpoint_context_server_id: int) -> Dict[str, Any]:
        """Trigger polling for an endpoint context server by numeric ID."""
        # See trigger_endpoint_context_server_poll_by_name: an empty JSON object is
        # required because the client always advertises a JSON content type.
        return await self._make_request(
            "PATCH", f"endpoint-context-server/{endpoint_context_server_id}/trigger-poll",
            data={}
        )

    # ================================
    # EVENT SOURCES
    # ================================

    async def list_event_sources(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of event sources."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "event-sources", params=params)

    async def create_event_source(self, event_source_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new event source."""
        return await self._make_request("POST", "event-sources", data=event_source_data)

    async def get_event_source_by_name(self, name: str) -> Dict[str, Any]:
        """Get an event source by name."""
        return await self._make_request("GET", f"event-sources/name/{name}")

    async def update_event_source_by_name(self, name: str, event_source_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an event source by name."""
        return await self._make_request("PATCH", f"event-sources/name/{name}", data=event_source_data)

    async def replace_event_source_by_name(self, name: str, event_source_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an event source by name."""
        return await self._make_request("PUT", f"event-sources/name/{name}", data=event_source_data)

    async def delete_event_source_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an event source by name."""
        return await self._make_request("DELETE", f"event-sources/name/{name}")

    async def get_event_source_by_id(self, event_sources_id: int) -> Dict[str, Any]:
        """Get an event source by numeric ID."""
        return await self._make_request("GET", f"event-sources/{event_sources_id}")

    async def update_event_source_by_id(
        self,
        event_sources_id: int,
        event_source_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an event source by numeric ID."""
        return await self._make_request("PATCH", f"event-sources/{event_sources_id}", data=event_source_data)

    async def replace_event_source_by_id(
        self,
        event_sources_id: int,
        event_source_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an event source by numeric ID."""
        return await self._make_request("PUT", f"event-sources/{event_sources_id}", data=event_source_data)

    async def delete_event_source_by_id(self, event_sources_id: int) -> Dict[str, Any]:
        """Delete an event source by numeric ID."""
        return await self._make_request("DELETE", f"event-sources/{event_sources_id}")

    # ================================
    # EXTENSION INSTANCES
    # ================================

    async def list_extension_instances(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of installed extensions."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "extension/instance", params=params)

    async def install_extension_instance(self, extension_data: Dict[str, Any]) -> Dict[str, Any]:
        """Install an extension."""
        return await self._make_request("POST", "extension/instance", data=extension_data)

    async def get_extension_instance(self, extension_id: str) -> Dict[str, Any]:
        """Get an installed extension by instance ID."""
        return await self._make_request("GET", f"extension/instance/{extension_id}")

    async def update_extension_instance_state(
        self,
        extension_id: str,
        extension_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Change the state of an installed extension."""
        return await self._make_request("PATCH", f"extension/instance/{extension_id}", data=extension_data)

    async def uninstall_extension_instance(
        self,
        extension_id: str,
        force: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Uninstall an extension, optionally killing it first."""
        params: Dict[str, Any] = {}
        if force is not None:
            params["force"] = force
        return await self._make_request("DELETE", f"extension/instance/{extension_id}", params=params)

    async def get_extension_instance_config(self, extension_id: str) -> Dict[str, Any]:
        """Get the configuration of an installed extension."""
        return await self._make_request("GET", f"extension/instance/{extension_id}/config")

    async def replace_extension_instance_config(
        self,
        extension_id: str,
        config_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Set the configuration of an installed extension."""
        return await self._make_request(
            "PUT", f"extension/instance/{extension_id}/config", data=config_data
        )

    async def get_extension_instance_log(
        self,
        extension_id: str,
        stdout: Optional[bool] = None,
        stderr: Optional[bool] = None,
        since: Optional[int] = None,
        timestamps: Optional[bool] = None,
        tail: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get the log output from an installed extension."""
        params: Dict[str, Any] = {}
        if stdout is not None:
            params["stdout"] = stdout
        if stderr is not None:
            params["stderr"] = stderr
        if since is not None:
            params["since"] = since
        if timestamps is not None:
            params["timestamps"] = timestamps
        if tail is not None:
            params["tail"] = tail
        return await self._make_request("GET", f"extension/instance/{extension_id}/log", params=params)

    async def reinstall_extension_instance(
        self,
        extension_id: str,
        reinstall_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Reinstall an extension."""
        return await self._make_request(
            "POST", f"extension/instance/{extension_id}/reinstall", data=reinstall_data or {}
        )

    async def restart_extension_instance(self, extension_id: str) -> Dict[str, Any]:
        """Restart an installed extension."""
        # data={} for the same reason as trigger-poll: the client advertises a JSON
        # content type on every request, so a body-less POST is malformed JSON.
        return await self._make_request(
            "POST", f"extension/instance/{extension_id}/restart", data={}
        )

    async def start_extension_instance(self, extension_id: str) -> Dict[str, Any]:
        """Start an installed extension."""
        return await self._make_request(
            "POST", f"extension/instance/{extension_id}/start", data={}
        )

    async def stop_extension_instance(self, extension_id: str) -> Dict[str, Any]:
        """Stop an installed extension."""
        return await self._make_request(
            "POST", f"extension/instance/{extension_id}/stop", data={}
        )

    async def get_extension_upgrade_info(self, extension_id: str) -> Dict[str, Any]:
        """Get information on an extension's available upgrade."""
        return await self._make_request("GET", f"extension/instance/{extension_id}/upgrade")

    async def upgrade_extension_instance(
        self,
        extension_id: str,
        upgrade_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Upgrade an installed extension."""
        return await self._make_request(
            "POST", f"extension/instance/{extension_id}/upgrade", data=upgrade_data or {}
        )

    # ================================
    # EXTENSION STORE
    # ================================

    async def list_extension_store(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Find extensions in the extension store."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "extension/store", params=params)

    async def get_extension_store_item(self, store_id: str) -> Dict[str, Any]:
        """Get an extension store entry by store ID."""
        return await self._make_request("GET", f"extension/store/{store_id}")

    # ================================
    # INGRESS EVENT DICTIONARIES
    # ================================

    async def list_ingress_event_dictionaries(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of ingress event dictionaries."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "ingress-event-dictionary", params=params)

    async def create_ingress_event_dictionary(self, dictionary_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new ingress event dictionary."""
        return await self._make_request("POST", "ingress-event-dictionary", data=dictionary_data)

    async def get_ingress_event_dictionary_by_format_name(self, format_name: str) -> Dict[str, Any]:
        """Get an ingress event dictionary by format name."""
        return await self._make_request("GET", f"ingress-event-dictionary/format_name/{format_name}")

    async def update_ingress_event_dictionary_by_format_name(
        self,
        format_name: str,
        dictionary_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an ingress event dictionary by format name."""
        return await self._make_request(
            "PATCH", f"ingress-event-dictionary/format_name/{format_name}", data=dictionary_data
        )

    async def replace_ingress_event_dictionary_by_format_name(
        self,
        format_name: str,
        dictionary_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an ingress event dictionary by format name."""
        return await self._make_request(
            "PUT", f"ingress-event-dictionary/format_name/{format_name}", data=dictionary_data
        )

    async def delete_ingress_event_dictionary_by_format_name(self, format_name: str) -> Dict[str, Any]:
        """Delete an ingress event dictionary by format name."""
        return await self._make_request("DELETE", f"ingress-event-dictionary/format_name/{format_name}")

    async def get_ingress_event_dictionary_by_id(self, ingress_event_dictionary_id: int) -> Dict[str, Any]:
        """Get an ingress event dictionary by numeric ID."""
        return await self._make_request("GET", f"ingress-event-dictionary/{ingress_event_dictionary_id}")

    async def update_ingress_event_dictionary_by_id(
        self,
        ingress_event_dictionary_id: int,
        dictionary_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an ingress event dictionary by numeric ID."""
        return await self._make_request(
            "PATCH", f"ingress-event-dictionary/{ingress_event_dictionary_id}", data=dictionary_data
        )

    async def replace_ingress_event_dictionary_by_id(
        self,
        ingress_event_dictionary_id: int,
        dictionary_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an ingress event dictionary by numeric ID."""
        return await self._make_request(
            "PUT", f"ingress-event-dictionary/{ingress_event_dictionary_id}", data=dictionary_data
        )

    async def delete_ingress_event_dictionary_by_id(self, ingress_event_dictionary_id: int) -> Dict[str, Any]:
        """Delete an ingress event dictionary by numeric ID."""
        return await self._make_request("DELETE", f"ingress-event-dictionary/{ingress_event_dictionary_id}")

    # ================================
    # SYSLOG EXPORT FILTERS
    # ================================

    async def list_syslog_export_filters(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of syslog export filters."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "syslog-export-filter", params=params)

    async def create_syslog_export_filter(self, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new syslog export filter."""
        return await self._make_request("POST", "syslog-export-filter", data=filter_data)

    async def get_syslog_export_filter_by_name(self, name: str) -> Dict[str, Any]:
        """Get a syslog export filter by name."""
        return await self._make_request("GET", f"syslog-export-filter/name/{name}")

    async def update_syslog_export_filter_by_name(self, name: str, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of a syslog export filter by name."""
        return await self._make_request("PATCH", f"syslog-export-filter/name/{name}", data=filter_data)

    async def replace_syslog_export_filter_by_name(self, name: str, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a syslog export filter by name."""
        return await self._make_request("PUT", f"syslog-export-filter/name/{name}", data=filter_data)

    async def delete_syslog_export_filter_by_name(self, name: str) -> Dict[str, Any]:
        """Delete a syslog export filter by name."""
        return await self._make_request("DELETE", f"syslog-export-filter/name/{name}")

    async def get_syslog_export_filter_by_id(self, syslog_export_filter_id: int) -> Dict[str, Any]:
        """Get a syslog export filter by numeric ID."""
        return await self._make_request("GET", f"syslog-export-filter/{syslog_export_filter_id}")

    async def update_syslog_export_filter_by_id(
        self,
        syslog_export_filter_id: int,
        filter_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a syslog export filter by numeric ID."""
        return await self._make_request(
            "PATCH", f"syslog-export-filter/{syslog_export_filter_id}", data=filter_data
        )

    async def replace_syslog_export_filter_by_id(
        self,
        syslog_export_filter_id: int,
        filter_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a syslog export filter by numeric ID."""
        return await self._make_request(
            "PUT", f"syslog-export-filter/{syslog_export_filter_id}", data=filter_data
        )

    async def delete_syslog_export_filter_by_id(self, syslog_export_filter_id: int) -> Dict[str, Any]:
        """Delete a syslog export filter by numeric ID."""
        return await self._make_request("DELETE", f"syslog-export-filter/{syslog_export_filter_id}")

    # ================================
    # SYSLOG TARGETS
    # ================================

    async def list_syslog_targets(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of syslog targets."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "syslog-target", params=params)

    async def create_syslog_target(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new syslog target."""
        return await self._make_request("POST", "syslog-target", data=target_data)

    async def get_syslog_target_by_host_address(self, host_address: str) -> Dict[str, Any]:
        """Get a syslog target by host address."""
        return await self._make_request("GET", f"syslog-target/host-address/{host_address}")

    async def update_syslog_target_by_host_address(
        self,
        host_address: str,
        target_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a syslog target by host address."""
        return await self._make_request(
            "PATCH", f"syslog-target/host-address/{host_address}", data=target_data
        )

    async def replace_syslog_target_by_host_address(
        self,
        host_address: str,
        target_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a syslog target by host address."""
        return await self._make_request(
            "PUT", f"syslog-target/host-address/{host_address}", data=target_data
        )

    async def delete_syslog_target_by_host_address(self, host_address: str) -> Dict[str, Any]:
        """Delete a syslog target by host address."""
        return await self._make_request("DELETE", f"syslog-target/host-address/{host_address}")

    async def get_syslog_target_by_id(self, syslog_target_id: int) -> Dict[str, Any]:
        """Get a syslog target by numeric ID."""
        return await self._make_request("GET", f"syslog-target/{syslog_target_id}")

    async def update_syslog_target_by_id(
        self,
        syslog_target_id: int,
        target_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a syslog target by numeric ID."""
        return await self._make_request("PATCH", f"syslog-target/{syslog_target_id}", data=target_data)

    async def replace_syslog_target_by_id(
        self,
        syslog_target_id: int,
        target_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a syslog target by numeric ID."""
        return await self._make_request("PUT", f"syslog-target/{syslog_target_id}", data=target_data)

    async def delete_syslog_target_by_id(self, syslog_target_id: int) -> Dict[str, Any]:
        """Delete a syslog target by numeric ID."""
        return await self._make_request("DELETE", f"syslog-target/{syslog_target_id}")
