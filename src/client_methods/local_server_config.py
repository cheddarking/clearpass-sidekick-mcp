"""
Mixin class for ClearPassClient to manage local server configuration API calls.
"""

from typing import Dict, Any, Optional, Union

class LocalServerConfigMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for local server configuration management.
    """

    async def get_server_access_control_settings(self, server_uuid: str) -> Dict[str, Any]:
        """Get all application access controls for a server."""
        return await self._make_request("GET", f"server/access-control/{server_uuid}")

    async def get_server_access_control_by_resource(self, server_uuid: str, resource_name: str) -> Dict[str, Any]:
        """Get an application access control by resource name."""
        return await self._make_request("GET", f"server/access-control/{server_uuid}/{resource_name}")

    async def update_server_access_control_by_resource(self, server_uuid: str, resource_name: str, access_control_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an application access control by resource name."""
        return await self._make_request("PUT", f"server/access-control/{server_uuid}/{resource_name}", data=access_control_data)

    async def delete_server_access_control_by_resource(self, server_uuid: str, resource_name: str) -> Dict[str, Any]:
        """Delete an application access control by resource name."""
        return await self._make_request("DELETE", f"server/access-control/{server_uuid}/{resource_name}")

    async def list_ad_domains(self, server_uuid: str) -> Dict[str, Any]:
        """Get a list of AD Domains for a server."""
        return await self._make_request("GET", f"ad-domain/{server_uuid}")

    async def get_ad_domain_details(self, server_uuid: str, netbios_name: str) -> Dict[str, Any]:
        """Get an AD domain by netbios_name."""
        return await self._make_request("GET", f"ad-domain/{server_uuid}/netbios-name/{netbios_name}")

    async def join_ad_domain(self, server_uuid: str, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Join AD Domain."""
        return await self._make_request("PUT", f"ad-domain/join/{server_uuid}", data=domain_data)

    async def leave_ad_domain(self, server_uuid: str, domain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Leave AD domain."""
        return await self._make_request("PUT", f"ad-domain/leave/{server_uuid}", data=domain_data)

    async def configure_ad_password_servers(self, server_uuid: str, password_servers_data: Dict[str, Any]) -> Dict[str, Any]:
        """Configure AD Password Servers."""
        return await self._make_request("PATCH", f"ad-domain/password-servers/{server_uuid}", data=password_servers_data)

    async def get_cppm_version(self) -> Dict[str, Any]:
        """Get ClearPass Policy Manager version."""
        return await self._make_request("GET", "cppm-version")

    async def get_cluster_servers(self) -> Dict[str, Any]:
        """Get list of cluster servers."""
        return await self._make_request("GET", "cluster/server")

    async def get_cluster_server_by_uuid(self, uuid: str) -> Dict[str, Any]:
        """Get cluster server details by UUID."""
        return await self._make_request("GET", f"cluster/server/{uuid}")

    async def update_cluster_server_by_uuid(self, uuid: str, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update cluster server configuration by UUID."""
        return await self._make_request("PATCH", f"cluster/server/{uuid}", data=server_data)

    async def get_server_fips_status(self) -> Dict[str, Any]:
        """Get server FIPS status."""
        return await self._make_request("GET", "server/fips")

    async def get_server_snmp_config(self, server_uuid: str) -> Dict[str, Any]:
        """Get server SNMP configuration."""
        return await self._make_request("GET", f"server/snmp/{server_uuid}")

    async def update_server_snmp_config(self, server_uuid: str, snmp_data: Dict[str, Any], replace: bool = False) -> Dict[str, Any]:
        """Update server SNMP configuration."""
        method = "PUT" if replace else "PATCH"
        return await self._make_request(method, f"server/snmp/{server_uuid}", data=snmp_data)

    async def get_server_version(self) -> Dict[str, Any]:
        """Get server version information."""
        return await self._make_request("GET", "server/version")

    async def get_service_parameters(self, server_uuid: str, service_id: str) -> Dict[str, Any]:
        """Get service parameters for a specific service."""
        return await self._make_request("GET", f"service-parameter/{server_uuid}/{service_id}")

    async def update_service_parameters(self, server_uuid: str, service_id: str, parameters_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update service parameters for a specific service."""
        return await self._make_request("PATCH", f"service-parameter/{server_uuid}/{service_id}", data=parameters_data)

    async def get_server_services(self, server_uuid: str) -> Dict[str, Any]:
        """Get list of services on a server."""
        return await self._make_request("GET", f"server/service/{server_uuid}")

    async def get_server_service_by_name(self, server_uuid: str, service_name: str) -> Dict[str, Any]:
        """Get specific service status by name."""
        return await self._make_request("GET", f"server/service/{server_uuid}/{service_name}")

    async def start_server_service(self, server_uuid: str, service_name: str) -> Dict[str, Any]:
        """Start a service on the server."""
        # data={} -- see run_insight_report_by_id: an omitted body with a JSON
        # Content-Type header is rejected as malformed JSON.
        return await self._make_request("PATCH", f"server/service/{server_uuid}/{service_name}/start", data={})

    async def stop_server_service(self, server_uuid: str, service_name: str) -> Dict[str, Any]:
        """Stop a service on the server."""
        # data={} -- see run_insight_report_by_id: an omitted body with a JSON
        # Content-Type header is rejected as malformed JSON.
        return await self._make_request("PATCH", f"server/service/{server_uuid}/{service_name}/stop", data={})