"""
MCP tools for Local Server Configuration management.
"""

import logging
from typing import Dict, List, Optional, Any, Union
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error, format_clarification_needed
from ..models.local_server_config import (
    ServerAccessControl,
    ADDomainJoin,
    ADDomainLeave,
    ADPasswordServersConfig,
    ServerSNMPConfig,
    ServiceParameter
)

logger = logging.getLogger(__name__)


@operation(domain="local_server_config")
async def list_cluster_servers(ctx: Context) -> Dict[str, Any]:
    """
    List the ClearPass cluster servers, with their UUIDs.

    This is the entry point for every operation in this domain that takes a
    `server_uuid` (server access control, AD domains, SNMP config, service
    parameters, service start/stop): without it there is no way for a caller to
    discover a valid UUID.

    Maps to 'get_cluster_server' in pyclearpass (GET cluster/server).
    """
    await ctx.info("Listing cluster servers...")
    try:
        client = await get_clearpass_client()
        response = await client.get_cluster_servers()

        # Unwrap by key presence, not truthiness, so an empty cluster listing
        # is not mistaken for an unrecognised envelope.
        if isinstance(response, list):
            servers = response
        elif isinstance(response, dict):
            embedded = response.get("_embedded")
            if isinstance(embedded, dict) and isinstance(embedded.get("items"), list):
                servers = embedded["items"]
            elif isinstance(embedded, list):
                servers = embedded
            elif isinstance(response.get("items"), list):
                servers = response["items"]
            elif response:
                servers = [response]
            else:
                servers = []
        else:
            servers = []

        return {
            "success": True,
            "cluster_servers": servers,
            "count": len(servers),
            "message": f"Retrieved {len(servers)} cluster server(s)."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list cluster servers: {e}")
        return await format_api_error(e, "list cluster servers")
    except Exception as e:
        logger.error(f"Unexpected error listing cluster servers: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_server_access_control_settings(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server")
) -> Dict[str, Any]:
    """
    Get all application access controls for a server.
    Maps to 'get_server_access_control_by_server_uuid' in pyclearpass.
    """
    await ctx.info(f"Getting server access control settings for server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        response = await client.get_server_access_control_settings(server_uuid)
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "access_controls": response,
            "message": "Server access control settings retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server access control settings: {e}")
        return await format_api_error(e, "get server access control settings")
    except Exception as e:
        logger.error(f"Unexpected error getting server access control settings: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_server_access_control_by_resource(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    resource_name: str = Field(..., description="Unique resource name of the access control")
) -> Dict[str, Any]:
    """
    Get an application access control by resource name.
    Maps to 'get_server_access_control_by_server_uuid_resource_name' in pyclearpass.
    """
    await ctx.info(f"Getting server access control for resource: {resource_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        response = await client.get_server_access_control_by_resource(server_uuid, resource_name)
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "resource_name": resource_name,
            "access_control": response,
            "message": "Server access control details retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server access control by resource: {e}")
        return await format_api_error(e, "get server access control by resource")
    except Exception as e:
        logger.error(f"Unexpected error getting server access control by resource: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def update_server_access_control_by_resource(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    resource_name: str = Field(..., description="Unique resource name of the access control"),
    access: str = Field(..., description="Access type of the Access control application (e.g., 'Allow', 'Deny')"),
    networks: List[str] = Field(..., description="List of hostname, IP address or subnet (CIDR) to be restricted")
) -> Dict[str, Any]:
    """
    Replace an application access control by resource name.
    Maps to 'replace_server_access_control_by_server_uuid_resource_name' in pyclearpass.
    """
    await ctx.info(f"Updating server access control for resource: {resource_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        access_control_data = ServerAccessControl(
            access=access,
            networks={"networks": networks},
            resource_name=resource_name
        )
        response = await client.update_server_access_control_by_resource(
            server_uuid, resource_name, access_control_data.model_dump(exclude_none=True, exclude={'resource_name'})
        )
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "resource_name": resource_name,
            "message": "Server access control updated successfully.",
            "updated_access_control": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update server access control: {e}")
        return await format_api_error(e, "update server access control")
    except Exception as e:
        logger.error(f"Unexpected error updating server access control: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def delete_server_access_control_by_resource(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    resource_name: str = Field(..., description="Unique resource name of the access control"),
    confirm: bool = Field(default=False, description="Confirm deletion (required for safety)")
) -> Dict[str, Any]:
    """
    Delete an application access control by resource name.
    Maps to 'delete_server_access_control_by_server_uuid_resource_name' in pyclearpass.
    """
    if not confirm:
        return await format_clarification_needed(
            message="Deletion requires confirmation as it's a destructive operation.",
            question=f"Are you sure you want to delete access control for resource '{resource_name}' on server '{server_uuid}'? Set 'confirm' to True to proceed."
        )

    await ctx.info(f"Deleting server access control for resource: {resource_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        await client.delete_server_access_control_by_resource(server_uuid, resource_name)
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "resource_name": resource_name,
            "message": "Server access control deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete server access control: {e}")
        return await format_api_error(e, "delete server access control")
    except Exception as e:
        logger.error(f"Unexpected error deleting server access control: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def list_ad_domains(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server")
) -> Dict[str, Any]:
    """
    Get a list of AD Domains for a server.
    Maps to 'get_ad_domain_by_server_uuid' in pyclearpass.
    """
    await ctx.info(f"Listing AD domains for server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        response = await client.list_ad_domains(server_uuid)
        
        # Handle response format - might be a direct list, an `_embedded`
        # envelope, or a bare `{"items": [...]}` envelope.
        #
        # `GET ad-domain/<uuid>` returns `{"items": []}` when the server has
        # joined no domains. Falling through to `[response]` there reported a
        # single AD domain that does not exist (count: 1), so every recognised
        # envelope shape is unwrapped explicitly and only a genuinely
        # unrecognised payload is wrapped as one item.
        if isinstance(response, list):
            domains = response
        elif isinstance(response, dict):
            embedded = response.get("_embedded")
            if isinstance(embedded, dict) and isinstance(embedded.get("items"), list):
                domains = embedded["items"]
            elif isinstance(embedded, list):
                domains = embedded
            elif isinstance(response.get("items"), list):
                domains = response["items"]
            elif response:
                domains = [response]
            else:
                domains = []
        else:
            domains = [response] if response else []

        return {
            "success": True,
            "server_uuid": server_uuid,
            "ad_domains": domains,
            "count": len(domains),
            "message": f"Retrieved {len(domains)} AD domains."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list AD domains: {e}")
        return await format_api_error(e, "list AD domains")
    except Exception as e:
        logger.error(f"Unexpected error listing AD domains: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_ad_domain_details(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    netbios_name: str = Field(..., description="NetBIOS name of the domain")
) -> Dict[str, Any]:
    """
    Get an AD domain by netbios_name.
    Maps to 'get_ad_domain_by_server_uuid_netbios_name_netbios_name' in pyclearpass.
    """
    await ctx.info(f"Getting AD domain details for NetBIOS name: {netbios_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        response = await client.get_ad_domain_details(server_uuid, netbios_name)
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "netbios_name": netbios_name,
            "ad_domain_details": response,
            "message": "AD domain details retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get AD domain details: {e}")
        return await format_api_error(e, "get AD domain details")
    except Exception as e:
        logger.error(f"Unexpected error getting AD domain details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def join_ad_domain(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    domain_controller: str = Field(..., description="FQDN of the domain controller"),
    netbios_name: str = Field(..., description="NetBIOS name of the domain"),
    username: str = Field(..., description="Domain username"),
    password: str = Field(..., description="Domain password"),
    on_name_conflict: int = Field(default=1, description="Action on controller name conflict (1-Use specified DC, 2-Use DNS returned DC, 3-Fail on conflict)")
) -> Dict[str, Any]:
    """
    Join AD Domain.
    Maps to 'replace_ad_domain_join_by_server_uuid' in pyclearpass.
    """
    await ctx.info(f"Joining AD domain {netbios_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        domain_data = ADDomainJoin(
            domain_controller=domain_controller,
            netbios_name=netbios_name,
            username=username,
            password=password,
            on_name_conflict=on_name_conflict
        )
        response = await client.join_ad_domain(server_uuid, domain_data.model_dump(exclude_none=True))
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "netbios_name": netbios_name,
            "message": "Successfully joined AD domain.",
            "join_result": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to join AD domain: {e}")
        return await format_api_error(e, "join AD domain")
    except Exception as e:
        logger.error(f"Unexpected error joining AD domain: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def leave_ad_domain(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    netbios_name: str = Field(..., description="NetBIOS name of the domain"),
    username: str = Field(..., description="Domain username"),
    password: str = Field(..., description="Domain password"),
    force_leave: bool = Field(default=False, description="Leave domain even if AD is down")
) -> Dict[str, Any]:
    """
    Leave AD domain.
    Maps to 'replace_ad_domain_leave_by_server_uuid' in pyclearpass.
    """
    await ctx.info(f"Leaving AD domain {netbios_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        domain_data = ADDomainLeave(
            netbios_name=netbios_name,
            username=username,
            password=password,
            force_leave=force_leave
        )
        response = await client.leave_ad_domain(server_uuid, domain_data.model_dump(exclude_none=True))
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "netbios_name": netbios_name,
            "message": "Successfully left AD domain.",
            "leave_result": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to leave AD domain: {e}")
        return await format_api_error(e, "leave AD domain")
    except Exception as e:
        logger.error(f"Unexpected error leaving AD domain: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def configure_ad_password_servers(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server"),
    netbios_name: str = Field(..., description="NetBIOS name of the domain"),
    password_servers: List[str] = Field(..., description="List of hostname or IP address of the AD password servers")
) -> Dict[str, Any]:
    """
    Configure AD Password Servers.
    Maps to 'update_ad_domain_password_servers_by_server_uuid' in pyclearpass.
    """
    await ctx.info(f"Configuring AD password servers for domain {netbios_name} on server: {server_uuid}")
    try:
        client = await get_clearpass_client()
        password_servers_data = ADPasswordServersConfig(
            netbios_name=netbios_name,
            password_servers=password_servers
        )
        response = await client.configure_ad_password_servers(
            server_uuid, password_servers_data.model_dump(exclude_none=True)
        )
        
        return {
            "success": True,
            "server_uuid": server_uuid,
            "netbios_name": netbios_name,
            "password_servers": password_servers,
            "message": "AD password servers configured successfully.",
            "configuration_result": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to configure AD password servers: {e}")
        return await format_api_error(e, "configure AD password servers")
    except Exception as e:
        logger.error(f"Unexpected error configuring AD password servers: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_cppm_version(ctx: Context) -> Dict[str, Any]:
    """
    Get ClearPass Policy Manager version.
    Maps to 'get_cppm_version' in pyclearpass.
    """
    await ctx.info("Getting ClearPass Policy Manager version")
    try:
        client = await get_clearpass_client()
        response = await client.get_cppm_version()
        
        return {
            "success": True,
            "version_info": response,
            "message": "ClearPass Policy Manager version retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get CPPM version: {e}")
        return await format_api_error(e, "get CPPM version")
    except Exception as e:
        logger.error(f"Unexpected error getting CPPM version: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_cluster_server_by_uuid(
    ctx: Context,
    uuid: str = Field(..., description="UUID of the server")
) -> Dict[str, Any]:
    """
    Get cluster server details by UUID.
    Maps to 'get_cluster_server_by_uuid' in pyclearpass.
    """
    await ctx.info(f"Getting cluster server details for UUID: {uuid}")
    try:
        client = await get_clearpass_client()
        response = await client.get_cluster_server_by_uuid(uuid)
        
        return {
            "success": True,
            "server_uuid": uuid,
            "server_details": response,
            "message": "Cluster server details retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get cluster server details: {e}")
        return await format_api_error(e, "get cluster server details")
    except Exception as e:
        logger.error(f"Unexpected error getting cluster server details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def update_cluster_server_by_uuid(
    ctx: Context,
    uuid: str = Field(..., description="UUID of the server"),
    server_data: Dict[str, Any] = Field(..., description="Server configuration data to update")
) -> Dict[str, Any]:
    """
    Update cluster server configuration by UUID.
    Maps to 'update_cluster_server_by_uuid' in pyclearpass.
    """
    await ctx.info(f"Updating cluster server configuration for UUID: {uuid}")
    try:
        client = await get_clearpass_client()
        response = await client.update_cluster_server_by_uuid(uuid, server_data)
        
        return {
            "success": True,
            "server_uuid": uuid,
            "message": "Cluster server configuration updated successfully.",
            "updated_server": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update cluster server: {e}")
        return await format_api_error(e, "update cluster server")
    except Exception as e:
        logger.error(f"Unexpected error updating cluster server: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_server_fips_status(ctx: Context) -> Dict[str, Any]:
    """
    Get server FIPS status.
    Maps to 'get_server_fips' in pyclearpass.
    """
    await ctx.info("Getting server FIPS status")
    try:
        client = await get_clearpass_client()
        response = await client.get_server_fips_status()
        
        return {
            "success": True,
            "fips_status": response,
            "message": "Server FIPS status retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server FIPS status: {e}")
        return await format_api_error(e, "get server FIPS status")
    except Exception as e:
        logger.error(f"Unexpected error getting server FIPS status: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="local_server_config")
async def get_server_version(ctx: Context) -> Dict[str, Any]:
    """
    Get server version information.
    Maps to 'get_server_version' in pyclearpass.
    """
    await ctx.info("Getting server version information")
    try:
        client = await get_clearpass_client()
        response = await client.get_server_version()
        
        return {
            "success": True,
            "version_info": response,
            "message": "Server version information retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server version: {e}")
        return await format_api_error(e, "get server version")
    except Exception as e:
        logger.error(f"Unexpected error getting server version: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."} 