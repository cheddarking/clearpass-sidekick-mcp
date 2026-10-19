"""
MCP tools for ClearPass Endpoint Visibility operations.

Covers the endpoint-visibility / posture surface of the ClearPass API:

- Agentless OnGuard settings and subnet mappings
- Network scan configuration (discovery and subnet scans)
- Device profiler fingerprints and the fingerprint dictionary
- OnGuard activity, custom scripts, settings and global settings
- OnGuard Policy Manager zones
- Profiler subnet mappings
- The Windows hotfix database used by posture policies
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


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


def _extract_items(response: Any) -> List[Dict[str, Any]]:
    """Pull the collection out of a ClearPass HAL list response."""
    if isinstance(response, dict):
        embedded = response.get("_embedded")
        if isinstance(embedded, dict) and isinstance(embedded.get("items"), list):
            return embedded["items"]
        if isinstance(response.get("items"), list):
            return response["items"]
    if isinstance(response, list):
        return response
    return []


# ============================================================================
# Agentless OnGuard Settings
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_agentless_onguard_settings(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get a list of Agentless OnGuard Settings.

    Returns the configured Agentless OnGuard settings on the ClearPass server.

    Maps to 'get_agentless_onguard_settings' in pyclearpass (GET /agentless-onguard/settings).
    """
    await ctx.info("Retrieving Agentless OnGuard settings...")

    try:
        client = await get_clearpass_client()
        response = await client.list_agentless_onguard_settings()

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "settings": items,
            "message": f"Retrieved {len(items)} Agentless OnGuard settings",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list agentless onguard settings: {e}")
        return await format_api_error(e, "list agentless onguard settings")
    except Exception as e:
        logger.error(f"Unexpected error during list agentless onguard settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list agentless onguard settings",
        }


@operation(domain="endpoint_visibility")
async def create_agentless_onguard_settings(
    ctx: Context,
    settings_data: Dict[str, Any] = Field(..., description="Required keys: name, client_os, working_dir, action, servers, download_url. Supported keys include: name, description, client_os, domain_account, ssh_account, working_dir, action, servers, download_url, validate_url_cert, override_checksum, checksums_32."),
) -> Dict[str, Any]:
    """
    Add an Agentless OnGuard Setting.

    Creates (or, for singleton settings resources, updates) the Agentless OnGuard setting.

    Body fields (settings_data):
        - name: Name of Agentless OnGuard Setting. Object Type: string
        - description: Description of Agentless OnGuard Setting. Object Type: string
        - client_os: Client OS type. Allowed Values: Windows, macOS and Linux. Object Type: string
        - domain_account: Name of domain account used to launch Agentless OnGuard on endpoints. Object Type: string
        - ssh_account: Name of ssh account used to launch Agentless OnGuard on endpoints. Object Type: string
        - working_dir: Full path of directory on endpoints where all files required to start Agentless OnGuard will be copied (e.g. C:OnGuard). Object Type: string
        - action: Action to be performed on endpoints. Object Type: string
        - servers: IP addresses or FQDN of ClearPass servers that Agentless OnGuard should use to read agent settings (e.g. ["hostname.example.com", "1.2.3.4"]). Object Type: array
        - download_url: HTTP/HTTPS URL to download Agentless OnGuardWrapper EXE from the Remote File Server (e.g. https://10.20.30.40/agent/AgentlessOnGuard/windows/AgentlessOnGuardWrapper.exe). Object Type: string
        - validate_url_cert: Should Agentless OnGuard Launcher validate the Server Certificate of the remote server while downloading Agentless OnGuardWrapper EXE? (default=true). Object Type: boolean
        - override_checksum: Override checksum fields (default=false). Object Type: boolean
        - checksums_32: SHA256 checksums of 32-bit Agentless OnGuard Wrapper EXEs. Object Type: array
        - checksums_64: SHA256 checksums of 64-bit Agentless OnGuard Wrapper EXEs. Object Type: array

    Maps to 'new_agentless_onguard_settings' in pyclearpass (POST /agentless-onguard/settings).
    """
    await ctx.info("Submitting Agentless OnGuard settings...")

    try:
        client = await get_clearpass_client()
        response = await client.create_agentless_onguard_settings(
            settings_data=settings_data,
        )

        return {
            "success": True,
            "setting": response,
            "message": "Saved Agentless OnGuard setting",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create agentless onguard settings: {e}")
        return await format_api_error(e, "create agentless onguard settings")
    except Exception as e:
        logger.error(f"Unexpected error during create agentless onguard settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create agentless onguard settings",
        }


@operation(domain="endpoint_visibility")
async def delete_agentless_onguard_settings_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard setting"),
) -> Dict[str, Any]:
    """
    Delete an Agentless OnGuard Setting by name.

    Permanently deletes the Agentless OnGuard setting. This cannot be undone.

    Maps to 'delete_agentless_onguard_settings_name_by_name' in pyclearpass (DELETE /agentless-onguard/settings/name/{name}).
    """
    await ctx.info(f"Deleting Agentless OnGuard setting {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_agentless_onguard_settings_by_name(
            name=name,
        )

        return {
            "success": True,
            "message": f"Deleted Agentless OnGuard setting {name}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete agentless onguard settings by name: {e}")
        return await format_api_error(e, "delete agentless onguard settings by name")
    except Exception as e:
        logger.error(f"Unexpected error during delete agentless onguard settings by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete agentless onguard settings by name",
        }


@operation(domain="endpoint_visibility")
async def get_agentless_onguard_settings_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard setting"),
) -> Dict[str, Any]:
    """
    Get an Agentless OnGuard Setting by name.

    Retrieves a single Agentless OnGuard setting.

    Maps to 'get_agentless_onguard_settings_name_by_name' in pyclearpass (GET /agentless-onguard/settings/name/{name}).
    """
    await ctx.info(f"Retrieving Agentless OnGuard setting {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_agentless_onguard_settings_by_name(
            name=name,
        )

        return {
            "success": True,
            "setting": response,
            "message": f"Retrieved Agentless OnGuard setting {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get agentless onguard settings by name: {e}")
        return await format_api_error(e, "get agentless onguard settings by name")
    except Exception as e:
        logger.error(f"Unexpected error during get agentless onguard settings by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get agentless onguard settings by name",
        }


@operation(domain="endpoint_visibility")
async def update_agentless_onguard_settings_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard setting"),
    settings_data: Dict[str, Any] = Field(..., description="Supported keys include: name, description, client_os, domain_account, ssh_account, working_dir, action, servers, download_url, validate_url_cert, override_checksum, checksums_32."),
) -> Dict[str, Any]:
    """
    Update some fields of an Agentless OnGuard Setting by name.

    Updates only the supplied fields of the Agentless OnGuard setting (HTTP PATCH).

    Body fields (settings_data):
        - name: Name of Agentless OnGuard Setting. Object Type: string
        - description: Description of Agentless OnGuard Setting. Object Type: string
        - client_os: Client OS type. Allowed Values: Windows, macOS and Linux. Object Type: string
        - domain_account: Name of domain account used to launch Agentless OnGuard on endpoints. Object Type: string
        - ssh_account: Name of ssh account used to launch Agentless OnGuard on endpoints. Object Type: string
        - working_dir: Full path of directory on endpoints where all files required to start Agentless OnGuard will be copied (e.g. C:OnGuard). Object Type: string
        - action: Action to be performed on endpoints. Object Type: string
        - servers: IP addresses or FQDN of ClearPass servers that Agentless OnGuard should use to read agent settings (e.g. ["hostname.example.com", "1.2.3.4"]). Object Type: array
        - download_url: HTTP/HTTPS URL to download Agentless OnGuardWrapper EXE from the Remote File Server (e.g. https://10.20.30.40/agent/AgentlessOnGuard/windows/AgentlessOnGuardWrapper.exe). Object Type: string
        - validate_url_cert: Should Agentless OnGuard Launcher validate the Server Certificate of the remote server while downloading Agentless OnGuardWrapper EXE? (default=true). Object Type: boolean
        - override_checksum: Override checksum fields (default=false). Object Type: boolean
        - checksums_32: SHA256 checksums of 32-bit Agentless OnGuard Wrapper EXEs. Object Type: array
        - checksums_64: SHA256 checksums of 64-bit Agentless OnGuard Wrapper EXEs. Object Type: array

    Maps to 'update_agentless_onguard_settings_name_by_name' in pyclearpass (PATCH /agentless-onguard/settings/name/{name}).
    """
    await ctx.info(f"Updating Agentless OnGuard setting {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_agentless_onguard_settings_by_name(
            name=name,
            settings_data=settings_data,
        )

        return {
            "success": True,
            "setting": response,
            "message": f"Updated Agentless OnGuard setting {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update agentless onguard settings by name: {e}")
        return await format_api_error(e, "update agentless onguard settings by name")
    except Exception as e:
        logger.error(f"Unexpected error during update agentless onguard settings by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update agentless onguard settings by name",
        }


@operation(domain="endpoint_visibility")
async def replace_agentless_onguard_settings_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard setting"),
    settings_data: Dict[str, Any] = Field(..., description="Required keys: name, client_os, working_dir, action, servers, download_url. Supported keys include: name, description, client_os, domain_account, ssh_account, working_dir, action, servers, download_url, validate_url_cert, override_checksum, checksums_32."),
) -> Dict[str, Any]:
    """
    Replace an Agentless OnGuard Setting by name.

    Replaces the whole Agentless OnGuard setting definition (HTTP PUT); omitted fields are reset.

    Body fields (settings_data):
        - name: Name of Agentless OnGuard Setting. Object Type: string
        - description: Description of Agentless OnGuard Setting. Object Type: string
        - client_os: Client OS type. Allowed Values: Windows, macOS and Linux. Object Type: string
        - domain_account: Name of domain account used to launch Agentless OnGuard on endpoints. Object Type: string
        - ssh_account: Name of ssh account used to launch Agentless OnGuard on endpoints. Object Type: string
        - working_dir: Full path of directory on endpoints where all files required to start Agentless OnGuard will be copied (e.g. C:OnGuard). Object Type: string
        - action: Action to be performed on endpoints. Object Type: string
        - servers: IP addresses or FQDN of ClearPass servers that Agentless OnGuard should use to read agent settings (e.g. ["hostname.example.com", "1.2.3.4"]). Object Type: array
        - download_url: HTTP/HTTPS URL to download Agentless OnGuardWrapper EXE from the Remote File Server (e.g. https://10.20.30.40/agent/AgentlessOnGuard/windows/AgentlessOnGuardWrapper.exe). Object Type: string
        - validate_url_cert: Should Agentless OnGuard Launcher validate the Server Certificate of the remote server while downloading Agentless OnGuardWrapper EXE? (default=true). Object Type: boolean
        - override_checksum: Override checksum fields (default=false). Object Type: boolean
        - checksums_32: SHA256 checksums of 32-bit Agentless OnGuard Wrapper EXEs. Object Type: array
        - checksums_64: SHA256 checksums of 64-bit Agentless OnGuard Wrapper EXEs. Object Type: array

    Maps to 'replace_agentless_onguard_settings_name_by_name' in pyclearpass (PUT /agentless-onguard/settings/name/{name}).
    """
    await ctx.info(f"Replacing Agentless OnGuard setting {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_agentless_onguard_settings_by_name(
            name=name,
            settings_data=settings_data,
        )

        return {
            "success": True,
            "setting": response,
            "message": f"Replaced Agentless OnGuard setting {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace agentless onguard settings by name: {e}")
        return await format_api_error(e, "replace agentless onguard settings by name")
    except Exception as e:
        logger.error(f"Unexpected error during replace agentless onguard settings by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace agentless onguard settings by name",
        }


@operation(domain="endpoint_visibility")
async def delete_agentless_onguard_settings_by_id(
    ctx: Context,
    settings_id: int = Field(..., description="Numeric ID of the Agentless OnGuard setting"),
) -> Dict[str, Any]:
    """
    Delete an Agentless OnGuard Setting.

    Permanently deletes the Agentless OnGuard setting. This cannot be undone.

    Maps to 'delete_agentless_onguard_settings_by_settings_id' in pyclearpass (DELETE /agentless-onguard/settings/{settings_id}).
    """
    await ctx.info(f"Deleting Agentless OnGuard setting {settings_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_agentless_onguard_settings_by_id(
            settings_id=settings_id,
        )

        return {
            "success": True,
            "message": f"Deleted Agentless OnGuard setting {settings_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete agentless onguard settings by id: {e}")
        return await format_api_error(e, "delete agentless onguard settings by id")
    except Exception as e:
        logger.error(f"Unexpected error during delete agentless onguard settings by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete agentless onguard settings by id",
        }


@operation(domain="endpoint_visibility")
async def get_agentless_onguard_settings_by_id(
    ctx: Context,
    settings_id: int = Field(..., description="Numeric ID of the Agentless OnGuard setting"),
) -> Dict[str, Any]:
    """
    Get an Agentless OnGuard Setting.

    Retrieves a single Agentless OnGuard setting.

    Maps to 'get_agentless_onguard_settings_by_settings_id' in pyclearpass (GET /agentless-onguard/settings/{settings_id}).
    """
    await ctx.info(f"Retrieving Agentless OnGuard setting {settings_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_agentless_onguard_settings_by_id(
            settings_id=settings_id,
        )

        return {
            "success": True,
            "setting": response,
            "message": f"Retrieved Agentless OnGuard setting {settings_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get agentless onguard settings by id: {e}")
        return await format_api_error(e, "get agentless onguard settings by id")
    except Exception as e:
        logger.error(f"Unexpected error during get agentless onguard settings by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get agentless onguard settings by id",
        }


@operation(domain="endpoint_visibility")
async def update_agentless_onguard_settings_by_id(
    ctx: Context,
    settings_id: int = Field(..., description="Numeric ID of the Agentless OnGuard setting"),
    settings_data: Dict[str, Any] = Field(..., description="Supported keys include: name, description, client_os, domain_account, ssh_account, working_dir, action, servers, download_url, validate_url_cert, override_checksum, checksums_32."),
) -> Dict[str, Any]:
    """
    Update some fields of an Agentless OnGuard Setting.

    Updates only the supplied fields of the Agentless OnGuard setting (HTTP PATCH).

    Body fields (settings_data):
        - name: Name of Agentless OnGuard Setting. Object Type: string
        - description: Description of Agentless OnGuard Setting. Object Type: string
        - client_os: Client OS type. Allowed Values: Windows, macOS and Linux. Object Type: string
        - domain_account: Name of domain account used to launch Agentless OnGuard on endpoints. Object Type: string
        - ssh_account: Name of ssh account used to launch Agentless OnGuard on endpoints. Object Type: string
        - working_dir: Full path of directory on endpoints where all files required to start Agentless OnGuard will be copied (e.g. C:OnGuard). Object Type: string
        - action: Action to be performed on endpoints. Object Type: string
        - servers: IP addresses or FQDN of ClearPass servers that Agentless OnGuard should use to read agent settings (e.g. ["hostname.example.com", "1.2.3.4"]). Object Type: array
        - download_url: HTTP/HTTPS URL to download Agentless OnGuardWrapper EXE from the Remote File Server (e.g. https://10.20.30.40/agent/AgentlessOnGuard/windows/AgentlessOnGuardWrapper.exe). Object Type: string
        - validate_url_cert: Should Agentless OnGuard Launcher validate the Server Certificate of the remote server while downloading Agentless OnGuardWrapper EXE? (default=true). Object Type: boolean
        - override_checksum: Override checksum fields (default=false). Object Type: boolean
        - checksums_32: SHA256 checksums of 32-bit Agentless OnGuard Wrapper EXEs. Object Type: array
        - checksums_64: SHA256 checksums of 64-bit Agentless OnGuard Wrapper EXEs. Object Type: array

    Maps to 'update_agentless_onguard_settings_by_settings_id' in pyclearpass (PATCH /agentless-onguard/settings/{settings_id}).
    """
    await ctx.info(f"Updating Agentless OnGuard setting {settings_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_agentless_onguard_settings_by_id(
            settings_id=settings_id,
            settings_data=settings_data,
        )

        return {
            "success": True,
            "setting": response,
            "message": f"Updated Agentless OnGuard setting {settings_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update agentless onguard settings by id: {e}")
        return await format_api_error(e, "update agentless onguard settings by id")
    except Exception as e:
        logger.error(f"Unexpected error during update agentless onguard settings by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update agentless onguard settings by id",
        }


@operation(domain="endpoint_visibility")
async def replace_agentless_onguard_settings_by_id(
    ctx: Context,
    settings_id: int = Field(..., description="Numeric ID of the Agentless OnGuard setting"),
    settings_data: Dict[str, Any] = Field(..., description="Required keys: name, client_os, working_dir, action, servers, download_url. Supported keys include: name, description, client_os, domain_account, ssh_account, working_dir, action, servers, download_url, validate_url_cert, override_checksum, checksums_32."),
) -> Dict[str, Any]:
    """
    Replace an Agentless OnGuard Setting.

    Replaces the whole Agentless OnGuard setting definition (HTTP PUT); omitted fields are reset.

    Body fields (settings_data):
        - name: Name of Agentless OnGuard Setting. Object Type: string
        - description: Description of Agentless OnGuard Setting. Object Type: string
        - client_os: Client OS type. Allowed Values: Windows, macOS and Linux. Object Type: string
        - domain_account: Name of domain account used to launch Agentless OnGuard on endpoints. Object Type: string
        - ssh_account: Name of ssh account used to launch Agentless OnGuard on endpoints. Object Type: string
        - working_dir: Full path of directory on endpoints where all files required to start Agentless OnGuard will be copied (e.g. C:OnGuard). Object Type: string
        - action: Action to be performed on endpoints. Object Type: string
        - servers: IP addresses or FQDN of ClearPass servers that Agentless OnGuard should use to read agent settings (e.g. ["hostname.example.com", "1.2.3.4"]). Object Type: array
        - download_url: HTTP/HTTPS URL to download Agentless OnGuardWrapper EXE from the Remote File Server (e.g. https://10.20.30.40/agent/AgentlessOnGuard/windows/AgentlessOnGuardWrapper.exe). Object Type: string
        - validate_url_cert: Should Agentless OnGuard Launcher validate the Server Certificate of the remote server while downloading Agentless OnGuardWrapper EXE? (default=true). Object Type: boolean
        - override_checksum: Override checksum fields (default=false). Object Type: boolean
        - checksums_32: SHA256 checksums of 32-bit Agentless OnGuard Wrapper EXEs. Object Type: array
        - checksums_64: SHA256 checksums of 64-bit Agentless OnGuard Wrapper EXEs. Object Type: array

    Maps to 'replace_agentless_onguard_settings_by_settings_id' in pyclearpass (PUT /agentless-onguard/settings/{settings_id}).
    """
    await ctx.info(f"Replacing Agentless OnGuard setting {settings_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_agentless_onguard_settings_by_id(
            settings_id=settings_id,
            settings_data=settings_data,
        )

        return {
            "success": True,
            "setting": response,
            "message": f"Replaced Agentless OnGuard setting {settings_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace agentless onguard settings by id: {e}")
        return await format_api_error(e, "replace agentless onguard settings by id")
    except Exception as e:
        logger.error(f"Unexpected error during replace agentless onguard settings by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace agentless onguard settings by id",
        }


# ============================================================================
# Agentless OnGuard Subnet Mappings
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_agentless_onguard_subnet_mappings(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"corp\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    Get a list of subnet mappings.

    Returns the configured Agentless OnGuard subnet mappings on the ClearPass server.

    Maps to 'get_agentless_onguard_subnet_mapping' in pyclearpass (GET /agentless-onguard/subnet-mapping).
    """
    await ctx.info("Retrieving Agentless OnGuard subnet mappings...")

    try:
        client = await get_clearpass_client()
        response = await client.list_agentless_onguard_subnet_mappings(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "subnet_mappings": items,
            "message": f"Retrieved {len(items)} Agentless OnGuard subnet mappings",
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "has_more": len(items) == limit if limit else False,
            },
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list agentless onguard subnet mappings: {e}")
        return await format_api_error(e, "list agentless onguard subnet mappings")
    except Exception as e:
        logger.error(f"Unexpected error during list agentless onguard subnet mappings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list agentless onguard subnet mappings",
        }


@operation(domain="endpoint_visibility")
async def create_agentless_onguard_subnet_mapping(
    ctx: Context,
    mapping_data: Dict[str, Any] = Field(..., description="Required keys: name, client_subnets, zone, client_scan_setting. Supported keys include: name, client_subnets, zone, agentless_onguard_setting_windows, agentless_onguard_setting_macOS, agentless_onguard_setting_linux, client_scan_setting, enabled."),
) -> Dict[str, Any]:
    """
    Add a subnet mapping.

    Creates (or, for singleton settings resources, updates) the Agentless OnGuard subnet mapping.

    Body fields (mapping_data):
        - name: Name of Agentless OnGuard Subnet Mapping. Object Type: string
        - client_subnets: IP subnets used for selecting clients. Object Type: array
        - zone: Name of Policy Manager Zone for which the specified client subnet is applicable. Object Type: string
        - agentless_onguard_setting_windows: Name of Agentless OnGuard setting for Windows for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_macOS: Name of Agentless OnGuard setting for macOS for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_linux: Name of Agentless OnGuard setting for Linux for the specified subnet and zone. To unset, use empty string. Object Type: string
        - client_scan_setting: Clients to be scanned in the subnet. Object Type: string
        - enabled: Enable Clearpass server to process clients in the subnet and run Agentless OnGuard (default=true). Object Type: boolean

    Maps to 'new_agentless_onguard_subnet_mapping' in pyclearpass (POST /agentless-onguard/subnet-mapping).
    """
    await ctx.info("Submitting Agentless OnGuard subnet mappings...")

    try:
        client = await get_clearpass_client()
        response = await client.create_agentless_onguard_subnet_mapping(
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": "Saved Agentless OnGuard subnet mapping",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create agentless onguard subnet mapping: {e}")
        return await format_api_error(e, "create agentless onguard subnet mapping")
    except Exception as e:
        logger.error(f"Unexpected error during create agentless onguard subnet mapping: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create agentless onguard subnet mapping",
        }


@operation(domain="endpoint_visibility")
async def delete_agentless_onguard_subnet_mapping_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Delete a subnet mapping by name.

    Permanently deletes the Agentless OnGuard subnet mapping. This cannot be undone.

    Maps to 'delete_agentless_onguard_subnet_mapping_name_by_name' in pyclearpass (DELETE /agentless-onguard/subnet-mapping/name/{name}).
    """
    await ctx.info(f"Deleting Agentless OnGuard subnet mapping {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_agentless_onguard_subnet_mapping_by_name(
            name=name,
        )

        return {
            "success": True,
            "message": f"Deleted Agentless OnGuard subnet mapping {name}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete agentless onguard subnet mapping by name: {e}")
        return await format_api_error(e, "delete agentless onguard subnet mapping by name")
    except Exception as e:
        logger.error(f"Unexpected error during delete agentless onguard subnet mapping by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete agentless onguard subnet mapping by name",
        }


@operation(domain="endpoint_visibility")
async def get_agentless_onguard_subnet_mapping_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Get a subnet mapping by name.

    Retrieves a single Agentless OnGuard subnet mapping.

    Maps to 'get_agentless_onguard_subnet_mapping_name_by_name' in pyclearpass (GET /agentless-onguard/subnet-mapping/name/{name}).
    """
    await ctx.info(f"Retrieving Agentless OnGuard subnet mapping {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_agentless_onguard_subnet_mapping_by_name(
            name=name,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Retrieved Agentless OnGuard subnet mapping {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get agentless onguard subnet mapping by name: {e}")
        return await format_api_error(e, "get agentless onguard subnet mapping by name")
    except Exception as e:
        logger.error(f"Unexpected error during get agentless onguard subnet mapping by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get agentless onguard subnet mapping by name",
        }


@operation(domain="endpoint_visibility")
async def update_agentless_onguard_subnet_mapping_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard subnet mapping"),
    mapping_data: Dict[str, Any] = Field(..., description="Supported keys include: name, client_subnets, zone, agentless_onguard_setting_windows, agentless_onguard_setting_macOS, agentless_onguard_setting_linux, client_scan_setting, enabled."),
) -> Dict[str, Any]:
    """
    Update some fields of a subnet mapping by name.

    Updates only the supplied fields of the Agentless OnGuard subnet mapping (HTTP PATCH).

    Body fields (mapping_data):
        - name: Name of Agentless OnGuard Subnet Mapping. Object Type: string
        - client_subnets: IP subnets used for selecting clients. Object Type: array
        - zone: Name of Policy Manager Zone for which the specified client subnet is applicable. Object Type: string
        - agentless_onguard_setting_windows: Name of Agentless OnGuard setting for Windows for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_macOS: Name of Agentless OnGuard setting for macOS for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_linux: Name of Agentless OnGuard setting for Linux for the specified subnet and zone. To unset, use empty string. Object Type: string
        - client_scan_setting: Clients to be scanned in the subnet. Object Type: string
        - enabled: Enable Clearpass server to process clients in the subnet and run Agentless OnGuard (default=true). Object Type: boolean

    Maps to 'update_agentless_onguard_subnet_mapping_name_by_name' in pyclearpass (PATCH /agentless-onguard/subnet-mapping/name/{name}).
    """
    await ctx.info(f"Updating Agentless OnGuard subnet mapping {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_agentless_onguard_subnet_mapping_by_name(
            name=name,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Updated Agentless OnGuard subnet mapping {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update agentless onguard subnet mapping by name: {e}")
        return await format_api_error(e, "update agentless onguard subnet mapping by name")
    except Exception as e:
        logger.error(f"Unexpected error during update agentless onguard subnet mapping by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update agentless onguard subnet mapping by name",
        }


@operation(domain="endpoint_visibility")
async def replace_agentless_onguard_subnet_mapping_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard subnet mapping"),
    mapping_data: Dict[str, Any] = Field(..., description="Required keys: name, client_subnets, zone, client_scan_setting. Supported keys include: name, client_subnets, zone, agentless_onguard_setting_windows, agentless_onguard_setting_macOS, agentless_onguard_setting_linux, client_scan_setting, enabled."),
) -> Dict[str, Any]:
    """
    Replace a subnet mapping by name.

    Replaces the whole Agentless OnGuard subnet mapping definition (HTTP PUT); omitted fields are reset.

    Body fields (mapping_data):
        - name: Name of Agentless OnGuard Subnet Mapping. Object Type: string
        - client_subnets: IP subnets used for selecting clients. Object Type: array
        - zone: Name of Policy Manager Zone for which the specified client subnet is applicable. Object Type: string
        - agentless_onguard_setting_windows: Name of Agentless OnGuard setting for Windows for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_macOS: Name of Agentless OnGuard setting for macOS for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_linux: Name of Agentless OnGuard setting for Linux for the specified subnet and zone. To unset, use empty string. Object Type: string
        - client_scan_setting: Clients to be scanned in the subnet. Object Type: string
        - enabled: Enable Clearpass server to process clients in the subnet and run Agentless OnGuard (default=true). Object Type: boolean

    Maps to 'replace_agentless_onguard_subnet_mapping_name_by_name' in pyclearpass (PUT /agentless-onguard/subnet-mapping/name/{name}).
    """
    await ctx.info(f"Replacing Agentless OnGuard subnet mapping {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_agentless_onguard_subnet_mapping_by_name(
            name=name,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Replaced Agentless OnGuard subnet mapping {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace agentless onguard subnet mapping by name: {e}")
        return await format_api_error(e, "replace agentless onguard subnet mapping by name")
    except Exception as e:
        logger.error(f"Unexpected error during replace agentless onguard subnet mapping by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace agentless onguard subnet mapping by name",
        }


@operation(domain="endpoint_visibility")
async def disable_agentless_onguard_subnet_mapping_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Disable Agentless OnGuard Settings on client subnets by subnet mapping name.

    Disables the Agentless OnGuard subnet mapping without deleting it.

    Maps to 'update_agentless_onguard_subnet_mapping_name_by_name_disable' in pyclearpass (PATCH /agentless-onguard/subnet-mapping/name/{name}/disable).
    """
    await ctx.info(f"Disabling Agentless OnGuard subnet mapping {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.disable_agentless_onguard_subnet_mapping_by_name(
            name=name,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Disabled Agentless OnGuard subnet mapping {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to disable agentless onguard subnet mapping by name: {e}")
        return await format_api_error(e, "disable agentless onguard subnet mapping by name")
    except Exception as e:
        logger.error(f"Unexpected error during disable agentless onguard subnet mapping by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to disable agentless onguard subnet mapping by name",
        }


@operation(domain="endpoint_visibility")
async def enable_agentless_onguard_subnet_mapping_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Enable Agentless OnGuard Settings on client subnets by subnet mapping name.

    Enables the Agentless OnGuard subnet mapping so that it becomes active.

    Maps to 'update_agentless_onguard_subnet_mapping_name_by_name_enable' in pyclearpass (PATCH /agentless-onguard/subnet-mapping/name/{name}/enable).
    """
    await ctx.info(f"Enabling Agentless OnGuard subnet mapping {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.enable_agentless_onguard_subnet_mapping_by_name(
            name=name,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Enabled Agentless OnGuard subnet mapping {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to enable agentless onguard subnet mapping by name: {e}")
        return await format_api_error(e, "enable agentless onguard subnet mapping by name")
    except Exception as e:
        logger.error(f"Unexpected error during enable agentless onguard subnet mapping by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to enable agentless onguard subnet mapping by name",
        }


@operation(domain="endpoint_visibility")
async def delete_agentless_onguard_subnet_mapping_by_id(
    ctx: Context,
    subnet_mapping_id: int = Field(..., description="Numeric ID of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Delete a subnet mapping.

    Permanently deletes the Agentless OnGuard subnet mapping. This cannot be undone.

    Maps to 'delete_agentless_onguard_subnet_mapping_by_subnet_mapping_id' in pyclearpass (DELETE /agentless-onguard/subnet-mapping/{subnet_mapping_id}).
    """
    await ctx.info(f"Deleting Agentless OnGuard subnet mapping {subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_agentless_onguard_subnet_mapping_by_id(
            subnet_mapping_id=subnet_mapping_id,
        )

        return {
            "success": True,
            "message": f"Deleted Agentless OnGuard subnet mapping {subnet_mapping_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete agentless onguard subnet mapping by id: {e}")
        return await format_api_error(e, "delete agentless onguard subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during delete agentless onguard subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete agentless onguard subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def get_agentless_onguard_subnet_mapping_by_id(
    ctx: Context,
    subnet_mapping_id: int = Field(..., description="Numeric ID of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Get a subnet mapping.

    Retrieves a single Agentless OnGuard subnet mapping.

    Maps to 'get_agentless_onguard_subnet_mapping_by_subnet_mapping_id' in pyclearpass (GET /agentless-onguard/subnet-mapping/{subnet_mapping_id}).
    """
    await ctx.info(f"Retrieving Agentless OnGuard subnet mapping {subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_agentless_onguard_subnet_mapping_by_id(
            subnet_mapping_id=subnet_mapping_id,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Retrieved Agentless OnGuard subnet mapping {subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get agentless onguard subnet mapping by id: {e}")
        return await format_api_error(e, "get agentless onguard subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during get agentless onguard subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get agentless onguard subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def update_agentless_onguard_subnet_mapping_by_id(
    ctx: Context,
    subnet_mapping_id: int = Field(..., description="Numeric ID of the Agentless OnGuard subnet mapping"),
    mapping_data: Dict[str, Any] = Field(..., description="Supported keys include: name, client_subnets, zone, agentless_onguard_setting_windows, agentless_onguard_setting_macOS, agentless_onguard_setting_linux, client_scan_setting, enabled."),
) -> Dict[str, Any]:
    """
    Update some fields of a subnet mapping.

    Updates only the supplied fields of the Agentless OnGuard subnet mapping (HTTP PATCH).

    Body fields (mapping_data):
        - name: Name of Agentless OnGuard Subnet Mapping. Object Type: string
        - client_subnets: IP subnets used for selecting clients. Object Type: array
        - zone: Name of Policy Manager Zone for which the specified client subnet is applicable. Object Type: string
        - agentless_onguard_setting_windows: Name of Agentless OnGuard setting for Windows for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_macOS: Name of Agentless OnGuard setting for macOS for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_linux: Name of Agentless OnGuard setting for Linux for the specified subnet and zone. To unset, use empty string. Object Type: string
        - client_scan_setting: Clients to be scanned in the subnet. Object Type: string
        - enabled: Enable Clearpass server to process clients in the subnet and run Agentless OnGuard (default=true). Object Type: boolean

    Maps to 'update_agentless_onguard_subnet_mapping_by_subnet_mapping_id' in pyclearpass (PATCH /agentless-onguard/subnet-mapping/{subnet_mapping_id}).
    """
    await ctx.info(f"Updating Agentless OnGuard subnet mapping {subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_agentless_onguard_subnet_mapping_by_id(
            subnet_mapping_id=subnet_mapping_id,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Updated Agentless OnGuard subnet mapping {subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update agentless onguard subnet mapping by id: {e}")
        return await format_api_error(e, "update agentless onguard subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during update agentless onguard subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update agentless onguard subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def replace_agentless_onguard_subnet_mapping_by_id(
    ctx: Context,
    subnet_mapping_id: int = Field(..., description="Numeric ID of the Agentless OnGuard subnet mapping"),
    mapping_data: Dict[str, Any] = Field(..., description="Required keys: name, client_subnets, zone, client_scan_setting. Supported keys include: name, client_subnets, zone, agentless_onguard_setting_windows, agentless_onguard_setting_macOS, agentless_onguard_setting_linux, client_scan_setting, enabled."),
) -> Dict[str, Any]:
    """
    Replace a subnet mapping.

    Replaces the whole Agentless OnGuard subnet mapping definition (HTTP PUT); omitted fields are reset.

    Body fields (mapping_data):
        - name: Name of Agentless OnGuard Subnet Mapping. Object Type: string
        - client_subnets: IP subnets used for selecting clients. Object Type: array
        - zone: Name of Policy Manager Zone for which the specified client subnet is applicable. Object Type: string
        - agentless_onguard_setting_windows: Name of Agentless OnGuard setting for Windows for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_macOS: Name of Agentless OnGuard setting for macOS for the specified subnet and zone. To unset, use empty string. Object Type: string
        - agentless_onguard_setting_linux: Name of Agentless OnGuard setting for Linux for the specified subnet and zone. To unset, use empty string. Object Type: string
        - client_scan_setting: Clients to be scanned in the subnet. Object Type: string
        - enabled: Enable Clearpass server to process clients in the subnet and run Agentless OnGuard (default=true). Object Type: boolean

    Maps to 'replace_agentless_onguard_subnet_mapping_by_subnet_mapping_id' in pyclearpass (PUT /agentless-onguard/subnet-mapping/{subnet_mapping_id}).
    """
    await ctx.info(f"Replacing Agentless OnGuard subnet mapping {subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_agentless_onguard_subnet_mapping_by_id(
            subnet_mapping_id=subnet_mapping_id,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Replaced Agentless OnGuard subnet mapping {subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace agentless onguard subnet mapping by id: {e}")
        return await format_api_error(e, "replace agentless onguard subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during replace agentless onguard subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace agentless onguard subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def disable_agentless_onguard_subnet_mapping_by_id(
    ctx: Context,
    subnet_mapping_id: int = Field(..., description="Numeric ID of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Disable Agentless OnGuard Settings on client subnets.

    Disables the Agentless OnGuard subnet mapping without deleting it.

    Maps to 'update_agentless_onguard_subnet_mapping_by_subnet_mapping_id_disable' in pyclearpass (PATCH /agentless-onguard/subnet-mapping/{subnet_mapping_id}/disable).
    """
    await ctx.info(f"Disabling Agentless OnGuard subnet mapping {subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.disable_agentless_onguard_subnet_mapping_by_id(
            subnet_mapping_id=subnet_mapping_id,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Disabled Agentless OnGuard subnet mapping {subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to disable agentless onguard subnet mapping by id: {e}")
        return await format_api_error(e, "disable agentless onguard subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during disable agentless onguard subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to disable agentless onguard subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def enable_agentless_onguard_subnet_mapping_by_id(
    ctx: Context,
    subnet_mapping_id: int = Field(..., description="Numeric ID of the Agentless OnGuard subnet mapping"),
) -> Dict[str, Any]:
    """
    Enable Agentless OnGuard Settings on client subnets.

    Enables the Agentless OnGuard subnet mapping so that it becomes active.

    Maps to 'update_agentless_onguard_subnet_mapping_by_subnet_mapping_id_enable' in pyclearpass (PATCH /agentless-onguard/subnet-mapping/{subnet_mapping_id}/enable).
    """
    await ctx.info(f"Enabling Agentless OnGuard subnet mapping {subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.enable_agentless_onguard_subnet_mapping_by_id(
            subnet_mapping_id=subnet_mapping_id,
        )

        return {
            "success": True,
            "subnet_mapping": response,
            "message": f"Enabled Agentless OnGuard subnet mapping {subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to enable agentless onguard subnet mapping by id: {e}")
        return await format_api_error(e, "enable agentless onguard subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during enable agentless onguard subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to enable agentless onguard subnet mapping by id",
        }


# ============================================================================
# Network Scan Configuration
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_network_scans(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"corp\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    Get a list of NetworkScan.

    Returns the configured network scans on the ClearPass server.

    Maps to 'get_config_network_scan' in pyclearpass (GET /config/network-scan).
    """
    await ctx.info("Retrieving network scans...")

    try:
        client = await get_clearpass_client()
        response = await client.list_network_scans(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "network_scans": items,
            "message": f"Retrieved {len(items)} network scans",
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "has_more": len(items) == limit if limit else False,
            },
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list network scans: {e}")
        return await format_api_error(e, "list network scans")
    except Exception as e:
        logger.error(f"Unexpected error during list network scans: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list network scans",
        }


@operation(domain="endpoint_visibility")
async def create_network_scan(
    ctx: Context,
    scan_data: Dict[str, Any] = Field(..., description="Required keys: type, zone, seed_device_or_ip_subnet, scan_frequency. Supported keys include: zone, type, seed_device_or_ip_subnet, scan_frequency, start_time, interval, day_of_week, depth, probe_arp, enabled."),
) -> Dict[str, Any]:
    """
    Add a NetworkScan.

    Creates (or, for singleton settings resources, updates) the network scan.

    Body fields (scan_data):
        - zone: Zone for the Network Scan. Object Type: string
        - type: Type of the Network Scan. Object Type: string
        - seed_device_or_ip_subnet: Network IP for DISCOVERY (e.g. ["hostname.example.com", "1.2.3.4"]) or IP Subnets for SUBNET (e.g. ["10.1.0.0/16"]) Network Scan. Object Type: string
        - scan_frequency: Frequency of Network Scan. Object Type: string
        - start_time: Start time (HH:MM) of Network Scan  (e.g. ["10:40", "23:20"]). Object Type: string
        - interval: Interval in hours (3 - 350) for HOURLY Network Scan. Object Type: integer
        - day_of_week: Day of Week for WEEKLY Network Scan. Object Type: string
        - depth: Depth level for DISCOVERY Network Scan. Object Type: integer
        - probe_arp: Probe all ARP entries found (default=false for type="DISCOVERY", not applicable for type="SUBNET"). Object Type: boolean
        - enabled: Is Network Scan enabled? (default=true). Object Type: boolean

    Maps to 'new_config_network_scan' in pyclearpass (POST /config/network-scan).
    """
    await ctx.info("Submitting network scans...")

    try:
        client = await get_clearpass_client()
        response = await client.create_network_scan(
            scan_data=scan_data,
        )

        return {
            "success": True,
            "network_scan": response,
            "message": "Saved network scan",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create network scan: {e}")
        return await format_api_error(e, "create network scan")
    except Exception as e:
        logger.error(f"Unexpected error during create network scan: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create network scan",
        }


@operation(domain="endpoint_visibility")
async def delete_network_scan_by_id(
    ctx: Context,
    scan_id: int = Field(..., description="Numeric ID of the network scan"),
) -> Dict[str, Any]:
    """
    Delete a NetworkScan.

    Permanently deletes the network scan. This cannot be undone.

    Maps to 'delete_config_network_scan_by_scan_id' in pyclearpass (DELETE /config/network-scan/{scan_id}).
    """
    await ctx.info(f"Deleting network scan {scan_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_network_scan_by_id(
            scan_id=scan_id,
        )

        return {
            "success": True,
            "message": f"Deleted network scan {scan_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete network scan by id: {e}")
        return await format_api_error(e, "delete network scan by id")
    except Exception as e:
        logger.error(f"Unexpected error during delete network scan by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete network scan by id",
        }


@operation(domain="endpoint_visibility")
async def get_network_scan_by_id(
    ctx: Context,
    scan_id: int = Field(..., description="Numeric ID of the network scan"),
) -> Dict[str, Any]:
    """
    Get a NetworkScan.

    Retrieves a single network scan.

    Maps to 'get_config_network_scan_by_scan_id' in pyclearpass (GET /config/network-scan/{scan_id}).
    """
    await ctx.info(f"Retrieving network scan {scan_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_network_scan_by_id(
            scan_id=scan_id,
        )

        return {
            "success": True,
            "network_scan": response,
            "message": f"Retrieved network scan {scan_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get network scan by id: {e}")
        return await format_api_error(e, "get network scan by id")
    except Exception as e:
        logger.error(f"Unexpected error during get network scan by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get network scan by id",
        }


@operation(domain="endpoint_visibility")
async def update_network_scan_by_id(
    ctx: Context,
    scan_id: int = Field(..., description="Numeric ID of the network scan"),
    scan_data: Dict[str, Any] = Field(..., description="Supported keys include: zone, type, seed_device_or_ip_subnet, scan_frequency, start_time, interval, day_of_week, depth, probe_arp, enabled."),
) -> Dict[str, Any]:
    """
    Update some fields of a NetworkScan.

    Updates only the supplied fields of the network scan (HTTP PATCH).

    Body fields (scan_data):
        - zone: Zone for the Network Scan. Object Type: string
        - type: Type of the Network Scan. Object Type: string
        - seed_device_or_ip_subnet: Network IP for DISCOVERY (e.g. ["hostname.example.com", "1.2.3.4"]) or IP Subnets for SUBNET (e.g. ["10.1.0.0/16"]) Network Scan. Object Type: string
        - scan_frequency: Frequency of Network Scan. Object Type: string
        - start_time: Start time (HH:MM) of Network Scan  (e.g. ["10:40", "23:20"]). Object Type: string
        - interval: Interval in hours (3 - 350) for HOURLY Network Scan. Object Type: integer
        - day_of_week: Day of Week for WEEKLY Network Scan. Object Type: string
        - depth: Depth level for DISCOVERY Network Scan. Object Type: integer
        - probe_arp: Probe all ARP entries found (default=false for type="DISCOVERY", not applicable for type="SUBNET"). Object Type: boolean
        - enabled: Is Network Scan enabled? (default=true). Object Type: boolean

    Maps to 'update_config_network_scan_by_scan_id' in pyclearpass (PATCH /config/network-scan/{scan_id}).
    """
    await ctx.info(f"Updating network scan {scan_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_network_scan_by_id(
            scan_id=scan_id,
            scan_data=scan_data,
        )

        return {
            "success": True,
            "network_scan": response,
            "message": f"Updated network scan {scan_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update network scan by id: {e}")
        return await format_api_error(e, "update network scan by id")
    except Exception as e:
        logger.error(f"Unexpected error during update network scan by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update network scan by id",
        }


@operation(domain="endpoint_visibility")
async def replace_network_scan_by_id(
    ctx: Context,
    scan_id: int = Field(..., description="Numeric ID of the network scan"),
    scan_data: Dict[str, Any] = Field(..., description="Required keys: type, zone, seed_device_or_ip_subnet, scan_frequency. Supported keys include: zone, type, seed_device_or_ip_subnet, scan_frequency, start_time, interval, day_of_week, depth, probe_arp, enabled."),
) -> Dict[str, Any]:
    """
    Update all fields of a NetworkScan.

    Replaces the whole network scan definition (HTTP PUT); omitted fields are reset.

    Body fields (scan_data):
        - zone: Zone for the Network Scan. Object Type: string
        - type: Type of the Network Scan. Object Type: string
        - seed_device_or_ip_subnet: Network IP for DISCOVERY (e.g. ["hostname.example.com", "1.2.3.4"]) or IP Subnets for SUBNET (e.g. ["10.1.0.0/16"]) Network Scan. Object Type: string
        - scan_frequency: Frequency of Network Scan. Object Type: string
        - start_time: Start time (HH:MM) of Network Scan  (e.g. ["10:40", "23:20"]). Object Type: string
        - interval: Interval in hours (3 - 350) for HOURLY Network Scan. Object Type: integer
        - day_of_week: Day of Week for WEEKLY Network Scan. Object Type: string
        - depth: Depth level for DISCOVERY Network Scan. Object Type: integer
        - probe_arp: Probe all ARP entries found (default=false for type="DISCOVERY", not applicable for type="SUBNET"). Object Type: boolean
        - enabled: Is Network Scan enabled? (default=true). Object Type: boolean

    Maps to 'replace_config_network_scan_by_scan_id' in pyclearpass (PUT /config/network-scan/{scan_id}).
    """
    await ctx.info(f"Replacing network scan {scan_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_network_scan_by_id(
            scan_id=scan_id,
            scan_data=scan_data,
        )

        return {
            "success": True,
            "network_scan": response,
            "message": f"Replaced network scan {scan_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace network scan by id: {e}")
        return await format_api_error(e, "replace network scan by id")
    except Exception as e:
        logger.error(f"Unexpected error during replace network scan by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace network scan by id",
        }


@operation(domain="endpoint_visibility")
async def disable_network_scan_by_id(
    ctx: Context,
    scan_id: int = Field(..., description="Numeric ID of the network scan"),
) -> Dict[str, Any]:
    """
    Update some fields of a NetworkScan.

    Disables the network scan without deleting it.

    Maps to 'update_config_network_scan_by_scan_id_disable' in pyclearpass (PATCH /config/network-scan/{scan_id}/disable).
    """
    await ctx.info(f"Disabling network scan {scan_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.disable_network_scan_by_id(
            scan_id=scan_id,
        )

        return {
            "success": True,
            "network_scan": response,
            "message": f"Disabled network scan {scan_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to disable network scan by id: {e}")
        return await format_api_error(e, "disable network scan by id")
    except Exception as e:
        logger.error(f"Unexpected error during disable network scan by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to disable network scan by id",
        }


@operation(domain="endpoint_visibility")
async def enable_network_scan_by_id(
    ctx: Context,
    scan_id: int = Field(..., description="Numeric ID of the network scan"),
) -> Dict[str, Any]:
    """
    Update some fields of a NetworkScan.

    Enables the network scan so that it becomes active.

    Maps to 'update_config_network_scan_by_scan_id_enable' in pyclearpass (PATCH /config/network-scan/{scan_id}/enable).
    """
    await ctx.info(f"Enabling network scan {scan_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.enable_network_scan_by_id(
            scan_id=scan_id,
        )

        return {
            "success": True,
            "network_scan": response,
            "message": f"Enabled network scan {scan_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to enable network scan by id: {e}")
        return await format_api_error(e, "enable network scan by id")
    except Exception as e:
        logger.error(f"Unexpected error during enable network scan by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to enable network scan by id",
        }


# ============================================================================
# Device Profiler Fingerprints
# ============================================================================

@operation(domain="endpoint_visibility")
async def create_device_fingerprint(
    ctx: Context,
    fingerprint_data: Dict[str, Any] = Field(..., description="Supported keys include: mac, ip, hostname, dhcp, active_sync, host, snmp, device, tcp, nmap, ssh, wmi."),
) -> Dict[str, Any]:
    """
    Post device fingerprint attributes for profiling.

    Creates (or, for singleton settings resources, updates) the device fingerprint.

    Body fields (fingerprint_data):
        - mac: MAC address of device. Object Type: string
        - ip: IP address of device. Object Type: string
        - hostname: Hostname of device. Object Type: string
        - dhcp: DHCP attributes as JSON. Object Type: DHCPAttributes
        - active_sync: Active Sync attributes as JSON. Object Type: ActiveSyncAttributes
        - host: Host attributes as JSON. Object Type: HostAttributes
        - snmp: SNMP attributes as JSON. Object Type: SNMPAttributes
        - device: Device attributes as JSON. Object Type: DeviceAttributes
        - tcp: TCP attributes as JSON. Object Type: TCPAttributes
        - nmap: NMAP attributes as JSON. Object Type: NMAPAttributes
        - ssh: SSH attributes as JSON. Object Type: SSHAttributes
        - wmi: WMI attributes as JSON. Object Type: WMIAttributes
        - ports: Port attributes as JSON. Object Type: PortsAttributes

    Maps to 'new_device_profiler_device_fingerprint' in pyclearpass (POST /device-profiler/device-fingerprint).
    """
    await ctx.info("Submitting device fingerprints...")

    try:
        client = await get_clearpass_client()
        response = await client.create_device_fingerprint(
            fingerprint_data=fingerprint_data,
        )

        return {
            "success": True,
            "device_fingerprint": response,
            "message": "Saved device fingerprint",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create device fingerprint: {e}")
        return await format_api_error(e, "create device fingerprint")
    except Exception as e:
        logger.error(f"Unexpected error during create device fingerprint: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create device fingerprint",
        }


@operation(domain="endpoint_visibility")
async def delete_device_fingerprint(
    ctx: Context,
    mac_or_ip: str = Field(..., description="MAC address or IP address of the endpoint to look up"),
) -> Dict[str, Any]:
    """
    Delete fingerprint of profiled device.

    Permanently deletes the device fingerprint. This cannot be undone.

    Maps to 'delete_device_profiler_device_fingerprint_by_mac_or_ip' in pyclearpass (DELETE /device-profiler/device-fingerprint/{mac_or_ip}).
    """
    await ctx.info(f"Deleting device fingerprint {mac_or_ip}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_device_fingerprint(
            mac_or_ip=mac_or_ip,
        )

        return {
            "success": True,
            "message": f"Deleted device fingerprint {mac_or_ip}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete device fingerprint: {e}")
        return await format_api_error(e, "delete device fingerprint")
    except Exception as e:
        logger.error(f"Unexpected error during delete device fingerprint: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete device fingerprint",
        }


@operation(domain="endpoint_visibility")
async def get_device_fingerprint(
    ctx: Context,
    mac_or_ip: str = Field(..., description="MAC address or IP address of the endpoint to look up"),
) -> Dict[str, Any]:
    """
    Get profiled device.

    Retrieves a single device fingerprint.

    Maps to 'get_device_profiler_device_fingerprint_by_mac_or_ip' in pyclearpass (GET /device-profiler/device-fingerprint/{mac_or_ip}).
    """
    await ctx.info(f"Retrieving device fingerprint {mac_or_ip}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_device_fingerprint(
            mac_or_ip=mac_or_ip,
        )

        return {
            "success": True,
            "device_fingerprint": response,
            "message": f"Retrieved device fingerprint {mac_or_ip}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get device fingerprint: {e}")
        return await format_api_error(e, "get device fingerprint")
    except Exception as e:
        logger.error(f"Unexpected error during get device fingerprint: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get device fingerprint",
        }


# ============================================================================
# Fingerprint Dictionary
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_fingerprints(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"corp\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    Get a list of Fingerprints.

    Returns the configured fingerprints on the ClearPass server.

    Maps to 'get_fingerprint' in pyclearpass (GET /fingerprint).
    """
    await ctx.info("Retrieving fingerprints...")

    try:
        client = await get_clearpass_client()
        response = await client.list_fingerprints(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "fingerprints": items,
            "message": f"Retrieved {len(items)} fingerprints",
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "has_more": len(items) == limit if limit else False,
            },
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list fingerprints: {e}")
        return await format_api_error(e, "list fingerprints")
    except Exception as e:
        logger.error(f"Unexpected error during list fingerprints: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list fingerprints",
        }


@operation(domain="endpoint_visibility")
async def create_fingerprint(
    ctx: Context,
    fingerprint_data: Dict[str, Any] = Field(..., description="Required keys: category, family, name. Supported keys include: category, family, name."),
) -> Dict[str, Any]:
    """
    Create a new Fingerprint.

    Creates (or, for singleton settings resources, updates) the fingerprint.

    Body fields (fingerprint_data):
        - category: Category name of the fingerprint. Object Type: string
        - family: Family name of the fingerprint. Object Type: string
        - name: Unique name of the fingerprint. Object Type: string

    Maps to 'new_fingerprint' in pyclearpass (POST /fingerprint).
    """
    await ctx.info("Submitting fingerprints...")

    try:
        client = await get_clearpass_client()
        response = await client.create_fingerprint(
            fingerprint_data=fingerprint_data,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": "Saved fingerprint",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create fingerprint: {e}")
        return await format_api_error(e, "create fingerprint")
    except Exception as e:
        logger.error(f"Unexpected error during create fingerprint: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create fingerprint",
        }


@operation(domain="endpoint_visibility")
async def delete_fingerprint_by_name(
    ctx: Context,
    category: str = Field(..., description="Category name of the fingerprint (e.g. 'Computer')"),
    family: str = Field(..., description="Family name of the fingerprint (e.g. 'Windows')"),
    name: str = Field(..., description="Name of the fingerprint"),
) -> Dict[str, Any]:
    """
    Delete a Fingerprint by name.

    Permanently deletes the fingerprint. This cannot be undone.

    Maps to 'delete_fingerprint_name_by_category_family_name' in pyclearpass (DELETE /fingerprint/name/{category}/{family}/{name}).
    """
    await ctx.info(f"Deleting fingerprint {category} / {family} / {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_fingerprint_by_name(
            category=category,
            family=family,
            name=name,
        )

        return {
            "success": True,
            "message": f"Deleted fingerprint {category} / {family} / {name}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete fingerprint by name: {e}")
        return await format_api_error(e, "delete fingerprint by name")
    except Exception as e:
        logger.error(f"Unexpected error during delete fingerprint by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete fingerprint by name",
        }


@operation(domain="endpoint_visibility")
async def get_fingerprint_by_name(
    ctx: Context,
    category: str = Field(..., description="Category name of the fingerprint (e.g. 'Computer')"),
    family: str = Field(..., description="Family name of the fingerprint (e.g. 'Windows')"),
    name: str = Field(..., description="Name of the fingerprint"),
) -> Dict[str, Any]:
    """
    Get a Fingerprint by name.

    Retrieves a single fingerprint.

    Maps to 'get_fingerprint_name_by_category_family_name' in pyclearpass (GET /fingerprint/name/{category}/{family}/{name}).
    """
    await ctx.info(f"Retrieving fingerprint {category} / {family} / {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_fingerprint_by_name(
            category=category,
            family=family,
            name=name,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": f"Retrieved fingerprint {category} / {family} / {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get fingerprint by name: {e}")
        return await format_api_error(e, "get fingerprint by name")
    except Exception as e:
        logger.error(f"Unexpected error during get fingerprint by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get fingerprint by name",
        }


@operation(domain="endpoint_visibility")
async def update_fingerprint_by_name(
    ctx: Context,
    category: str = Field(..., description="Category name of the fingerprint (e.g. 'Computer')"),
    family: str = Field(..., description="Family name of the fingerprint (e.g. 'Windows')"),
    name: str = Field(..., description="Name of the fingerprint"),
    fingerprint_data: Dict[str, Any] = Field(..., description="Supported keys include: category, family, name."),
) -> Dict[str, Any]:
    """
    Update some fields of a Fingerprint by name.

    Updates only the supplied fields of the fingerprint (HTTP PATCH).

    Body fields (fingerprint_data):
        - category: Category name of the fingerprint. Object Type: string
        - family: Family name of the fingerprint. Object Type: string
        - name: Unique name of the fingerprint. Object Type: string

    Maps to 'update_fingerprint_name_by_category_family_name' in pyclearpass (PATCH /fingerprint/name/{category}/{family}/{name}).
    """
    await ctx.info(f"Updating fingerprint {category} / {family} / {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_fingerprint_by_name(
            category=category,
            family=family,
            name=name,
            fingerprint_data=fingerprint_data,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": f"Updated fingerprint {category} / {family} / {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update fingerprint by name: {e}")
        return await format_api_error(e, "update fingerprint by name")
    except Exception as e:
        logger.error(f"Unexpected error during update fingerprint by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update fingerprint by name",
        }


@operation(domain="endpoint_visibility")
async def replace_fingerprint_by_name(
    ctx: Context,
    category: str = Field(..., description="Category name of the fingerprint (e.g. 'Computer')"),
    family: str = Field(..., description="Family name of the fingerprint (e.g. 'Windows')"),
    name: str = Field(..., description="Name of the fingerprint"),
    fingerprint_data: Dict[str, Any] = Field(..., description="Required keys: category, family, name. Supported keys include: category, family, name."),
) -> Dict[str, Any]:
    """
    Replace a Fingerprint by name.

    Replaces the whole fingerprint definition (HTTP PUT); omitted fields are reset.

    Body fields (fingerprint_data):
        - category: Category name of the fingerprint. Object Type: string
        - family: Family name of the fingerprint. Object Type: string
        - name: Unique name of the fingerprint. Object Type: string

    Maps to 'replace_fingerprint_name_by_category_family_name' in pyclearpass (PUT /fingerprint/name/{category}/{family}/{name}).
    """
    await ctx.info(f"Replacing fingerprint {category} / {family} / {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_fingerprint_by_name(
            category=category,
            family=family,
            name=name,
            fingerprint_data=fingerprint_data,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": f"Replaced fingerprint {category} / {family} / {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace fingerprint by name: {e}")
        return await format_api_error(e, "replace fingerprint by name")
    except Exception as e:
        logger.error(f"Unexpected error during replace fingerprint by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace fingerprint by name",
        }


@operation(domain="endpoint_visibility")
async def delete_fingerprint_by_id(
    ctx: Context,
    fingerprint_id: int = Field(..., description="Numeric ID of the fingerprint"),
) -> Dict[str, Any]:
    """
    Delete a Fingerprint.

    Permanently deletes the fingerprint. This cannot be undone.

    Maps to 'delete_fingerprint_by_fingerprint_id' in pyclearpass (DELETE /fingerprint/{fingerprint_id}).
    """
    await ctx.info(f"Deleting fingerprint {fingerprint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_fingerprint_by_id(
            fingerprint_id=fingerprint_id,
        )

        return {
            "success": True,
            "message": f"Deleted fingerprint {fingerprint_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete fingerprint by id: {e}")
        return await format_api_error(e, "delete fingerprint by id")
    except Exception as e:
        logger.error(f"Unexpected error during delete fingerprint by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete fingerprint by id",
        }


@operation(domain="endpoint_visibility")
async def get_fingerprint_by_id(
    ctx: Context,
    fingerprint_id: int = Field(..., description="Numeric ID of the fingerprint"),
) -> Dict[str, Any]:
    """
    Get a Fingerprint.

    Retrieves a single fingerprint.

    Maps to 'get_fingerprint_by_fingerprint_id' in pyclearpass (GET /fingerprint/{fingerprint_id}).
    """
    await ctx.info(f"Retrieving fingerprint {fingerprint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_fingerprint_by_id(
            fingerprint_id=fingerprint_id,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": f"Retrieved fingerprint {fingerprint_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get fingerprint by id: {e}")
        return await format_api_error(e, "get fingerprint by id")
    except Exception as e:
        logger.error(f"Unexpected error during get fingerprint by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get fingerprint by id",
        }


@operation(domain="endpoint_visibility")
async def update_fingerprint_by_id(
    ctx: Context,
    fingerprint_id: int = Field(..., description="Numeric ID of the fingerprint"),
    fingerprint_data: Dict[str, Any] = Field(..., description="Supported keys include: category, family, name."),
) -> Dict[str, Any]:
    """
    Update some fields of a Fingerprint.

    Updates only the supplied fields of the fingerprint (HTTP PATCH).

    Body fields (fingerprint_data):
        - category: Category name of the fingerprint. Object Type: string
        - family: Family name of the fingerprint. Object Type: string
        - name: Unique name of the fingerprint. Object Type: string

    Maps to 'update_fingerprint_by_fingerprint_id' in pyclearpass (PATCH /fingerprint/{fingerprint_id}).
    """
    await ctx.info(f"Updating fingerprint {fingerprint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_fingerprint_by_id(
            fingerprint_id=fingerprint_id,
            fingerprint_data=fingerprint_data,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": f"Updated fingerprint {fingerprint_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update fingerprint by id: {e}")
        return await format_api_error(e, "update fingerprint by id")
    except Exception as e:
        logger.error(f"Unexpected error during update fingerprint by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update fingerprint by id",
        }


@operation(domain="endpoint_visibility")
async def replace_fingerprint_by_id(
    ctx: Context,
    fingerprint_id: int = Field(..., description="Numeric ID of the fingerprint"),
    fingerprint_data: Dict[str, Any] = Field(..., description="Required keys: category, family, name. Supported keys include: category, family, name."),
) -> Dict[str, Any]:
    """
    Replace a Fingerprint.

    Replaces the whole fingerprint definition (HTTP PUT); omitted fields are reset.

    Body fields (fingerprint_data):
        - category: Category name of the fingerprint. Object Type: string
        - family: Family name of the fingerprint. Object Type: string
        - name: Unique name of the fingerprint. Object Type: string

    Maps to 'replace_fingerprint_by_fingerprint_id' in pyclearpass (PUT /fingerprint/{fingerprint_id}).
    """
    await ctx.info(f"Replacing fingerprint {fingerprint_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_fingerprint_by_id(
            fingerprint_id=fingerprint_id,
            fingerprint_data=fingerprint_data,
        )

        return {
            "success": True,
            "fingerprint": response,
            "message": f"Replaced fingerprint {fingerprint_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace fingerprint by id: {e}")
        return await format_api_error(e, "replace fingerprint by id")
    except Exception as e:
        logger.error(f"Unexpected error during replace fingerprint by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace fingerprint by id",
        }


# ============================================================================
# OnGuard Activity
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_onguard_activity(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"corp\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    Get a list of Clearpass OnGuard Endpoints.

    Returns the configured OnGuard activity records on the ClearPass server.

    Maps to 'get_onguard_activity' in pyclearpass (GET /onguard-activity).
    """
    await ctx.info("Retrieving OnGuard activity records...")

    try:
        client = await get_clearpass_client()
        response = await client.list_onguard_activity(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "onguard_activity": items,
            "message": f"Retrieved {len(items)} OnGuard activity records",
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "has_more": len(items) == limit if limit else False,
            },
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list onguard activity: {e}")
        return await format_api_error(e, "list onguard activity")
    except Exception as e:
        logger.error(f"Unexpected error during list onguard activity: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list onguard activity",
        }


@operation(domain="endpoint_visibility")
async def get_onguard_activity_by_host_mac(
    ctx: Context,
    host_mac: str = Field(..., description="MAC address of the host (endpoint), e.g. '00:11:22:33:44:55'"),
) -> Dict[str, Any]:
    """
    Get a Clearpass OnGuard Endpoint Details by host_mac.

    Retrieves a single OnGuard activity record.

    Maps to 'get_onguard_activity_host_mac_by_host_mac' in pyclearpass (GET /onguard-activity/host_mac/{host_mac}).
    """
    await ctx.info(f"Retrieving OnGuard activity record {host_mac}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_onguard_activity_by_host_mac(
            host_mac=host_mac,
        )

        return {
            "success": True,
            "onguard_activity": response,
            "message": f"Retrieved OnGuard activity record {host_mac}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get onguard activity by host mac: {e}")
        return await format_api_error(e, "get onguard activity by host mac")
    except Exception as e:
        logger.error(f"Unexpected error during get onguard activity by host mac: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get onguard activity by host mac",
        }


@operation(domain="endpoint_visibility")
async def send_onguard_activity_message(
    ctx: Context,
    message_data: Dict[str, Any] = Field(..., description="Required keys: host_mac_list, message, is_broadcast. Supported keys include: host_mac_list, message, info_url, is_broadcast."),
) -> Dict[str, Any]:
    """
    Send/Broadcast Message.

    Sends the request to the ClearPass OnGuard activity record endpoint.

    Body fields (message_data):
        - host_mac_list: List of host MAC Address. Object Type: object
        - message: Message. Object Type: string
        - info_url: URL. Object Type: string
        - is_broadcast: Is a broadcast. Object Type: boolean

    Maps to 'new_onguard_activity_message' in pyclearpass (POST /onguard-activity/message).
    """
    await ctx.info("Sending OnGuard activity records...")

    try:
        client = await get_clearpass_client()
        response = await client.send_onguard_activity_message(
            message_data=message_data,
        )

        return {
            "success": True,
            "onguard_activity": response,
            "message": "Sent OnGuard activity record",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to send onguard activity message: {e}")
        return await format_api_error(e, "send onguard activity message")
    except Exception as e:
        logger.error(f"Unexpected error during send onguard activity message: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to send onguard activity message",
        }


@operation(domain="endpoint_visibility")
async def send_onguard_activity_notification(
    ctx: Context,
    message_data: Dict[str, Any] = Field(..., description="Required keys: host_mac_list, message, is_broadcast, action. Supported keys include: host_mac_list, message, info_url, is_broadcast, action, endpoint_status."),
) -> Dict[str, Any]:
    """
    Send/Broadcast Notification.

    Sends the request to the ClearPass OnGuard activity record endpoint.

    Body fields (message_data):
        - host_mac_list: List of host MAC Address. Object Type: object
        - message: Message. Object Type: string
        - info_url: URL. Object Type: string
        - is_broadcast: Is a broadcast. Object Type: boolean
        - action: Action. Object Type: string
        - endpoint_status: Status of the endpoint. Object Type: string

    Maps to 'new_onguard_activity_notification' in pyclearpass (POST /onguard-activity/notification).
    """
    await ctx.info("Sending OnGuard activity records...")

    try:
        client = await get_clearpass_client()
        response = await client.send_onguard_activity_notification(
            message_data=message_data,
        )

        return {
            "success": True,
            "onguard_activity": response,
            "message": "Sent OnGuard activity record",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to send onguard activity notification: {e}")
        return await format_api_error(e, "send onguard activity notification")
    except Exception as e:
        logger.error(f"Unexpected error during send onguard activity notification: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to send onguard activity notification",
        }


@operation(domain="endpoint_visibility")
async def get_onguard_activity_by_id(
    ctx: Context,
    onguard_activity_id: int = Field(..., description="Numeric ID of the OnGuard activity record"),
) -> Dict[str, Any]:
    """
    Get a Clearpass OnGuard Endpoint Details.

    Retrieves a single OnGuard activity record.

    Maps to 'get_onguard_activity_by_onguard_activity_id' in pyclearpass (GET /onguard-activity/{onguard_activity_id}).
    """
    await ctx.info(f"Retrieving OnGuard activity record {onguard_activity_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_onguard_activity_by_id(
            onguard_activity_id=onguard_activity_id,
        )

        return {
            "success": True,
            "onguard_activity": response,
            "message": f"Retrieved OnGuard activity record {onguard_activity_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get onguard activity by id: {e}")
        return await format_api_error(e, "get onguard activity by id")
    except Exception as e:
        logger.error(f"Unexpected error during get onguard activity by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get onguard activity by id",
        }


# ============================================================================
# OnGuard Custom Scripts
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_onguard_custom_scripts(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"corp\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    Get a list of OnGuard Custom Scripts.

    Returns the configured OnGuard custom scripts on the ClearPass server.

    Maps to 'get_onguard_custom_script' in pyclearpass (GET /onguard-custom-script).
    """
    await ctx.info("Retrieving OnGuard custom scripts...")

    try:
        client = await get_clearpass_client()
        response = await client.list_onguard_custom_scripts(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "custom_scripts": items,
            "message": f"Retrieved {len(items)} OnGuard custom scripts",
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "has_more": len(items) == limit if limit else False,
            },
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list onguard custom scripts: {e}")
        return await format_api_error(e, "list onguard custom scripts")
    except Exception as e:
        logger.error(f"Unexpected error during list onguard custom scripts: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list onguard custom scripts",
        }


@operation(domain="endpoint_visibility")
async def create_onguard_custom_script(
    ctx: Context,
    script_data: Dict[str, Any] = Field(..., description="Required keys: name, os_type, script_type, attributes. Supported keys include: name, description, os_type, script_type, attributes, output_format, output_details, rule_eval_algo, rules."),
) -> Dict[str, Any]:
    """
    Create a new OnGuard Custom Script.

    Creates (or, for singleton settings resources, updates) the OnGuard custom script.

    Body fields (script_data):
        - name: Name of Custom Script. Object Type: string
        - description: Description of Custom Script. Object Type: string
        - os_type: OS Type of Custom Script. Object Type: string
        - script_type: Type of Custom Script. Object Type: string
        - attributes: Attributes of Custom Script, allowed attributes - Path,Command,SHA256,ExecutionLevel,WaitTime,PassResults,SuccessMsg,FailureMsg,ProgressMsg,Description,DownloadURL,ValidateURLCert,ScriptExecutionTimeOut,SignerName (e.g. {"Path": "/home/aruba/scripts","SHA256": "cfd6...f7ca","ExecutionLevel": "User","Command": "runscript.sh","SignerName": "signer"}). Object Type: object
        - output_format: Output Format of Custom Script, applicable only for health collection scripts. Object Type: string
        - output_details: Output Details of Custom Script, applicable only for health collection scripts (e.g. {"ExitCode":"Integer", "OutVar1":"Boolean", "OutVar2":"String"}). Object Type: object
        - rule_eval_algo: Rule Evaluation Algorithm for rules of Custom Script, applicable only for health collection scripts. Object Type: string
        - rules: List of Rules for Custom Script, applicable only for health collection scripts (e.g. [{"match_type":"OR","health_status":"Healthy","condition":[{"type":"Script","name":"ExitCode","oper":"EQUALS","value":"0"}]}]). Object Type: object

    Maps to 'new_onguard_custom_script' in pyclearpass (POST /onguard-custom-script).
    """
    await ctx.info("Submitting OnGuard custom scripts...")

    try:
        client = await get_clearpass_client()
        response = await client.create_onguard_custom_script(
            script_data=script_data,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": "Saved OnGuard custom script",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create onguard custom script: {e}")
        return await format_api_error(e, "create onguard custom script")
    except Exception as e:
        logger.error(f"Unexpected error during create onguard custom script: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create onguard custom script",
        }


@operation(domain="endpoint_visibility")
async def delete_onguard_custom_script_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard custom script"),
) -> Dict[str, Any]:
    """
    Delete an OnGuard Custom Script by name.

    Permanently deletes the OnGuard custom script. This cannot be undone.

    Maps to 'delete_onguard_custom_script_name_by_name' in pyclearpass (DELETE /onguard-custom-script/name/{name}).
    """
    await ctx.info(f"Deleting OnGuard custom script {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_onguard_custom_script_by_name(
            name=name,
        )

        return {
            "success": True,
            "message": f"Deleted OnGuard custom script {name}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete onguard custom script by name: {e}")
        return await format_api_error(e, "delete onguard custom script by name")
    except Exception as e:
        logger.error(f"Unexpected error during delete onguard custom script by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete onguard custom script by name",
        }


@operation(domain="endpoint_visibility")
async def get_onguard_custom_script_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard custom script"),
) -> Dict[str, Any]:
    """
    Get an OnGuard Custom Script by name.

    Retrieves a single OnGuard custom script.

    Maps to 'get_onguard_custom_script_name_by_name' in pyclearpass (GET /onguard-custom-script/name/{name}).
    """
    await ctx.info(f"Retrieving OnGuard custom script {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_onguard_custom_script_by_name(
            name=name,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": f"Retrieved OnGuard custom script {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get onguard custom script by name: {e}")
        return await format_api_error(e, "get onguard custom script by name")
    except Exception as e:
        logger.error(f"Unexpected error during get onguard custom script by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get onguard custom script by name",
        }


@operation(domain="endpoint_visibility")
async def update_onguard_custom_script_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard custom script"),
    script_data: Dict[str, Any] = Field(..., description="Supported keys include: name, description, attributes, output_format, output_details, rule_eval_algo, rules."),
) -> Dict[str, Any]:
    """
    Update some fields of an OnGuard Custom Script by name.

    Updates only the supplied fields of the OnGuard custom script (HTTP PATCH).

    Body fields (script_data):
        - name: Name of Custom Script. Object Type: string
        - description: Description of Custom Script. Object Type: string
        - attributes: Attributes of Custom Script, allowed attributes - Path,Command,SHA256,ExecutionLevel,WaitTime,PassResults,SuccessMsg,FailureMsg,ProgressMsg,Description,DownloadURL,ValidateURLCert,ScriptExecutionTimeOut,SignerName (e.g. {"Path": "/home/aruba/scripts","SHA256": "cfd6...f7ca","ExecutionLevel": "User","Command": "runscript.sh","SignerName": "signer"}). Object Type: object
        - output_format: Output Format of Custom Script, applicable only for health collection scripts. Object Type: string
        - output_details: Output Details of Custom Script, applicable only for health collection scripts (e.g. {"ExitCode":"Integer", "OutVar1":"Boolean", "OutVar2":"String"}). Object Type: object
        - rule_eval_algo: Rule Evaluation Algorithm for rules of Custom Script, applicable only for health collection scripts. Object Type: string
        - rules: List of Rules for Custom Script, applicable only for health collection scripts (e.g. [{"match_type":"OR","health_status":"Healthy","condition":[{"type":"Script","name":"ExitCode","oper":"EQUALS","value":"0"}]}]). Object Type: object

    Maps to 'update_onguard_custom_script_name_by_name' in pyclearpass (PATCH /onguard-custom-script/name/{name}).
    """
    await ctx.info(f"Updating OnGuard custom script {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_onguard_custom_script_by_name(
            name=name,
            script_data=script_data,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": f"Updated OnGuard custom script {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update onguard custom script by name: {e}")
        return await format_api_error(e, "update onguard custom script by name")
    except Exception as e:
        logger.error(f"Unexpected error during update onguard custom script by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update onguard custom script by name",
        }


@operation(domain="endpoint_visibility")
async def replace_onguard_custom_script_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard custom script"),
    script_data: Dict[str, Any] = Field(..., description="Required keys: name, os_type, script_type, attributes. Supported keys include: name, description, os_type, script_type, attributes, output_format, output_details, rule_eval_algo, rules."),
) -> Dict[str, Any]:
    """
    Replace an OnGuard Custom Script by name.

    Replaces the whole OnGuard custom script definition (HTTP PUT); omitted fields are reset.

    Body fields (script_data):
        - name: Name of Custom Script. Object Type: string
        - description: Description of Custom Script. Object Type: string
        - os_type: OS Type of Custom Script. Object Type: string
        - script_type: Type of Custom Script. Object Type: string
        - attributes: Attributes of Custom Script, allowed attributes - Path,Command,SHA256,ExecutionLevel,WaitTime,PassResults,SuccessMsg,FailureMsg,ProgressMsg,Description,DownloadURL,ValidateURLCert,ScriptExecutionTimeOut,SignerName (e.g. {"Path": "/home/aruba/scripts","SHA256": "cfd6...f7ca","ExecutionLevel": "User","Command": "runscript.sh","SignerName": "signer"}). Object Type: object
        - output_format: Output Format of Custom Script, applicable only for health collection scripts. Object Type: string
        - output_details: Output Details of Custom Script, applicable only for health collection scripts (e.g. {"ExitCode":"Integer", "OutVar1":"Boolean", "OutVar2":"String"}). Object Type: object
        - rule_eval_algo: Rule Evaluation Algorithm for rules of Custom Script, applicable only for health collection scripts. Object Type: string
        - rules: List of Rules for Custom Script, applicable only for health collection scripts (e.g. [{"match_type":"OR","health_status":"Healthy","condition":[{"type":"Script","name":"ExitCode","oper":"EQUALS","value":"0"}]}]). Object Type: object

    Maps to 'replace_onguard_custom_script_name_by_name' in pyclearpass (PUT /onguard-custom-script/name/{name}).
    """
    await ctx.info(f"Replacing OnGuard custom script {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_onguard_custom_script_by_name(
            name=name,
            script_data=script_data,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": f"Replaced OnGuard custom script {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace onguard custom script by name: {e}")
        return await format_api_error(e, "replace onguard custom script by name")
    except Exception as e:
        logger.error(f"Unexpected error during replace onguard custom script by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace onguard custom script by name",
        }


@operation(domain="endpoint_visibility")
async def delete_onguard_custom_script_by_id(
    ctx: Context,
    onguard_custom_script_id: int = Field(..., description="Numeric ID of the OnGuard custom script"),
) -> Dict[str, Any]:
    """
    Delete an OnGuard Custom Script.

    Permanently deletes the OnGuard custom script. This cannot be undone.

    Maps to 'delete_onguard_custom_script_by_onguard_custom_script_id' in pyclearpass (DELETE /onguard-custom-script/{onguard_custom_script_id}).
    """
    await ctx.info(f"Deleting OnGuard custom script {onguard_custom_script_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_onguard_custom_script_by_id(
            onguard_custom_script_id=onguard_custom_script_id,
        )

        return {
            "success": True,
            "message": f"Deleted OnGuard custom script {onguard_custom_script_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete onguard custom script by id: {e}")
        return await format_api_error(e, "delete onguard custom script by id")
    except Exception as e:
        logger.error(f"Unexpected error during delete onguard custom script by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete onguard custom script by id",
        }


@operation(domain="endpoint_visibility")
async def get_onguard_custom_script_by_id(
    ctx: Context,
    onguard_custom_script_id: int = Field(..., description="Numeric ID of the OnGuard custom script"),
) -> Dict[str, Any]:
    """
    Get an OnGuard Custom Script.

    Retrieves a single OnGuard custom script.

    Maps to 'get_onguard_custom_script_by_onguard_custom_script_id' in pyclearpass (GET /onguard-custom-script/{onguard_custom_script_id}).
    """
    await ctx.info(f"Retrieving OnGuard custom script {onguard_custom_script_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_onguard_custom_script_by_id(
            onguard_custom_script_id=onguard_custom_script_id,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": f"Retrieved OnGuard custom script {onguard_custom_script_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get onguard custom script by id: {e}")
        return await format_api_error(e, "get onguard custom script by id")
    except Exception as e:
        logger.error(f"Unexpected error during get onguard custom script by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get onguard custom script by id",
        }


@operation(domain="endpoint_visibility")
async def update_onguard_custom_script_by_id(
    ctx: Context,
    onguard_custom_script_id: int = Field(..., description="Numeric ID of the OnGuard custom script"),
    script_data: Dict[str, Any] = Field(..., description="Supported keys include: name, description, attributes, output_format, output_details, rule_eval_algo, rules."),
) -> Dict[str, Any]:
    """
    Update some fields of an OnGuard Custom Script.

    Updates only the supplied fields of the OnGuard custom script (HTTP PATCH).

    Body fields (script_data):
        - name: Name of Custom Script. Object Type: string
        - description: Description of Custom Script. Object Type: string
        - attributes: Attributes of Custom Script, allowed attributes - Path,Command,SHA256,ExecutionLevel,WaitTime,PassResults,SuccessMsg,FailureMsg,ProgressMsg,Description,DownloadURL,ValidateURLCert,ScriptExecutionTimeOut,SignerName (e.g. {"Path": "/home/aruba/scripts","SHA256": "cfd6...f7ca","ExecutionLevel": "User","Command": "runscript.sh","SignerName": "signer"}). Object Type: object
        - output_format: Output Format of Custom Script, applicable only for health collection scripts. Object Type: string
        - output_details: Output Details of Custom Script, applicable only for health collection scripts (e.g. {"ExitCode":"Integer", "OutVar1":"Boolean", "OutVar2":"String"}). Object Type: object
        - rule_eval_algo: Rule Evaluation Algorithm for rules of Custom Script, applicable only for health collection scripts. Object Type: string
        - rules: List of Rules for Custom Script, applicable only for health collection scripts (e.g. [{"match_type":"OR","health_status":"Healthy","condition":[{"type":"Script","name":"ExitCode","oper":"EQUALS","value":"0"}]}]). Object Type: object

    Maps to 'update_onguard_custom_script_by_onguard_custom_script_id' in pyclearpass (PATCH /onguard-custom-script/{onguard_custom_script_id}).
    """
    await ctx.info(f"Updating OnGuard custom script {onguard_custom_script_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_onguard_custom_script_by_id(
            onguard_custom_script_id=onguard_custom_script_id,
            script_data=script_data,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": f"Updated OnGuard custom script {onguard_custom_script_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update onguard custom script by id: {e}")
        return await format_api_error(e, "update onguard custom script by id")
    except Exception as e:
        logger.error(f"Unexpected error during update onguard custom script by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update onguard custom script by id",
        }


@operation(domain="endpoint_visibility")
async def replace_onguard_custom_script_by_id(
    ctx: Context,
    onguard_custom_script_id: int = Field(..., description="Numeric ID of the OnGuard custom script"),
    script_data: Dict[str, Any] = Field(..., description="Required keys: name, os_type, script_type, attributes. Supported keys include: name, description, os_type, script_type, attributes, output_format, output_details, rule_eval_algo, rules."),
) -> Dict[str, Any]:
    """
    Replace an OnGuard Custom Script.

    Replaces the whole OnGuard custom script definition (HTTP PUT); omitted fields are reset.

    Body fields (script_data):
        - name: Name of Custom Script. Object Type: string
        - description: Description of Custom Script. Object Type: string
        - os_type: OS Type of Custom Script. Object Type: string
        - script_type: Type of Custom Script. Object Type: string
        - attributes: Attributes of Custom Script, allowed attributes - Path,Command,SHA256,ExecutionLevel,WaitTime,PassResults,SuccessMsg,FailureMsg,ProgressMsg,Description,DownloadURL,ValidateURLCert,ScriptExecutionTimeOut,SignerName (e.g. {"Path": "/home/aruba/scripts","SHA256": "cfd6...f7ca","ExecutionLevel": "User","Command": "runscript.sh","SignerName": "signer"}). Object Type: object
        - output_format: Output Format of Custom Script, applicable only for health collection scripts. Object Type: string
        - output_details: Output Details of Custom Script, applicable only for health collection scripts (e.g. {"ExitCode":"Integer", "OutVar1":"Boolean", "OutVar2":"String"}). Object Type: object
        - rule_eval_algo: Rule Evaluation Algorithm for rules of Custom Script, applicable only for health collection scripts. Object Type: string
        - rules: List of Rules for Custom Script, applicable only for health collection scripts (e.g. [{"match_type":"OR","health_status":"Healthy","condition":[{"type":"Script","name":"ExitCode","oper":"EQUALS","value":"0"}]}]). Object Type: object

    Maps to 'replace_onguard_custom_script_by_onguard_custom_script_id' in pyclearpass (PUT /onguard-custom-script/{onguard_custom_script_id}).
    """
    await ctx.info(f"Replacing OnGuard custom script {onguard_custom_script_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_onguard_custom_script_by_id(
            onguard_custom_script_id=onguard_custom_script_id,
            script_data=script_data,
        )

        return {
            "success": True,
            "custom_script": response,
            "message": f"Replaced OnGuard custom script {onguard_custom_script_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace onguard custom script by id: {e}")
        return await format_api_error(e, "replace onguard custom script by id")
    except Exception as e:
        logger.error(f"Unexpected error during replace onguard custom script by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace onguard custom script by id",
        }


# ============================================================================
# OnGuard Global Settings
# ============================================================================

@operation(domain="endpoint_visibility")
async def onguard_list_global_settings(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get OnGuard global settings.

    Returns the configured OnGuard global settings on the ClearPass server.

    Maps to 'get_onguard_global_settings' in pyclearpass (GET /onguard/global-settings).
    """
    await ctx.info("Retrieving OnGuard global settings...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_list_global_settings()

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "global_settings": items,
            "message": f"Retrieved {len(items)} OnGuard global settings",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard list global settings: {e}")
        return await format_api_error(e, "onguard list global settings")
    except Exception as e:
        logger.error(f"Unexpected error during onguard list global settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard list global settings",
        }


@operation(domain="endpoint_visibility")
async def onguard_update_global_settings(
    ctx: Context,
    settings_data: Dict[str, Any] = Field(..., description="Supported keys include: AllowRemoteDesktopSession, CacheCredentialsForDays, EnableClientLoadBalance, HealthCheckQuietPeriod, HideLogoutButton, InstallVPNComponent, KeepAliveIntervalSeconds, LogoutBounceDelay, RunOnGuardAs, ServerCertificateValidation, ServerCommunicationMode, SupportEmailAddress."),
) -> Dict[str, Any]:
    """
    Update OnGuard global settings.

    Creates (or, for singleton settings resources, updates) the OnGuard global settings.

    Body fields (settings_data):
        - AllowRemoteDesktopSession: Enable access over Remote Desktop Session. Object Type: boolean
        - CacheCredentialsForDays: Cache Credentials Interval(in days). Object Type: integer
        - EnableClientLoadBalance: Enable OnGuard requests load-balancing. Object Type: boolean
        - HealthCheckQuietPeriod: OnGuard Health Check Interval (in hours). Object Type: integer
        - HideLogoutButton: Enable to hide Logout button. Object Type: boolean
        - InstallVPNComponent: Enable to install VPN component. Object Type: boolean
        - KeepAliveIntervalSeconds: Keep-alive Interval (in seconds). Object Type: integer
        - LogoutBounceDelay: Delay to bounce after Logout (in minutes). Object Type: integer
        - RunOnGuardAs: Run OnGuard As. Object Type: string
        - ServerCertificateValidation: Server Certificate Validation. Object Type: string
        - ServerCommunicationMode: Server Communication Mode. Object Type: string
        - SupportEmailAddress: Support Team Email Address. Object Type: string
        - UseCurrentOSLanguage: Use Current OS Language (Windows only). Object Type: boolean
        - UseWindowsCredentials: Enable to use Windows Single-Sign On. Object Type: boolean
        - VPNDeviceNames: VPN Device Names (Windows). Object Type: string
        - VPNDeviceNamesMacOS: VPN Device Names (macOS). Object Type: string
        - VPNDeviceNamesLinux: VPN Device Names (Linux). Object Type: string
        - WiredAllowedSubnets: [Deprecated] Allowed Subnets for Wired access. Object Type: string
        - WirelessAllowedSubnets: [Deprecated] Allowed Subnets for Wireless access. Object Type: string

    Maps to 'new_onguard_global_settings' in pyclearpass (POST /onguard/global-settings).
    """
    await ctx.info("Submitting OnGuard global settings...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_update_global_settings(
            settings_data=settings_data,
        )

        return {
            "success": True,
            "global_settings": response,
            "message": "Saved OnGuard global settings",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard update global settings: {e}")
        return await format_api_error(e, "onguard update global settings")
    except Exception as e:
        logger.error(f"Unexpected error during onguard update global settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard update global settings",
        }


# ============================================================================
# OnGuard Policy Manager Zones
# ============================================================================

@operation(domain="endpoint_visibility")
async def onguard_list_policy_manager_zones(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get Policy Manager Zones with associated authentication server IP addresses(Client Subnets and Server IPs).

    Returns the configured OnGuard Policy Manager zones on the ClearPass server.

    Maps to 'get_onguard_policy_manager_zones' in pyclearpass (GET /onguard/policy-manager-zones).
    """
    await ctx.info("Retrieving OnGuard Policy Manager zones...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_list_policy_manager_zones()

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "policy_manager_zones": items,
            "message": f"Retrieved {len(items)} OnGuard Policy Manager zones",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard list policy manager zones: {e}")
        return await format_api_error(e, "onguard list policy manager zones")
    except Exception as e:
        logger.error(f"Unexpected error during onguard list policy manager zones: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard list policy manager zones",
        }


@operation(domain="endpoint_visibility")
async def onguard_create_policy_manager_zone(
    ctx: Context,
    zone_data: Dict[str, Any] = Field(..., description="Required keys: policy_manager_zone_name, client_subnets. Supported keys include: policy_manager_zone_name, client_subnets, override_server_ips."),
) -> Dict[str, Any]:
    """
    Post Policy Manager Zones with associated authentication server IP addresses.

    Creates (or, for singleton settings resources, updates) the OnGuard Policy Manager zone.

    Body fields (zone_data):
        - policy_manager_zone_name: Name of the Policy Manager Zone. Object Type: string
        - client_subnets: client subnet addresses specific to the Policy Manager zone. Object Type: string
        - override_server_ips: IP addresses or FQDN to which OnGuard agent will send request. This will override the Default ClearPass Server IPs. Object Type: string

    Maps to 'new_onguard_policy_manager_zones' in pyclearpass (POST /onguard/policy-manager-zones).
    """
    await ctx.info("Submitting OnGuard Policy Manager zones...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_create_policy_manager_zone(
            zone_data=zone_data,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": "Saved OnGuard Policy Manager zone",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard create policy manager zone: {e}")
        return await format_api_error(e, "onguard create policy manager zone")
    except Exception as e:
        logger.error(f"Unexpected error during onguard create policy manager zone: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard create policy manager zone",
        }


@operation(domain="endpoint_visibility")
async def onguard_delete_policy_manager_zone_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard Policy Manager zone"),
) -> Dict[str, Any]:
    """
    Delete authentication server IP addresses for Policy Manager Zone by name.

    Permanently deletes the OnGuard Policy Manager zone. This cannot be undone.

    Maps to 'delete_onguard_policy_manager_zones_name_by_name' in pyclearpass (DELETE /onguard/policy-manager-zones/name/{name}).
    """
    await ctx.info(f"Deleting OnGuard Policy Manager zone {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_delete_policy_manager_zone_by_name(
            name=name,
        )

        return {
            "success": True,
            "message": f"Deleted OnGuard Policy Manager zone {name}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard delete policy manager zone by name: {e}")
        return await format_api_error(e, "onguard delete policy manager zone by name")
    except Exception as e:
        logger.error(f"Unexpected error during onguard delete policy manager zone by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard delete policy manager zone by name",
        }


@operation(domain="endpoint_visibility")
async def onguard_get_policy_manager_zone_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard Policy Manager zone"),
) -> Dict[str, Any]:
    """
    Get Client Subnets and Server IPs for Policy Manager Zone by name.

    Retrieves a single OnGuard Policy Manager zone.

    Maps to 'get_onguard_policy_manager_zones_name_by_name' in pyclearpass (GET /onguard/policy-manager-zones/name/{name}).
    """
    await ctx.info(f"Retrieving OnGuard Policy Manager zone {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_get_policy_manager_zone_by_name(
            name=name,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": f"Retrieved OnGuard Policy Manager zone {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard get policy manager zone by name: {e}")
        return await format_api_error(e, "onguard get policy manager zone by name")
    except Exception as e:
        logger.error(f"Unexpected error during onguard get policy manager zone by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard get policy manager zone by name",
        }


@operation(domain="endpoint_visibility")
async def onguard_update_policy_manager_zone_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard Policy Manager zone"),
    zone_data: Dict[str, Any] = Field(..., description="Supported keys include: client_subnets, override_server_ips."),
) -> Dict[str, Any]:
    """
    Update authentication server IP addresses for Policy Manager Zone by name.

    Updates only the supplied fields of the OnGuard Policy Manager zone (HTTP PATCH).

    Body fields (zone_data):
        - client_subnets: client subnet addresses specific to the Policy Manager zone. Object Type: string
        - override_server_ips: IP addresses or FQDN to which OnGuard agent will send request. This will override the Default ClearPass Server IPs. Object Type: string

    Maps to 'update_onguard_policy_manager_zones_name_by_name' in pyclearpass (PATCH /onguard/policy-manager-zones/name/{name}).
    """
    await ctx.info(f"Updating OnGuard Policy Manager zone {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_update_policy_manager_zone_by_name(
            name=name,
            zone_data=zone_data,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": f"Updated OnGuard Policy Manager zone {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard update policy manager zone by name: {e}")
        return await format_api_error(e, "onguard update policy manager zone by name")
    except Exception as e:
        logger.error(f"Unexpected error during onguard update policy manager zone by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard update policy manager zone by name",
        }


@operation(domain="endpoint_visibility")
async def onguard_replace_policy_manager_zone_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the OnGuard Policy Manager zone"),
    zone_data: Dict[str, Any] = Field(..., description="Required keys: client_subnets. Supported keys include: client_subnets, override_server_ips."),
) -> Dict[str, Any]:
    """
    Post Client Subnets and Server IPs for Policy Manager Zone by name.

    Replaces the whole OnGuard Policy Manager zone definition (HTTP PUT); omitted fields are reset.

    Body fields (zone_data):
        - client_subnets: client subnet addresses specific to the Policy Manager zone. Object Type: string
        - override_server_ips: IP addresses or FQDN to which OnGuard agent will send request. This will override the Default ClearPass Server IPs. Object Type: string

    Maps to 'replace_onguard_policy_manager_zones_name_by_name' in pyclearpass (PUT /onguard/policy-manager-zones/name/{name}).
    """
    await ctx.info(f"Replacing OnGuard Policy Manager zone {name}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_replace_policy_manager_zone_by_name(
            name=name,
            zone_data=zone_data,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": f"Replaced OnGuard Policy Manager zone {name}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard replace policy manager zone by name: {e}")
        return await format_api_error(e, "onguard replace policy manager zone by name")
    except Exception as e:
        logger.error(f"Unexpected error during onguard replace policy manager zone by name: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard replace policy manager zone by name",
        }


@operation(domain="endpoint_visibility")
async def onguard_delete_policy_manager_zone_by_id(
    ctx: Context,
    policy_manager_zones_id: int = Field(..., description="Numeric ID of the OnGuard Policy Manager zone"),
) -> Dict[str, Any]:
    """
    Delete authentication server IP addresses for Policy Manager Zone.

    Permanently deletes the OnGuard Policy Manager zone. This cannot be undone.

    Maps to 'delete_onguard_policy_manager_zones_by_policy_manager_zones_id' in pyclearpass (DELETE /onguard/policy-manager-zones/{policy_manager_zones_id}).
    """
    await ctx.info(f"Deleting OnGuard Policy Manager zone {policy_manager_zones_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_delete_policy_manager_zone_by_id(
            policy_manager_zones_id=policy_manager_zones_id,
        )

        return {
            "success": True,
            "message": f"Deleted OnGuard Policy Manager zone {policy_manager_zones_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard delete policy manager zone by id: {e}")
        return await format_api_error(e, "onguard delete policy manager zone by id")
    except Exception as e:
        logger.error(f"Unexpected error during onguard delete policy manager zone by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard delete policy manager zone by id",
        }


@operation(domain="endpoint_visibility")
async def onguard_get_policy_manager_zone_by_id(
    ctx: Context,
    policy_manager_zones_id: int = Field(..., description="Numeric ID of the OnGuard Policy Manager zone"),
) -> Dict[str, Any]:
    """
    Get Client Subnets and Server IPs for Policy Manager Zone.

    Retrieves a single OnGuard Policy Manager zone.

    Maps to 'get_onguard_policy_manager_zones_by_policy_manager_zones_id' in pyclearpass (GET /onguard/policy-manager-zones/{policy_manager_zones_id}).
    """
    await ctx.info(f"Retrieving OnGuard Policy Manager zone {policy_manager_zones_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_get_policy_manager_zone_by_id(
            policy_manager_zones_id=policy_manager_zones_id,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": f"Retrieved OnGuard Policy Manager zone {policy_manager_zones_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard get policy manager zone by id: {e}")
        return await format_api_error(e, "onguard get policy manager zone by id")
    except Exception as e:
        logger.error(f"Unexpected error during onguard get policy manager zone by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard get policy manager zone by id",
        }


@operation(domain="endpoint_visibility")
async def onguard_update_policy_manager_zone_by_id(
    ctx: Context,
    policy_manager_zones_id: int = Field(..., description="Numeric ID of the OnGuard Policy Manager zone"),
    zone_data: Dict[str, Any] = Field(..., description="Supported keys include: client_subnets, override_server_ips."),
) -> Dict[str, Any]:
    """
    Update authentication server IP addresses for Policy Manager Zone.

    Updates only the supplied fields of the OnGuard Policy Manager zone (HTTP PATCH).

    Body fields (zone_data):
        - client_subnets: client subnet addresses specific to the Policy Manager zone. Object Type: string
        - override_server_ips: IP addresses or FQDN to which OnGuard agent will send request. This will override the Default ClearPass Server IPs. Object Type: string

    Maps to 'update_onguard_policy_manager_zones_by_policy_manager_zones_id' in pyclearpass (PATCH /onguard/policy-manager-zones/{policy_manager_zones_id}).
    """
    await ctx.info(f"Updating OnGuard Policy Manager zone {policy_manager_zones_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_update_policy_manager_zone_by_id(
            policy_manager_zones_id=policy_manager_zones_id,
            zone_data=zone_data,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": f"Updated OnGuard Policy Manager zone {policy_manager_zones_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard update policy manager zone by id: {e}")
        return await format_api_error(e, "onguard update policy manager zone by id")
    except Exception as e:
        logger.error(f"Unexpected error during onguard update policy manager zone by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard update policy manager zone by id",
        }


@operation(domain="endpoint_visibility")
async def onguard_replace_policy_manager_zone_by_id(
    ctx: Context,
    policy_manager_zones_id: int = Field(..., description="Numeric ID of the OnGuard Policy Manager zone"),
    zone_data: Dict[str, Any] = Field(..., description="Required keys: client_subnets. Supported keys include: client_subnets, override_server_ips."),
) -> Dict[str, Any]:
    """
    Post Client Subnets and Server IPs for Policy Manager Zone.

    Replaces the whole OnGuard Policy Manager zone definition (HTTP PUT); omitted fields are reset.

    Body fields (zone_data):
        - client_subnets: client subnet addresses specific to the Policy Manager zone. Object Type: string
        - override_server_ips: IP addresses or FQDN to which OnGuard agent will send request. This will override the Default ClearPass Server IPs. Object Type: string

    Maps to 'replace_onguard_policy_manager_zones_by_policy_manager_zones_id' in pyclearpass (PUT /onguard/policy-manager-zones/{policy_manager_zones_id}).
    """
    await ctx.info(f"Replacing OnGuard Policy Manager zone {policy_manager_zones_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_replace_policy_manager_zone_by_id(
            policy_manager_zones_id=policy_manager_zones_id,
            zone_data=zone_data,
        )

        return {
            "success": True,
            "policy_manager_zone": response,
            "message": f"Replaced OnGuard Policy Manager zone {policy_manager_zones_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard replace policy manager zone by id: {e}")
        return await format_api_error(e, "onguard replace policy manager zone by id")
    except Exception as e:
        logger.error(f"Unexpected error during onguard replace policy manager zone by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard replace policy manager zone by id",
        }


# ============================================================================
# OnGuard Settings
# ============================================================================

@operation(domain="endpoint_visibility")
async def onguard_list_settings(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get OnGuard settings.

    Returns the configured OnGuard settings on the ClearPass server.

    Maps to 'get_onguard_settings' in pyclearpass (GET /onguard/settings).
    """
    await ctx.info("Retrieving OnGuard settings...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_list_settings()

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "onguard_settings": items,
            "message": f"Retrieved {len(items)} OnGuard settings",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard list settings: {e}")
        return await format_api_error(e, "onguard list settings")
    except Exception as e:
        logger.error(f"Unexpected error during onguard list settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard list settings",
        }


@operation(domain="endpoint_visibility")
async def onguard_update_settings(
    ctx: Context,
    settings_data: Dict[str, Any] = Field(..., description="Supported keys include: mode, interfaces, web_agent_interfaces, auth_type, field_username_caption, field_password_caption, cert_filter_criteria, upgrade_action, install_vpn_component, version, agentLibraryVersion, installer_modified_time."),
) -> Dict[str, Any]:
    """
    Update OnGuard settings.

    Creates (or, for singleton settings resources, updates) the OnGuard settings.

    Body fields (settings_data):
        - mode: Mode of operation. Object Type: string
        - interfaces: [wired, wireless, vpn, other]: Network interfaces Agent should monitor. Object Type: string
        - web_agent_interfaces: [wired, wireless, vpn, other]: Network interfaces Native Dissolvable Agent should monitor. Object Type: string
        - auth_type: Authentication type. Object Type: string
        - field_username_caption: Caption for username field. Object Type: string
        - field_password_caption: Caption for password field. Object Type: string
        - cert_filter_criteria: Filter criteria used by OnGuard client to select certificates for authentication. Object Type: string
        - upgrade_action: Agent action when an update is available. Object Type: string
        - install_vpn_component: Install VIA component. Object Type: boolean
        - version: Agent version. This is read only field. Object Type: string
        - agentLibraryVersion: Version of the OnGuard Agent Library. This is read-only field. Object Type: string
        - installer_modified_time: Time when Agent Installers was last updated. This is read only field. Object Type: string
        - installer_modified_time_formatted: Formatted Time when Agent Installers was last updated. This is read only field. Object Type: string
        - agent_installers: Details about Agent installers. This is read-only field. Object Type: object
        - agent_web_installers: Details about Native Dissolvable Agent installers. This is read only field. Object Type: object
        - ip_version_onguard: IP Version for Server Communication (OnGuard). Object Type: string
        - ip_version_native: IP Version for Server Communication (Native). Object Type: string
        - ip_version_agentless: IP Version for Server Communication (Agentless). Object Type: string
        - custom_remediation: Customize webpage details for Agent Remediation UI. Input should be in JSON format.. Object Type: object

    Maps to 'new_onguard_settings' in pyclearpass (POST /onguard/settings).
    """
    await ctx.info("Submitting OnGuard settings...")

    try:
        client = await get_clearpass_client()
        response = await client.onguard_update_settings(
            settings_data=settings_data,
        )

        return {
            "success": True,
            "onguard_settings": response,
            "message": "Saved OnGuard settings",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to onguard update settings: {e}")
        return await format_api_error(e, "onguard update settings")
    except Exception as e:
        logger.error(f"Unexpected error during onguard update settings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to onguard update settings",
        }


# ============================================================================
# Profiler Subnet Mappings
# ============================================================================

@operation(domain="endpoint_visibility")
async def profiler_list_subnet_mappings(
    ctx: Context,
) -> Dict[str, Any]:
    """
    Get a list of profiler subnet mappings.

    Returns the configured profiler subnet mappings on the ClearPass server.

    Maps to 'get_profiler_subnet_mapping' in pyclearpass (GET /profiler-subnet-mapping).
    """
    await ctx.info("Retrieving profiler subnet mappings...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_list_subnet_mappings()

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "profiler_subnet_mappings": items,
            "message": f"Retrieved {len(items)} profiler subnet mappings",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler list subnet mappings: {e}")
        return await format_api_error(e, "profiler list subnet mappings")
    except Exception as e:
        logger.error(f"Unexpected error during profiler list subnet mappings: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler list subnet mappings",
        }


@operation(domain="endpoint_visibility")
async def profiler_create_subnet_mapping(
    ctx: Context,
    mapping_data: Dict[str, Any] = Field(..., description="Required keys: network, scan_type, ext_accounts. Supported keys include: network, scan_type, ext_accounts."),
) -> Dict[str, Any]:
    """
    Add a profiler subnet mapping.

    Creates (or, for singleton settings resources, updates) the profiler subnet mapping.

    Body fields (mapping_data):
        - network: IP Subnets/IP Addresses in CSV format (e.g. "10.21.11.0/24,12.12.12.12"). Object Type: string
        - scan_type: Scan type of Profiler Subnet Mapping. Object Type: string
        - ext_accounts: List of external account names according to Scan Type (e.g. ["acc-wmi-1", "acc-wmi-2", "acc-wmi-3"] for Scan Type WMI). Object Type: array

    Maps to 'new_profiler_subnet_mapping' in pyclearpass (POST /profiler-subnet-mapping).
    """
    await ctx.info("Submitting profiler subnet mappings...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_create_subnet_mapping(
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": "Saved profiler subnet mapping",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler create subnet mapping: {e}")
        return await format_api_error(e, "profiler create subnet mapping")
    except Exception as e:
        logger.error(f"Unexpected error during profiler create subnet mapping: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler create subnet mapping",
        }


@operation(domain="endpoint_visibility")
async def profiler_delete_subnet_mapping_by_network(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    network: str = Field(..., description="IP subnets / IP addresses in CSV format (e.g. '10.21.11.0/24,12.12.12.12')"),
) -> Dict[str, Any]:
    """
    Delete a profiler subnet mapping.

    Permanently deletes the profiler subnet mapping. This cannot be undone.

    Maps to 'delete_profiler_subnet_mapping_by_scan_type_network_network' in pyclearpass (DELETE /profiler-subnet-mapping/{scan_type}/network/{network}).
    """
    await ctx.info(f"Deleting profiler subnet mapping {scan_type} / {network}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_delete_subnet_mapping_by_network(
            scan_type=scan_type,
            network=network,
        )

        return {
            "success": True,
            "message": f"Deleted profiler subnet mapping {scan_type} / {network}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler delete subnet mapping by network: {e}")
        return await format_api_error(e, "profiler delete subnet mapping by network")
    except Exception as e:
        logger.error(f"Unexpected error during profiler delete subnet mapping by network: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler delete subnet mapping by network",
        }


@operation(domain="endpoint_visibility")
async def profiler_get_subnet_mapping_by_network(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    network: str = Field(..., description="IP subnets / IP addresses in CSV format (e.g. '10.21.11.0/24,12.12.12.12')"),
) -> Dict[str, Any]:
    """
    Get a profiler subnet mapping.

    Retrieves a single profiler subnet mapping.

    Maps to 'get_profiler_subnet_mapping_by_scan_type_network_network' in pyclearpass (GET /profiler-subnet-mapping/{scan_type}/network/{network}).
    """
    await ctx.info(f"Retrieving profiler subnet mapping {scan_type} / {network}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_get_subnet_mapping_by_network(
            scan_type=scan_type,
            network=network,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": f"Retrieved profiler subnet mapping {scan_type} / {network}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler get subnet mapping by network: {e}")
        return await format_api_error(e, "profiler get subnet mapping by network")
    except Exception as e:
        logger.error(f"Unexpected error during profiler get subnet mapping by network: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler get subnet mapping by network",
        }


@operation(domain="endpoint_visibility")
async def profiler_update_subnet_mapping_by_network(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    network: str = Field(..., description="IP subnets / IP addresses in CSV format (e.g. '10.21.11.0/24,12.12.12.12')"),
    mapping_data: Dict[str, Any] = Field(..., description="Supported keys include: network, scan_type, ext_accounts."),
) -> Dict[str, Any]:
    """
    Update some fields of a profiler subnet mapping.

    Updates only the supplied fields of the profiler subnet mapping (HTTP PATCH).

    Body fields (mapping_data):
        - network: IP Subnets/IP Addresses in CSV format (e.g. "10.21.11.0/24,12.12.12.12"). Object Type: string
        - scan_type: Scan type of Profiler Subnet Mapping. Object Type: string
        - ext_accounts: List of external account names according to Scan Type (e.g. ["acc-wmi-1", "acc-wmi-2", "acc-wmi-3"] for Scan Type WMI). Object Type: array

    Maps to 'update_profiler_subnet_mapping_by_scan_type_network_network' in pyclearpass (PATCH /profiler-subnet-mapping/{scan_type}/network/{network}).
    """
    await ctx.info(f"Updating profiler subnet mapping {scan_type} / {network}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_update_subnet_mapping_by_network(
            scan_type=scan_type,
            network=network,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": f"Updated profiler subnet mapping {scan_type} / {network}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler update subnet mapping by network: {e}")
        return await format_api_error(e, "profiler update subnet mapping by network")
    except Exception as e:
        logger.error(f"Unexpected error during profiler update subnet mapping by network: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler update subnet mapping by network",
        }


@operation(domain="endpoint_visibility")
async def profiler_replace_subnet_mapping_by_network(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    network: str = Field(..., description="IP subnets / IP addresses in CSV format (e.g. '10.21.11.0/24,12.12.12.12')"),
    mapping_data: Dict[str, Any] = Field(..., description="Required keys: network, scan_type, ext_accounts. Supported keys include: network, scan_type, ext_accounts."),
) -> Dict[str, Any]:
    """
    Replace a profiler subnet mapping.

    Replaces the whole profiler subnet mapping definition (HTTP PUT); omitted fields are reset.

    Body fields (mapping_data):
        - network: IP Subnets/IP Addresses in CSV format (e.g. "10.21.11.0/24,12.12.12.12"). Object Type: string
        - scan_type: Scan type of Profiler Subnet Mapping. Object Type: string
        - ext_accounts: List of external account names according to Scan Type (e.g. ["acc-wmi-1", "acc-wmi-2", "acc-wmi-3"] for Scan Type WMI). Object Type: array

    Maps to 'replace_profiler_subnet_mapping_by_scan_type_network_network' in pyclearpass (PUT /profiler-subnet-mapping/{scan_type}/network/{network}).
    """
    await ctx.info(f"Replacing profiler subnet mapping {scan_type} / {network}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_replace_subnet_mapping_by_network(
            scan_type=scan_type,
            network=network,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": f"Replaced profiler subnet mapping {scan_type} / {network}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler replace subnet mapping by network: {e}")
        return await format_api_error(e, "profiler replace subnet mapping by network")
    except Exception as e:
        logger.error(f"Unexpected error during profiler replace subnet mapping by network: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler replace subnet mapping by network",
        }


@operation(domain="endpoint_visibility")
async def profiler_delete_subnet_mapping_by_id(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    profiler_subnet_mapping_id: int = Field(..., description="Numeric ID of the profiler subnet mapping"),
) -> Dict[str, Any]:
    """
    Delete a profiler subnet mapping.

    Permanently deletes the profiler subnet mapping. This cannot be undone.

    Maps to 'delete_profiler_subnet_mapping_by_scan_type_profiler_subnet_mapping_id' in pyclearpass (DELETE /profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}).
    """
    await ctx.info(f"Deleting profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_delete_subnet_mapping_by_id(
            scan_type=scan_type,
            profiler_subnet_mapping_id=profiler_subnet_mapping_id,
        )

        return {
            "success": True,
            "message": f"Deleted profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler delete subnet mapping by id: {e}")
        return await format_api_error(e, "profiler delete subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during profiler delete subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler delete subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def profiler_get_subnet_mapping_by_id(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    profiler_subnet_mapping_id: int = Field(..., description="Numeric ID of the profiler subnet mapping"),
) -> Dict[str, Any]:
    """
    Get a profiler subnet mapping.

    Retrieves a single profiler subnet mapping.

    Maps to 'get_profiler_subnet_mapping_by_scan_type_profiler_subnet_mapping_id' in pyclearpass (GET /profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}).
    """
    await ctx.info(f"Retrieving profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_get_subnet_mapping_by_id(
            scan_type=scan_type,
            profiler_subnet_mapping_id=profiler_subnet_mapping_id,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": f"Retrieved profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler get subnet mapping by id: {e}")
        return await format_api_error(e, "profiler get subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during profiler get subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler get subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def profiler_update_subnet_mapping_by_id(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    profiler_subnet_mapping_id: int = Field(..., description="Numeric ID of the profiler subnet mapping"),
    mapping_data: Dict[str, Any] = Field(..., description="Supported keys include: network, scan_type, ext_accounts."),
) -> Dict[str, Any]:
    """
    Update some fields of a profiler subnet mapping.

    Updates only the supplied fields of the profiler subnet mapping (HTTP PATCH).

    Body fields (mapping_data):
        - network: IP Subnets/IP Addresses in CSV format (e.g. "10.21.11.0/24,12.12.12.12"). Object Type: string
        - scan_type: Scan type of Profiler Subnet Mapping. Object Type: string
        - ext_accounts: List of external account names according to Scan Type (e.g. ["acc-wmi-1", "acc-wmi-2", "acc-wmi-3"] for Scan Type WMI). Object Type: array

    Maps to 'update_profiler_subnet_mapping_by_scan_type_profiler_subnet_mapping_id' in pyclearpass (PATCH /profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}).
    """
    await ctx.info(f"Updating profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_update_subnet_mapping_by_id(
            scan_type=scan_type,
            profiler_subnet_mapping_id=profiler_subnet_mapping_id,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": f"Updated profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler update subnet mapping by id: {e}")
        return await format_api_error(e, "profiler update subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during profiler update subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler update subnet mapping by id",
        }


@operation(domain="endpoint_visibility")
async def profiler_replace_subnet_mapping_by_id(
    ctx: Context,
    scan_type: str = Field(..., description="Scan type of the profiler subnet mapping (e.g. 'WMI', 'SSH', 'SNMP')"),
    profiler_subnet_mapping_id: int = Field(..., description="Numeric ID of the profiler subnet mapping"),
    mapping_data: Dict[str, Any] = Field(..., description="Required keys: network, scan_type, ext_accounts. Supported keys include: network, scan_type, ext_accounts."),
) -> Dict[str, Any]:
    """
    Replace a profiler subnet mapping.

    Replaces the whole profiler subnet mapping definition (HTTP PUT); omitted fields are reset.

    Body fields (mapping_data):
        - network: IP Subnets/IP Addresses in CSV format (e.g. "10.21.11.0/24,12.12.12.12"). Object Type: string
        - scan_type: Scan type of Profiler Subnet Mapping. Object Type: string
        - ext_accounts: List of external account names according to Scan Type (e.g. ["acc-wmi-1", "acc-wmi-2", "acc-wmi-3"] for Scan Type WMI). Object Type: array

    Maps to 'replace_profiler_subnet_mapping_by_scan_type_profiler_subnet_mapping_id' in pyclearpass (PUT /profiler-subnet-mapping/{scan_type}/{profiler_subnet_mapping_id}).
    """
    await ctx.info(f"Replacing profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.profiler_replace_subnet_mapping_by_id(
            scan_type=scan_type,
            profiler_subnet_mapping_id=profiler_subnet_mapping_id,
            mapping_data=mapping_data,
        )

        return {
            "success": True,
            "profiler_subnet_mapping": response,
            "message": f"Replaced profiler subnet mapping {scan_type} / {profiler_subnet_mapping_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to profiler replace subnet mapping by id: {e}")
        return await format_api_error(e, "profiler replace subnet mapping by id")
    except Exception as e:
        logger.error(f"Unexpected error during profiler replace subnet mapping by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to profiler replace subnet mapping by id",
        }


# ============================================================================
# Windows Hotfixes
# ============================================================================

@operation(domain="endpoint_visibility")
async def list_windows_hotfixes(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"corp\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    Get a list of Windows Hotfixes.

    Returns the configured Windows hotfixes on the ClearPass server.

    Maps to 'get_windows_hotfix' in pyclearpass (GET /windows-hotfix).
    """
    await ctx.info("Retrieving Windows hotfixes...")

    try:
        client = await get_clearpass_client()
        response = await client.list_windows_hotfixes(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )

        items = _extract_items(response)
        return {
            "success": True,
            "total_count": len(items),
            "windows_hotfixes": items,
            "message": f"Retrieved {len(items)} Windows hotfixes",
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "has_more": len(items) == limit if limit else False,
            },
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to list windows hotfixes: {e}")
        return await format_api_error(e, "list windows hotfixes")
    except Exception as e:
        logger.error(f"Unexpected error during list windows hotfixes: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to list windows hotfixes",
        }


@operation(domain="endpoint_visibility")
async def create_windows_hotfix(
    ctx: Context,
    hotfix_data: Dict[str, Any] = Field(..., description="Required keys: kbid, operating_system, title, severity_rating. Supported keys include: kbid, operating_system, title, severity_rating, superseded_by, superseding, reboot_behavior, release_date, url, description."),
) -> Dict[str, Any]:
    """
    Add a Windows Hotfix.

    Creates (or, for singleton settings resources, updates) the Windows hotfix.

    Body fields (hotfix_data):
        - kbid: KBID of the windows hotfix. Object Type: string
        - operating_system: OS of the windows hotfix. Object Type: string
        - title: Title of the windows hotfix. Object Type: string
        - severity_rating: Severity rating of the windows hotfix. Object Type: string
        - superseded_by: Superseded_by of the windows hotfix. Object Type: string
        - superseding: Superseding of the windows hotfix. Object Type: string
        - reboot_behavior: Reboot Behavior of the windows hotfix. Object Type: string
        - release_date: Release Date of the windows hotfix. Object Type: string
        - url: URL of the windows hotfix. Object Type: string
        - description: Description of the windows hotfix. Object Type: string

    Maps to 'new_windows_hotfix' in pyclearpass (POST /windows-hotfix).
    """
    await ctx.info("Submitting Windows hotfixes...")

    try:
        client = await get_clearpass_client()
        response = await client.create_windows_hotfix(
            hotfix_data=hotfix_data,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": "Saved Windows hotfix",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to create windows hotfix: {e}")
        return await format_api_error(e, "create windows hotfix")
    except Exception as e:
        logger.error(f"Unexpected error during create windows hotfix: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to create windows hotfix",
        }


@operation(domain="endpoint_visibility")
async def delete_windows_hotfix_by_kbid(
    ctx: Context,
    kbid: str = Field(..., description="Knowledge Base ID (KBID) of the Windows hotfix"),
    operating_system: str = Field(..., description="Operating system the Windows hotfix applies to"),
) -> Dict[str, Any]:
    """
    Delete a windows hotfix by kbid and os.

    Permanently deletes the Windows hotfix. This cannot be undone.

    Maps to 'delete_windows_hotfix_kbid_by_kbid_operating_system_operating_system' in pyclearpass (DELETE /windows-hotfix/kbid/{kbid}/operating_system/{operating_system}).
    """
    await ctx.info(f"Deleting Windows hotfix {kbid} / {operating_system}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_windows_hotfix_by_kbid(
            kbid=kbid,
            operating_system=operating_system,
        )

        return {
            "success": True,
            "message": f"Deleted Windows hotfix {kbid} / {operating_system}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete windows hotfix by kbid: {e}")
        return await format_api_error(e, "delete windows hotfix by kbid")
    except Exception as e:
        logger.error(f"Unexpected error during delete windows hotfix by kbid: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete windows hotfix by kbid",
        }


@operation(domain="endpoint_visibility")
async def get_windows_hotfix_by_kbid(
    ctx: Context,
    kbid: str = Field(..., description="Knowledge Base ID (KBID) of the Windows hotfix"),
    operating_system: str = Field(..., description="Operating system the Windows hotfix applies to"),
) -> Dict[str, Any]:
    """
    Get a windows hotfix by kbid and os.

    Retrieves a single Windows hotfix.

    Maps to 'get_windows_hotfix_kbid_by_kbid_operating_system_operating_system' in pyclearpass (GET /windows-hotfix/kbid/{kbid}/operating_system/{operating_system}).
    """
    await ctx.info(f"Retrieving Windows hotfix {kbid} / {operating_system}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_windows_hotfix_by_kbid(
            kbid=kbid,
            operating_system=operating_system,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": f"Retrieved Windows hotfix {kbid} / {operating_system}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get windows hotfix by kbid: {e}")
        return await format_api_error(e, "get windows hotfix by kbid")
    except Exception as e:
        logger.error(f"Unexpected error during get windows hotfix by kbid: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get windows hotfix by kbid",
        }


@operation(domain="endpoint_visibility")
async def update_windows_hotfix_by_kbid(
    ctx: Context,
    kbid: str = Field(..., description="Knowledge Base ID (KBID) of the Windows hotfix"),
    operating_system: str = Field(..., description="Operating system the Windows hotfix applies to"),
    hotfix_data: Dict[str, Any] = Field(..., description="Supported keys include: kbid, operating_system, title, severity_rating, superseded_by, superseding, reboot_behavior, release_date, url, description."),
) -> Dict[str, Any]:
    """
    Update some fields of a windows hotfix by kbid and os.

    Updates only the supplied fields of the Windows hotfix (HTTP PATCH).

    Body fields (hotfix_data):
        - kbid: KBID of the windows hotfix. Object Type: string
        - operating_system: OS of the windows hotfix. Object Type: string
        - title: Title of the windows hotfix. Object Type: string
        - severity_rating: Severity rating of the windows hotfix. Object Type: string
        - superseded_by: Superseded_by of the windows hotfix. Object Type: string
        - superseding: Superseding of the windows hotfix. Object Type: string
        - reboot_behavior: Reboot Behavior of the windows hotfix. Object Type: string
        - release_date: Release Date of the windows hotfix. Object Type: string
        - url: URL of the windows hotfix. Object Type: string
        - description: Description of the windows hotfix. Object Type: string

    Maps to 'update_windows_hotfix_kbid_by_kbid_operating_system_operating_system' in pyclearpass (PATCH /windows-hotfix/kbid/{kbid}/operating_system/{operating_system}).
    """
    await ctx.info(f"Updating Windows hotfix {kbid} / {operating_system}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_windows_hotfix_by_kbid(
            kbid=kbid,
            operating_system=operating_system,
            hotfix_data=hotfix_data,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": f"Updated Windows hotfix {kbid} / {operating_system}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update windows hotfix by kbid: {e}")
        return await format_api_error(e, "update windows hotfix by kbid")
    except Exception as e:
        logger.error(f"Unexpected error during update windows hotfix by kbid: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update windows hotfix by kbid",
        }


@operation(domain="endpoint_visibility")
async def replace_windows_hotfix_by_kbid(
    ctx: Context,
    kbid: str = Field(..., description="Knowledge Base ID (KBID) of the Windows hotfix"),
    operating_system: str = Field(..., description="Operating system the Windows hotfix applies to"),
    hotfix_data: Dict[str, Any] = Field(..., description="Required keys: kbid, operating_system, title, severity_rating. Supported keys include: kbid, operating_system, title, severity_rating, superseded_by, superseding, reboot_behavior, release_date, url, description."),
) -> Dict[str, Any]:
    """
    Replace a windows hotfix by kbid and os.

    Replaces the whole Windows hotfix definition (HTTP PUT); omitted fields are reset.

    Body fields (hotfix_data):
        - kbid: KBID of the windows hotfix. Object Type: string
        - operating_system: OS of the windows hotfix. Object Type: string
        - title: Title of the windows hotfix. Object Type: string
        - severity_rating: Severity rating of the windows hotfix. Object Type: string
        - superseded_by: Superseded_by of the windows hotfix. Object Type: string
        - superseding: Superseding of the windows hotfix. Object Type: string
        - reboot_behavior: Reboot Behavior of the windows hotfix. Object Type: string
        - release_date: Release Date of the windows hotfix. Object Type: string
        - url: URL of the windows hotfix. Object Type: string
        - description: Description of the windows hotfix. Object Type: string

    Maps to 'replace_windows_hotfix_kbid_by_kbid_operating_system_operating_system' in pyclearpass (PUT /windows-hotfix/kbid/{kbid}/operating_system/{operating_system}).
    """
    await ctx.info(f"Replacing Windows hotfix {kbid} / {operating_system}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_windows_hotfix_by_kbid(
            kbid=kbid,
            operating_system=operating_system,
            hotfix_data=hotfix_data,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": f"Replaced Windows hotfix {kbid} / {operating_system}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace windows hotfix by kbid: {e}")
        return await format_api_error(e, "replace windows hotfix by kbid")
    except Exception as e:
        logger.error(f"Unexpected error during replace windows hotfix by kbid: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace windows hotfix by kbid",
        }


@operation(domain="endpoint_visibility")
async def delete_windows_hotfix_by_id(
    ctx: Context,
    windows_hotfix_id: int = Field(..., description="Numeric ID of the Windows hotfix"),
) -> Dict[str, Any]:
    """
    Delete a windows hotfix.

    Permanently deletes the Windows hotfix. This cannot be undone.

    Maps to 'delete_windows_hotfix_by_windows_hotfix_id' in pyclearpass (DELETE /windows-hotfix/{windows_hotfix_id}).
    """
    await ctx.info(f"Deleting Windows hotfix {windows_hotfix_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.delete_windows_hotfix_by_id(
            windows_hotfix_id=windows_hotfix_id,
        )

        return {
            "success": True,
            "message": f"Deleted Windows hotfix {windows_hotfix_id}",
            "details": response,
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to delete windows hotfix by id: {e}")
        return await format_api_error(e, "delete windows hotfix by id")
    except Exception as e:
        logger.error(f"Unexpected error during delete windows hotfix by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to delete windows hotfix by id",
        }


@operation(domain="endpoint_visibility")
async def get_windows_hotfix_by_id(
    ctx: Context,
    windows_hotfix_id: int = Field(..., description="Numeric ID of the Windows hotfix"),
) -> Dict[str, Any]:
    """
    Get a windows hotfix.

    Retrieves a single Windows hotfix.

    Maps to 'get_windows_hotfix_by_windows_hotfix_id' in pyclearpass (GET /windows-hotfix/{windows_hotfix_id}).
    """
    await ctx.info(f"Retrieving Windows hotfix {windows_hotfix_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.get_windows_hotfix_by_id(
            windows_hotfix_id=windows_hotfix_id,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": f"Retrieved Windows hotfix {windows_hotfix_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to get windows hotfix by id: {e}")
        return await format_api_error(e, "get windows hotfix by id")
    except Exception as e:
        logger.error(f"Unexpected error during get windows hotfix by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to get windows hotfix by id",
        }


@operation(domain="endpoint_visibility")
async def update_windows_hotfix_by_id(
    ctx: Context,
    windows_hotfix_id: int = Field(..., description="Numeric ID of the Windows hotfix"),
    hotfix_data: Dict[str, Any] = Field(..., description="Supported keys include: kbid, operating_system, title, severity_rating, superseded_by, superseding, reboot_behavior, release_date, url, description."),
) -> Dict[str, Any]:
    """
    Update some fields of a windows hotfix.

    Updates only the supplied fields of the Windows hotfix (HTTP PATCH).

    Body fields (hotfix_data):
        - kbid: KBID of the windows hotfix. Object Type: string
        - operating_system: OS of the windows hotfix. Object Type: string
        - title: Title of the windows hotfix. Object Type: string
        - severity_rating: Severity rating of the windows hotfix. Object Type: string
        - superseded_by: Superseded_by of the windows hotfix. Object Type: string
        - superseding: Superseding of the windows hotfix. Object Type: string
        - reboot_behavior: Reboot Behavior of the windows hotfix. Object Type: string
        - release_date: Release Date of the windows hotfix. Object Type: string
        - url: URL of the windows hotfix. Object Type: string
        - description: Description of the windows hotfix. Object Type: string

    Maps to 'update_windows_hotfix_by_windows_hotfix_id' in pyclearpass (PATCH /windows-hotfix/{windows_hotfix_id}).
    """
    await ctx.info(f"Updating Windows hotfix {windows_hotfix_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.update_windows_hotfix_by_id(
            windows_hotfix_id=windows_hotfix_id,
            hotfix_data=hotfix_data,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": f"Updated Windows hotfix {windows_hotfix_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to update windows hotfix by id: {e}")
        return await format_api_error(e, "update windows hotfix by id")
    except Exception as e:
        logger.error(f"Unexpected error during update windows hotfix by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to update windows hotfix by id",
        }


@operation(domain="endpoint_visibility")
async def replace_windows_hotfix_by_id(
    ctx: Context,
    windows_hotfix_id: int = Field(..., description="Numeric ID of the Windows hotfix"),
    hotfix_data: Dict[str, Any] = Field(..., description="Required keys: kbid, operating_system, title, severity_rating. Supported keys include: kbid, operating_system, title, severity_rating, superseded_by, superseding, reboot_behavior, release_date, url, description."),
) -> Dict[str, Any]:
    """
    Replace a windows hotfix.

    Replaces the whole Windows hotfix definition (HTTP PUT); omitted fields are reset.

    Body fields (hotfix_data):
        - kbid: KBID of the windows hotfix. Object Type: string
        - operating_system: OS of the windows hotfix. Object Type: string
        - title: Title of the windows hotfix. Object Type: string
        - severity_rating: Severity rating of the windows hotfix. Object Type: string
        - superseded_by: Superseded_by of the windows hotfix. Object Type: string
        - superseding: Superseding of the windows hotfix. Object Type: string
        - reboot_behavior: Reboot Behavior of the windows hotfix. Object Type: string
        - release_date: Release Date of the windows hotfix. Object Type: string
        - url: URL of the windows hotfix. Object Type: string
        - description: Description of the windows hotfix. Object Type: string

    Maps to 'replace_windows_hotfix_by_windows_hotfix_id' in pyclearpass (PUT /windows-hotfix/{windows_hotfix_id}).
    """
    await ctx.info(f"Replacing Windows hotfix {windows_hotfix_id}...")

    try:
        client = await get_clearpass_client()
        response = await client.replace_windows_hotfix_by_id(
            windows_hotfix_id=windows_hotfix_id,
            hotfix_data=hotfix_data,
        )

        return {
            "success": True,
            "windows_hotfix": response,
            "message": f"Replaced Windows hotfix {windows_hotfix_id}",
        }

    except ClearPassAPIError as e:
        logger.error(f"Failed to replace windows hotfix by id: {e}")
        return await format_api_error(e, "replace windows hotfix by id")
    except Exception as e:
        logger.error(f"Unexpected error during replace windows hotfix by id: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while trying to replace windows hotfix by id",
        }
