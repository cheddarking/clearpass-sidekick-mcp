"""
MCP operations for ClearPass Downloadable User Role (DUR) enforcement-profile objects.

A Downloadable User Role is not a single object: it is assembled from per-product building
blocks served under ``/enforcement-profile-dur/<resource>/{product_name}``. This module exposes
all 14 resource families (session/stateless/MAC/ethertype ACLs, QoS, policer and VoIP profiles,
NAT pools, net destinations and services, DUR classes, DUR policies, time ranges and captive
portal profiles) with the full ten-operation surface each: list, create, and get/update/replace/
delete addressed either by numeric id or by name.

Every DUR operation is scoped by ``product_name`` — the Aruba product the role is downloaded to
(ArubaOS-CX, ArubaOS-Switch, Mobility Access Switch, Mobility Controller). The same object name
under two different products is two different objects.

The module also carries the two full-replace (PUT) operations on the base
``/enforcement-profile`` resource, which complement the PATCH-based
``update_enforcement_profile`` in :mod:`src.tools.enforcement_profiles`.

All operation names are prefixed ``dur_`` so they stay unique across the global registry.
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
#
# The DUR surface is 14 near-identical resource families x 10 verbs. The wire
# handling (client lookup, response unwrapping, error shaping) is identical for
# every one of them, so it lives here once. Each public operation stays a
# separate named function so the gateway catalogue keeps one entry per endpoint.
# ============================================================================


def _extract_items(response: Any) -> List[Dict[str, Any]]:
    """Pull the collection out of a ClearPass DUR list response.

    The DUR collection endpoints do not answer with the ``_embedded.items``
    HAL envelope the rest of the API uses -- they return ``{"list": [...],
    "_links": {...}}``. Reading only the HAL shapes reported an empty
    collection for every populated DUR family, so ``list`` is handled too.
    """
    if isinstance(response, dict):
        embedded = response.get("_embedded")
        if isinstance(embedded, dict) and isinstance(embedded.get("items"), list):
            return embedded["items"]
        if isinstance(response.get("items"), list):
            return response["items"]
        if isinstance(response.get("list"), list):
            return response["list"]
    return []


async def _dur_list(
    ctx: Context,
    *,
    client_method: str,
    resource_plural: str,
    product_name: str,
    filter_str: Optional[str],
    sort: Optional[str],
    offset: Optional[int],
    limit: Optional[int],
    calculate_count: Optional[bool],
) -> Dict[str, Any]:
    """Run a DUR collection GET and shape it for the LLM."""
    operation_label = f"list {resource_plural}"
    await ctx.info(
        f"Retrieving {resource_plural} for product '{product_name}' (limit: {limit})..."
    )
    try:
        client = await get_clearpass_client()
        response = await getattr(client, client_method)(
            product_name=product_name,
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count,
        )
        items = _extract_items(response)
        total_count = response.get("count", len(items)) if isinstance(response, dict) else len(items)
        return {
            "success": True,
            "product_name": product_name,
            "items": items,
            "count": len(items),
            "total_count": total_count,
            "message": (
                f"Retrieved {len(items)} {resource_plural} for product '{product_name}'"
            ),
            "pagination_info": {
                "offset": offset or 0,
                "limit": limit,
                "returned": len(items),
            },
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to {operation_label}: {e}")
        return await format_api_error(e, operation_label)
    except Exception as e:
        logger.error(f"Unexpected error trying to {operation_label}: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"An unexpected error occurred while trying to {operation_label}",
        }


async def _dur_call(
    ctx: Context,
    *,
    client_method: str,
    call_kwargs: Dict[str, Any],
    operation_label: str,
    info_message: str,
    success_message: str,
    product_name: Optional[str] = None,
    result_key: str = "item",
) -> Dict[str, Any]:
    """Run a single-object DUR call (GET/POST/PATCH/PUT/DELETE) and shape the result."""
    await ctx.info(info_message)
    try:
        client = await get_clearpass_client()
        response = await getattr(client, client_method)(**call_kwargs)
        payload: Dict[str, Any] = {"success": True, "message": success_message}
        if product_name is not None:
            payload["product_name"] = product_name
        payload[result_key] = response
        return payload
    except ClearPassAPIError as e:
        logger.error(f"Failed to {operation_label}: {e}")
        return await format_api_error(e, operation_label)
    except Exception as e:
        logger.error(f"Unexpected error trying to {operation_label}: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"An unexpected error occurred while trying to {operation_label}",
        }


# ============================================================================
# Captive Portal Profiles
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_captive_portal_profiles(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Captive Portal Profiles for an Aruba product.

    Captive Portal Profiles carry the redirect URL (and, for AOS devices, the captive-portal
    attribute block) pushed to a device as part of a Downloadable User Role.

    Maps to 'get_enforcement_profile_dur_captive_portal_profile_by_product_name' in pyclearpass (GET /enforcement-profile-dur/captive-portal-profile/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_captive_portal_profiles",
        resource_plural="DUR Captive Portal Profiles",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_captive_portal_profile(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    captive_portal_profile_data: Dict[str, Any] = Field(..., description="Captive Portal Profile object. Required keys: 'name', 'url'. Recognised top-level keys: name, url, url_hashkey, aos_attributes."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Captive Portal Profile for an Aruba product.

    Captive Portal Profiles carry the redirect URL (and, for AOS devices, the captive-portal
    attribute block) pushed to a device as part of a Downloadable User Role.
    Required body keys: 'name', 'url'.

    Maps to 'new_enforcement_profile_dur_captive_portal_profile_by_product_name' in pyclearpass (POST /enforcement-profile-dur/captive-portal-profile/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_captive_portal_profile",
        call_kwargs={
            "product_name": product_name,
            "captive_portal_profile_data": captive_portal_profile_data,
        },
        operation_label="create DUR Captive Portal Profile",
        info_message=f"Creating DUR Captive Portal Profile for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_captive_portal_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    captive_portal_profile_id: str = Field(..., description="Numeric ID of the Captive Portal Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Captive Portal Profile by numeric ID.

    Captive Portal Profiles carry the redirect URL (and, for AOS devices, the captive-portal
    attribute block) pushed to a device as part of a Downloadable User Role.

    Maps to 'get_enforcement_profile_dur_captive_portal_profile_by_product_name_captive_portal_profile_id' in pyclearpass (GET /enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_captive_portal_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "captive_portal_profile_id": captive_portal_profile_id,
        },
        operation_label="get DUR Captive Portal Profile by ID",
        info_message=f"Retrieving DUR Captive Portal Profile {captive_portal_profile_id} for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile {captive_portal_profile_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_captive_portal_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    captive_portal_profile_id: str = Field(..., description="Numeric ID of the Captive Portal Profile."),
    captive_portal_profile_data: Dict[str, Any] = Field(..., description="Partial Captive Portal Profile object — only the keys you supply are changed. Recognised top-level keys: name, url, url_hashkey, aos_attributes."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Captive Portal Profile by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Captive Portal Profiles carry the redirect URL (and, for AOS devices, the captive-portal
    attribute block) pushed to a device as part of a Downloadable User Role.

    Maps to 'update_enforcement_profile_dur_captive_portal_profile_by_product_name_captive_portal_profile_id' in pyclearpass (PATCH /enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_captive_portal_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "captive_portal_profile_id": captive_portal_profile_id,
            "captive_portal_profile_data": captive_portal_profile_data,
        },
        operation_label="update DUR Captive Portal Profile by ID",
        info_message=f"Updating DUR Captive Portal Profile {captive_portal_profile_id} for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile {captive_portal_profile_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_captive_portal_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    captive_portal_profile_id: str = Field(..., description="Numeric ID of the Captive Portal Profile."),
    captive_portal_profile_data: Dict[str, Any] = Field(..., description="Complete replacement Captive Portal Profile object. Required keys: 'name', 'url'. Recognised top-level keys: name, url, url_hashkey, aos_attributes."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Captive Portal Profile by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Captive Portal Profiles carry the redirect URL (and, for AOS devices, the captive-portal
    attribute block) pushed to a device as part of a Downloadable User Role.

    Maps to 'replace_enforcement_profile_dur_captive_portal_profile_by_product_name_captive_portal_profile_id' in pyclearpass (PUT /enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_captive_portal_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "captive_portal_profile_id": captive_portal_profile_id,
            "captive_portal_profile_data": captive_portal_profile_data,
        },
        operation_label="replace DUR Captive Portal Profile by ID",
        info_message=f"Replacing DUR Captive Portal Profile {captive_portal_profile_id} for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile {captive_portal_profile_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_captive_portal_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    captive_portal_profile_id: str = Field(..., description="Numeric ID of the Captive Portal Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Captive Portal Profile by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Captive Portal Profiles carry the redirect URL (and, for AOS devices, the captive-portal
    attribute block) pushed to a device as part of a Downloadable User Role.

    Maps to 'delete_enforcement_profile_dur_captive_portal_profile_by_product_name_captive_portal_profile_id' in pyclearpass (DELETE /enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_captive_portal_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "captive_portal_profile_id": captive_portal_profile_id,
        },
        operation_label="delete DUR Captive Portal Profile by ID",
        info_message=f"Deleting DUR Captive Portal Profile {captive_portal_profile_id} for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile {captive_portal_profile_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_captive_portal_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Captive Portal Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Captive Portal Profile by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Captive Portal Profile.

    Maps to 'get_enforcement_profile_dur_captive_portal_profile_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_captive_portal_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Captive Portal Profile by name",
        info_message=f"Retrieving DUR Captive Portal Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_captive_portal_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Captive Portal Profile."),
    captive_portal_profile_data: Dict[str, Any] = Field(..., description="Partial Captive Portal Profile object — only the keys you supply are changed. Recognised top-level keys: name, url, url_hashkey, aos_attributes."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Captive Portal Profile by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Captive Portal Profile.

    Maps to 'update_enforcement_profile_dur_captive_portal_profile_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_captive_portal_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "captive_portal_profile_data": captive_portal_profile_data,
        },
        operation_label="update DUR Captive Portal Profile by name",
        info_message=f"Updating DUR Captive Portal Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_captive_portal_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Captive Portal Profile."),
    captive_portal_profile_data: Dict[str, Any] = Field(..., description="Complete replacement Captive Portal Profile object. Required keys: 'name', 'url'. Recognised top-level keys: name, url, url_hashkey, aos_attributes."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Captive Portal Profile by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Captive Portal Profile.

    Maps to 'replace_enforcement_profile_dur_captive_portal_profile_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_captive_portal_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "captive_portal_profile_data": captive_portal_profile_data,
        },
        operation_label="replace DUR Captive Portal Profile by name",
        info_message=f"Replacing DUR Captive Portal Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_captive_portal_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Captive Portal Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Captive Portal Profile by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Captive Portal Profile.

    Maps to 'delete_enforcement_profile_dur_captive_portal_profile_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_captive_portal_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Captive Portal Profile by name",
        info_message=f"Deleting DUR Captive Portal Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Captive Portal Profile '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# DUR Classes
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_dur_classes(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List DUR Classes for an Aruba product.

    DUR Classes are named traffic classifiers (HPE and AOS-CX rule sets) referenced by DUR
    policies.

    Maps to 'get_enforcement_profile_dur_dur_class_by_product_name' in pyclearpass (GET /enforcement-profile-dur/dur-class/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_dur_classes",
        resource_plural="DUR Classes",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_dur_class(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    dur_class_data: Dict[str, Any] = Field(..., description="DUR Class object. Required keys: 'name', 'hpe_rules', 'aos_cx_rules'. Recognised top-level keys: number, packet_match, traffic_match_type, net_source, net_destination, net_service, protocol, source, source_port, source_port_value, protocol_number, destination, destination_value, destination_port, destination_port_value, ip_dscp, vlan_id, ip_precedence, ip_service_type, established, fin, rst, syn, number, packet_match, protocol, protocol_number, source, source_ip_address, source_port, source_port_value, destination, destination_ip_address, destination_port, destination_port_value, dscp, vlan_id, ecn, ip_precedence, service_type, ttl, fragment, count_packet, cwr, ece, urg, ack, psh, rst, syn, fin, established, icmp_type, icmp_type_value, icmp_code."),
) -> Dict[str, Any]:
    """
    Create a DUR Class for an Aruba product.

    DUR Classes are named traffic classifiers (HPE and AOS-CX rule sets) referenced by DUR
    policies.
    Required body keys: 'name', 'hpe_rules', 'aos_cx_rules'.

    Maps to 'new_enforcement_profile_dur_dur_class_by_product_name' in pyclearpass (POST /enforcement-profile-dur/dur-class/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_dur_class",
        call_kwargs={
            "product_name": product_name,
            "dur_class_data": dur_class_data,
        },
        operation_label="create DUR Class",
        info_message=f"Creating DUR Class for product '{product_name}'...",
        success_message=f"DUR Class created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_dur_class_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    dur_class_id: str = Field(..., description="Numeric ID of the DUR Class."),
) -> Dict[str, Any]:
    """
    Get a DUR Class by numeric ID.

    DUR Classes are named traffic classifiers (HPE and AOS-CX rule sets) referenced by DUR
    policies.

    Maps to 'get_enforcement_profile_dur_dur_class_by_product_name_dur_class_id' in pyclearpass (GET /enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_dur_class_by_id",
        call_kwargs={
            "product_name": product_name,
            "dur_class_id": dur_class_id,
        },
        operation_label="get DUR Class by ID",
        info_message=f"Retrieving DUR Class {dur_class_id} for product '{product_name}'...",
        success_message=f"DUR Class {dur_class_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_dur_class_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    dur_class_id: str = Field(..., description="Numeric ID of the DUR Class."),
    dur_class_data: Dict[str, Any] = Field(..., description="Partial DUR Class object — only the keys you supply are changed. Recognised top-level keys: number, packet_match, traffic_match_type, net_source, net_destination, net_service, protocol, source, source_port, source_port_value, protocol_number, destination, destination_value, destination_port, destination_port_value, ip_dscp, vlan_id, ip_precedence, ip_service_type, established, fin, rst, syn, number, packet_match, protocol, protocol_number, source, source_ip_address, source_port, source_port_value, destination, destination_ip_address, destination_port, destination_port_value, dscp, vlan_id, ecn, ip_precedence, service_type, ttl, fragment, count_packet, cwr, ece, urg, ack, psh, rst, syn, fin, established, icmp_type, icmp_type_value, icmp_code."),
) -> Dict[str, Any]:
    """
    Update some fields of a DUR Class by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    DUR Classes are named traffic classifiers (HPE and AOS-CX rule sets) referenced by DUR
    policies.

    Maps to 'update_enforcement_profile_dur_dur_class_by_product_name_dur_class_id' in pyclearpass (PATCH /enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_dur_class_by_id",
        call_kwargs={
            "product_name": product_name,
            "dur_class_id": dur_class_id,
            "dur_class_data": dur_class_data,
        },
        operation_label="update DUR Class by ID",
        info_message=f"Updating DUR Class {dur_class_id} for product '{product_name}'...",
        success_message=f"DUR Class {dur_class_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_dur_class_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    dur_class_id: str = Field(..., description="Numeric ID of the DUR Class."),
    dur_class_data: Dict[str, Any] = Field(..., description="Complete replacement DUR Class object. Required keys: 'name', 'hpe_rules', 'aos_cx_rules'. Recognised top-level keys: number, packet_match, traffic_match_type, net_source, net_destination, net_service, protocol, source, source_port, source_port_value, protocol_number, destination, destination_value, destination_port, destination_port_value, ip_dscp, vlan_id, ip_precedence, ip_service_type, established, fin, rst, syn, number, packet_match, protocol, protocol_number, source, source_ip_address, source_port, source_port_value, destination, destination_ip_address, destination_port, destination_port_value, dscp, vlan_id, ecn, ip_precedence, service_type, ttl, fragment, count_packet, cwr, ece, urg, ack, psh, rst, syn, fin, established, icmp_type, icmp_type_value, icmp_code."),
) -> Dict[str, Any]:
    """
    Replace a DUR Class by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    DUR Classes are named traffic classifiers (HPE and AOS-CX rule sets) referenced by DUR
    policies.

    Maps to 'replace_enforcement_profile_dur_dur_class_by_product_name_dur_class_id' in pyclearpass (PUT /enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_dur_class_by_id",
        call_kwargs={
            "product_name": product_name,
            "dur_class_id": dur_class_id,
            "dur_class_data": dur_class_data,
        },
        operation_label="replace DUR Class by ID",
        info_message=f"Replacing DUR Class {dur_class_id} for product '{product_name}'...",
        success_message=f"DUR Class {dur_class_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_dur_class_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    dur_class_id: str = Field(..., description="Numeric ID of the DUR Class."),
) -> Dict[str, Any]:
    """
    Delete a DUR Class by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    DUR Classes are named traffic classifiers (HPE and AOS-CX rule sets) referenced by DUR
    policies.

    Maps to 'delete_enforcement_profile_dur_dur_class_by_product_name_dur_class_id' in pyclearpass (DELETE /enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_dur_class_by_id",
        call_kwargs={
            "product_name": product_name,
            "dur_class_id": dur_class_id,
        },
        operation_label="delete DUR Class by ID",
        info_message=f"Deleting DUR Class {dur_class_id} for product '{product_name}'...",
        success_message=f"DUR Class {dur_class_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_dur_class_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the DUR Class."),
) -> Dict[str, Any]:
    """
    Get a DUR Class by name.

    Names are scoped per product, so the same name under a different product_name is a
    different DUR Class.

    Maps to 'get_enforcement_profile_dur_dur_class_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/dur-class/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_dur_class_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Class by name",
        info_message=f"Retrieving DUR Class '{name}' for product '{product_name}'...",
        success_message=f"DUR Class '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_dur_class_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the DUR Class."),
    dur_class_data: Dict[str, Any] = Field(..., description="Partial DUR Class object — only the keys you supply are changed. Recognised top-level keys: number, packet_match, traffic_match_type, net_source, net_destination, net_service, protocol, source, source_port, source_port_value, protocol_number, destination, destination_value, destination_port, destination_port_value, ip_dscp, vlan_id, ip_precedence, ip_service_type, established, fin, rst, syn, number, packet_match, protocol, protocol_number, source, source_ip_address, source_port, source_port_value, destination, destination_ip_address, destination_port, destination_port_value, dscp, vlan_id, ecn, ip_precedence, service_type, ttl, fragment, count_packet, cwr, ece, urg, ack, psh, rst, syn, fin, established, icmp_type, icmp_type_value, icmp_code."),
) -> Dict[str, Any]:
    """
    Update some fields of a DUR Class by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different DUR Class.

    Maps to 'update_enforcement_profile_dur_dur_class_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/dur-class/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_dur_class_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "dur_class_data": dur_class_data,
        },
        operation_label="update DUR Class by name",
        info_message=f"Updating DUR Class '{name}' for product '{product_name}'...",
        success_message=f"DUR Class '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_dur_class_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the DUR Class."),
    dur_class_data: Dict[str, Any] = Field(..., description="Complete replacement DUR Class object. Required keys: 'name', 'hpe_rules', 'aos_cx_rules'. Recognised top-level keys: number, packet_match, traffic_match_type, net_source, net_destination, net_service, protocol, source, source_port, source_port_value, protocol_number, destination, destination_value, destination_port, destination_port_value, ip_dscp, vlan_id, ip_precedence, ip_service_type, established, fin, rst, syn, number, packet_match, protocol, protocol_number, source, source_ip_address, source_port, source_port_value, destination, destination_ip_address, destination_port, destination_port_value, dscp, vlan_id, ecn, ip_precedence, service_type, ttl, fragment, count_packet, cwr, ece, urg, ack, psh, rst, syn, fin, established, icmp_type, icmp_type_value, icmp_code."),
) -> Dict[str, Any]:
    """
    Replace a DUR Class by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different DUR Class.

    Maps to 'replace_enforcement_profile_dur_dur_class_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/dur-class/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_dur_class_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "dur_class_data": dur_class_data,
        },
        operation_label="replace DUR Class by name",
        info_message=f"Replacing DUR Class '{name}' for product '{product_name}'...",
        success_message=f"DUR Class '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_dur_class_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the DUR Class."),
) -> Dict[str, Any]:
    """
    Delete a DUR Class by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different DUR Class.

    Maps to 'delete_enforcement_profile_dur_dur_class_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/dur-class/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_dur_class_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Class by name",
        info_message=f"Deleting DUR Class '{name}' for product '{product_name}'...",
        success_message=f"DUR Class '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Ethertype Access Control Lists
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_ethertype_access_control_lists(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Ethertype Access Control Lists for an Aruba product.

    Ethertype ACLs permit or deny traffic by layer-2 ethertype.

    Maps to 'get_enforcement_profile_dur_ethertype_access_control_list_by_product_name' in pyclearpass (GET /enforcement-profile-dur/ethertype-access-control-list/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_ethertype_access_control_lists",
        resource_plural="DUR Ethertype Access Control Lists",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_ethertype_access_control_list(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    ethertype_access_control_list_data: Dict[str, Any] = Field(..., description="Ethertype Access Control List object. Required keys: 'name'. Recognised top-level keys: action, ethertype_type, ethertype_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Ethertype Access Control List for an Aruba product.

    Ethertype ACLs permit or deny traffic by layer-2 ethertype.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_ethertype_access_control_list_by_product_name' in pyclearpass (POST /enforcement-profile-dur/ethertype-access-control-list/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_ethertype_access_control_list",
        call_kwargs={
            "product_name": product_name,
            "ethertype_access_control_list_data": ethertype_access_control_list_data,
        },
        operation_label="create DUR Ethertype Access Control List",
        info_message=f"Creating DUR Ethertype Access Control List for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_ethertype_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    ethertype_access_control_list_id: str = Field(..., description="Numeric ID of the Ethertype Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Ethertype Access Control List by numeric ID.

    Ethertype ACLs permit or deny traffic by layer-2 ethertype.

    Maps to 'get_enforcement_profile_dur_ethertype_access_control_list_by_product_name_ethertype_access_control_list_id' in pyclearpass (GET /enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_ethertype_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "ethertype_access_control_list_id": ethertype_access_control_list_id,
        },
        operation_label="get DUR Ethertype Access Control List by ID",
        info_message=f"Retrieving DUR Ethertype Access Control List {ethertype_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List {ethertype_access_control_list_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_ethertype_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    ethertype_access_control_list_id: str = Field(..., description="Numeric ID of the Ethertype Access Control List."),
    ethertype_access_control_list_data: Dict[str, Any] = Field(..., description="Partial Ethertype Access Control List object — only the keys you supply are changed. Recognised top-level keys: action, ethertype_type, ethertype_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Ethertype Access Control List by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Ethertype ACLs permit or deny traffic by layer-2 ethertype.

    Maps to 'update_enforcement_profile_dur_ethertype_access_control_list_by_product_name_ethertype_access_control_list_id' in pyclearpass (PATCH /enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_ethertype_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "ethertype_access_control_list_id": ethertype_access_control_list_id,
            "ethertype_access_control_list_data": ethertype_access_control_list_data,
        },
        operation_label="update DUR Ethertype Access Control List by ID",
        info_message=f"Updating DUR Ethertype Access Control List {ethertype_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List {ethertype_access_control_list_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_ethertype_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    ethertype_access_control_list_id: str = Field(..., description="Numeric ID of the Ethertype Access Control List."),
    ethertype_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement Ethertype Access Control List object. Required keys: 'name'. Recognised top-level keys: action, ethertype_type, ethertype_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Ethertype Access Control List by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Ethertype ACLs permit or deny traffic by layer-2 ethertype.

    Maps to 'replace_enforcement_profile_dur_ethertype_access_control_list_by_product_name_ethertype_access_control_list_id' in pyclearpass (PUT /enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_ethertype_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "ethertype_access_control_list_id": ethertype_access_control_list_id,
            "ethertype_access_control_list_data": ethertype_access_control_list_data,
        },
        operation_label="replace DUR Ethertype Access Control List by ID",
        info_message=f"Replacing DUR Ethertype Access Control List {ethertype_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List {ethertype_access_control_list_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_ethertype_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    ethertype_access_control_list_id: str = Field(..., description="Numeric ID of the Ethertype Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Ethertype Access Control List by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Ethertype ACLs permit or deny traffic by layer-2 ethertype.

    Maps to 'delete_enforcement_profile_dur_ethertype_access_control_list_by_product_name_ethertype_access_control_list_id' in pyclearpass (DELETE /enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_ethertype_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "ethertype_access_control_list_id": ethertype_access_control_list_id,
        },
        operation_label="delete DUR Ethertype Access Control List by ID",
        info_message=f"Deleting DUR Ethertype Access Control List {ethertype_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List {ethertype_access_control_list_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_ethertype_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Ethertype Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Ethertype Access Control List by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Ethertype Access Control List.

    Maps to 'get_enforcement_profile_dur_ethertype_access_control_list_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_ethertype_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Ethertype Access Control List by name",
        info_message=f"Retrieving DUR Ethertype Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_ethertype_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Ethertype Access Control List."),
    ethertype_access_control_list_data: Dict[str, Any] = Field(..., description="Partial Ethertype Access Control List object — only the keys you supply are changed. Recognised top-level keys: action, ethertype_type, ethertype_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Ethertype Access Control List by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Ethertype Access Control List.

    Maps to 'update_enforcement_profile_dur_ethertype_access_control_list_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_ethertype_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "ethertype_access_control_list_data": ethertype_access_control_list_data,
        },
        operation_label="update DUR Ethertype Access Control List by name",
        info_message=f"Updating DUR Ethertype Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_ethertype_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Ethertype Access Control List."),
    ethertype_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement Ethertype Access Control List object. Required keys: 'name'. Recognised top-level keys: action, ethertype_type, ethertype_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Ethertype Access Control List by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Ethertype Access Control List.

    Maps to 'replace_enforcement_profile_dur_ethertype_access_control_list_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_ethertype_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "ethertype_access_control_list_data": ethertype_access_control_list_data,
        },
        operation_label="replace DUR Ethertype Access Control List by name",
        info_message=f"Replacing DUR Ethertype Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_ethertype_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Ethertype Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Ethertype Access Control List by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Ethertype Access Control List.

    Maps to 'delete_enforcement_profile_dur_ethertype_access_control_list_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_ethertype_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Ethertype Access Control List by name",
        info_message=f"Deleting DUR Ethertype Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Ethertype Access Control List '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# MAC Access Control Lists
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_mac_access_control_lists(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role MAC Access Control Lists for an Aruba product.

    MAC ACLs permit or deny traffic by source MAC address or MAC range.

    Maps to 'get_enforcement_profile_dur_mac_access_control_list_by_product_name' in pyclearpass (GET /enforcement-profile-dur/mac-access-control-list/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_mac_access_control_lists",
        resource_plural="DUR MAC Access Control Lists",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_mac_access_control_list(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    mac_access_control_list_data: Dict[str, Any] = Field(..., description="MAC Access Control List object. Required keys: 'name'. Recognised top-level keys: action, mac_address_type, mac_address_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role MAC Access Control List for an Aruba product.

    MAC ACLs permit or deny traffic by source MAC address or MAC range.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_mac_access_control_list_by_product_name' in pyclearpass (POST /enforcement-profile-dur/mac-access-control-list/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_mac_access_control_list",
        call_kwargs={
            "product_name": product_name,
            "mac_access_control_list_data": mac_access_control_list_data,
        },
        operation_label="create DUR MAC Access Control List",
        info_message=f"Creating DUR MAC Access Control List for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_mac_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    mac_access_control_list_id: str = Field(..., description="Numeric ID of the MAC Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role MAC Access Control List by numeric ID.

    MAC ACLs permit or deny traffic by source MAC address or MAC range.

    Maps to 'get_enforcement_profile_dur_mac_access_control_list_by_product_name_mac_access_control_list_id' in pyclearpass (GET /enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_mac_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "mac_access_control_list_id": mac_access_control_list_id,
        },
        operation_label="get DUR MAC Access Control List by ID",
        info_message=f"Retrieving DUR MAC Access Control List {mac_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List {mac_access_control_list_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_mac_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    mac_access_control_list_id: str = Field(..., description="Numeric ID of the MAC Access Control List."),
    mac_access_control_list_data: Dict[str, Any] = Field(..., description="Partial MAC Access Control List object — only the keys you supply are changed. Recognised top-level keys: action, mac_address_type, mac_address_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role MAC Access Control List by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    MAC ACLs permit or deny traffic by source MAC address or MAC range.

    Maps to 'update_enforcement_profile_dur_mac_access_control_list_by_product_name_mac_access_control_list_id' in pyclearpass (PATCH /enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_mac_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "mac_access_control_list_id": mac_access_control_list_id,
            "mac_access_control_list_data": mac_access_control_list_data,
        },
        operation_label="update DUR MAC Access Control List by ID",
        info_message=f"Updating DUR MAC Access Control List {mac_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List {mac_access_control_list_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_mac_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    mac_access_control_list_id: str = Field(..., description="Numeric ID of the MAC Access Control List."),
    mac_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement MAC Access Control List object. Required keys: 'name'. Recognised top-level keys: action, mac_address_type, mac_address_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role MAC Access Control List by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    MAC ACLs permit or deny traffic by source MAC address or MAC range.

    Maps to 'replace_enforcement_profile_dur_mac_access_control_list_by_product_name_mac_access_control_list_id' in pyclearpass (PUT /enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_mac_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "mac_access_control_list_id": mac_access_control_list_id,
            "mac_access_control_list_data": mac_access_control_list_data,
        },
        operation_label="replace DUR MAC Access Control List by ID",
        info_message=f"Replacing DUR MAC Access Control List {mac_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List {mac_access_control_list_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_mac_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    mac_access_control_list_id: str = Field(..., description="Numeric ID of the MAC Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role MAC Access Control List by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    MAC ACLs permit or deny traffic by source MAC address or MAC range.

    Maps to 'delete_enforcement_profile_dur_mac_access_control_list_by_product_name_mac_access_control_list_id' in pyclearpass (DELETE /enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_mac_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "mac_access_control_list_id": mac_access_control_list_id,
        },
        operation_label="delete DUR MAC Access Control List by ID",
        info_message=f"Deleting DUR MAC Access Control List {mac_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List {mac_access_control_list_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_mac_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the MAC Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role MAC Access Control List by name.

    Names are scoped per product, so the same name under a different product_name is a
    different MAC Access Control List.

    Maps to 'get_enforcement_profile_dur_mac_access_control_list_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_mac_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR MAC Access Control List by name",
        info_message=f"Retrieving DUR MAC Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_mac_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the MAC Access Control List."),
    mac_access_control_list_data: Dict[str, Any] = Field(..., description="Partial MAC Access Control List object — only the keys you supply are changed. Recognised top-level keys: action, mac_address_type, mac_address_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role MAC Access Control List by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different MAC Access Control List.

    Maps to 'update_enforcement_profile_dur_mac_access_control_list_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_mac_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "mac_access_control_list_data": mac_access_control_list_data,
        },
        operation_label="update DUR MAC Access Control List by name",
        info_message=f"Updating DUR MAC Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_mac_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the MAC Access Control List."),
    mac_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement MAC Access Control List object. Required keys: 'name'. Recognised top-level keys: action, mac_address_type, mac_address_value, subnet_bits."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role MAC Access Control List by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different MAC Access Control List.

    Maps to 'replace_enforcement_profile_dur_mac_access_control_list_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_mac_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "mac_access_control_list_data": mac_access_control_list_data,
        },
        operation_label="replace DUR MAC Access Control List by name",
        info_message=f"Replacing DUR MAC Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_mac_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the MAC Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role MAC Access Control List by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different MAC Access Control List.

    Maps to 'delete_enforcement_profile_dur_mac_access_control_list_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_mac_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR MAC Access Control List by name",
        info_message=f"Deleting DUR MAC Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR MAC Access Control List '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# NAT Pools
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_nat_pools(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role NAT Pools for an Aruba product.

    NAT Pools define the source-address range (and optional destination NAT address) used by DUR
    session ACL rules that perform NAT.

    Maps to 'get_enforcement_profile_dur_nat_pool_by_product_name' in pyclearpass (GET /enforcement-profile-dur/nat-pool/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_nat_pools",
        resource_plural="DUR NAT Pools",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_nat_pool(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    nat_pool_data: Dict[str, Any] = Field(..., description="NAT Pool object. Required keys: 'name', 'start_src_range', 'end_src_range'. Recognised top-level keys: name, start_src_range, end_src_range, destination_nat_ip_address."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role NAT Pool for an Aruba product.

    NAT Pools define the source-address range (and optional destination NAT address) used by DUR
    session ACL rules that perform NAT.
    Required body keys: 'name', 'start_src_range', 'end_src_range'.

    Maps to 'new_enforcement_profile_dur_nat_pool_by_product_name' in pyclearpass (POST /enforcement-profile-dur/nat-pool/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_nat_pool",
        call_kwargs={
            "product_name": product_name,
            "nat_pool_data": nat_pool_data,
        },
        operation_label="create DUR NAT Pool",
        info_message=f"Creating DUR NAT Pool for product '{product_name}'...",
        success_message=f"DUR NAT Pool created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_nat_pool_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    nat_pool_id: str = Field(..., description="Numeric ID of the NAT Pool."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role NAT Pool by numeric ID.

    NAT Pools define the source-address range (and optional destination NAT address) used by DUR
    session ACL rules that perform NAT.

    Maps to 'get_enforcement_profile_dur_nat_pool_by_product_name_nat_pool_id' in pyclearpass (GET /enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_nat_pool_by_id",
        call_kwargs={
            "product_name": product_name,
            "nat_pool_id": nat_pool_id,
        },
        operation_label="get DUR NAT Pool by ID",
        info_message=f"Retrieving DUR NAT Pool {nat_pool_id} for product '{product_name}'...",
        success_message=f"DUR NAT Pool {nat_pool_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_nat_pool_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    nat_pool_id: str = Field(..., description="Numeric ID of the NAT Pool."),
    nat_pool_data: Dict[str, Any] = Field(..., description="Partial NAT Pool object — only the keys you supply are changed. Recognised top-level keys: name, start_src_range, end_src_range, destination_nat_ip_address."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role NAT Pool by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    NAT Pools define the source-address range (and optional destination NAT address) used by DUR
    session ACL rules that perform NAT.

    Maps to 'update_enforcement_profile_dur_nat_pool_by_product_name_nat_pool_id' in pyclearpass (PATCH /enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_nat_pool_by_id",
        call_kwargs={
            "product_name": product_name,
            "nat_pool_id": nat_pool_id,
            "nat_pool_data": nat_pool_data,
        },
        operation_label="update DUR NAT Pool by ID",
        info_message=f"Updating DUR NAT Pool {nat_pool_id} for product '{product_name}'...",
        success_message=f"DUR NAT Pool {nat_pool_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_nat_pool_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    nat_pool_id: str = Field(..., description="Numeric ID of the NAT Pool."),
    nat_pool_data: Dict[str, Any] = Field(..., description="Complete replacement NAT Pool object. Required keys: 'name', 'start_src_range', 'end_src_range'. Recognised top-level keys: name, start_src_range, end_src_range, destination_nat_ip_address."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role NAT Pool by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    NAT Pools define the source-address range (and optional destination NAT address) used by DUR
    session ACL rules that perform NAT.

    Maps to 'replace_enforcement_profile_dur_nat_pool_by_product_name_nat_pool_id' in pyclearpass (PUT /enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_nat_pool_by_id",
        call_kwargs={
            "product_name": product_name,
            "nat_pool_id": nat_pool_id,
            "nat_pool_data": nat_pool_data,
        },
        operation_label="replace DUR NAT Pool by ID",
        info_message=f"Replacing DUR NAT Pool {nat_pool_id} for product '{product_name}'...",
        success_message=f"DUR NAT Pool {nat_pool_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_nat_pool_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    nat_pool_id: str = Field(..., description="Numeric ID of the NAT Pool."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role NAT Pool by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    NAT Pools define the source-address range (and optional destination NAT address) used by DUR
    session ACL rules that perform NAT.

    Maps to 'delete_enforcement_profile_dur_nat_pool_by_product_name_nat_pool_id' in pyclearpass (DELETE /enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_nat_pool_by_id",
        call_kwargs={
            "product_name": product_name,
            "nat_pool_id": nat_pool_id,
        },
        operation_label="delete DUR NAT Pool by ID",
        info_message=f"Deleting DUR NAT Pool {nat_pool_id} for product '{product_name}'...",
        success_message=f"DUR NAT Pool {nat_pool_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_nat_pool_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the NAT Pool."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role NAT Pool by name.

    Names are scoped per product, so the same name under a different product_name is a
    different NAT Pool.

    Maps to 'get_enforcement_profile_dur_nat_pool_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/nat-pool/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_nat_pool_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR NAT Pool by name",
        info_message=f"Retrieving DUR NAT Pool '{name}' for product '{product_name}'...",
        success_message=f"DUR NAT Pool '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_nat_pool_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the NAT Pool."),
    nat_pool_data: Dict[str, Any] = Field(..., description="Partial NAT Pool object — only the keys you supply are changed. Recognised top-level keys: name, start_src_range, end_src_range, destination_nat_ip_address."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role NAT Pool by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different NAT Pool.

    Maps to 'update_enforcement_profile_dur_nat_pool_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/nat-pool/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_nat_pool_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "nat_pool_data": nat_pool_data,
        },
        operation_label="update DUR NAT Pool by name",
        info_message=f"Updating DUR NAT Pool '{name}' for product '{product_name}'...",
        success_message=f"DUR NAT Pool '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_nat_pool_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the NAT Pool."),
    nat_pool_data: Dict[str, Any] = Field(..., description="Complete replacement NAT Pool object. Required keys: 'name', 'start_src_range', 'end_src_range'. Recognised top-level keys: name, start_src_range, end_src_range, destination_nat_ip_address."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role NAT Pool by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different NAT Pool.

    Maps to 'replace_enforcement_profile_dur_nat_pool_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/nat-pool/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_nat_pool_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "nat_pool_data": nat_pool_data,
        },
        operation_label="replace DUR NAT Pool by name",
        info_message=f"Replacing DUR NAT Pool '{name}' for product '{product_name}'...",
        success_message=f"DUR NAT Pool '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_nat_pool_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the NAT Pool."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role NAT Pool by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different NAT Pool.

    Maps to 'delete_enforcement_profile_dur_nat_pool_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/nat-pool/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_nat_pool_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR NAT Pool by name",
        info_message=f"Deleting DUR NAT Pool '{name}' for product '{product_name}'...",
        success_message=f"DUR NAT Pool '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Net Destinations
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_net_destinations(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Net Destinations for an Aruba product.

    Net Destinations are named aliases for one or more hosts, subnets, ranges or host names,
    referenced from ACL rules.

    Maps to 'get_enforcement_profile_dur_net_destination_by_product_name' in pyclearpass (GET /enforcement-profile-dur/net-destination/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_net_destinations",
        resource_plural="DUR Net Destinations",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_net_destination(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_destination_data: Dict[str, Any] = Field(..., description="Net Destination object. Required keys: 'name', 'rules'. Recognised top-level keys: rule_type, ip_address, netmask, end_ip_address, host_name, position."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Net Destination for an Aruba product.

    Net Destinations are named aliases for one or more hosts, subnets, ranges or host names,
    referenced from ACL rules.
    Required body keys: 'name', 'rules'.

    Maps to 'new_enforcement_profile_dur_net_destination_by_product_name' in pyclearpass (POST /enforcement-profile-dur/net-destination/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_net_destination",
        call_kwargs={
            "product_name": product_name,
            "net_destination_data": net_destination_data,
        },
        operation_label="create DUR Net Destination",
        info_message=f"Creating DUR Net Destination for product '{product_name}'...",
        success_message=f"DUR Net Destination created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_net_destination_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_destination_id: str = Field(..., description="Numeric ID of the Net Destination."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Net Destination by numeric ID.

    Net Destinations are named aliases for one or more hosts, subnets, ranges or host names,
    referenced from ACL rules.

    Maps to 'get_enforcement_profile_dur_net_destination_by_product_name_net_destination_id' in pyclearpass (GET /enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_net_destination_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_destination_id": net_destination_id,
        },
        operation_label="get DUR Net Destination by ID",
        info_message=f"Retrieving DUR Net Destination {net_destination_id} for product '{product_name}'...",
        success_message=f"DUR Net Destination {net_destination_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_net_destination_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_destination_id: str = Field(..., description="Numeric ID of the Net Destination."),
    net_destination_data: Dict[str, Any] = Field(..., description="Partial Net Destination object — only the keys you supply are changed. Recognised top-level keys: rule_type, ip_address, netmask, end_ip_address, host_name, position."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Net Destination by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Net Destinations are named aliases for one or more hosts, subnets, ranges or host names,
    referenced from ACL rules.

    Maps to 'update_enforcement_profile_dur_net_destination_by_product_name_net_destination_id' in pyclearpass (PATCH /enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_net_destination_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_destination_id": net_destination_id,
            "net_destination_data": net_destination_data,
        },
        operation_label="update DUR Net Destination by ID",
        info_message=f"Updating DUR Net Destination {net_destination_id} for product '{product_name}'...",
        success_message=f"DUR Net Destination {net_destination_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_net_destination_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_destination_id: str = Field(..., description="Numeric ID of the Net Destination."),
    net_destination_data: Dict[str, Any] = Field(..., description="Complete replacement Net Destination object. Required keys: 'name', 'rules'. Recognised top-level keys: rule_type, ip_address, netmask, end_ip_address, host_name, position."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Net Destination by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Net Destinations are named aliases for one or more hosts, subnets, ranges or host names,
    referenced from ACL rules.

    Maps to 'replace_enforcement_profile_dur_net_destination_by_product_name_net_destination_id' in pyclearpass (PUT /enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_net_destination_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_destination_id": net_destination_id,
            "net_destination_data": net_destination_data,
        },
        operation_label="replace DUR Net Destination by ID",
        info_message=f"Replacing DUR Net Destination {net_destination_id} for product '{product_name}'...",
        success_message=f"DUR Net Destination {net_destination_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_net_destination_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_destination_id: str = Field(..., description="Numeric ID of the Net Destination."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Net Destination by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Net Destinations are named aliases for one or more hosts, subnets, ranges or host names,
    referenced from ACL rules.

    Maps to 'delete_enforcement_profile_dur_net_destination_by_product_name_net_destination_id' in pyclearpass (DELETE /enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_net_destination_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_destination_id": net_destination_id,
        },
        operation_label="delete DUR Net Destination by ID",
        info_message=f"Deleting DUR Net Destination {net_destination_id} for product '{product_name}'...",
        success_message=f"DUR Net Destination {net_destination_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_net_destination_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Destination."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Net Destination by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Destination.

    Maps to 'get_enforcement_profile_dur_net_destination_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/net-destination/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_net_destination_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Net Destination by name",
        info_message=f"Retrieving DUR Net Destination '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Destination '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_net_destination_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Destination."),
    net_destination_data: Dict[str, Any] = Field(..., description="Partial Net Destination object — only the keys you supply are changed. Recognised top-level keys: rule_type, ip_address, netmask, end_ip_address, host_name, position."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Net Destination by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Destination.

    Maps to 'update_enforcement_profile_dur_net_destination_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/net-destination/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_net_destination_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "net_destination_data": net_destination_data,
        },
        operation_label="update DUR Net Destination by name",
        info_message=f"Updating DUR Net Destination '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Destination '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_net_destination_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Destination."),
    net_destination_data: Dict[str, Any] = Field(..., description="Complete replacement Net Destination object. Required keys: 'name', 'rules'. Recognised top-level keys: rule_type, ip_address, netmask, end_ip_address, host_name, position."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Net Destination by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Destination.

    Maps to 'replace_enforcement_profile_dur_net_destination_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/net-destination/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_net_destination_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "net_destination_data": net_destination_data,
        },
        operation_label="replace DUR Net Destination by name",
        info_message=f"Replacing DUR Net Destination '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Destination '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_net_destination_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Destination."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Net Destination by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Destination.

    Maps to 'delete_enforcement_profile_dur_net_destination_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/net-destination/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_net_destination_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Net Destination by name",
        info_message=f"Deleting DUR Net Destination '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Destination '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Net Services
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_net_services(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Net Services for an Aruba product.

    Net Services are named protocol/port aliases referenced from ACL rules.

    Maps to 'get_enforcement_profile_dur_net_service_by_product_name' in pyclearpass (GET /enforcement-profile-dur/net-service/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_net_services",
        resource_plural="DUR Net Services",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_net_service(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_service_data: Dict[str, Any] = Field(..., description="Net Service object. Required keys: 'name'. Recognised top-level keys: name, description, protocol, port_selection, port_list, port, max_port, ip_protocol_number, application_level_gateway."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Net Service for an Aruba product.

    Net Services are named protocol/port aliases referenced from ACL rules.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_net_service_by_product_name' in pyclearpass (POST /enforcement-profile-dur/net-service/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_net_service",
        call_kwargs={
            "product_name": product_name,
            "net_service_data": net_service_data,
        },
        operation_label="create DUR Net Service",
        info_message=f"Creating DUR Net Service for product '{product_name}'...",
        success_message=f"DUR Net Service created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_net_service_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_service_id: str = Field(..., description="Numeric ID of the Net Service."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Net Service by numeric ID.

    Net Services are named protocol/port aliases referenced from ACL rules.

    Maps to 'get_enforcement_profile_dur_net_service_by_product_name_net_service_id' in pyclearpass (GET /enforcement-profile-dur/net-service/{product_name}/{net_service_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_net_service_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_service_id": net_service_id,
        },
        operation_label="get DUR Net Service by ID",
        info_message=f"Retrieving DUR Net Service {net_service_id} for product '{product_name}'...",
        success_message=f"DUR Net Service {net_service_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_net_service_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_service_id: str = Field(..., description="Numeric ID of the Net Service."),
    net_service_data: Dict[str, Any] = Field(..., description="Partial Net Service object — only the keys you supply are changed. Recognised top-level keys: name, description, protocol, port_selection, port_list, port, max_port, ip_protocol_number, application_level_gateway."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Net Service by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Net Services are named protocol/port aliases referenced from ACL rules.

    Maps to 'update_enforcement_profile_dur_net_service_by_product_name_net_service_id' in pyclearpass (PATCH /enforcement-profile-dur/net-service/{product_name}/{net_service_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_net_service_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_service_id": net_service_id,
            "net_service_data": net_service_data,
        },
        operation_label="update DUR Net Service by ID",
        info_message=f"Updating DUR Net Service {net_service_id} for product '{product_name}'...",
        success_message=f"DUR Net Service {net_service_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_net_service_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_service_id: str = Field(..., description="Numeric ID of the Net Service."),
    net_service_data: Dict[str, Any] = Field(..., description="Complete replacement Net Service object. Required keys: 'name'. Recognised top-level keys: name, description, protocol, port_selection, port_list, port, max_port, ip_protocol_number, application_level_gateway."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Net Service by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Net Services are named protocol/port aliases referenced from ACL rules.

    Maps to 'replace_enforcement_profile_dur_net_service_by_product_name_net_service_id' in pyclearpass (PUT /enforcement-profile-dur/net-service/{product_name}/{net_service_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_net_service_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_service_id": net_service_id,
            "net_service_data": net_service_data,
        },
        operation_label="replace DUR Net Service by ID",
        info_message=f"Replacing DUR Net Service {net_service_id} for product '{product_name}'...",
        success_message=f"DUR Net Service {net_service_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_net_service_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    net_service_id: str = Field(..., description="Numeric ID of the Net Service."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Net Service by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Net Services are named protocol/port aliases referenced from ACL rules.

    Maps to 'delete_enforcement_profile_dur_net_service_by_product_name_net_service_id' in pyclearpass (DELETE /enforcement-profile-dur/net-service/{product_name}/{net_service_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_net_service_by_id",
        call_kwargs={
            "product_name": product_name,
            "net_service_id": net_service_id,
        },
        operation_label="delete DUR Net Service by ID",
        info_message=f"Deleting DUR Net Service {net_service_id} for product '{product_name}'...",
        success_message=f"DUR Net Service {net_service_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_net_service_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Service."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Net Service by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Service.

    Maps to 'get_enforcement_profile_dur_net_service_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/net-service/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_net_service_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Net Service by name",
        info_message=f"Retrieving DUR Net Service '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Service '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_net_service_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Service."),
    net_service_data: Dict[str, Any] = Field(..., description="Partial Net Service object — only the keys you supply are changed. Recognised top-level keys: name, description, protocol, port_selection, port_list, port, max_port, ip_protocol_number, application_level_gateway."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Net Service by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Service.

    Maps to 'update_enforcement_profile_dur_net_service_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/net-service/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_net_service_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "net_service_data": net_service_data,
        },
        operation_label="update DUR Net Service by name",
        info_message=f"Updating DUR Net Service '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Service '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_net_service_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Service."),
    net_service_data: Dict[str, Any] = Field(..., description="Complete replacement Net Service object. Required keys: 'name'. Recognised top-level keys: name, description, protocol, port_selection, port_list, port, max_port, ip_protocol_number, application_level_gateway."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Net Service by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Service.

    Maps to 'replace_enforcement_profile_dur_net_service_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/net-service/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_net_service_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "net_service_data": net_service_data,
        },
        operation_label="replace DUR Net Service by name",
        info_message=f"Replacing DUR Net Service '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Service '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_net_service_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Net Service."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Net Service by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Net Service.

    Maps to 'delete_enforcement_profile_dur_net_service_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/net-service/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_net_service_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Net Service by name",
        info_message=f"Deleting DUR Net Service '{name}' for product '{product_name}'...",
        success_message=f"DUR Net Service '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Policer Profiles
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_policer_profiles(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Policer Profiles for an Aruba product.

    Policer Profiles define committed/excess rate and burst limits plus exceed and violate
    actions.

    Maps to 'get_enforcement_profile_dur_policer_profile_by_product_name' in pyclearpass (GET /enforcement-profile-dur/policer-profile/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_policer_profiles",
        resource_plural="DUR Policer Profiles",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_policer_profile(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policer_profile_data: Dict[str, Any] = Field(..., description="Policer Profile object. Required keys: 'name'. Recognised top-level keys: name, cbs, cir, ebs, exceed_action, exceed_qos_profile, violate_action, violate_qos_profile."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Policer Profile for an Aruba product.

    Policer Profiles define committed/excess rate and burst limits plus exceed and violate
    actions.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_policer_profile_by_product_name' in pyclearpass (POST /enforcement-profile-dur/policer-profile/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_policer_profile",
        call_kwargs={
            "product_name": product_name,
            "policer_profile_data": policer_profile_data,
        },
        operation_label="create DUR Policer Profile",
        info_message=f"Creating DUR Policer Profile for product '{product_name}'...",
        success_message=f"DUR Policer Profile created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_policer_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policer_profile_id: str = Field(..., description="Numeric ID of the Policer Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Policer Profile by numeric ID.

    Policer Profiles define committed/excess rate and burst limits plus exceed and violate
    actions.

    Maps to 'get_enforcement_profile_dur_policer_profile_by_product_name_policer_profile_id' in pyclearpass (GET /enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_policer_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "policer_profile_id": policer_profile_id,
        },
        operation_label="get DUR Policer Profile by ID",
        info_message=f"Retrieving DUR Policer Profile {policer_profile_id} for product '{product_name}'...",
        success_message=f"DUR Policer Profile {policer_profile_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_policer_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policer_profile_id: str = Field(..., description="Numeric ID of the Policer Profile."),
    policer_profile_data: Dict[str, Any] = Field(..., description="Partial Policer Profile object — only the keys you supply are changed. Recognised top-level keys: name, cbs, cir, ebs, exceed_action, exceed_qos_profile, violate_action, violate_qos_profile."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Policer Profile by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Policer Profiles define committed/excess rate and burst limits plus exceed and violate
    actions.

    Maps to 'update_enforcement_profile_dur_policer_profile_by_product_name_policer_profile_id' in pyclearpass (PATCH /enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_policer_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "policer_profile_id": policer_profile_id,
            "policer_profile_data": policer_profile_data,
        },
        operation_label="update DUR Policer Profile by ID",
        info_message=f"Updating DUR Policer Profile {policer_profile_id} for product '{product_name}'...",
        success_message=f"DUR Policer Profile {policer_profile_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_policer_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policer_profile_id: str = Field(..., description="Numeric ID of the Policer Profile."),
    policer_profile_data: Dict[str, Any] = Field(..., description="Complete replacement Policer Profile object. Required keys: 'name'. Recognised top-level keys: name, cbs, cir, ebs, exceed_action, exceed_qos_profile, violate_action, violate_qos_profile."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Policer Profile by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Policer Profiles define committed/excess rate and burst limits plus exceed and violate
    actions.

    Maps to 'replace_enforcement_profile_dur_policer_profile_by_product_name_policer_profile_id' in pyclearpass (PUT /enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_policer_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "policer_profile_id": policer_profile_id,
            "policer_profile_data": policer_profile_data,
        },
        operation_label="replace DUR Policer Profile by ID",
        info_message=f"Replacing DUR Policer Profile {policer_profile_id} for product '{product_name}'...",
        success_message=f"DUR Policer Profile {policer_profile_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_policer_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policer_profile_id: str = Field(..., description="Numeric ID of the Policer Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Policer Profile by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Policer Profiles define committed/excess rate and burst limits plus exceed and violate
    actions.

    Maps to 'delete_enforcement_profile_dur_policer_profile_by_product_name_policer_profile_id' in pyclearpass (DELETE /enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_policer_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "policer_profile_id": policer_profile_id,
        },
        operation_label="delete DUR Policer Profile by ID",
        info_message=f"Deleting DUR Policer Profile {policer_profile_id} for product '{product_name}'...",
        success_message=f"DUR Policer Profile {policer_profile_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_policer_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policer Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Policer Profile by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Policer Profile.

    Maps to 'get_enforcement_profile_dur_policer_profile_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/policer-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_policer_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Policer Profile by name",
        info_message=f"Retrieving DUR Policer Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Policer Profile '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_policer_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policer Profile."),
    policer_profile_data: Dict[str, Any] = Field(..., description="Partial Policer Profile object — only the keys you supply are changed. Recognised top-level keys: name, cbs, cir, ebs, exceed_action, exceed_qos_profile, violate_action, violate_qos_profile."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Policer Profile by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Policer Profile.

    Maps to 'update_enforcement_profile_dur_policer_profile_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/policer-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_policer_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "policer_profile_data": policer_profile_data,
        },
        operation_label="update DUR Policer Profile by name",
        info_message=f"Updating DUR Policer Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Policer Profile '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_policer_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policer Profile."),
    policer_profile_data: Dict[str, Any] = Field(..., description="Complete replacement Policer Profile object. Required keys: 'name'. Recognised top-level keys: name, cbs, cir, ebs, exceed_action, exceed_qos_profile, violate_action, violate_qos_profile."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Policer Profile by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Policer Profile.

    Maps to 'replace_enforcement_profile_dur_policer_profile_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/policer-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_policer_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "policer_profile_data": policer_profile_data,
        },
        operation_label="replace DUR Policer Profile by name",
        info_message=f"Replacing DUR Policer Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Policer Profile '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_policer_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policer Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Policer Profile by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Policer Profile.

    Maps to 'delete_enforcement_profile_dur_policer_profile_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/policer-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_policer_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Policer Profile by name",
        info_message=f"Deleting DUR Policer Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR Policer Profile '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Policies
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_policies(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Policies for an Aruba product.

    DUR Policies bind classes to actions (permit/deny, marking, rate limiting) and are the top-
    level object attached to a role.

    Maps to 'get_enforcement_profile_dur_policy_by_product_name' in pyclearpass (GET /enforcement-profile-dur/policy/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_policies",
        resource_plural="DUR Policies",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_policy(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policy_data: Dict[str, Any] = Field(..., description="Policy object. Required keys: 'name', 'rules'. Recognised top-level keys: number, class_type, class_name, action, dscp, ip_precedence, priority, rate_limit, committed_information_rate, committed_burst_size, exceed_action, priority_code_point."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Policy for an Aruba product.

    DUR Policies bind classes to actions (permit/deny, marking, rate limiting) and are the top-
    level object attached to a role.
    Required body keys: 'name', 'rules'.

    Maps to 'new_enforcement_profile_dur_policy_by_product_name' in pyclearpass (POST /enforcement-profile-dur/policy/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_policy",
        call_kwargs={
            "product_name": product_name,
            "policy_data": policy_data,
        },
        operation_label="create DUR Policy",
        info_message=f"Creating DUR Policy for product '{product_name}'...",
        success_message=f"DUR Policy created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_policy_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policy_id: str = Field(..., description="Numeric ID of the Policy."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Policy by numeric ID.

    DUR Policies bind classes to actions (permit/deny, marking, rate limiting) and are the top-
    level object attached to a role.

    Maps to 'get_enforcement_profile_dur_policy_by_product_name_policy_id' in pyclearpass (GET /enforcement-profile-dur/policy/{product_name}/{policy_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_policy_by_id",
        call_kwargs={
            "product_name": product_name,
            "policy_id": policy_id,
        },
        operation_label="get DUR Policy by ID",
        info_message=f"Retrieving DUR Policy {policy_id} for product '{product_name}'...",
        success_message=f"DUR Policy {policy_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_policy_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policy_id: str = Field(..., description="Numeric ID of the Policy."),
    policy_data: Dict[str, Any] = Field(..., description="Partial Policy object — only the keys you supply are changed. Recognised top-level keys: number, class_type, class_name, action, dscp, ip_precedence, priority, rate_limit, committed_information_rate, committed_burst_size, exceed_action, priority_code_point."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Policy by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    DUR Policies bind classes to actions (permit/deny, marking, rate limiting) and are the top-
    level object attached to a role.

    Maps to 'update_enforcement_profile_dur_policy_by_product_name_policy_id' in pyclearpass (PATCH /enforcement-profile-dur/policy/{product_name}/{policy_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_policy_by_id",
        call_kwargs={
            "product_name": product_name,
            "policy_id": policy_id,
            "policy_data": policy_data,
        },
        operation_label="update DUR Policy by ID",
        info_message=f"Updating DUR Policy {policy_id} for product '{product_name}'...",
        success_message=f"DUR Policy {policy_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_policy_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policy_id: str = Field(..., description="Numeric ID of the Policy."),
    policy_data: Dict[str, Any] = Field(..., description="Complete replacement Policy object. Required keys: 'name', 'rules'. Recognised top-level keys: number, class_type, class_name, action, dscp, ip_precedence, priority, rate_limit, committed_information_rate, committed_burst_size, exceed_action, priority_code_point."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Policy by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    DUR Policies bind classes to actions (permit/deny, marking, rate limiting) and are the top-
    level object attached to a role.

    Maps to 'replace_enforcement_profile_dur_policy_by_product_name_policy_id' in pyclearpass (PUT /enforcement-profile-dur/policy/{product_name}/{policy_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_policy_by_id",
        call_kwargs={
            "product_name": product_name,
            "policy_id": policy_id,
            "policy_data": policy_data,
        },
        operation_label="replace DUR Policy by ID",
        info_message=f"Replacing DUR Policy {policy_id} for product '{product_name}'...",
        success_message=f"DUR Policy {policy_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_policy_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    policy_id: str = Field(..., description="Numeric ID of the Policy."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Policy by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    DUR Policies bind classes to actions (permit/deny, marking, rate limiting) and are the top-
    level object attached to a role.

    Maps to 'delete_enforcement_profile_dur_policy_by_product_name_policy_id' in pyclearpass (DELETE /enforcement-profile-dur/policy/{product_name}/{policy_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_policy_by_id",
        call_kwargs={
            "product_name": product_name,
            "policy_id": policy_id,
        },
        operation_label="delete DUR Policy by ID",
        info_message=f"Deleting DUR Policy {policy_id} for product '{product_name}'...",
        success_message=f"DUR Policy {policy_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_policy_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policy."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Policy by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Policy.

    Maps to 'get_enforcement_profile_dur_policy_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/policy/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_policy_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Policy by name",
        info_message=f"Retrieving DUR Policy '{name}' for product '{product_name}'...",
        success_message=f"DUR Policy '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_policy_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policy."),
    policy_data: Dict[str, Any] = Field(..., description="Partial Policy object — only the keys you supply are changed. Recognised top-level keys: number, class_type, class_name, action, dscp, ip_precedence, priority, rate_limit, committed_information_rate, committed_burst_size, exceed_action, priority_code_point."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Policy by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Policy.

    Maps to 'update_enforcement_profile_dur_policy_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/policy/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_policy_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "policy_data": policy_data,
        },
        operation_label="update DUR Policy by name",
        info_message=f"Updating DUR Policy '{name}' for product '{product_name}'...",
        success_message=f"DUR Policy '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_policy_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policy."),
    policy_data: Dict[str, Any] = Field(..., description="Complete replacement Policy object. Required keys: 'name', 'rules'. Recognised top-level keys: number, class_type, class_name, action, dscp, ip_precedence, priority, rate_limit, committed_information_rate, committed_burst_size, exceed_action, priority_code_point."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Policy by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Policy.

    Maps to 'replace_enforcement_profile_dur_policy_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/policy/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_policy_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "policy_data": policy_data,
        },
        operation_label="replace DUR Policy by name",
        info_message=f"Replacing DUR Policy '{name}' for product '{product_name}'...",
        success_message=f"DUR Policy '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_policy_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Policy."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Policy by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Policy.

    Maps to 'delete_enforcement_profile_dur_policy_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/policy/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_policy_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Policy by name",
        info_message=f"Deleting DUR Policy '{name}' for product '{product_name}'...",
        success_message=f"DUR Policy '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# QoS Profiles
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_qos_profiles(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role QoS Profiles for an Aruba product.

    QoS Profiles define traffic class, drop precedence, DSCP and 802.1p marking.

    Maps to 'get_enforcement_profile_dur_qos_profile_by_product_name' in pyclearpass (GET /enforcement-profile-dur/qos-profile/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_qos_profiles",
        resource_plural="DUR QoS Profiles",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_qos_profile(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    qos_profile_data: Dict[str, Any] = Field(..., description="QoS Profile object. Required keys: 'name'. Recognised top-level keys: name, traffic_class, drop_precedence, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role QoS Profile for an Aruba product.

    QoS Profiles define traffic class, drop precedence, DSCP and 802.1p marking.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_qos_profile_by_product_name' in pyclearpass (POST /enforcement-profile-dur/qos-profile/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_qos_profile",
        call_kwargs={
            "product_name": product_name,
            "qos_profile_data": qos_profile_data,
        },
        operation_label="create DUR QoS Profile",
        info_message=f"Creating DUR QoS Profile for product '{product_name}'...",
        success_message=f"DUR QoS Profile created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_qos_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    qos_profile_id: str = Field(..., description="Numeric ID of the QoS Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role QoS Profile by numeric ID.

    QoS Profiles define traffic class, drop precedence, DSCP and 802.1p marking.

    Maps to 'get_enforcement_profile_dur_qos_profile_by_product_name_qos_profile_id' in pyclearpass (GET /enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_qos_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "qos_profile_id": qos_profile_id,
        },
        operation_label="get DUR QoS Profile by ID",
        info_message=f"Retrieving DUR QoS Profile {qos_profile_id} for product '{product_name}'...",
        success_message=f"DUR QoS Profile {qos_profile_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_qos_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    qos_profile_id: str = Field(..., description="Numeric ID of the QoS Profile."),
    qos_profile_data: Dict[str, Any] = Field(..., description="Partial QoS Profile object — only the keys you supply are changed. Recognised top-level keys: name, traffic_class, drop_precedence, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role QoS Profile by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    QoS Profiles define traffic class, drop precedence, DSCP and 802.1p marking.

    Maps to 'update_enforcement_profile_dur_qos_profile_by_product_name_qos_profile_id' in pyclearpass (PATCH /enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_qos_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "qos_profile_id": qos_profile_id,
            "qos_profile_data": qos_profile_data,
        },
        operation_label="update DUR QoS Profile by ID",
        info_message=f"Updating DUR QoS Profile {qos_profile_id} for product '{product_name}'...",
        success_message=f"DUR QoS Profile {qos_profile_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_qos_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    qos_profile_id: str = Field(..., description="Numeric ID of the QoS Profile."),
    qos_profile_data: Dict[str, Any] = Field(..., description="Complete replacement QoS Profile object. Required keys: 'name'. Recognised top-level keys: name, traffic_class, drop_precedence, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role QoS Profile by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    QoS Profiles define traffic class, drop precedence, DSCP and 802.1p marking.

    Maps to 'replace_enforcement_profile_dur_qos_profile_by_product_name_qos_profile_id' in pyclearpass (PUT /enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_qos_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "qos_profile_id": qos_profile_id,
            "qos_profile_data": qos_profile_data,
        },
        operation_label="replace DUR QoS Profile by ID",
        info_message=f"Replacing DUR QoS Profile {qos_profile_id} for product '{product_name}'...",
        success_message=f"DUR QoS Profile {qos_profile_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_qos_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    qos_profile_id: str = Field(..., description="Numeric ID of the QoS Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role QoS Profile by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    QoS Profiles define traffic class, drop precedence, DSCP and 802.1p marking.

    Maps to 'delete_enforcement_profile_dur_qos_profile_by_product_name_qos_profile_id' in pyclearpass (DELETE /enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_qos_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "qos_profile_id": qos_profile_id,
        },
        operation_label="delete DUR QoS Profile by ID",
        info_message=f"Deleting DUR QoS Profile {qos_profile_id} for product '{product_name}'...",
        success_message=f"DUR QoS Profile {qos_profile_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_qos_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the QoS Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role QoS Profile by name.

    Names are scoped per product, so the same name under a different product_name is a
    different QoS Profile.

    Maps to 'get_enforcement_profile_dur_qos_profile_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/qos-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_qos_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR QoS Profile by name",
        info_message=f"Retrieving DUR QoS Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR QoS Profile '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_qos_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the QoS Profile."),
    qos_profile_data: Dict[str, Any] = Field(..., description="Partial QoS Profile object — only the keys you supply are changed. Recognised top-level keys: name, traffic_class, drop_precedence, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role QoS Profile by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different QoS Profile.

    Maps to 'update_enforcement_profile_dur_qos_profile_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/qos-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_qos_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "qos_profile_data": qos_profile_data,
        },
        operation_label="update DUR QoS Profile by name",
        info_message=f"Updating DUR QoS Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR QoS Profile '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_qos_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the QoS Profile."),
    qos_profile_data: Dict[str, Any] = Field(..., description="Complete replacement QoS Profile object. Required keys: 'name'. Recognised top-level keys: name, traffic_class, drop_precedence, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role QoS Profile by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different QoS Profile.

    Maps to 'replace_enforcement_profile_dur_qos_profile_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/qos-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_qos_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "qos_profile_data": qos_profile_data,
        },
        operation_label="replace DUR QoS Profile by name",
        info_message=f"Replacing DUR QoS Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR QoS Profile '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_qos_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the QoS Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role QoS Profile by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different QoS Profile.

    Maps to 'delete_enforcement_profile_dur_qos_profile_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/qos-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_qos_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR QoS Profile by name",
        info_message=f"Deleting DUR QoS Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR QoS Profile '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Session Access Control Lists
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_session_access_control_lists(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Session Access Control Lists for an Aruba product.

    Session ACLs are the stateful layer-3/4 rule sets that make up most of a Downloadable User
    Role.

    Maps to 'get_enforcement_profile_dur_session_access_control_list_by_product_name' in pyclearpass (GET /enforcement-profile-dur/session-access-control-list/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_session_access_control_lists",
        resource_plural="DUR Session Access Control Lists",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_session_access_control_list(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    session_access_control_list_data: Dict[str, Any] = Field(..., description="Session Access Control List object. Required keys: 'name'. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, dst_nat_ip_address, dst_nat_port, network_name, dual_nat_pool, tunnel_id, src_nat_pool, deny_list_user_if_acl_applied, dot1p_priority, log_if_acl_applied, mirror, position, queue_priority, time_range, tos."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Session Access Control List for an Aruba product.

    Session ACLs are the stateful layer-3/4 rule sets that make up most of a Downloadable User
    Role.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_session_access_control_list_by_product_name' in pyclearpass (POST /enforcement-profile-dur/session-access-control-list/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_session_access_control_list",
        call_kwargs={
            "product_name": product_name,
            "session_access_control_list_data": session_access_control_list_data,
        },
        operation_label="create DUR Session Access Control List",
        info_message=f"Creating DUR Session Access Control List for product '{product_name}'...",
        success_message=f"DUR Session Access Control List created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_session_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    session_access_control_list_id: str = Field(..., description="Numeric ID of the Session Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Session Access Control List by numeric ID.

    Session ACLs are the stateful layer-3/4 rule sets that make up most of a Downloadable User
    Role.

    Maps to 'get_enforcement_profile_dur_session_access_control_list_by_product_name_session_access_control_list_id' in pyclearpass (GET /enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_session_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "session_access_control_list_id": session_access_control_list_id,
        },
        operation_label="get DUR Session Access Control List by ID",
        info_message=f"Retrieving DUR Session Access Control List {session_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Session Access Control List {session_access_control_list_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_session_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    session_access_control_list_id: str = Field(..., description="Numeric ID of the Session Access Control List."),
    session_access_control_list_data: Dict[str, Any] = Field(..., description="Partial Session Access Control List object — only the keys you supply are changed. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, dst_nat_ip_address, dst_nat_port, network_name, dual_nat_pool, tunnel_id, src_nat_pool, deny_list_user_if_acl_applied, dot1p_priority, log_if_acl_applied, mirror, position, queue_priority, time_range, tos."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Session Access Control List by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Session ACLs are the stateful layer-3/4 rule sets that make up most of a Downloadable User
    Role.

    Maps to 'update_enforcement_profile_dur_session_access_control_list_by_product_name_session_access_control_list_id' in pyclearpass (PATCH /enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_session_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "session_access_control_list_id": session_access_control_list_id,
            "session_access_control_list_data": session_access_control_list_data,
        },
        operation_label="update DUR Session Access Control List by ID",
        info_message=f"Updating DUR Session Access Control List {session_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Session Access Control List {session_access_control_list_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_session_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    session_access_control_list_id: str = Field(..., description="Numeric ID of the Session Access Control List."),
    session_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement Session Access Control List object. Required keys: 'name'. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, dst_nat_ip_address, dst_nat_port, network_name, dual_nat_pool, tunnel_id, src_nat_pool, deny_list_user_if_acl_applied, dot1p_priority, log_if_acl_applied, mirror, position, queue_priority, time_range, tos."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Session Access Control List by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Session ACLs are the stateful layer-3/4 rule sets that make up most of a Downloadable User
    Role.

    Maps to 'replace_enforcement_profile_dur_session_access_control_list_by_product_name_session_access_control_list_id' in pyclearpass (PUT /enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_session_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "session_access_control_list_id": session_access_control_list_id,
            "session_access_control_list_data": session_access_control_list_data,
        },
        operation_label="replace DUR Session Access Control List by ID",
        info_message=f"Replacing DUR Session Access Control List {session_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Session Access Control List {session_access_control_list_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_session_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    session_access_control_list_id: str = Field(..., description="Numeric ID of the Session Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Session Access Control List by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Session ACLs are the stateful layer-3/4 rule sets that make up most of a Downloadable User
    Role.

    Maps to 'delete_enforcement_profile_dur_session_access_control_list_by_product_name_session_access_control_list_id' in pyclearpass (DELETE /enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_session_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "session_access_control_list_id": session_access_control_list_id,
        },
        operation_label="delete DUR Session Access Control List by ID",
        info_message=f"Deleting DUR Session Access Control List {session_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Session Access Control List {session_access_control_list_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_session_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Session Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Session Access Control List by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Session Access Control List.

    Maps to 'get_enforcement_profile_dur_session_access_control_list_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_session_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Session Access Control List by name",
        info_message=f"Retrieving DUR Session Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Session Access Control List '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_session_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Session Access Control List."),
    session_access_control_list_data: Dict[str, Any] = Field(..., description="Partial Session Access Control List object — only the keys you supply are changed. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, dst_nat_ip_address, dst_nat_port, network_name, dual_nat_pool, tunnel_id, src_nat_pool, deny_list_user_if_acl_applied, dot1p_priority, log_if_acl_applied, mirror, position, queue_priority, time_range, tos."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Session Access Control List by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Session Access Control List.

    Maps to 'update_enforcement_profile_dur_session_access_control_list_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_session_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "session_access_control_list_data": session_access_control_list_data,
        },
        operation_label="update DUR Session Access Control List by name",
        info_message=f"Updating DUR Session Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Session Access Control List '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_session_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Session Access Control List."),
    session_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement Session Access Control List object. Required keys: 'name'. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, dst_nat_ip_address, dst_nat_port, network_name, dual_nat_pool, tunnel_id, src_nat_pool, deny_list_user_if_acl_applied, dot1p_priority, log_if_acl_applied, mirror, position, queue_priority, time_range, tos."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Session Access Control List by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Session Access Control List.

    Maps to 'replace_enforcement_profile_dur_session_access_control_list_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_session_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "session_access_control_list_data": session_access_control_list_data,
        },
        operation_label="replace DUR Session Access Control List by name",
        info_message=f"Replacing DUR Session Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Session Access Control List '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_session_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Session Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Session Access Control List by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Session Access Control List.

    Maps to 'delete_enforcement_profile_dur_session_access_control_list_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_session_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Session Access Control List by name",
        info_message=f"Deleting DUR Session Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Session Access Control List '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Stateless Access Control Lists
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_stateless_access_control_lists(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Stateless Access Control Lists for an Aruba product.

    Stateless ACLs are layer-3/4 rule sets evaluated without connection tracking.

    Maps to 'get_enforcement_profile_dur_stateless_access_control_list_by_product_name' in pyclearpass (GET /enforcement-profile-dur/stateless-access-control-list/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_stateless_access_control_lists",
        resource_plural="DUR Stateless Access Control Lists",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_stateless_access_control_list(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    stateless_access_control_list_data: Dict[str, Any] = Field(..., description="Stateless Access Control List object. Required keys: 'name'. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, redirect_type, ipsec_map_based_redirect, tunnel_id, deny_list_user_if_acl_applied, log_if_acl_applied, position, policer_profile, qos_profile, time_range."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Stateless Access Control List for an Aruba product.

    Stateless ACLs are layer-3/4 rule sets evaluated without connection tracking.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_stateless_access_control_list_by_product_name' in pyclearpass (POST /enforcement-profile-dur/stateless-access-control-list/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_stateless_access_control_list",
        call_kwargs={
            "product_name": product_name,
            "stateless_access_control_list_data": stateless_access_control_list_data,
        },
        operation_label="create DUR Stateless Access Control List",
        info_message=f"Creating DUR Stateless Access Control List for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_stateless_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    stateless_access_control_list_id: str = Field(..., description="Numeric ID of the Stateless Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Stateless Access Control List by numeric ID.

    Stateless ACLs are layer-3/4 rule sets evaluated without connection tracking.

    Maps to 'get_enforcement_profile_dur_stateless_access_control_list_by_product_name_stateless_access_control_list_id' in pyclearpass (GET /enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_stateless_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "stateless_access_control_list_id": stateless_access_control_list_id,
        },
        operation_label="get DUR Stateless Access Control List by ID",
        info_message=f"Retrieving DUR Stateless Access Control List {stateless_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List {stateless_access_control_list_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_stateless_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    stateless_access_control_list_id: str = Field(..., description="Numeric ID of the Stateless Access Control List."),
    stateless_access_control_list_data: Dict[str, Any] = Field(..., description="Partial Stateless Access Control List object — only the keys you supply are changed. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, redirect_type, ipsec_map_based_redirect, tunnel_id, deny_list_user_if_acl_applied, log_if_acl_applied, position, policer_profile, qos_profile, time_range."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Stateless Access Control List by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Stateless ACLs are layer-3/4 rule sets evaluated without connection tracking.

    Maps to 'update_enforcement_profile_dur_stateless_access_control_list_by_product_name_stateless_access_control_list_id' in pyclearpass (PATCH /enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_stateless_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "stateless_access_control_list_id": stateless_access_control_list_id,
            "stateless_access_control_list_data": stateless_access_control_list_data,
        },
        operation_label="update DUR Stateless Access Control List by ID",
        info_message=f"Updating DUR Stateless Access Control List {stateless_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List {stateless_access_control_list_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_stateless_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    stateless_access_control_list_id: str = Field(..., description="Numeric ID of the Stateless Access Control List."),
    stateless_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement Stateless Access Control List object. Required keys: 'name'. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, redirect_type, ipsec_map_based_redirect, tunnel_id, deny_list_user_if_acl_applied, log_if_acl_applied, position, policer_profile, qos_profile, time_range."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Stateless Access Control List by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Stateless ACLs are layer-3/4 rule sets evaluated without connection tracking.

    Maps to 'replace_enforcement_profile_dur_stateless_access_control_list_by_product_name_stateless_access_control_list_id' in pyclearpass (PUT /enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_stateless_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "stateless_access_control_list_id": stateless_access_control_list_id,
            "stateless_access_control_list_data": stateless_access_control_list_data,
        },
        operation_label="replace DUR Stateless Access Control List by ID",
        info_message=f"Replacing DUR Stateless Access Control List {stateless_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List {stateless_access_control_list_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_stateless_access_control_list_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    stateless_access_control_list_id: str = Field(..., description="Numeric ID of the Stateless Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Stateless Access Control List by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Stateless ACLs are layer-3/4 rule sets evaluated without connection tracking.

    Maps to 'delete_enforcement_profile_dur_stateless_access_control_list_by_product_name_stateless_access_control_list_id' in pyclearpass (DELETE /enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_stateless_access_control_list_by_id",
        call_kwargs={
            "product_name": product_name,
            "stateless_access_control_list_id": stateless_access_control_list_id,
        },
        operation_label="delete DUR Stateless Access Control List by ID",
        info_message=f"Deleting DUR Stateless Access Control List {stateless_access_control_list_id} for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List {stateless_access_control_list_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_stateless_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Stateless Access Control List."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Stateless Access Control List by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Stateless Access Control List.

    Maps to 'get_enforcement_profile_dur_stateless_access_control_list_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_stateless_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Stateless Access Control List by name",
        info_message=f"Retrieving DUR Stateless Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_stateless_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Stateless Access Control List."),
    stateless_access_control_list_data: Dict[str, Any] = Field(..., description="Partial Stateless Access Control List object — only the keys you supply are changed. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, redirect_type, ipsec_map_based_redirect, tunnel_id, deny_list_user_if_acl_applied, log_if_acl_applied, position, policer_profile, qos_profile, time_range."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Stateless Access Control List by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Stateless Access Control List.

    Maps to 'update_enforcement_profile_dur_stateless_access_control_list_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_stateless_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "stateless_access_control_list_data": stateless_access_control_list_data,
        },
        operation_label="update DUR Stateless Access Control List by name",
        info_message=f"Updating DUR Stateless Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_stateless_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Stateless Access Control List."),
    stateless_access_control_list_data: Dict[str, Any] = Field(..., description="Complete replacement Stateless Access Control List object. Required keys: 'name'. Recognised top-level keys: src_traffic_match, src_alias, src_ip_address, src_netmask, dst_traffic_match, dst_alias, dst_ip_address, dst_netmask, service_type, protocol_number, service, tcp_min_port, tcp_max_port, udp_min_port, udp_max_port, action, redirect_type, ipsec_map_based_redirect, tunnel_id, deny_list_user_if_acl_applied, log_if_acl_applied, position, policer_profile, qos_profile, time_range."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Stateless Access Control List by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Stateless Access Control List.

    Maps to 'replace_enforcement_profile_dur_stateless_access_control_list_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_stateless_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "stateless_access_control_list_data": stateless_access_control_list_data,
        },
        operation_label="replace DUR Stateless Access Control List by name",
        info_message=f"Replacing DUR Stateless Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_stateless_access_control_list_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Stateless Access Control List."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Stateless Access Control List by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Stateless Access Control List.

    Maps to 'delete_enforcement_profile_dur_stateless_access_control_list_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_stateless_access_control_list_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Stateless Access Control List by name",
        info_message=f"Deleting DUR Stateless Access Control List '{name}' for product '{product_name}'...",
        success_message=f"DUR Stateless Access Control List '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# Time Ranges
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_time_ranges(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role Time Ranges for an Aruba product.

    Time Ranges define absolute or periodic windows that ACL rules can be scoped to.

    Maps to 'get_enforcement_profile_dur_time_range_by_product_name' in pyclearpass (GET /enforcement-profile-dur/time-range/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_time_ranges",
        resource_plural="DUR Time Ranges",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_time_range(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    time_range_data: Dict[str, Any] = Field(..., description="Time Range object. Required keys: 'name', 'rules'. Recognised top-level keys: start_day_or_date, end_day_or_date, start_time, end_time."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role Time Range for an Aruba product.

    Time Ranges define absolute or periodic windows that ACL rules can be scoped to.
    Required body keys: 'name', 'rules'.

    Maps to 'new_enforcement_profile_dur_time_range_by_product_name' in pyclearpass (POST /enforcement-profile-dur/time-range/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_time_range",
        call_kwargs={
            "product_name": product_name,
            "time_range_data": time_range_data,
        },
        operation_label="create DUR Time Range",
        info_message=f"Creating DUR Time Range for product '{product_name}'...",
        success_message=f"DUR Time Range created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_time_range_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    time_range_id: str = Field(..., description="Numeric ID of the Time Range."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Time Range by numeric ID.

    Time Ranges define absolute or periodic windows that ACL rules can be scoped to.

    Maps to 'get_enforcement_profile_dur_time_range_by_product_name_time_range_id' in pyclearpass (GET /enforcement-profile-dur/time-range/{product_name}/{time_range_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_time_range_by_id",
        call_kwargs={
            "product_name": product_name,
            "time_range_id": time_range_id,
        },
        operation_label="get DUR Time Range by ID",
        info_message=f"Retrieving DUR Time Range {time_range_id} for product '{product_name}'...",
        success_message=f"DUR Time Range {time_range_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_time_range_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    time_range_id: str = Field(..., description="Numeric ID of the Time Range."),
    time_range_data: Dict[str, Any] = Field(..., description="Partial Time Range object — only the keys you supply are changed. Recognised top-level keys: start_day_or_date, end_day_or_date, start_time, end_time."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Time Range by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Time Ranges define absolute or periodic windows that ACL rules can be scoped to.

    Maps to 'update_enforcement_profile_dur_time_range_by_product_name_time_range_id' in pyclearpass (PATCH /enforcement-profile-dur/time-range/{product_name}/{time_range_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_time_range_by_id",
        call_kwargs={
            "product_name": product_name,
            "time_range_id": time_range_id,
            "time_range_data": time_range_data,
        },
        operation_label="update DUR Time Range by ID",
        info_message=f"Updating DUR Time Range {time_range_id} for product '{product_name}'...",
        success_message=f"DUR Time Range {time_range_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_time_range_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    time_range_id: str = Field(..., description="Numeric ID of the Time Range."),
    time_range_data: Dict[str, Any] = Field(..., description="Complete replacement Time Range object. Required keys: 'name', 'rules'. Recognised top-level keys: start_day_or_date, end_day_or_date, start_time, end_time."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Time Range by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Time Ranges define absolute or periodic windows that ACL rules can be scoped to.

    Maps to 'replace_enforcement_profile_dur_time_range_by_product_name_time_range_id' in pyclearpass (PUT /enforcement-profile-dur/time-range/{product_name}/{time_range_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_time_range_by_id",
        call_kwargs={
            "product_name": product_name,
            "time_range_id": time_range_id,
            "time_range_data": time_range_data,
        },
        operation_label="replace DUR Time Range by ID",
        info_message=f"Replacing DUR Time Range {time_range_id} for product '{product_name}'...",
        success_message=f"DUR Time Range {time_range_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_time_range_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    time_range_id: str = Field(..., description="Numeric ID of the Time Range."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Time Range by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Time Ranges define absolute or periodic windows that ACL rules can be scoped to.

    Maps to 'delete_enforcement_profile_dur_time_range_by_product_name_time_range_id' in pyclearpass (DELETE /enforcement-profile-dur/time-range/{product_name}/{time_range_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_time_range_by_id",
        call_kwargs={
            "product_name": product_name,
            "time_range_id": time_range_id,
        },
        operation_label="delete DUR Time Range by ID",
        info_message=f"Deleting DUR Time Range {time_range_id} for product '{product_name}'...",
        success_message=f"DUR Time Range {time_range_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_time_range_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Time Range."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role Time Range by name.

    Names are scoped per product, so the same name under a different product_name is a
    different Time Range.

    Maps to 'get_enforcement_profile_dur_time_range_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/time-range/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_time_range_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR Time Range by name",
        info_message=f"Retrieving DUR Time Range '{name}' for product '{product_name}'...",
        success_message=f"DUR Time Range '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_time_range_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Time Range."),
    time_range_data: Dict[str, Any] = Field(..., description="Partial Time Range object — only the keys you supply are changed. Recognised top-level keys: start_day_or_date, end_day_or_date, start_time, end_time."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role Time Range by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different Time Range.

    Maps to 'update_enforcement_profile_dur_time_range_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/time-range/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_time_range_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "time_range_data": time_range_data,
        },
        operation_label="update DUR Time Range by name",
        info_message=f"Updating DUR Time Range '{name}' for product '{product_name}'...",
        success_message=f"DUR Time Range '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_time_range_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Time Range."),
    time_range_data: Dict[str, Any] = Field(..., description="Complete replacement Time Range object. Required keys: 'name', 'rules'. Recognised top-level keys: start_day_or_date, end_day_or_date, start_time, end_time."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role Time Range by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different Time Range.

    Maps to 'replace_enforcement_profile_dur_time_range_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/time-range/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_time_range_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "time_range_data": time_range_data,
        },
        operation_label="replace DUR Time Range by name",
        info_message=f"Replacing DUR Time Range '{name}' for product '{product_name}'...",
        success_message=f"DUR Time Range '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_time_range_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the Time Range."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role Time Range by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different Time Range.

    Maps to 'delete_enforcement_profile_dur_time_range_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/time-range/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_time_range_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR Time Range by name",
        info_message=f"Deleting DUR Time Range '{name}' for product '{product_name}'...",
        success_message=f"DUR Time Range '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )



# ============================================================================
# VoIP Profiles
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def dur_list_voip_profiles(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g. '{\"name\": {\"$contains\": \"guest\"}}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g. '+name', '-id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count."),
) -> Dict[str, Any]:
    """
    List Downloadable User Role VoIP Profiles for an Aruba product.

    VoIP Profiles set the voice VLAN and the DSCP/802.1p marking applied to voice traffic.

    Maps to 'get_enforcement_profile_dur_voip_profile_by_product_name' in pyclearpass (GET /enforcement-profile-dur/voip-profile/{product_name}).
    """
    return await _dur_list(
        ctx,
        client_method="dur_list_voip_profiles",
        resource_plural="DUR VoIP Profiles",
        product_name=product_name,
        filter_str=filter_str,
        sort=sort,
        offset=offset,
        limit=limit,
        calculate_count=calculate_count,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_create_voip_profile(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    voip_profile_data: Dict[str, Any] = Field(..., description="VoIP Profile object. Required keys: 'name'. Recognised top-level keys: name, voip_vlan, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Create a Downloadable User Role VoIP Profile for an Aruba product.

    VoIP Profiles set the voice VLAN and the DSCP/802.1p marking applied to voice traffic.
    Required body keys: 'name'.

    Maps to 'new_enforcement_profile_dur_voip_profile_by_product_name' in pyclearpass (POST /enforcement-profile-dur/voip-profile/{product_name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_create_voip_profile",
        call_kwargs={
            "product_name": product_name,
            "voip_profile_data": voip_profile_data,
        },
        operation_label="create DUR VoIP Profile",
        info_message=f"Creating DUR VoIP Profile for product '{product_name}'...",
        success_message=f"DUR VoIP Profile created for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_voip_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    voip_profile_id: str = Field(..., description="Numeric ID of the VoIP Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role VoIP Profile by numeric ID.

    VoIP Profiles set the voice VLAN and the DSCP/802.1p marking applied to voice traffic.

    Maps to 'get_enforcement_profile_dur_voip_profile_by_product_name_voip_profile_id' in pyclearpass (GET /enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_voip_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "voip_profile_id": voip_profile_id,
        },
        operation_label="get DUR VoIP Profile by ID",
        info_message=f"Retrieving DUR VoIP Profile {voip_profile_id} for product '{product_name}'...",
        success_message=f"DUR VoIP Profile {voip_profile_id} retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_voip_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    voip_profile_id: str = Field(..., description="Numeric ID of the VoIP Profile."),
    voip_profile_data: Dict[str, Any] = Field(..., description="Partial VoIP Profile object — only the keys you supply are changed. Recognised top-level keys: name, voip_vlan, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role VoIP Profile by numeric ID.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    VoIP Profiles set the voice VLAN and the DSCP/802.1p marking applied to voice traffic.

    Maps to 'update_enforcement_profile_dur_voip_profile_by_product_name_voip_profile_id' in pyclearpass (PATCH /enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_voip_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "voip_profile_id": voip_profile_id,
            "voip_profile_data": voip_profile_data,
        },
        operation_label="update DUR VoIP Profile by ID",
        info_message=f"Updating DUR VoIP Profile {voip_profile_id} for product '{product_name}'...",
        success_message=f"DUR VoIP Profile {voip_profile_id} updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_voip_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    voip_profile_id: str = Field(..., description="Numeric ID of the VoIP Profile."),
    voip_profile_data: Dict[str, Any] = Field(..., description="Complete replacement VoIP Profile object. Required keys: 'name'. Recognised top-level keys: name, voip_vlan, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role VoIP Profile by numeric ID.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    VoIP Profiles set the voice VLAN and the DSCP/802.1p marking applied to voice traffic.

    Maps to 'replace_enforcement_profile_dur_voip_profile_by_product_name_voip_profile_id' in pyclearpass (PUT /enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_voip_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "voip_profile_id": voip_profile_id,
            "voip_profile_data": voip_profile_data,
        },
        operation_label="replace DUR VoIP Profile by ID",
        info_message=f"Replacing DUR VoIP Profile {voip_profile_id} for product '{product_name}'...",
        success_message=f"DUR VoIP Profile {voip_profile_id} replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_voip_profile_by_id(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    voip_profile_id: str = Field(..., description="Numeric ID of the VoIP Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role VoIP Profile by numeric ID.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    VoIP Profiles set the voice VLAN and the DSCP/802.1p marking applied to voice traffic.

    Maps to 'delete_enforcement_profile_dur_voip_profile_by_product_name_voip_profile_id' in pyclearpass (DELETE /enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_voip_profile_by_id",
        call_kwargs={
            "product_name": product_name,
            "voip_profile_id": voip_profile_id,
        },
        operation_label="delete DUR VoIP Profile by ID",
        info_message=f"Deleting DUR VoIP Profile {voip_profile_id} for product '{product_name}'...",
        success_message=f"DUR VoIP Profile {voip_profile_id} deleted for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_get_voip_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the VoIP Profile."),
) -> Dict[str, Any]:
    """
    Get a Downloadable User Role VoIP Profile by name.

    Names are scoped per product, so the same name under a different product_name is a
    different VoIP Profile.

    Maps to 'get_enforcement_profile_dur_voip_profile_by_product_name_name_name' in pyclearpass (GET /enforcement-profile-dur/voip-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_get_voip_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="get DUR VoIP Profile by name",
        info_message=f"Retrieving DUR VoIP Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR VoIP Profile '{name}' retrieved for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_update_voip_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the VoIP Profile."),
    voip_profile_data: Dict[str, Any] = Field(..., description="Partial VoIP Profile object — only the keys you supply are changed. Recognised top-level keys: name, voip_vlan, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Update some fields of a Downloadable User Role VoIP Profile by name.

    Only the keys present in the request body are modified; everything else is left
    as-is. Use the replace operation for a full overwrite.

    Names are scoped per product, so the same name under a different product_name is a
    different VoIP Profile.

    Maps to 'update_enforcement_profile_dur_voip_profile_by_product_name_name_name' in pyclearpass (PATCH /enforcement-profile-dur/voip-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_update_voip_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "voip_profile_data": voip_profile_data,
        },
        operation_label="update DUR VoIP Profile by name",
        info_message=f"Updating DUR VoIP Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR VoIP Profile '{name}' updated for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_replace_voip_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the VoIP Profile."),
    voip_profile_data: Dict[str, Any] = Field(..., description="Complete replacement VoIP Profile object. Required keys: 'name'. Recognised top-level keys: name, voip_vlan, dscp, dot1p."),
) -> Dict[str, Any]:
    """
    Replace a Downloadable User Role VoIP Profile by name.

    This overwrites the whole object — omitted fields are cleared. Use the update
    operation for a partial change.

    Names are scoped per product, so the same name under a different product_name is a
    different VoIP Profile.

    Maps to 'replace_enforcement_profile_dur_voip_profile_by_product_name_name_name' in pyclearpass (PUT /enforcement-profile-dur/voip-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_replace_voip_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
            "voip_profile_data": voip_profile_data,
        },
        operation_label="replace DUR VoIP Profile by name",
        info_message=f"Replacing DUR VoIP Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR VoIP Profile '{name}' replaced for product '{product_name}'",
        product_name=product_name,
    )


@operation(domain="enforcement_profiles_dur")
async def dur_delete_voip_profile_by_name(
    ctx: Context,
    product_name: str = Field(..., description="Aruba product the Downloadable User Role targets, e.g. 'ArubaOS-CX', 'ArubaOS-Switch', 'Mobility Access Switch', 'Mobility Controller'."),
    name: str = Field(..., description="Name of the VoIP Profile."),
) -> Dict[str, Any]:
    """
    Delete a Downloadable User Role VoIP Profile by name.

    The deletion is permanent. Make sure no DUR policy or enforcement profile still
    references this object.

    Names are scoped per product, so the same name under a different product_name is a
    different VoIP Profile.

    Maps to 'delete_enforcement_profile_dur_voip_profile_by_product_name_name_name' in pyclearpass (DELETE /enforcement-profile-dur/voip-profile/{product_name}/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="dur_delete_voip_profile_by_name",
        call_kwargs={
            "product_name": product_name,
            "name": name,
        },
        operation_label="delete DUR VoIP Profile by name",
        info_message=f"Deleting DUR VoIP Profile '{name}' for product '{product_name}'...",
        success_message=f"DUR VoIP Profile '{name}' deleted for product '{product_name}'",
        product_name=product_name,
    )


# ============================================================================
# Base enforcement profile — full replace (PUT)
#
# These two are not DUR endpoints; they complete the /enforcement-profile CRUD
# surface, whose PATCH-based update lives in src/tools/enforcement_profiles.py.
# They live here because a full PUT is the usual way to rewrite a profile's
# dur_config block.
# ============================================================================

@operation(domain="enforcement_profiles_dur")
async def replace_enforcement_profile_by_name(
    ctx: Context,
    name: str = Field(..., description="Name of the enforcement profile."),
    profile_data: Dict[str, Any] = Field(..., description="Complete replacement enforcement profile object. Required keys: 'name', 'type'. Recognised top-level keys: name, description, type, agent_template, post_auth_template, radius_dyn_authz_template, action, device_group_list, attributes, tacacs_service_params, dur_config."),
) -> Dict[str, Any]:
    """
    Replace an enforcement profile by name (full PUT).

    This overwrites the entire profile — any field omitted from profile_data is cleared,
    including 'attributes' and 'dur_config'. Use update_enforcement_profile for a partial
    (PATCH) change.

    Maps to 'replace_enforcement_profile_name_by_name' in pyclearpass (PUT /enforcement-profile/name/{name}).
    """
    return await _dur_call(
        ctx,
        client_method="replace_enforcement_profile_by_name",
        call_kwargs={
            "name": name,
            "profile_data": profile_data,
        },
        operation_label="replace enforcement profile by name",
        info_message=f"Replacing enforcement profile '{name}'...",
        success_message=f"Enforcement profile '{name}' replaced",
        result_key="profile",
    )


@operation(domain="enforcement_profiles_dur")
async def replace_enforcement_profile_by_id(
    ctx: Context,
    enforcement_profile_id: int = Field(..., description="Numeric ID of the enforcement profile."),
    profile_data: Dict[str, Any] = Field(..., description="Complete replacement enforcement profile object. Required keys: 'name', 'type'. Recognised top-level keys: name, description, type, agent_template, post_auth_template, radius_dyn_authz_template, action, device_group_list, attributes, tacacs_service_params, dur_config."),
) -> Dict[str, Any]:
    """
    Replace an enforcement profile by numeric ID (full PUT).

    This overwrites the entire profile — any field omitted from profile_data is cleared,
    including 'attributes' and 'dur_config'. Use update_enforcement_profile for a partial
    (PATCH) change.

    Maps to 'replace_enforcement_profile_by_enforcement_profile_id' in pyclearpass (PUT /enforcement-profile/{enforcement_profile_id}).
    """
    return await _dur_call(
        ctx,
        client_method="replace_enforcement_profile_by_id",
        call_kwargs={
            "enforcement_profile_id": enforcement_profile_id,
            "profile_data": profile_data,
        },
        operation_label="replace enforcement profile by ID",
        info_message=f"Replacing enforcement profile {enforcement_profile_id}...",
        success_message=f"Enforcement profile {enforcement_profile_id} replaced",
        result_key="profile",
    )
