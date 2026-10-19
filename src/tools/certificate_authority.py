"""
MCP tools for Onboard Certificate Authority operations.

Provides natural language automation for the ClearPass Onboard certificate authority:
listing and retrieving certificates, creating/importing/signing certificate requests,
revoking and exporting certificates, plus management of Onboard devices and Onboard users.

All operation names are prefixed `onboard_` because the platform certificates domain
already owns the generic certificate operation names.
"""

import logging
from typing import Dict, Any, Optional

from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


# ================================
# ONBOARD CERTIFICATES
# ================================

@operation(domain="certificate_authority")
async def onboard_list_certificates(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1 - 1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List Onboard certificates and certificate signing requests.

    Use this to browse the Onboard certificate authority inventory before issuing,
    signing, exporting, or revoking a certificate.

    Maps to 'get_certificate' in pyclearpass (GET /certificate).
    """
    await ctx.info(f"Retrieving Onboard certificates (limit: {limit})...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_list_certificates(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        certificates = response.get("_embedded", {}).get("items", response.get("items", []))

        return {
            "success": True,
            "total_count": len(certificates),
            "certificates": certificates,
            "message": f"Retrieved {len(certificates)} Onboard certificates"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Onboard certificates: {e}")
        return await format_api_error(e, "list onboard certificates")
    except Exception as e:
        logger.error(f"Unexpected error listing Onboard certificates: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_get_certificate_by_id(
    ctx: Context,
    certificate_id: int = Field(..., description="Numeric ID of the certificate")
) -> Dict[str, Any]:
    """
    Get an Onboard certificate or certificate signing request by ID.

    Maps to 'get_certificate_by_certificate_id' in pyclearpass (GET /certificate/{certificate_id}).
    """
    await ctx.info(f"Retrieving Onboard certificate {certificate_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_get_certificate_by_id(certificate_id)

        return {
            "success": True,
            "certificate": response,
            "message": f"Retrieved Onboard certificate {certificate_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Onboard certificate {certificate_id}: {e}")
        return await format_api_error(e, "get onboard certificate")
    except Exception as e:
        logger.error(f"Unexpected error getting Onboard certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_get_certificate_chain(
    ctx: Context,
    cert_id: int = Field(..., description="Numeric ID of the certificate")
) -> Dict[str, Any]:
    """
    Get an Onboard certificate together with its trust chain.

    Returns the certificate plus the CA and any intermediate certificates required to
    validate it.

    Maps to 'get_certificate_by_cert_id_chain' in pyclearpass (GET /certificate/{cert_id}/chain).
    """
    await ctx.info(f"Retrieving trust chain for Onboard certificate {cert_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_get_certificate_chain(cert_id)

        return {
            "success": True,
            "certificate_chain": response,
            "message": f"Retrieved trust chain for Onboard certificate {cert_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get certificate chain for {cert_id}: {e}")
        return await format_api_error(e, "get onboard certificate chain")
    except Exception as e:
        logger.error(f"Unexpected error getting certificate chain: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_import_certificate(
    ctx: Context,
    certificate_data: Dict[str, Any] = Field(..., description=(
        "Certificate import payload. Required: 'type' (certificate type), 'certificate_file' "
        "(certificate contents), 'certificate_file_encoding'. Optional: 'ca_id', 'key_file', "
        "'key_file_encoding', 'key_passphrase'."
    ))
) -> Dict[str, Any]:
    """
    Import a code-signing, trusted, or CA certificate into Onboard.

    Maps to 'new_certificate_import' in pyclearpass (POST /certificate/import).
    """
    await ctx.info("Importing certificate into the Onboard certificate authority...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_import_certificate(certificate_data)

        return {
            "success": True,
            "certificate": response,
            "message": "Certificate imported successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to import Onboard certificate: {e}")
        return await format_api_error(e, "import onboard certificate")
    except Exception as e:
        logger.error(f"Unexpected error importing Onboard certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_create_certificate(
    ctx: Context,
    certificate_data: Dict[str, Any] = Field(..., description=(
        "New certificate payload. Required: 'ca_id', 'cert_type', 'country', 'state', 'locality', "
        "'organization', 'common_name', 'email_address', 'key_type'. Optional subject-alt-name and "
        "issuance fields include 'organizational_unit', 'dns_name', 'mac_address', 'device_name', "
        "'user_name', 'issue_cert' and 'days'."
    ))
) -> Dict[str, Any]:
    """
    Create a new certificate signing request and private key in Onboard.

    Set 'issue_cert' to true in the payload to have the certificate authority issue the
    certificate immediately rather than leaving a pending request.

    Maps to 'new_certificate_new' in pyclearpass (POST /certificate/new).
    """
    await ctx.info("Creating a new Onboard certificate signing request...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_create_certificate(certificate_data)

        return {
            "success": True,
            "certificate": response,
            "message": "Onboard certificate signing request created successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create Onboard certificate: {e}")
        return await format_api_error(e, "create onboard certificate")
    except Exception as e:
        logger.error(f"Unexpected error creating Onboard certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_import_certificate_request(
    ctx: Context,
    request_data: Dict[str, Any] = Field(..., description=(
        "Certificate signing request payload. Required: 'ca_id', 'file_csr' (PEM encoded PKCS#10 "
        "request), 'cert_type'. Optional: 'file_csr_encoding', 'issue_cert', 'days'."
    ))
) -> Dict[str, Any]:
    """
    Import an existing certificate signing request into Onboard.

    Maps to 'new_certificate_request' in pyclearpass (POST /certificate/request).
    """
    await ctx.info("Importing a certificate signing request into Onboard...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_import_certificate_request(request_data)

        return {
            "success": True,
            "certificate_request": response,
            "message": "Certificate signing request imported successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to import certificate signing request: {e}")
        return await format_api_error(e, "import onboard certificate request")
    except Exception as e:
        logger.error(f"Unexpected error importing certificate signing request: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_sign_certificate_request(
    ctx: Context,
    cert_id: int = Field(..., description="Numeric ID of the certificate signing request"),
    sign_data: Dict[str, Any] = Field(..., description=(
        "Signing payload. Required: 'ca_id', 'days', 'confirm_sign' (must be true to sign). "
        "Optional: 'custom_subject' and 'custom_subject_alt_name' field/value lists."
    ))
) -> Dict[str, Any]:
    """
    Sign a pending Onboard certificate signing request and issue a certificate.

    The request is only signed when 'confirm_sign' is true in the payload.

    Maps to 'new_certificate_by_cert_id_sign' in pyclearpass (POST /certificate/{cert_id}/sign).
    """
    await ctx.info(f"Signing Onboard certificate signing request {cert_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_sign_certificate_request(cert_id, sign_data)

        return {
            "success": True,
            "certificate": response,
            "message": f"Certificate signing request {cert_id} signed successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to sign certificate request {cert_id}: {e}")
        return await format_api_error(e, "sign onboard certificate request")
    except Exception as e:
        logger.error(f"Unexpected error signing certificate request: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_reject_certificate_request(
    ctx: Context,
    cert_id: int = Field(..., description="Numeric ID of the certificate signing request"),
    reject_data: Dict[str, Any] = Field(..., description=(
        "Rejection payload. Set 'confirm_reject' to true to confirm rejection of this request."
    ))
) -> Dict[str, Any]:
    """
    Reject a pending Onboard certificate signing request.

    The request is only rejected when 'confirm_reject' is true in the payload.

    Maps to 'new_certificate_by_cert_id_reject' in pyclearpass (POST /certificate/{cert_id}/reject).
    """
    await ctx.info(f"Rejecting Onboard certificate signing request {cert_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_reject_certificate_request(cert_id, reject_data)

        return {
            "success": True,
            "result": response,
            "message": f"Certificate signing request {cert_id} rejected"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to reject certificate request {cert_id}: {e}")
        return await format_api_error(e, "reject onboard certificate request")
    except Exception as e:
        logger.error(f"Unexpected error rejecting certificate request: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_revoke_certificate(
    ctx: Context,
    cert_id: int = Field(..., description="Numeric ID of the certificate"),
    revoke_data: Dict[str, Any] = Field(..., description=(
        "Revocation payload. Required: 'ca_id' (numeric ID of the certificate authority) and "
        "'confirm_revoke' (must be true to confirm revocation)."
    ))
) -> Dict[str, Any]:
    """
    Revoke an Onboard certificate.

    Revocation immediately invalidates the certificate for network access. The
    certificate is only revoked when 'confirm_revoke' is true in the payload.

    Maps to 'new_certificate_by_cert_id_revoke' in pyclearpass (POST /certificate/{cert_id}/revoke).
    """
    await ctx.info(f"Revoking Onboard certificate {cert_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_revoke_certificate(cert_id, revoke_data)

        return {
            "success": True,
            "result": response,
            "message": f"Onboard certificate {cert_id} revoked"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to revoke certificate {cert_id}: {e}")
        return await format_api_error(e, "revoke onboard certificate")
    except Exception as e:
        logger.error(f"Unexpected error revoking certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_export_certificate(
    ctx: Context,
    cert_id: int = Field(..., description="Numeric ID of the certificate"),
    export_data: Dict[str, Any] = Field(..., description=(
        "Export payload. Required: 'export_format' (file format for the exported item). "
        "Optional: 'include_chain', 'include_ca', 'export_password', 'export_password2'."
    ))
) -> Dict[str, Any]:
    """
    Export an Onboard certificate or certificate signing request.

    The export format ('export_format') determines the returned encoding; PKCS#12 exports
    require an 'export_password'.

    Maps to 'new_certificate_by_cert_id_export' in pyclearpass (POST /certificate/{cert_id}/export).
    """
    await ctx.info(f"Exporting Onboard certificate {cert_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_export_certificate(cert_id, export_data)

        return {
            "success": True,
            "export": response,
            "message": f"Onboard certificate {cert_id} exported"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to export certificate {cert_id}: {e}")
        return await format_api_error(e, "export onboard certificate")
    except Exception as e:
        logger.error(f"Unexpected error exporting certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_delete_certificate(
    ctx: Context,
    certificate_id: int = Field(..., description="Numeric ID of the certificate")
) -> Dict[str, Any]:
    """
    Delete an Onboard certificate or certificate signing request.

    Deletion is permanent. To invalidate an issued certificate while retaining its
    record, use onboard_revoke_certificate instead.

    Maps to 'delete_certificate_by_certificate_id' in pyclearpass (DELETE /certificate/{certificate_id}).
    """
    await ctx.info(f"Deleting Onboard certificate {certificate_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_delete_certificate(certificate_id)

        return {
            "success": True,
            "result": response,
            "message": f"Onboard certificate {certificate_id} deleted"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete certificate {certificate_id}: {e}")
        return await format_api_error(e, "delete onboard certificate")
    except Exception as e:
        logger.error(f"Unexpected error deleting certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ================================
# ONBOARD DEVICES
# ================================

@operation(domain="certificate_authority")
async def onboard_list_devices(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1 - 1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List devices enrolled through ClearPass Onboard.

    Maps to 'get_onboard_device' in pyclearpass (GET /onboard/device).
    """
    await ctx.info(f"Retrieving Onboard devices (limit: {limit})...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_list_devices(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        devices = response.get("_embedded", {}).get("items", response.get("items", []))

        return {
            "success": True,
            "total_count": len(devices),
            "devices": devices,
            "message": f"Retrieved {len(devices)} Onboard devices"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Onboard devices: {e}")
        return await format_api_error(e, "list onboard devices")
    except Exception as e:
        logger.error(f"Unexpected error listing Onboard devices: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_get_device_by_id(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the device")
) -> Dict[str, Any]:
    """
    Get a single Onboard device by ID.

    Maps to 'get_onboard_device_by_id' in pyclearpass (GET /onboard/device/{id}).
    """
    await ctx.info(f"Retrieving Onboard device {device_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_get_device_by_id(device_id)

        return {
            "success": True,
            "device": response,
            "message": f"Retrieved Onboard device {device_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Onboard device {device_id}: {e}")
        return await format_api_error(e, "get onboard device")
    except Exception as e:
        logger.error(f"Unexpected error getting Onboard device: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_update_device(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the device"),
    device_data: Dict[str, Any] = Field(..., description=(
        "Fields to update on the Onboard device, e.g. 'status' (controls whether the device may "
        "enroll and access the network), 'device_name', 'device_type', 'mac_address', 'usernames'."
    ))
) -> Dict[str, Any]:
    """
    Update settings for an Onboard device.

    Setting 'status' to a denied value stops the device from enrolling and accessing
    the network without deleting its record.

    Maps to 'update_onboard_device_by_id' in pyclearpass (PATCH /onboard/device/{id}).
    """
    await ctx.info(f"Updating Onboard device {device_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_update_device(device_id, device_data)

        return {
            "success": True,
            "device": response,
            "message": f"Onboard device {device_id} updated"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update Onboard device {device_id}: {e}")
        return await format_api_error(e, "update onboard device")
    except Exception as e:
        logger.error(f"Unexpected error updating Onboard device: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_delete_device(
    ctx: Context,
    device_id: int = Field(..., description="Numeric ID of the device"),
    disconnect_active_sessions: Optional[bool] = Field(None, description="true: disconnect the device from the network (default). false: take no action"),
    ignore_disconnect_errors: Optional[bool] = Field(None, description=(
        "true: optional disconnect — failure to disconnect is ignored and the device is forcibly deleted. "
        "false: require disconnect (recommended, default) — failure to disconnect stops the deletion. "
        "Ignored when disconnect_active_sessions is false."
    ))
) -> Dict[str, Any]:
    """
    Delete an Onboard device.

    By default active sessions are disconnected and the delete fails if they cannot be,
    so the device does not retain network access through an existing session.

    Maps to 'delete_onboard_device_by_id' in pyclearpass (DELETE /onboard/device/{id}).
    """
    await ctx.info(f"Deleting Onboard device {device_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_delete_device(
            device_id,
            disconnect_active_sessions=disconnect_active_sessions,
            ignore_disconnect_errors=ignore_disconnect_errors
        )

        return {
            "success": True,
            "result": response,
            "message": f"Onboard device {device_id} deleted"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete Onboard device {device_id}: {e}")
        return await format_api_error(e, "delete onboard device")
    except Exception as e:
        logger.error(f"Unexpected error deleting Onboard device: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ================================
# ONBOARD USERS
# ================================

@operation(domain="certificate_authority")
async def onboard_list_users(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return"),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default +id)"),
    offset: Optional[int] = Field(None, description="Zero based offset to start from"),
    limit: Optional[int] = Field(25, description="Maximum number of items to return (1 - 1000)"),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count")
) -> Dict[str, Any]:
    """
    List users known to ClearPass Onboard.

    These are the users who have enrolled (or may enroll) devices through Onboard.

    Maps to 'get_user' in pyclearpass (GET /user).
    """
    await ctx.info(f"Retrieving Onboard users (limit: {limit})...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_list_users(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        users = response.get("_embedded", {}).get("items", response.get("items", []))

        return {
            "success": True,
            "total_count": len(users),
            "users": users,
            "message": f"Retrieved {len(users)} Onboard users"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Onboard users: {e}")
        return await format_api_error(e, "list onboard users")
    except Exception as e:
        logger.error(f"Unexpected error listing Onboard users: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_get_user_by_id(
    ctx: Context,
    user_id: int = Field(..., description="Numeric ID of the user")
) -> Dict[str, Any]:
    """
    Get a single Onboard user by ID.

    Maps to 'get_user_by_id' in pyclearpass (GET /user/{id}).
    """
    await ctx.info(f"Retrieving Onboard user {user_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_get_user_by_id(user_id)

        return {
            "success": True,
            "user": response,
            "message": f"Retrieved Onboard user {user_id}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Onboard user {user_id}: {e}")
        return await format_api_error(e, "get onboard user")
    except Exception as e:
        logger.error(f"Unexpected error getting Onboard user: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_update_user(
    ctx: Context,
    user_id: int = Field(..., description="Numeric ID of the user"),
    user_data: Dict[str, Any] = Field(..., description=(
        "Fields to update on the Onboard user, e.g. 'status' (determines whether the user can "
        "enroll devices) and 'username'."
    ))
) -> Dict[str, Any]:
    """
    Update settings for an Onboard user.

    Maps to 'update_user_by_id' in pyclearpass (PATCH /user/{id}).
    """
    await ctx.info(f"Updating Onboard user {user_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_update_user(user_id, user_data)

        return {
            "success": True,
            "user": response,
            "message": f"Onboard user {user_id} updated"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update Onboard user {user_id}: {e}")
        return await format_api_error(e, "update onboard user")
    except Exception as e:
        logger.error(f"Unexpected error updating Onboard user: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificate_authority")
async def onboard_delete_user(
    ctx: Context,
    user_id: int = Field(..., description="Numeric ID of the user")
) -> Dict[str, Any]:
    """
    Delete an Onboard user.

    Maps to 'delete_user_by_id' in pyclearpass (DELETE /user/{id}).
    """
    await ctx.info(f"Deleting Onboard user {user_id}...")
    try:
        client = await get_clearpass_client()
        response = await client.onboard_delete_user(user_id)

        return {
            "success": True,
            "result": response,
            "message": f"Onboard user {user_id} deleted"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete Onboard user {user_id}: {e}")
        return await format_api_error(e, "delete onboard user")
    except Exception as e:
        logger.error(f"Unexpected error deleting Onboard user: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}
