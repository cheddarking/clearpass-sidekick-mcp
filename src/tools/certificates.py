"""
MCP tools for Certificate management.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Union
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error, format_clarification_needed
from ..models.certificates import (
    CertificateSigningRequestCreate,
    CertificateTrustListImport
)

logger = logging.getLogger(__name__)


@operation(domain="certificates")
async def create_certificate_signing_request(
    ctx: Context,
    subject_cn: str = Field(..., description="Common Name (e.g., server.example.com) for the certificate."),
    private_key_password: str = Field(..., description="Password to protect the private key."),
    private_key_type: str = Field(default="RSA-2048", description="Type of private key (e.g., RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384)."),
    digest_algorithm: str = Field(default="SHA256", description="Digest algorithm for the signature (e.g., SHA256, SHA384, SHA512, MD5)."),
    subject_o: Optional[str] = Field(None, description="Organization (O)."),
    subject_ou: Optional[str] = Field(None, description="Organizational Unit (OU)."),
    subject_l: Optional[str] = Field(None, description="Locality/City (L)."),
    subject_st: Optional[str] = Field(None, description="State/Province (ST)."),
    subject_c: Optional[str] = Field(None, description="Country (C) - 2-letter code."),
    subject_san: Optional[str] = Field(None, description="Subject Alternative Names (SAN), comma-separated (e.g., dns:alt.example.com,ip:1.2.3.4).")
) -> Dict[str, Any]:
    """
    Create a Certificate Signing Request (CSR) on ClearPass.
    This maps to the 'new_cert_sign_request' function in pyclearpass.
    """
    await ctx.info(f"Creating Certificate Signing Request for CN: {subject_cn}")
    try:
        client = await get_clearpass_client()
        # Normalize digest algorithm to uppercase as commonly expected by ClearPass API
        normalized_digest = digest_algorithm.upper() if digest_algorithm else "SHA256"
        
        csr_data = CertificateSigningRequestCreate(
            subject_CN=subject_cn,
            subject_O=subject_o,
            subject_OU=subject_ou,
            subject_L=subject_l,
            subject_ST=subject_st,
            subject_C=subject_c,
            subject_SAN=subject_san,
            private_key_password=private_key_password,
            private_key_type=private_key_type,
            digest_algorithm=normalized_digest
        )
        response = await client.create_certificate_signing_request(csr_data.model_dump(exclude_none=True))
        # Assuming response contains the created CSR details, including id and potentially the PEM
        return {
            "success": True,
            "message": "Certificate Signing Request created successfully.",
            "csr_details": response 
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create CSR: {e}")
        return await format_api_error(e, "create certificate signing request")
    except Exception as e:
        logger.error(f"Unexpected error creating CSR: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def list_certificate_trust_list(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"alias_name\": \"MyCert\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+id', '-alias_name')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List entries in the Certificate Trust List (CTL).
    Maps to 'get_cert_trust_list' in pyclearpass.
    """
    await ctx.info("Listing Certificate Trust List entries...")
    try:
        client = await get_clearpass_client()
        params = {
            "sort": sort,
            "offset": offset,
            "limit": limit,
            "calculate_count": calculate_count
        }
        
        # Handle filter parameter specially - only add if provided and valid JSON
        if filter_str:
            try:
                # Validate that filter_str is valid JSON
                json.loads(filter_str)
                params["filter"] = filter_str
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON filter provided: {filter_str}")
                # Don't include invalid filter
        
        # Remove None values from params before passing to client
        active_params = {k: v for k, v in params.items() if v is not None}
        
        response = await client.list_certificate_trust_list(**active_params)
        
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "trust_list_entries": items,
            "message": f"Retrieved {len(items)} Certificate Trust List entries."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Certificate Trust List: {e}")
        return await format_api_error(e, "list certificate trust list")
    except Exception as e:
        logger.error(f"Unexpected error listing Certificate Trust List: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_certificate_trust_list_details(
    ctx: Context,
    cert_trust_list_details_id: int = Field(..., description="ID of the Certificate Trust List detail entry.")
    # The pyclearpass function is get_cert_trust_list_details_by_cert_trust_list_details_id,
    # but the API endpoint seems to be /cert-trust-list-details/{id} which is simpler.
    # The implementation plan also refers to it as get_certificate_trust_list_details.
    # Let's assume for now it means getting a *specific detail entry* by its ID.
    # If it means listing all details with filtering, the parameters would be different.
) -> Dict[str, Any]:
    """
    Get details for a specific entry in the Certificate Trust List.
    Maps to 'get_cert_trust_list_details_by_cert_trust_list_details_id' in pyclearpass.
    """
    await ctx.info(f"Getting Certificate Trust List details for ID: {cert_trust_list_details_id}")
    try:
        client = await get_clearpass_client()
        response = await client.get_certificate_trust_list_details(cert_trust_list_details_id)
        return {
            "success": True,
            "trust_list_detail": response,
            "message": "Certificate Trust List details retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Certificate Trust List details: {e}")
        return await format_api_error(e, "get certificate trust list details")
    except Exception as e:
        logger.error(f"Unexpected error getting Certificate Trust List details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def import_certificate_to_trust_list(
    ctx: Context,
    cert_file_content: str = Field(..., description="Content of the certificate file (PEM format, can be plain text or Base64 encoded string)."),
    cert_usage: List[str] = Field(..., description="List of usages for this certificate. Must come from the appliance vocabulary: 'EAP', 'Others', 'SAML', 'SMTP', 'AD/LDAP Servers', 'Aruba Services', 'Aruba Infrastructure', 'Endpoint Context Servers', 'RadSec', 'Database'. Common aliases ('TLS', 'other', 'SAML_IDP', ...) are mapped for you. Example: ['Others']."),
    enabled: bool = Field(default=True, description="Set to true to enable the certificate in the trust list upon import.")
) -> Dict[str, Any]:
    """
    Import a certificate into the Certificate Trust List.
    Maps to 'new_cert_trust_list' in pyclearpass.

    Example: cert_usage=['Others'], enabled=False for an inert import.
    """
    # cert_usage vocabulary.
    #
    # These are the values ClearPass 6.12.4 actually accepts, read off the live
    # appliance (2026-07-30): the distinct `cert_usage` entries on the 51
    # existing trust-list objects, then confirmed one-by-one by POSTing each
    # candidate -- an accepted usage falls through to
    # 'Invalid certificate file...' while a rejected one answers
    # 'Invalid Certificate usage "<x>" specified' (HTTP 422).
    #
    # The constants this tool used to emit -- 'OTHER_TLS', 'HTTPS_SERVER',
    # 'SAML_IDP', 'RADIUS_PROXY_TLS' -- are all rejected with that 422. They
    # were never appliance values, so an LLM following the old docstring could
    # not get a 200. They are kept below purely as inbound aliases.
    _CANONICAL_USAGES = (
        "EAP",
        "Others",
        "SAML",
        "SMTP",
        "AD/LDAP Servers",
        "Aruba Services",
        "Aruba Infrastructure",
        "Endpoint Context Servers",
        "RadSec",
        "Database",
    )

    # Lookup is keyed on the upper-cased input so any casing of a real value
    # round-trips to the appliance's own spelling.
    valid_usages = {value.upper(): value for value in _CANONICAL_USAGES}
    valid_usages.update({
        # Legacy invented constants -> nearest real value.
        "OTHER_TLS": "Others",
        "OTHER": "Others",
        "TLS": "Others",
        "HTTPS": "Others",
        "HTTPS_SERVER": "Others",
        "SAML_IDP": "SAML",
        "RADIUS_PROXY_TLS": "RadSec",
        # Conversational aliases.
        "AD": "AD/LDAP Servers",
        "LDAP": "AD/LDAP Servers",
        "AD/LDAP": "AD/LDAP Servers",
        "ARUBA": "Aruba Services",
        "ARUBA_SERVICES": "Aruba Services",
        "ARUBA_INFRASTRUCTURE": "Aruba Infrastructure",
        "ENDPOINT_CONTEXT_SERVERS": "Endpoint Context Servers",
        "ECS": "Endpoint Context Servers",
        "DB": "Database",
    })

    # Normalize usage values. Anything unrecognised is passed through
    # untouched so a vocabulary added by a newer ClearPass release still works.
    normalized_usage = []
    for usage in cert_usage:
        normalized = valid_usages.get(usage.upper(), usage)
        normalized_usage.append(normalized)

    await ctx.info(f"Importing certificate with normalized usage: {normalized_usage}")

    try:
        client = await get_clearpass_client()
        import_data = CertificateTrustListImport(
            cert_file=cert_file_content, # pyclearpass expects 'cert_file'
            cert_usage=normalized_usage,
            enabled=enabled
        )
        response = await client.import_certificate_to_trust_list(import_data.model_dump(exclude_none=True))
        return {
            "success": True,
            "message": "Certificate imported to Trust List successfully.",
            "imported_certificate_details": response 
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to import certificate to Trust List: {e}")
        return await format_api_error(e, "import certificate to trust list")
    except Exception as e:
        logger.error(f"Unexpected error importing certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def list_client_certificates(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression."),
    sort: Optional[str] = Field(None, description="Sort ordering."),
    offset: Optional[int] = Field(None, description="Zero-based offset."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate total count.")
) -> Dict[str, Any]:
    """
    List client certificates.
    Maps to 'get_client_cert' in pyclearpass.
    """
    await ctx.info("Listing client certificates...")
    try:
        client = await get_clearpass_client()
        params = {k: v for k, v in locals().items() if k not in ["ctx", "client"] and v is not None}
        # Correcting param name for filter_str to filter for the client call
        if "filter_str" in params:
            params["filter"] = params.pop("filter_str")
            
        response = await client.list_client_certificates(**params)
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "client_certificates": items,
            "message": f"Retrieved {len(items)} client certificates."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list client certificates: {e}")
        return await format_api_error(e, "list client certificates")
    except Exception as e:
        logger.error(f"Unexpected error listing client certificates: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_client_certificate_by_id(
    ctx: Context,
    client_cert_id: int = Field(..., description="ID of the client certificate.")
) -> Dict[str, Any]:
    """
    Get a specific client certificate by its ID.
    Maps to 'get_client_cert_by_client_cert_id' in pyclearpass.
    """
    await ctx.info(f"Getting client certificate ID: {client_cert_id}")
    try:
        client = await get_clearpass_client()
        response = await client.get_client_certificate_by_id(client_cert_id)
        return {
            "success": True,
            "client_certificate": response,
            "message": "Client certificate details retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get client certificate: {e}")
        return await format_api_error(e, "get client certificate by id")
    except Exception as e:
        logger.error(f"Unexpected error getting client certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def list_server_certificates(ctx: Context) -> Dict[str, Any]:
    """
    List server certificates (summary view).
    Maps to 'get_server_cert' in pyclearpass. Note: This pyclearpass function does not support pagination/filtering directly.
    """
    await ctx.info("Listing server certificates...")
    try:
        client = await get_clearpass_client()
        # get_server_cert in pyclearpass does not take parameters like filter, sort, limit
        response = await client.list_server_certificates()
        
        # The response from get_server_cert is expected to be a list directly, not a dict with _embedded.
        # Adjusting based on typical pyclearpass patterns if it were paginated, but respecting its current direct list return.
        if isinstance(response, list):
            server_certs = response
            count = len(server_certs)
            message = f"Retrieved {count} server certificates."
        elif isinstance(response, dict) and "_embedded" in response and "items" in response["_embedded"]:
            # Fallback if API behaves differently than pyclearpass docstring implies for this specific call
            server_certs = response["_embedded"]["items"]
            count = len(server_certs)
            message = f"Retrieved {count} server certificates (from _embedded)."
        elif isinstance(response, dict): # case where it might return a dict but not with _embedded
             server_certs = [response] # wrap in list if it's a single object not in a list
             count = 1
             message = "Retrieved 1 server certificate (wrapped)."
        else:
            server_certs = []
            count = 0
            message = "Retrieved 0 server certificates or unexpected format."
            logger.warning(f"Unexpected response format from list_server_certificates: {type(response)}")

        return {
            "success": True,
            "count": count,
            "server_certificates": server_certs,
            "message": message
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list server certificates: {e}")
        return await format_api_error(e, "list server certificates")
    except Exception as e:
        logger.error(f"Unexpected error listing server certificates: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_server_certificate_details(
    ctx: Context,
    service_id: Optional[Union[str, int]] = Field(None, description="Service ID (numeric preferred, e.g., 1 for RADIUS, 2 for HTTPS(ECC), 7 for HTTPS(RSA), 21 for RadSec, 106 for Database). Provide this OR server_uuid and service_name."),
    server_uuid: Optional[str] = Field(None, description="Server UUID. Provide this AND service_name if not using service_id."),
    service_name: Optional[str] = Field(None, description="Service Name (e.g., 'RadiusServer'). Provide this AND server_uuid if not using service_id.")
) -> Dict[str, Any]:
    """
    Get details for a specific server certificate.

    With ``service_id`` this is ``GET server-cert/{service_id}``; with
    ``server_uuid`` + ``service_name`` it is
    ``GET server-cert/name/{server_uuid}/{service_name}``.
    """
    if service_id:
        await ctx.info(f"Getting server certificate details for service ID: {service_id}")
    elif server_uuid and service_name:
        await ctx.info(f"Getting server certificate details for server UUID: {server_uuid} and service name: {service_name}")
    else:
        return await format_clarification_needed(
            message="Insufficient parameters provided to identify the server certificate.",
            question="Please provide either a 'service_id' OR both 'server_uuid' and 'service_name'."
        )
    
    try:
        client = await get_clearpass_client()
        if service_id is not None:
            # Convert service_id to string as the API endpoint expects string in URL path
            service_id_str = str(service_id)
            response = await client.get_server_certificate_by_service_id(service_id_str)
        else: # server_uuid and service_name must be present due to check above
            response = await client.get_server_certificate_by_name(server_uuid, service_name)
        
        return {
            "success": True,
            "server_certificate_detail": response,
            "message": "Server certificate details retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server certificate details: {e}")
        return await format_api_error(e, "get server certificate details")
    except Exception as e:
        logger.error(f"Unexpected error getting server certificate details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def list_service_certificates(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression."),
    sort: Optional[str] = Field(None, description="Sort ordering."),
    offset: Optional[int] = Field(None, description="Zero-based offset."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate total count.")
) -> Dict[str, Any]:
    """
    List service certificates.
    Maps to 'get_service_cert' in pyclearpass.
    """
    await ctx.info("Listing service certificates...")
    try:
        client = await get_clearpass_client()
        params = {k: v for k, v in locals().items() if k not in ["ctx", "client"] and v is not None}
        if "filter_str" in params:
            params["filter"] = params.pop("filter_str")

        response = await client.list_service_certificates(**params)
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "service_certificates": items,
            "message": f"Retrieved {len(items)} service certificates."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list service certificates: {e}")
        return await format_api_error(e, "list service certificates")
    except Exception as e:
        logger.error(f"Unexpected error listing service certificates: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def list_certificate_trust_list_details(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return."),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default '+id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset to start from."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    Get a list of Certificate Trust List details.

    Returns the detailed view of every certificate in the ClearPass Certificate
    Trust List (issuer, subject, validity, usage and enabled state).

    Maps to 'get_cert_trust_list_details' in pyclearpass (GET /cert-trust-list-details).
    """
    await ctx.info("Listing Certificate Trust List details...")
    try:
        client = await get_clearpass_client()
        params = {
            "sort": sort,
            "offset": offset,
            "limit": limit,
            "calculate_count": calculate_count
        }
        if filter_str:
            params["filter"] = filter_str
        active_params = {k: v for k, v in params.items() if v is not None}

        response = await client.list_certificate_trust_list_details(**active_params)
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "trust_list_details": items,
            "message": f"Retrieved {len(items)} Certificate Trust List detail entries."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list Certificate Trust List details: {e}")
        return await format_api_error(e, "list certificate trust list details")
    except Exception as e:
        logger.error(f"Unexpected error listing Certificate Trust List details: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_certificate_trust_list_by_id(
    ctx: Context,
    cert_trust_list_id: int = Field(..., description="ID of the Certificate Trust List entry.")
) -> Dict[str, Any]:
    """
    Get a Certificate Trust List entry by its ID.

    Maps to 'get_cert_trust_list_by_cert_trust_list_id' in pyclearpass (GET /cert-trust-list/{cert_trust_list_id}).
    """
    await ctx.info(f"Getting Certificate Trust List entry ID: {cert_trust_list_id}")
    try:
        client = await get_clearpass_client()
        response = await client.get_certificate_trust_list_by_id(cert_trust_list_id)
        return {
            "success": True,
            "trust_list_entry": response,
            "message": "Certificate Trust List entry retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get Certificate Trust List entry: {e}")
        return await format_api_error(e, "get certificate trust list by id")
    except Exception as e:
        logger.error(f"Unexpected error getting Certificate Trust List entry: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def update_certificate_trust_list(
    ctx: Context,
    cert_trust_list_id: int = Field(..., description="ID of the Certificate Trust List entry to update."),
    trust_list_data: Dict[str, Any] = Field(..., description="Fields to update. Supported keys: 'cert_file' (certificate trust list file, string), 'enabled' (boolean, enable/disable the trust list entry), 'cert_usage' (array of usages from the appliance vocabulary: 'EAP', 'Others', 'SAML', 'SMTP', 'AD/LDAP Servers', 'Aruba Services', 'Aruba Infrastructure', 'Endpoint Context Servers', 'RadSec', 'Database' -- e.g. ['Others']).")
) -> Dict[str, Any]:
    """
    Update (enable/disable or modify) a Certificate Trust List entry.

    Performs a partial update — only the keys supplied in trust_list_data are changed.

    Maps to 'update_cert_trust_list_by_cert_trust_list_id' in pyclearpass (PATCH /cert-trust-list/{cert_trust_list_id}).
    """
    await ctx.info(f"Updating Certificate Trust List entry ID: {cert_trust_list_id}")
    try:
        client = await get_clearpass_client()
        response = await client.update_certificate_trust_list(cert_trust_list_id, trust_list_data)
        return {
            "success": True,
            "trust_list_entry": response,
            "message": f"Certificate Trust List entry {cert_trust_list_id} updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update Certificate Trust List entry: {e}")
        return await format_api_error(e, "update certificate trust list")
    except Exception as e:
        logger.error(f"Unexpected error updating Certificate Trust List entry: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def delete_certificate_trust_list(
    ctx: Context,
    cert_trust_list_id: int = Field(..., description="ID of the Certificate Trust List entry to delete.")
) -> Dict[str, Any]:
    """
    Delete a Certificate Trust List entry.

    Maps to 'delete_cert_trust_list_by_cert_trust_list_id' in pyclearpass (DELETE /cert-trust-list/{cert_trust_list_id}).
    """
    await ctx.info(f"Deleting Certificate Trust List entry ID: {cert_trust_list_id}")
    try:
        client = await get_clearpass_client()
        await client.delete_certificate_trust_list(cert_trust_list_id)
        return {
            "success": True,
            "cert_trust_list_id": cert_trust_list_id,
            "message": f"Certificate Trust List entry {cert_trust_list_id} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete Certificate Trust List entry: {e}")
        return await format_api_error(e, "delete certificate trust list")
    except Exception as e:
        logger.error(f"Unexpected error deleting Certificate Trust List entry: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def create_client_certificate(
    ctx: Context,
    client_cert_data: Dict[str, Any] = Field(..., description="Client certificate payload. Supported keys: 'certificate_url' (certificate file URL, string), 'pkcs12_file_url' (PKCS12 file URL, string), 'pkcs12_passphrase' (PKCS12 passphrase, string).")
) -> Dict[str, Any]:
    """
    Add a client certificate.

    Uploads a client certificate from a certificate URL or a PKCS12 bundle URL.

    Maps to 'new_client_cert' in pyclearpass (POST /client-cert).
    """
    await ctx.info("Adding client certificate...")
    try:
        client = await get_clearpass_client()
        response = await client.create_client_certificate(client_cert_data)
        return {
            "success": True,
            "client_certificate": response,
            "message": "Client certificate added successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to add client certificate: {e}")
        return await format_api_error(e, "create client certificate")
    except Exception as e:
        logger.error(f"Unexpected error adding client certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def delete_client_certificate(
    ctx: Context,
    client_cert_id: int = Field(..., description="ID of the client certificate to delete.")
) -> Dict[str, Any]:
    """
    Delete a client certificate.

    Maps to 'delete_client_cert_by_client_cert_id' in pyclearpass (DELETE /client-cert/{client_cert_id}).
    """
    await ctx.info(f"Deleting client certificate ID: {client_cert_id}")
    try:
        client = await get_clearpass_client()
        await client.delete_client_certificate(client_cert_id)
        return {
            "success": True,
            "client_cert_id": client_cert_id,
            "message": f"Client certificate {client_cert_id} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete client certificate: {e}")
        return await format_api_error(e, "delete client certificate")
    except Exception as e:
        logger.error(f"Unexpected error deleting client certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def list_certificate_revocation_lists(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression specifying the items to return."),
    sort: Optional[str] = Field(None, description="Sort ordering for returned items (default '+id')."),
    offset: Optional[int] = Field(None, description="Zero-based offset to start from."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    Get a list of certificate revocation lists (CRLs).

    Maps to 'get_revocation_list' in pyclearpass (GET /revocation-list).
    """
    await ctx.info("Listing certificate revocation lists...")
    try:
        client = await get_clearpass_client()
        params = {
            "sort": sort,
            "offset": offset,
            "limit": limit,
            "calculate_count": calculate_count
        }
        if filter_str:
            params["filter"] = filter_str
        active_params = {k: v for k, v in params.items() if v is not None}

        response = await client.list_certificate_revocation_lists(**active_params)
        items = response.get("_embedded", {}).get("items", [])
        total_count = response.get("count", len(items)) if calculate_count else None
        return {
            "success": True,
            "total_count": total_count,
            "returned_count": len(items),
            "revocation_lists": items,
            "message": f"Retrieved {len(items)} certificate revocation lists."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to list certificate revocation lists: {e}")
        return await format_api_error(e, "list certificate revocation lists")
    except Exception as e:
        logger.error(f"Unexpected error listing certificate revocation lists: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def create_certificate_revocation_list(
    ctx: Context,
    revocation_list_data: Dict[str, Any] = Field(..., description="Revocation list payload. Required key: 'url' (URL of the certificate revocation list). Optional keys: 'bypass_proxy' (boolean), 'periodic_update' (boolean), 'periodic_update_interval' (integer, minutes), 'last_update_status', 'last_updated_time', 'next_updated_time'.")
) -> Dict[str, Any]:
    """
    Add a new certificate revocation list (CRL).

    Maps to 'new_revocation_list' in pyclearpass (POST /revocation-list).
    """
    await ctx.info("Adding certificate revocation list...")
    try:
        client = await get_clearpass_client()
        response = await client.create_certificate_revocation_list(revocation_list_data)
        return {
            "success": True,
            "revocation_list": response,
            "message": "Certificate revocation list added successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to add certificate revocation list: {e}")
        return await format_api_error(e, "create certificate revocation list")
    except Exception as e:
        logger.error(f"Unexpected error adding certificate revocation list: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_certificate_revocation_list_by_id(
    ctx: Context,
    revocation_list_id: int = Field(..., description="ID of the certificate revocation list.")
) -> Dict[str, Any]:
    """
    Get a certificate revocation list by its ID.

    Maps to 'get_revocation_list_by_revocation_list_id' in pyclearpass (GET /revocation-list/{revocation_list_id}).
    """
    await ctx.info(f"Getting certificate revocation list ID: {revocation_list_id}")
    try:
        client = await get_clearpass_client()
        response = await client.get_certificate_revocation_list_by_id(revocation_list_id)
        return {
            "success": True,
            "revocation_list": response,
            "message": "Certificate revocation list retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get certificate revocation list: {e}")
        return await format_api_error(e, "get certificate revocation list by id")
    except Exception as e:
        logger.error(f"Unexpected error getting certificate revocation list: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def update_certificate_revocation_list(
    ctx: Context,
    revocation_list_id: int = Field(..., description="ID of the certificate revocation list to update."),
    revocation_list_data: Dict[str, Any] = Field(..., description="Fields to update. Supported keys: 'url', 'bypass_proxy' (boolean), 'periodic_update' (boolean), 'periodic_update_interval' (integer), 'last_update_status', 'last_updated_time', 'next_updated_time'.")
) -> Dict[str, Any]:
    """
    Update a certificate revocation list.

    Performs a partial update — only the keys supplied in revocation_list_data are changed.

    Maps to 'update_revocation_list_by_revocation_list_id' in pyclearpass (PATCH /revocation-list/{revocation_list_id}).
    """
    await ctx.info(f"Updating certificate revocation list ID: {revocation_list_id}")
    try:
        client = await get_clearpass_client()
        response = await client.update_certificate_revocation_list(revocation_list_id, revocation_list_data)
        return {
            "success": True,
            "revocation_list": response,
            "message": f"Certificate revocation list {revocation_list_id} updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update certificate revocation list: {e}")
        return await format_api_error(e, "update certificate revocation list")
    except Exception as e:
        logger.error(f"Unexpected error updating certificate revocation list: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def delete_certificate_revocation_list(
    ctx: Context,
    revocation_list_id: int = Field(..., description="ID of the certificate revocation list to delete.")
) -> Dict[str, Any]:
    """
    Delete a certificate revocation list by its ID.

    Maps to 'delete_revocation_list_by_revocation_list_id' in pyclearpass (DELETE /revocation-list/{revocation_list_id}).
    """
    await ctx.info(f"Deleting certificate revocation list ID: {revocation_list_id}")
    try:
        client = await get_clearpass_client()
        await client.delete_certificate_revocation_list(revocation_list_id)
        return {
            "success": True,
            "revocation_list_id": revocation_list_id,
            "message": f"Certificate revocation list {revocation_list_id} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete certificate revocation list: {e}")
        return await format_api_error(e, "delete certificate revocation list")
    except Exception as e:
        logger.error(f"Unexpected error deleting certificate revocation list: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def create_self_signed_certificate(
    ctx: Context,
    self_signed_cert_data: Dict[str, Any] = Field(..., description="Self-signed certificate payload. Required keys: 'certificate_type', 'server' (server hostname), 'type' (service type), 'subject_CN', 'private_key_password', 'private_key_type', 'digest_algorithm'. Optional keys: 'subject_O', 'subject_OU', 'subject_L', 'subject_ST', 'subject_C', 'subject_SAN'.")
) -> Dict[str, Any]:
    """
    Create a self-signed certificate.

    Generates a self-signed certificate for a ClearPass server service
    (e.g. RADIUS, HTTPS(RSA), HTTPS(ECC), RadSec).

    Maps to 'new_self_signed_cert' in pyclearpass (POST /self-signed-cert).
    """
    await ctx.info("Creating self-signed certificate...")
    try:
        client = await get_clearpass_client()
        response = await client.create_self_signed_certificate(self_signed_cert_data)
        return {
            "success": True,
            "self_signed_certificate": response,
            "message": "Self-signed certificate created successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to create self-signed certificate: {e}")
        return await format_api_error(e, "create self signed certificate")
    except Exception as e:
        logger.error(f"Unexpected error creating self-signed certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_server_certificate_by_name(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server."),
    service_name: str = Field(..., description="Service name (RADIUS, HTTPS(RSA), HTTPS(ECC) or RadSec).")
) -> Dict[str, Any]:
    """
    Get a server certificate by server UUID and service name.

    Maps to 'get_server_cert_name_by_server_uuid_service_name' in pyclearpass (GET /server-cert/name/{server_uuid}/{service_name}).
    """
    await ctx.info(f"Getting server certificate for server {server_uuid}, service {service_name}")
    try:
        client = await get_clearpass_client()
        response = await client.get_server_certificate_by_name(server_uuid, service_name)
        return {
            "success": True,
            "server_certificate": response,
            "message": "Server certificate retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get server certificate by name: {e}")
        return await format_api_error(e, "get server certificate by name")
    except Exception as e:
        logger.error(f"Unexpected error getting server certificate by name: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def replace_server_certificate_by_name(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server."),
    service_name: str = Field(..., description="Service name (RADIUS, HTTPS(RSA), HTTPS(ECC) or RadSec)."),
    server_cert_data: Dict[str, Any] = Field(..., description="Server certificate payload. Supported keys: 'certificate_url' (certificate file URL), 'pkcs12_file_url' (PKCS12 file URL), 'pkcs12_passphrase' (PKCS12 passphrase).")
) -> Dict[str, Any]:
    """
    Add (replace) a server certificate for a server UUID and service name.

    Full replacement of the certificate currently bound to that service.

    Maps to 'replace_server_cert_name_by_server_uuid_service_name' in pyclearpass (PUT /server-cert/name/{server_uuid}/{service_name}).
    """
    await ctx.info(f"Replacing server certificate for server {server_uuid}, service {service_name}")
    try:
        client = await get_clearpass_client()
        response = await client.replace_server_certificate_by_name(server_uuid, service_name, server_cert_data)
        return {
            "success": True,
            "server_certificate": response,
            "message": f"Server certificate for service '{service_name}' replaced successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to replace server certificate: {e}")
        return await format_api_error(e, "replace server certificate by name")
    except Exception as e:
        logger.error(f"Unexpected error replacing server certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def disable_server_certificate(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server."),
    service_name: str = Field(..., description="Service name (HTTPS(RSA) or HTTPS(ECC)).")
) -> Dict[str, Any]:
    """
    Disable a server certificate for a server UUID and service name.

    Maps to 'update_server_cert_name_by_server_uuid_service_name_disable' in pyclearpass (PATCH /server-cert/name/{server_uuid}/{service_name}/disable).
    """
    await ctx.info(f"Disabling server certificate for server {server_uuid}, service {service_name}")
    try:
        client = await get_clearpass_client()
        response = await client.disable_server_certificate(server_uuid, service_name)
        return {
            "success": True,
            "server_certificate": response,
            "message": f"Server certificate for service '{service_name}' disabled successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to disable server certificate: {e}")
        return await format_api_error(e, "disable server certificate")
    except Exception as e:
        logger.error(f"Unexpected error disabling server certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def enable_server_certificate(
    ctx: Context,
    server_uuid: str = Field(..., description="UUID of the server."),
    service_name: str = Field(..., description="Service name (HTTPS(RSA) or HTTPS(ECC)).")
) -> Dict[str, Any]:
    """
    Enable a server certificate for a server UUID and service name.

    Maps to 'update_server_cert_name_by_server_uuid_service_name_enable' in pyclearpass (PATCH /server-cert/name/{server_uuid}/{service_name}/enable).
    """
    await ctx.info(f"Enabling server certificate for server {server_uuid}, service {service_name}")
    try:
        client = await get_clearpass_client()
        response = await client.enable_server_certificate(server_uuid, service_name)
        return {
            "success": True,
            "server_certificate": response,
            "message": f"Server certificate for service '{service_name}' enabled successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to enable server certificate: {e}")
        return await format_api_error(e, "enable server certificate")
    except Exception as e:
        logger.error(f"Unexpected error enabling server certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def update_server_certificate(
    ctx: Context,
    service_id: Union[str, int] = Field(..., description="Service ID of the server certificate (1-RADIUS, 2-HTTPS(ECC), 7-HTTPS(RSA), 21-RadSec, 106-Database)."),
    server_cert_data: Dict[str, Any] = Field(..., description="Fields to update. Supported keys: 'service_id' (integer), 'service_name', 'certificate_type', 'subject', 'expiry_date', 'issue_date', 'issue_by', 'validity', 'public_key_algorithm', 'enabled' (boolean), 'root_ca_cert' (object), 'intermediate_ca_cert' (array), 'cert_file', 'certificate_url', 'pkcs12_file_url', 'pkcs12_passphrase'.")
) -> Dict[str, Any]:
    """
    Update a server certificate by service ID.

    Performs a partial update — only the keys supplied in server_cert_data are changed.

    Maps to 'update_server_cert_by_service_id' in pyclearpass (PATCH /server-cert/{service_id}).
    """
    await ctx.info(f"Updating server certificate for service ID: {service_id}")
    try:
        client = await get_clearpass_client()
        response = await client.update_server_certificate(str(service_id), server_cert_data)
        return {
            "success": True,
            "server_certificate": response,
            "message": f"Server certificate for service ID {service_id} updated successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to update server certificate: {e}")
        return await format_api_error(e, "update server certificate")
    except Exception as e:
        logger.error(f"Unexpected error updating server certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def create_service_certificate(
    ctx: Context,
    service_cert_data: Dict[str, Any] = Field(..., description="Service certificate payload. Supported keys: 'certificate_url' (certificate file URL), 'pkcs12_file_url' (PKCS12 file URL), 'pkcs12_passphrase' (PKCS12 passphrase).")
) -> Dict[str, Any]:
    """
    Add a service certificate.

    Maps to 'new_service_cert' in pyclearpass (POST /service-cert).
    """
    await ctx.info("Adding service certificate...")
    try:
        client = await get_clearpass_client()
        response = await client.create_service_certificate(service_cert_data)
        return {
            "success": True,
            "service_certificate": response,
            "message": "Service certificate added successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to add service certificate: {e}")
        return await format_api_error(e, "create service certificate")
    except Exception as e:
        logger.error(f"Unexpected error adding service certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def get_service_certificate_by_id(
    ctx: Context,
    service_cert_id: int = Field(..., description="ID of the service certificate.")
) -> Dict[str, Any]:
    """
    Get a service certificate by its ID.

    Maps to 'get_service_cert_by_service_cert_id' in pyclearpass (GET /service-cert/{service_cert_id}).
    """
    await ctx.info(f"Getting service certificate ID: {service_cert_id}")
    try:
        client = await get_clearpass_client()
        response = await client.get_service_certificate_by_id(service_cert_id)
        return {
            "success": True,
            "service_certificate": response,
            "message": "Service certificate retrieved successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get service certificate: {e}")
        return await format_api_error(e, "get service certificate by id")
    except Exception as e:
        logger.error(f"Unexpected error getting service certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="certificates")
async def delete_service_certificate(
    ctx: Context,
    service_cert_id: int = Field(..., description="ID of the service certificate to delete.")
) -> Dict[str, Any]:
    """
    Delete a service certificate.

    Maps to 'delete_service_cert_by_service_cert_id' in pyclearpass (DELETE /service-cert/{service_cert_id}).
    """
    await ctx.info(f"Deleting service certificate ID: {service_cert_id}")
    try:
        client = await get_clearpass_client()
        await client.delete_service_certificate(service_cert_id)
        return {
            "success": True,
            "service_cert_id": service_cert_id,
            "message": f"Service certificate {service_cert_id} deleted successfully."
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to delete service certificate: {e}")
        return await format_api_error(e, "delete service certificate")
    except Exception as e:
        logger.error(f"Unexpected error deleting service certificate: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}