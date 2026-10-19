"""
Mixin class for ClearPassClient to manage certificate-related API calls.
"""

from typing import Dict, Any, Optional, Union, List

class CertificateMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for certificate management.
    """

    async def create_certificate_signing_request(self, csr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Certificate Signing Request (CSR)."""
        return await self._make_request("POST", "cert-sign-request", data=csr_data)

    async def list_certificate_trust_list(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """List entries in the Certificate Trust List (CTL)."""
        params = {}
        if filter is not None: params["filter"] = filter
        if sort is not None: params["sort"] = sort
        if offset is not None: params["offset"] = offset
        if limit is not None: params["limit"] = limit
        if calculate_count is not None: params["calculate_count"] = calculate_count
        return await self._make_request("GET", "cert-trust-list", params=params)

    async def get_certificate_trust_list_details(self, cert_trust_list_details_id: int) -> Dict[str, Any]:
        """Get details for a specific entry in the Certificate Trust List."""
        return await self._make_request("GET", f"cert-trust-list-details/{cert_trust_list_details_id}")

    async def import_certificate_to_trust_list(self, import_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import a certificate into the Certificate Trust List."""
        return await self._make_request("POST", "cert-trust-list", data=import_data)

    async def list_client_certificates(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """List client certificates."""
        params = {k: v for k, v in locals().items() if k != 'self' and v is not None}
        return await self._make_request("GET", "client-cert", params=params)

    async def get_client_certificate_by_id(self, client_cert_id: int) -> Dict[str, Any]:
        """Get a specific client certificate by its ID."""
        return await self._make_request("GET", f"client-cert/{client_cert_id}")

    async def list_server_certificates(self) -> Dict[str, Any]:
        """List server certificates (summary view)."""
        return await self._make_request("GET", "server-cert")

    async def get_server_certificate_by_service_id(self, service_id: str) -> Dict[str, Any]:
        """Get server certificate details by service ID."""
        return await self._make_request("GET", f"server-cert/{service_id}")

    # NOTE: a former `get_server_certificate_by_uuid_and_name` lived here and
    # issued `GET server-cert-name/{server_uuid}/{service_name}`. That path is
    # not served by ClearPass and answered 404 unconditionally (re-measured by
    # curl on 2026-07-31 against 6.12.4 at the unversioned `/api` root: 404 for
    # both `RADIUS` and `HTTPS(RSA)`). The real route is
    # `server-cert/name/{server_uuid}/{service_name}` (200 for both), which
    # `get_server_certificate_by_name` below already implements, so the dead
    # duplicate was removed rather than repointed.

    async def list_service_certificates(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """List service certificates."""
        params = {k: v for k, v in locals().items() if k != 'self' and v is not None}
        return await self._make_request("GET", "service-cert", params=params)

    # ------------------------------------------------------------------
    # Certificate Trust List (details / by-id lifecycle)
    # ------------------------------------------------------------------

    async def list_certificate_trust_list_details(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """List Certificate Trust List detail entries."""
        params = {}
        if filter is not None: params["filter"] = filter
        if sort is not None: params["sort"] = sort
        if offset is not None: params["offset"] = offset
        if limit is not None: params["limit"] = limit
        if calculate_count is not None: params["calculate_count"] = calculate_count
        return await self._make_request("GET", "cert-trust-list-details", params=params)

    async def get_certificate_trust_list_by_id(self, cert_trust_list_id: int) -> Dict[str, Any]:
        """Get a Certificate Trust List entry by its ID."""
        return await self._make_request("GET", f"cert-trust-list/{cert_trust_list_id}")

    async def update_certificate_trust_list(self, cert_trust_list_id: int, trust_list_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update (partially) a Certificate Trust List entry by its ID."""
        return await self._make_request("PATCH", f"cert-trust-list/{cert_trust_list_id}", data=trust_list_data)

    async def delete_certificate_trust_list(self, cert_trust_list_id: int) -> Dict[str, Any]:
        """Delete a Certificate Trust List entry by its ID."""
        return await self._make_request("DELETE", f"cert-trust-list/{cert_trust_list_id}")

    # ------------------------------------------------------------------
    # Client certificates
    # ------------------------------------------------------------------

    async def create_client_certificate(self, client_cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a client certificate."""
        return await self._make_request("POST", "client-cert", data=client_cert_data)

    async def delete_client_certificate(self, client_cert_id: int) -> Dict[str, Any]:
        """Delete a client certificate by its ID."""
        return await self._make_request("DELETE", f"client-cert/{client_cert_id}")

    # ------------------------------------------------------------------
    # Certificate revocation lists
    # ------------------------------------------------------------------

    async def list_certificate_revocation_lists(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """List certificate revocation lists."""
        params = {}
        if filter is not None: params["filter"] = filter
        if sort is not None: params["sort"] = sort
        if offset is not None: params["offset"] = offset
        if limit is not None: params["limit"] = limit
        if calculate_count is not None: params["calculate_count"] = calculate_count
        return await self._make_request("GET", "revocation-list", params=params)

    async def create_certificate_revocation_list(self, revocation_list_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new certificate revocation list."""
        return await self._make_request("POST", "revocation-list", data=revocation_list_data)

    async def get_certificate_revocation_list_by_id(self, revocation_list_id: int) -> Dict[str, Any]:
        """Get a certificate revocation list by its ID."""
        return await self._make_request("GET", f"revocation-list/{revocation_list_id}")

    async def update_certificate_revocation_list(self, revocation_list_id: int, revocation_list_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update (partially) a certificate revocation list by its ID."""
        return await self._make_request("PATCH", f"revocation-list/{revocation_list_id}", data=revocation_list_data)

    async def delete_certificate_revocation_list(self, revocation_list_id: int) -> Dict[str, Any]:
        """Delete a certificate revocation list by its ID."""
        return await self._make_request("DELETE", f"revocation-list/{revocation_list_id}")

    # ------------------------------------------------------------------
    # Self-signed / server / service certificates
    # ------------------------------------------------------------------

    async def create_self_signed_certificate(self, self_signed_cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a self-signed certificate."""
        return await self._make_request("POST", "self-signed-cert", data=self_signed_cert_data)

    async def get_server_certificate_by_name(self, server_uuid: str, service_name: str) -> Dict[str, Any]:
        """Get a server certificate by server UUID and service name."""
        return await self._make_request("GET", f"server-cert/name/{server_uuid}/{service_name}")

    async def replace_server_certificate_by_name(
        self,
        server_uuid: str,
        service_name: str,
        server_cert_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace (add) a server certificate by server UUID and service name."""
        return await self._make_request("PUT", f"server-cert/name/{server_uuid}/{service_name}", data=server_cert_data)

    async def disable_server_certificate(self, server_uuid: str, service_name: str) -> Dict[str, Any]:
        """Disable a server certificate by server UUID and service name."""
        return await self._make_request("PATCH", f"server-cert/name/{server_uuid}/{service_name}/disable")

    async def enable_server_certificate(self, server_uuid: str, service_name: str) -> Dict[str, Any]:
        """Enable a server certificate by server UUID and service name."""
        return await self._make_request("PATCH", f"server-cert/name/{server_uuid}/{service_name}/enable")

    async def update_server_certificate(self, service_id: str, server_cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update (partially) a server certificate by service ID."""
        return await self._make_request("PATCH", f"server-cert/{service_id}", data=server_cert_data)

    async def create_service_certificate(self, service_cert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a service certificate."""
        return await self._make_request("POST", "service-cert", data=service_cert_data)

    async def get_service_certificate_by_id(self, service_cert_id: int) -> Dict[str, Any]:
        """Get a service certificate by its ID."""
        return await self._make_request("GET", f"service-cert/{service_cert_id}")

    async def delete_service_certificate(self, service_cert_id: int) -> Dict[str, Any]:
        """Delete a service certificate by its ID."""
        return await self._make_request("DELETE", f"service-cert/{service_cert_id}")