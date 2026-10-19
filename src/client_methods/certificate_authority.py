"""
Mixin class for ClearPassClient to manage Onboard Certificate Authority API calls.

This module contains client methods for the ClearPass Onboard certificate authority:
certificate listing/retrieval/issuance/revocation, the Onboard device inventory, and
Onboard user records.
"""

from typing import Dict, Any, Optional


class CertificateAuthorityMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for Onboard certificate authority
    management (certificates, Onboard devices, Onboard users).
    """

    # ================================
    # ONBOARD CERTIFICATES
    # ================================

    async def onboard_list_certificates(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of Onboard certificates."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "certificate", params=params)

    async def onboard_import_certificate(self, certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import a code-signing, trusted, or CA certificate."""
        return await self._make_request("POST", "certificate/import", data=certificate_data)

    async def onboard_create_certificate(self, certificate_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new certificate signing request and private key."""
        return await self._make_request("POST", "certificate/new", data=certificate_data)

    async def onboard_import_certificate_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Import a certificate signing request."""
        return await self._make_request("POST", "certificate/request", data=request_data)

    async def onboard_get_certificate_chain(self, cert_id: int) -> Dict[str, Any]:
        """Get a certificate and its trust chain."""
        return await self._make_request("GET", f"certificate/{cert_id}/chain")

    async def onboard_export_certificate(self, cert_id: int, export_data: Dict[str, Any]) -> Dict[str, Any]:
        """Export a certificate or certificate signing request."""
        return await self._make_request("POST", f"certificate/{cert_id}/export", data=export_data)

    async def onboard_reject_certificate_request(self, cert_id: int, reject_data: Dict[str, Any]) -> Dict[str, Any]:
        """Reject a certificate signing request."""
        return await self._make_request("POST", f"certificate/{cert_id}/reject", data=reject_data)

    async def onboard_revoke_certificate(self, cert_id: int, revoke_data: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke a certificate."""
        return await self._make_request("POST", f"certificate/{cert_id}/revoke", data=revoke_data)

    async def onboard_sign_certificate_request(self, cert_id: int, sign_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sign a certificate signing request."""
        return await self._make_request("POST", f"certificate/{cert_id}/sign", data=sign_data)

    async def onboard_get_certificate_by_id(self, certificate_id: int) -> Dict[str, Any]:
        """Get a certificate or certificate signing request."""
        return await self._make_request("GET", f"certificate/{certificate_id}")

    async def onboard_delete_certificate(self, certificate_id: int) -> Dict[str, Any]:
        """Delete a certificate or certificate signing request."""
        return await self._make_request("DELETE", f"certificate/{certificate_id}")

    # ================================
    # ONBOARD DEVICES
    # ================================

    async def onboard_list_devices(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of Onboard devices."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "onboard/device", params=params)

    async def onboard_get_device_by_id(self, device_id: int) -> Dict[str, Any]:
        """Get an Onboard device by ID."""
        return await self._make_request("GET", f"onboard/device/{device_id}")

    async def onboard_update_device(self, device_id: int, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update settings for an Onboard device."""
        return await self._make_request("PATCH", f"onboard/device/{device_id}", data=device_data)

    async def onboard_delete_device(
        self,
        device_id: int,
        disconnect_active_sessions: Optional[bool] = None,
        ignore_disconnect_errors: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Delete an Onboard device."""
        params = {}
        if disconnect_active_sessions is not None:
            params['disconnect_active_sessions'] = disconnect_active_sessions
        if ignore_disconnect_errors is not None:
            params['ignore_disconnect_errors'] = ignore_disconnect_errors
        return await self._make_request("DELETE", f"onboard/device/{device_id}", params=params or None)

    # ================================
    # ONBOARD USERS
    # ================================

    async def onboard_list_users(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of Onboard users."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "user", params=params)

    async def onboard_get_user_by_id(self, user_id: int) -> Dict[str, Any]:
        """Get an Onboard user by ID."""
        return await self._make_request("GET", f"user/{user_id}")

    async def onboard_update_user(self, user_id: int, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update settings for an Onboard user."""
        return await self._make_request("PATCH", f"user/{user_id}", data=user_data)

    async def onboard_delete_user(self, user_id: int) -> Dict[str, Any]:
        """Delete an Onboard user."""
        return await self._make_request("DELETE", f"user/{user_id}")
