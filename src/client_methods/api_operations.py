"""
Mixin class for ClearPassClient to manage API Operations (OAuth2) calls.

This module contains client methods for the ClearPass OAuth2 surface: inspecting the
authenticated client/user, listing the privileges granted to that identity, and
(for API parity/diagnostics) requesting an access token directly.
"""

from typing import Dict, Any


class ApiOperationsMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for OAuth2 API operations.
    """

    # ================================
    # OAUTH2 IDENTITY
    # ================================

    async def get_oauth_me(self) -> Dict[str, Any]:
        """Get information about the OAuth2 authenticated client or user."""
        return await self._make_request("GET", "oauth/me")

    async def post_oauth_me_info(self, me_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get information about the OAuth2 authenticated client or user, using a request body."""
        return await self._make_request("POST", "oauth/me", data=me_data)

    async def get_oauth_privileges(self) -> Dict[str, Any]:
        """Get the list of privileges available to the authenticated user."""
        return await self._make_request("GET", "oauth/privileges")

    # ================================
    # OAUTH2 TOKEN
    # ================================

    async def request_oauth_token(self, token_request: Dict[str, Any]) -> Dict[str, Any]:
        """Obtain an OAuth2 access token. The client authenticates automatically; this exists
        for API parity and diagnostics."""
        return await self._make_request("POST", "oauth", data=token_request)
