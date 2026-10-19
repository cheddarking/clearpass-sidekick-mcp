"""
Mixin class for ClearPassClient to manage guest configuration-related API calls.
"""

from typing import Dict, Any, Union, Optional


class GuestConfigurationMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for guest configuration.
    Includes pass templates, print templates, web login pages, and global settings.
    """

    # ========================================================================
    # Pass Templates (Digital Passes - Apple Wallet / Google Pay)
    # ========================================================================

    async def list_pass_templates(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Get a list of pass templates.

        Args:
            filter: JSON filter expression
            sort: Sort ordering (default -id)
            offset: Zero based offset
            limit: Maximum number of items (1-1000)
            calculate_count: Whether to calculate total count

        Returns:
            Dict containing pass templates
        """
        params = {}
        if filter:
            params["filter"] = filter
        if sort:
            params["sort"] = sort
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if calculate_count is not None:
            params["calculate_count"] = calculate_count

        return await self._make_request("GET", "template/pass", params=params)

    async def get_pass_template(self, template_id: Union[int, str]) -> Dict[str, Any]:
        """Get a specific pass template by ID."""
        return await self._make_request("GET", f"template/pass/{template_id}")

    async def create_pass_template(self, template_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new pass template."""
        return await self._make_request("POST", "template/pass", data=template_data)

    async def update_pass_template(
        self,
        template_id: Union[int, str],
        template_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a pass template (PATCH)."""
        return await self._make_request("PATCH", f"template/pass/{template_id}", data=template_data)

    async def replace_pass_template(
        self,
        template_id: Union[int, str],
        template_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a pass template (PUT)."""
        return await self._make_request("PUT", f"template/pass/{template_id}", data=template_data)

    async def delete_pass_template(self, template_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a pass template."""
        return await self._make_request("DELETE", f"template/pass/{template_id}")

    # ========================================================================
    # Print Templates (Receipt Printing)
    # ========================================================================

    async def list_print_templates(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Get a list of print templates.

        Args:
            filter: JSON filter expression
            sort: Sort ordering (default -id)
            offset: Zero based offset
            limit: Maximum number of items (1-1000)
            calculate_count: Whether to calculate total count

        Returns:
            Dict containing print templates
        """
        params = {}
        if filter:
            params["filter"] = filter
        if sort:
            params["sort"] = sort
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if calculate_count is not None:
            params["calculate_count"] = calculate_count

        return await self._make_request("GET", "template/print", params=params)

    async def get_print_template(self, template_id: Union[int, str]) -> Dict[str, Any]:
        """Get a specific print template by ID."""
        return await self._make_request("GET", f"template/print/{template_id}")

    async def create_print_template(self, template_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new print template."""
        return await self._make_request("POST", "template/print", data=template_data)

    async def update_print_template(
        self,
        template_id: Union[int, str],
        template_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a print template (PATCH)."""
        return await self._make_request("PATCH", f"template/print/{template_id}", data=template_data)

    async def replace_print_template(
        self,
        template_id: Union[int, str],
        template_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a print template (PUT)."""
        return await self._make_request("PUT", f"template/print/{template_id}", data=template_data)

    async def delete_print_template(self, template_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a print template."""
        return await self._make_request("DELETE", f"template/print/{template_id}")

    # ========================================================================
    # Web Login Pages (Captive Portal)
    # ========================================================================

    async def list_weblogin_pages(
        self,
        filter: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Get a list of web login pages.

        Args:
            filter: JSON filter expression
            sort: Sort ordering (default +name)
            offset: Zero based offset
            limit: Maximum number of items (1-1000)
            calculate_count: Whether to calculate total count

        Returns:
            Dict containing web login pages
        """
        params = {}
        if filter:
            params["filter"] = filter
        if sort:
            params["sort"] = sort
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if calculate_count is not None:
            params["calculate_count"] = calculate_count

        return await self._make_request("GET", "weblogin", params=params)

    async def get_weblogin_page(self, page_id: Union[int, str]) -> Dict[str, Any]:
        """Get a specific web login page by ID."""
        return await self._make_request("GET", f"weblogin/{page_id}")

    async def create_weblogin_page(self, page_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new web login page."""
        return await self._make_request("POST", "weblogin", data=page_data)

    async def update_weblogin_page(
        self,
        page_id: Union[int, str],
        page_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a web login page by ID (PATCH)."""
        return await self._make_request("PATCH", f"weblogin/{page_id}", data=page_data)

    async def replace_weblogin_page(
        self,
        page_id: Union[int, str],
        page_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a web login page by ID (PUT)."""
        return await self._make_request("PUT", f"weblogin/{page_id}", data=page_data)

    async def delete_weblogin_page(self, page_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a web login page by ID."""
        return await self._make_request("DELETE", f"weblogin/{page_id}")

    async def get_weblogin_page_by_name(self, page_name: str) -> Dict[str, Any]:
        """Get a specific web login page by page name."""
        return await self._make_request("GET", f"weblogin/page-name/{page_name}")

    async def update_weblogin_page_by_name(
        self,
        page_name: str,
        page_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a web login page by name (PATCH)."""
        return await self._make_request("PATCH", f"weblogin/page-name/{page_name}", data=page_data)

    async def replace_weblogin_page_by_name(
        self,
        page_name: str,
        page_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a web login page by name (PUT)."""
        return await self._make_request("PUT", f"weblogin/page-name/{page_name}", data=page_data)

    async def delete_weblogin_page_by_name(self, page_name: str) -> Dict[str, Any]:
        """Delete a web login page by name."""
        return await self._make_request("DELETE", f"weblogin/page-name/{page_name}")

    # ========================================================================
    # Guest Authentication Settings
    # ========================================================================

    async def get_guest_authentication_settings(self) -> Dict[str, Any]:
        """Return settings from Configuration -> Authentication."""
        return await self._make_request("GET", "guest/authentication")

    async def create_guest_authentication_settings(
        self,
        settings_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Modify settings at Configuration -> Authentication (POST).
        Requires g_radius_internal_auth_type field.
        """
        return await self._make_request("POST", "guest/authentication", data=settings_data)

    async def update_guest_authentication_settings(
        self,
        settings_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Modify settings at Configuration -> Authentication (PATCH).
        Requires g_radius_internal_auth_type field.
        """
        return await self._make_request("PATCH", "guest/authentication", data=settings_data)

    # ========================================================================
    # Guest Manager Settings
    # ========================================================================

    async def get_guest_manager_settings(self) -> Dict[str, Any]:
        """Return settings from Configuration -> Guest Manager."""
        return await self._make_request("GET", "guestmanager")

    async def create_guest_manager_settings(
        self,
        settings_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Modify settings at Configuration -> Guest Manager (POST).
        Requires multiple fields for username/password generation and expiration.
        """
        return await self._make_request("POST", "guestmanager", data=settings_data)

    async def update_guest_manager_settings(
        self,
        settings_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Modify settings at Configuration -> Guest Manager (PATCH).
        Requires multiple fields for username/password generation and expiration.
        """
        return await self._make_request("PATCH", "guestmanager", data=settings_data)
