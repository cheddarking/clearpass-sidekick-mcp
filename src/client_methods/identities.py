"""
Mixin class for ClearPassClient to manage identity API calls.

This module contains client methods for the ClearPass identity resources:
endpoints, device accounts, local users, static host lists, deny-listed users,
external accounts, plus the replace (PUT) variants of guest accounts and API
clients that are not covered by the guest/api-client mixins.

Every resource is addressable both by numeric id and by its natural key
(MAC address, username/user_id or name), and both addressing modes are
distinct ClearPass endpoints, so both are implemented here.
"""

from typing import Dict, Any, Optional


def _list_params(
    filter_str: Optional[str] = None,
    sort: Optional[str] = None,
    offset: Optional[int] = None,
    limit: Optional[int] = None,
    calculate_count: Optional[bool] = None,
    **extra: Any
) -> Dict[str, Any]:
    """Build the standard ClearPass list query-string dict, dropping None values."""
    params: Dict[str, Any] = {
        "filter": filter_str,
        "sort": sort,
        "offset": offset,
        "limit": limit,
        "calculate_count": calculate_count,
    }
    params.update(extra)
    return {k: v for k, v in params.items() if v is not None}


def _coa_params(change_of_authorization: Optional[bool] = None) -> Dict[str, Any]:
    """Build the `change_of_authorization` query-string dict, dropping None."""
    if change_of_authorization is None:
        return {}
    return {"change_of_authorization": change_of_authorization}


class IdentitiesMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for identity management.
    """

    # ================================
    # ENDPOINTS
    # ================================

    async def list_endpoints(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
        profile_details: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of endpoints along with their profiling information."""
        params = _list_params(
            filter_str, sort, offset, limit, calculate_count,
            profile_details=profile_details
        )
        return await self._make_request("GET", "endpoint", params=params)

    async def create_endpoint(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new endpoint."""
        return await self._make_request("POST", "endpoint", data=endpoint_data)

    async def get_endpoint_by_id(
        self,
        endpoint_id: int,
        profile_details: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get an endpoint along with its profiling information by id."""
        params = {} if profile_details is None else {"profile_details": profile_details}
        return await self._make_request("GET", f"endpoint/{endpoint_id}", params=params)

    async def update_endpoint_by_id(
        self,
        endpoint_id: int,
        endpoint_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an endpoint by id."""
        return await self._make_request("PATCH", f"endpoint/{endpoint_id}", data=endpoint_data)

    async def replace_endpoint_by_id(
        self,
        endpoint_id: int,
        endpoint_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an endpoint by id."""
        return await self._make_request("PUT", f"endpoint/{endpoint_id}", data=endpoint_data)

    async def delete_endpoint_by_id(self, endpoint_id: int) -> Dict[str, Any]:
        """Delete an endpoint by id."""
        return await self._make_request("DELETE", f"endpoint/{endpoint_id}")

    async def get_endpoint_by_mac(
        self,
        mac_address: str,
        profile_details: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get an endpoint along with its profiling information by MAC address."""
        params = {} if profile_details is None else {"profile_details": profile_details}
        return await self._make_request(
            "GET", f"endpoint/mac-address/{mac_address}", params=params
        )

    async def update_endpoint_by_mac(
        self,
        mac_address: str,
        endpoint_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an endpoint by MAC address."""
        return await self._make_request(
            "PATCH", f"endpoint/mac-address/{mac_address}", data=endpoint_data
        )

    async def replace_endpoint_by_mac(
        self,
        mac_address: str,
        endpoint_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an endpoint by MAC address."""
        return await self._make_request(
            "PUT", f"endpoint/mac-address/{mac_address}", data=endpoint_data
        )

    async def delete_endpoint_by_mac(self, mac_address: str) -> Dict[str, Any]:
        """Delete an endpoint by MAC address."""
        return await self._make_request("DELETE", f"endpoint/mac-address/{mac_address}")

    # ================================
    # DEVICE ACCOUNTS
    # ================================

    async def list_devices(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of device accounts."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "device", params=params)

    async def create_device(
        self,
        device_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Create a new device account."""
        return await self._make_request(
            "POST", "device",
            data=device_data,
            params=_coa_params(change_of_authorization)
        )

    async def get_device_by_id(self, device_id: int) -> Dict[str, Any]:
        """Get a device account by id."""
        return await self._make_request("GET", f"device/{device_id}")

    async def update_device_by_id(
        self,
        device_id: int,
        device_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Update some fields of a device account by id."""
        return await self._make_request(
            "PATCH", f"device/{device_id}",
            data=device_data,
            params=_coa_params(change_of_authorization)
        )

    async def replace_device_by_id(
        self,
        device_id: int,
        device_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Replace a device account by id."""
        return await self._make_request(
            "PUT", f"device/{device_id}",
            data=device_data,
            params=_coa_params(change_of_authorization)
        )

    async def delete_device_by_id(
        self,
        device_id: int,
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Delete a device account by id."""
        return await self._make_request(
            "DELETE", f"device/{device_id}",
            params=_coa_params(change_of_authorization)
        )

    async def get_device_by_mac(self, macaddr: str) -> Dict[str, Any]:
        """Get a device account by MAC address."""
        return await self._make_request("GET", f"device/mac/{macaddr}")

    async def update_device_by_mac(
        self,
        macaddr: str,
        device_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Update some fields of a device account by MAC address."""
        return await self._make_request(
            "PATCH", f"device/mac/{macaddr}",
            data=device_data,
            params=_coa_params(change_of_authorization)
        )

    async def replace_device_by_mac(
        self,
        macaddr: str,
        device_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Replace a device account by MAC address."""
        return await self._make_request(
            "PUT", f"device/mac/{macaddr}",
            data=device_data,
            params=_coa_params(change_of_authorization)
        )

    async def delete_device_by_mac(
        self,
        macaddr: str,
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Delete a device account by MAC address."""
        return await self._make_request(
            "DELETE", f"device/mac/{macaddr}",
            params=_coa_params(change_of_authorization)
        )

    # ================================
    # LOCAL USERS
    # ================================

    async def list_local_users(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of local users."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "local-user", params=params)

    async def create_local_user(self, local_user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new local user."""
        return await self._make_request("POST", "local-user", data=local_user_data)

    async def get_local_user_by_id(self, local_user_id: int) -> Dict[str, Any]:
        """Get a local user by id."""
        return await self._make_request("GET", f"local-user/{local_user_id}")

    async def update_local_user_by_id(
        self,
        local_user_id: int,
        local_user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a local user by id."""
        return await self._make_request(
            "PATCH", f"local-user/{local_user_id}", data=local_user_data
        )

    async def replace_local_user_by_id(
        self,
        local_user_id: int,
        local_user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a local user by id."""
        return await self._make_request(
            "PUT", f"local-user/{local_user_id}", data=local_user_data
        )

    async def delete_local_user_by_id(self, local_user_id: int) -> Dict[str, Any]:
        """Delete a local user by id."""
        return await self._make_request("DELETE", f"local-user/{local_user_id}")

    async def get_local_user_by_user_id(self, user_id: str) -> Dict[str, Any]:
        """Get a local user by user_id."""
        return await self._make_request("GET", f"local-user/user-id/{user_id}")

    async def update_local_user_by_user_id(
        self,
        user_id: str,
        local_user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a local user by user_id."""
        return await self._make_request(
            "PATCH", f"local-user/user-id/{user_id}", data=local_user_data
        )

    async def replace_local_user_by_user_id(
        self,
        user_id: str,
        local_user_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a local user by user_id."""
        return await self._make_request(
            "PUT", f"local-user/user-id/{user_id}", data=local_user_data
        )

    async def delete_local_user_by_user_id(self, user_id: str) -> Dict[str, Any]:
        """Delete a local user by user_id."""
        return await self._make_request("DELETE", f"local-user/user-id/{user_id}")

    # ================================
    # STATIC HOST LISTS
    # ================================

    async def list_static_host_lists(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of static host lists."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "static-host-list", params=params)

    async def create_static_host_list(
        self,
        static_host_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create a static host list."""
        return await self._make_request(
            "POST", "static-host-list", data=static_host_list_data
        )

    async def get_static_host_list_by_id(self, static_host_list_id: int) -> Dict[str, Any]:
        """Get a static host list by id."""
        return await self._make_request("GET", f"static-host-list/{static_host_list_id}")

    async def update_static_host_list_by_id(
        self,
        static_host_list_id: int,
        static_host_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a static host list by id."""
        return await self._make_request(
            "PATCH", f"static-host-list/{static_host_list_id}", data=static_host_list_data
        )

    async def replace_static_host_list_by_id(
        self,
        static_host_list_id: int,
        static_host_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a static host list by id."""
        return await self._make_request(
            "PUT", f"static-host-list/{static_host_list_id}", data=static_host_list_data
        )

    async def delete_static_host_list_by_id(self, static_host_list_id: int) -> Dict[str, Any]:
        """Delete a static host list by id."""
        return await self._make_request("DELETE", f"static-host-list/{static_host_list_id}")

    async def get_static_host_list_by_name(self, name: str) -> Dict[str, Any]:
        """Get a static host list by name."""
        return await self._make_request("GET", f"static-host-list/name/{name}")

    async def update_static_host_list_by_name(
        self,
        name: str,
        static_host_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a static host list by name."""
        return await self._make_request(
            "PATCH", f"static-host-list/name/{name}", data=static_host_list_data
        )

    async def replace_static_host_list_by_name(
        self,
        name: str,
        static_host_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a static host list by name."""
        return await self._make_request(
            "PUT", f"static-host-list/name/{name}", data=static_host_list_data
        )

    async def delete_static_host_list_by_name(self, name: str) -> Dict[str, Any]:
        """Delete a static host list by name."""
        return await self._make_request("DELETE", f"static-host-list/name/{name}")

    # ================================
    # DENY-LISTED USERS
    # ================================

    async def list_deny_listed_users(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of deny listed users."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "deny-listed-users", params=params)

    async def get_deny_listed_user_by_id(self, deny_listed_users_id: int) -> Dict[str, Any]:
        """Get a deny listed user by id."""
        return await self._make_request("GET", f"deny-listed-users/{deny_listed_users_id}")

    async def delete_deny_listed_user_by_id(self, deny_listed_users_id: int) -> Dict[str, Any]:
        """Delete a deny listed user by id."""
        return await self._make_request("DELETE", f"deny-listed-users/{deny_listed_users_id}")

    async def get_deny_listed_user_by_user_and_mac(
        self,
        user_id: str,
        mac_address: str
    ) -> Dict[str, Any]:
        """Get a deny listed user by username and MAC address."""
        return await self._make_request(
            "GET", f"deny-listed-users/user_id/{user_id}/mac_address/{mac_address}"
        )

    async def delete_deny_listed_user_by_user_and_mac(
        self,
        user_id: str,
        mac_address: str
    ) -> Dict[str, Any]:
        """Delete a deny listed user by username and MAC address."""
        return await self._make_request(
            "DELETE", f"deny-listed-users/user_id/{user_id}/mac_address/{mac_address}"
        )

    # ================================
    # EXTERNAL ACCOUNTS
    # ================================

    async def list_external_accounts(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of external accounts."""
        params = _list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", "external-account", params=params)

    async def create_external_account(
        self,
        external_account_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an external account."""
        return await self._make_request(
            "POST", "external-account", data=external_account_data
        )

    async def get_external_account_by_id(self, external_account_id: int) -> Dict[str, Any]:
        """Get an external account by id."""
        return await self._make_request("GET", f"external-account/{external_account_id}")

    async def update_external_account_by_id(
        self,
        external_account_id: int,
        external_account_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an external account by id."""
        return await self._make_request(
            "PATCH", f"external-account/{external_account_id}", data=external_account_data
        )

    async def replace_external_account_by_id(
        self,
        external_account_id: int,
        external_account_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an external account by id."""
        return await self._make_request(
            "PUT", f"external-account/{external_account_id}", data=external_account_data
        )

    async def delete_external_account_by_id(self, external_account_id: int) -> Dict[str, Any]:
        """Delete an external account by id."""
        return await self._make_request("DELETE", f"external-account/{external_account_id}")

    async def get_external_account_by_name(self, name: str) -> Dict[str, Any]:
        """Get an external account by name."""
        return await self._make_request("GET", f"external-account/name/{name}")

    async def update_external_account_by_name(
        self,
        name: str,
        external_account_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of an external account by name."""
        return await self._make_request(
            "PATCH", f"external-account/name/{name}", data=external_account_data
        )

    async def replace_external_account_by_name(
        self,
        name: str,
        external_account_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an external account by name."""
        return await self._make_request(
            "PUT", f"external-account/name/{name}", data=external_account_data
        )

    async def delete_external_account_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an external account by name."""
        return await self._make_request("DELETE", f"external-account/name/{name}")

    # ================================
    # GUEST ACCOUNT REPLACE (PUT)
    # ================================

    async def replace_guest_by_id(
        self,
        guest_id: int,
        guest_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Replace a guest account by id."""
        return await self._make_request(
            "PUT", f"guest/{guest_id}",
            data=guest_data,
            params=_coa_params(change_of_authorization)
        )

    async def replace_guest_by_username(
        self,
        username: str,
        guest_data: Dict[str, Any],
        change_of_authorization: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Replace a guest account by username."""
        return await self._make_request(
            "PUT", f"guest/username/{username}",
            data=guest_data,
            params=_coa_params(change_of_authorization)
        )

    # ================================
    # API CLIENT REPLACE (PUT)
    # ================================

    async def replace_api_client(
        self,
        client_id: str,
        api_client_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an API client by client_id."""
        return await self._make_request(
            "PUT", f"api-client/{client_id}", data=api_client_data
        )
