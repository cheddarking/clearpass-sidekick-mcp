"""
Mixin class for ClearPassClient to manage global server configuration API calls.
"""

from typing import Dict, Any, Optional, Union

class GlobalServerConfigMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for global server configuration management.
    """

    # Admin Privilege Management
    async def list_admin_privileges(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of admin privileges."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "admin-privilege", params=params)

    async def create_admin_privilege(self, privilege_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new admin privilege."""
        return await self._make_request("POST", "admin-privilege", data=privilege_data)

    async def get_admin_privilege_by_id(self, admin_privilege_id: int) -> Dict[str, Any]:
        """Get an admin privilege by ID."""
        return await self._make_request("GET", f"admin-privilege/{admin_privilege_id}")

    async def get_admin_privilege_by_name(self, name: str) -> Dict[str, Any]:
        """Get an admin privilege by name."""
        return await self._make_request("GET", f"admin-privilege/name/{name}")

    async def update_admin_privilege_by_id(self, admin_privilege_id: int, privilege_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an admin privilege."""
        return await self._make_request("PATCH", f"admin-privilege/{admin_privilege_id}", data=privilege_data)

    async def replace_admin_privilege_by_id(self, admin_privilege_id: int, privilege_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an admin privilege."""
        return await self._make_request("PUT", f"admin-privilege/{admin_privilege_id}", data=privilege_data)

    async def delete_admin_privilege_by_id(self, admin_privilege_id: int) -> Dict[str, Any]:
        """Delete an admin privilege."""
        return await self._make_request("DELETE", f"admin-privilege/{admin_privilege_id}")

    # Admin User Management
    async def list_admin_users(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of admin users."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "admin-user", params=params)

    async def create_admin_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new admin user."""
        return await self._make_request("POST", "admin-user", data=user_data)

    async def get_admin_user_by_id(self, user_id: int) -> Dict[str, Any]:
        """Get an admin user by ID."""
        return await self._make_request("GET", f"admin-user/{user_id}")

    async def get_admin_user_by_user_id(self, user_id: str) -> Dict[str, Any]:
        """Get an admin user by user ID."""
        return await self._make_request("GET", f"admin-user/user-id/{user_id}")

    async def update_admin_user_by_id(self, user_id: int, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an admin user."""
        return await self._make_request("PATCH", f"admin-user/{user_id}", data=user_data)

    async def replace_admin_user_by_id(self, user_id: int, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an admin user."""
        return await self._make_request("PUT", f"admin-user/{user_id}", data=user_data)

    async def delete_admin_user_by_id(self, user_id: int) -> Dict[str, Any]:
        """Delete an admin user."""
        return await self._make_request("DELETE", f"admin-user/{user_id}")

    # Password Policy Management
    #
    # The four legacy hyphen-path methods that lived here
    # (get/update_admin_password_policy, get/update_local_user_password_policy)
    # were removed on 2026-07-31. They targeted `/admin-user-password-policy`
    # and `/local-user-password-policy`, which return 404 on ClearPass 6.12.4 —
    # the real resources are `/admin-user/password-policy` and
    # `/local-user/password-policy`, already served by
    # get/update/replace_admin_user_password_policy and
    # get/update/replace_local_user_password_policy_settings further down this
    # module.

    # Application License Management
    async def list_application_licenses(self) -> Dict[str, Any]:
        """Get application licenses."""
        return await self._make_request("GET", "application-license")

    async def create_application_license(self, license_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new application license."""
        return await self._make_request("POST", "application-license", data=license_data)

    async def get_application_license_by_id(self, license_id: str) -> Dict[str, Any]:
        """Get an application license by ID."""
        return await self._make_request("GET", f"application-license/{license_id}")

    async def replace_application_license_by_id(self, license_id: str, license_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an application license."""
        return await self._make_request("PUT", f"application-license/{license_id}", data=license_data)

    async def delete_application_license_by_id(self, license_id: str) -> Dict[str, Any]:
        """Delete an application license."""
        return await self._make_request("DELETE", f"application-license/{license_id}")

    async def activate_application_license_online(self, license_id: str) -> Dict[str, Any]:
        """Activate application license online."""
        # The API expects an empty JSON body for PATCH requests
        return await self._make_request("PATCH", f"application-license/activate-online/{license_id}", data={})

    async def activate_application_license_offline(self, license_id: str) -> Dict[str, Any]:
        """Activate application license offline."""
        # Note: Offline activation typically requires additional data (activation key)
        # but keeping the same signature for consistency with pyclearpass
        # The API expects an empty JSON body for PATCH requests
        return await self._make_request("PATCH", f"application-license/activate-offline/{license_id}", data={})

    # `get_application_license_summary` was removed on 2026-07-31: it targeted
    # `/application-license-summary`, which 404s on ClearPass 6.12.4. The real
    # resource is `/application-license/summary`, served by
    # `get_application_license_summary_detail` further down this module.

    # Cluster Parameters Management
    async def get_cluster_parameters(self) -> Dict[str, Any]:
        """Get cluster parameters."""
        return await self._make_request("GET", "cluster/parameters")

    async def update_cluster_parameters(self, parameters_data: Dict[str, Any], replace: bool = False) -> Dict[str, Any]:
        """Update cluster parameters."""
        method = "PUT" if replace else "PATCH"
        return await self._make_request(method, "cluster/parameters", data=parameters_data)

    # Attribute Management
    async def list_attributes(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of attributes."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "attribute", params=params)

    async def create_attribute(self, attribute_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new attribute."""
        return await self._make_request("POST", "attribute", data=attribute_data)

    async def get_attribute_by_id(self, attribute_id: int) -> Dict[str, Any]:
        """Get an attribute by ID."""
        return await self._make_request("GET", f"attribute/{attribute_id}")

    async def get_attribute_by_entity_and_name(self, entity_name: str, name: str) -> Dict[str, Any]:
        """Get an attribute by entity name and name."""
        return await self._make_request("GET", f"attribute/{entity_name}/name/{name}")

    async def update_attribute_by_id(self, attribute_id: int, attribute_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an attribute."""
        return await self._make_request("PATCH", f"attribute/{attribute_id}", data=attribute_data)

    async def replace_attribute_by_id(self, attribute_id: int, attribute_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an attribute."""
        return await self._make_request("PUT", f"attribute/{attribute_id}", data=attribute_data)

    async def delete_attribute_by_id(self, attribute_id: int) -> Dict[str, Any]:
        """Delete an attribute."""
        return await self._make_request("DELETE", f"attribute/{attribute_id}")

    # Data Filter Management
    async def list_data_filters(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of data filters."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "data-filter", params=params)

    async def create_data_filter(self, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new data filter."""
        return await self._make_request("POST", "data-filter", data=filter_data)

    async def get_data_filter_by_id(self, data_filter_id: int) -> Dict[str, Any]:
        """Get a data filter by ID."""
        return await self._make_request("GET", f"data-filter/{data_filter_id}")

    async def get_data_filter_by_name(self, name: str) -> Dict[str, Any]:
        """Get a data filter by name."""
        return await self._make_request("GET", f"data-filter/name/{name}")

    async def update_data_filter_by_id(self, data_filter_id: int, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of a data filter."""
        return await self._make_request("PATCH", f"data-filter/{data_filter_id}", data=filter_data)

    async def replace_data_filter_by_id(self, data_filter_id: int, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a data filter."""
        return await self._make_request("PUT", f"data-filter/{data_filter_id}", data=filter_data)

    async def delete_data_filter_by_id(self, data_filter_id: int) -> Dict[str, Any]:
        """Delete a data filter."""
        return await self._make_request("DELETE", f"data-filter/{data_filter_id}")

    # Operator Profile Management
    async def list_operator_profiles(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of operator profiles."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "operator-profile", params=params)

    async def create_operator_profile(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new operator profile."""
        return await self._make_request("POST", "operator-profile", data=profile_data)

    async def get_operator_profile_by_id(self, profile_id: int) -> Dict[str, Any]:
        """Get an operator profile by ID."""
        return await self._make_request("GET", f"operator-profile/{profile_id}")

    async def get_operator_profile_by_name(self, name: str) -> Dict[str, Any]:
        """Get an operator profile by name."""
        return await self._make_request("GET", f"operator-profile/name/{name}")

    async def update_operator_profile_by_id(self, profile_id: int, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an operator profile."""
        return await self._make_request("PATCH", f"operator-profile/{profile_id}", data=profile_data)

    async def replace_operator_profile_by_id(self, profile_id: int, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an operator profile."""
        return await self._make_request("PUT", f"operator-profile/{profile_id}", data=profile_data)

    async def delete_operator_profile_by_id(self, profile_id: int) -> Dict[str, Any]:
        """Delete an operator profile."""
        return await self._make_request("DELETE", f"operator-profile/{profile_id}")

    # SNMP Trap Receiver Management
    async def list_snmp_trap_receivers(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of SNMP trap receivers."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "snmp-trap-receiver", params=params)

    async def create_snmp_trap_receiver(self, receiver_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new SNMP trap receiver."""
        return await self._make_request("POST", "snmp-trap-receiver", data=receiver_data)

    async def get_snmp_trap_receiver_by_id(self, snmp_trap_receiver_id: int) -> Dict[str, Any]:
        """Get an SNMP trap receiver by ID."""
        return await self._make_request("GET", f"snmp-trap-receiver/{snmp_trap_receiver_id}")

    async def get_snmp_trap_receiver_by_name(self, name: str) -> Dict[str, Any]:
        """Get an SNMP trap receiver by name."""
        return await self._make_request("GET", f"snmp-trap-receiver/name/{name}")

    async def update_snmp_trap_receiver_by_id(self, snmp_trap_receiver_id: int, receiver_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an SNMP trap receiver."""
        return await self._make_request("PATCH", f"snmp-trap-receiver/{snmp_trap_receiver_id}", data=receiver_data)

    async def replace_snmp_trap_receiver_by_id(self, snmp_trap_receiver_id: int, receiver_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an SNMP trap receiver."""
        return await self._make_request("PUT", f"snmp-trap-receiver/{snmp_trap_receiver_id}", data=receiver_data)

    async def delete_snmp_trap_receiver_by_id(self, snmp_trap_receiver_id: int) -> Dict[str, Any]:
        """Delete an SNMP trap receiver."""
        return await self._make_request("DELETE", f"snmp-trap-receiver/{snmp_trap_receiver_id}")

    # Messaging Setup
    async def get_messaging_setup(self) -> Dict[str, Any]:
        """Get messaging setup configuration."""
        return await self._make_request("GET", "messaging-setup")

    async def create_messaging_setup(self, messaging_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create messaging setup configuration."""
        return await self._make_request("POST", "messaging-setup", data=messaging_data)

    async def delete_messaging_setup(self) -> Dict[str, Any]:
        """Delete messaging setup configuration."""
        return await self._make_request("DELETE", "messaging-setup")

    # OAuth Privileges
    async def get_oauth_all_privileges(self, format_type: Optional[str] = None) -> Dict[str, Any]:
        """Get all OAuth privileges."""
        params = {"format": format_type} if format_type else {}
        return await self._make_request("GET", "oauth/all-privileges", params=params)

    # File Backup Server Management
    async def list_file_backup_servers(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of file backup servers."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "file-backup-server", params=params)

    async def create_file_backup_server(self, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new file backup server."""
        return await self._make_request("POST", "file-backup-server", data=server_data)

    async def get_file_backup_server_by_id(self, file_backup_server_id: int) -> Dict[str, Any]:
        """Get a file backup server by ID."""
        return await self._make_request("GET", f"file-backup-server/{file_backup_server_id}")

    async def get_file_backup_server_by_host_address(self, host_address: str) -> Dict[str, Any]:
        """Get a file backup server by host address."""
        return await self._make_request("GET", f"file-backup-server/host-address/{host_address}")

    async def update_file_backup_server_by_id(self, file_backup_server_id: int, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of a file backup server."""
        return await self._make_request("PATCH", f"file-backup-server/{file_backup_server_id}", data=server_data)

    async def replace_file_backup_server_by_id(self, file_backup_server_id: int, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a file backup server."""
        return await self._make_request("PUT", f"file-backup-server/{file_backup_server_id}", data=server_data)

    async def delete_file_backup_server_by_id(self, file_backup_server_id: int) -> Dict[str, Any]:
        """Delete a file backup server."""
        return await self._make_request("DELETE", f"file-backup-server/{file_backup_server_id}")

    async def update_file_backup_server_by_host_address(self, host_address: str, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of a file backup server by host address."""
        return await self._make_request("PATCH", f"file-backup-server/host-address/{host_address}", data=server_data)

    async def replace_file_backup_server_by_host_address(self, host_address: str, server_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a file backup server by host address."""
        return await self._make_request("PUT", f"file-backup-server/host-address/{host_address}", data=server_data)

    async def delete_file_backup_server_by_host_address(self, host_address: str) -> Dict[str, Any]:
        """Delete a file backup server by host address."""
        return await self._make_request("DELETE", f"file-backup-server/host-address/{host_address}")

    # Server Policy Manager Zones Management
    async def list_server_policy_manager_zones(self) -> Dict[str, Any]:
        """Get a list of server policy manager zones."""
        return await self._make_request("GET", "server/policy-manager-zones")

    async def create_server_policy_manager_zone(self, zone_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new server policy manager zone."""
        return await self._make_request("POST", "server/policy-manager-zones", data=zone_data)

    async def get_server_policy_manager_zone_by_zone_id(self, zone_id: str) -> Dict[str, Any]:
        """Get a server policy manager zone by zone ID."""
        return await self._make_request("GET", f"server/policy-manager-zones/{zone_id}")

    async def get_server_policy_manager_zone_by_name(self, name: str) -> Dict[str, Any]:
        """Get a server policy manager zone by name."""
        return await self._make_request("GET", f"server/policy-manager-zones/name/{name}")

    async def replace_server_policy_manager_zone_by_zone_id(self, zone_id: str, zone_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a server policy manager zone by zone ID."""
        return await self._make_request("PUT", f"server/policy-manager-zones/{zone_id}", data=zone_data)

    async def replace_server_policy_manager_zone_by_name(self, name: str, zone_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a server policy manager zone by name."""
        return await self._make_request("PUT", f"server/policy-manager-zones/name/{name}", data=zone_data)

    async def delete_server_policy_manager_zone_by_zone_id(self, zone_id: str) -> Dict[str, Any]:
        """Delete a server policy manager zone by zone ID."""
        return await self._make_request("DELETE", f"server/policy-manager-zones/{zone_id}")

    async def delete_server_policy_manager_zone_by_name(self, name: str) -> Dict[str, Any]:
        """Delete a server policy manager zone by name."""
        return await self._make_request("DELETE", f"server/policy-manager-zones/name/{name}")

    # Admin Privilege Management (by name)
    async def update_admin_privilege_by_name(self, name: str, privilege_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an admin privilege by name."""
        return await self._make_request("PATCH", f"admin-privilege/name/{name}", data=privilege_data)

    async def replace_admin_privilege_by_name(self, name: str, privilege_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an admin privilege by name."""
        return await self._make_request("PUT", f"admin-privilege/name/{name}", data=privilege_data)

    async def delete_admin_privilege_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an admin privilege by name."""
        return await self._make_request("DELETE", f"admin-privilege/name/{name}")

    # Admin User Password Policy (/admin-user/password-policy)
    async def get_admin_user_password_policy(self) -> Dict[str, Any]:
        """Get the admin user password policies."""
        return await self._make_request("GET", "admin-user/password-policy")

    async def update_admin_user_password_policy(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Patch the admin user password policies."""
        return await self._make_request("PATCH", "admin-user/password-policy", data=policy_data)

    async def replace_admin_user_password_policy(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Put the admin user password policies."""
        return await self._make_request("PUT", "admin-user/password-policy", data=policy_data)

    # Admin User Management (by user_id)
    async def update_admin_user_by_user_id(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an admin user by user_id."""
        return await self._make_request("PATCH", f"admin-user/user-id/{user_id}", data=user_data)

    async def replace_admin_user_by_user_id(self, user_id: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an admin user by user_id."""
        return await self._make_request("PUT", f"admin-user/user-id/{user_id}", data=user_data)

    async def delete_admin_user_by_user_id(self, user_id: str) -> Dict[str, Any]:
        """Delete an admin user by user_id."""
        return await self._make_request("DELETE", f"admin-user/user-id/{user_id}")

    # Application License Summary (/application-license/summary)
    async def get_application_license_summary_detail(self) -> Dict[str, Any]:
        """Get application license summary from the /application-license/summary endpoint."""
        return await self._make_request("GET", "application-license/summary")

    # Attribute Management (by entity name and name)
    async def update_attribute_by_entity_and_name(self, entity_name: str, name: str, attribute_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an attribute by entity name and name."""
        return await self._make_request("PATCH", f"attribute/{entity_name}/name/{name}", data=attribute_data)

    async def replace_attribute_by_entity_and_name(self, entity_name: str, name: str, attribute_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an attribute by entity name and name."""
        return await self._make_request("PUT", f"attribute/{entity_name}/name/{name}", data=attribute_data)

    async def delete_attribute_by_entity_and_name(self, entity_name: str, name: str) -> Dict[str, Any]:
        """Delete an attribute by entity name and name."""
        return await self._make_request("DELETE", f"attribute/{entity_name}/name/{name}")

    # ClearPass Portal
    async def get_clearpass_portal(self) -> Dict[str, Any]:
        """Get the ClearPass Portal configuration."""
        return await self._make_request("GET", "clearpass-portal")

    async def create_clearpass_portal(self, portal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Change the ClearPass Portal configuration."""
        return await self._make_request("POST", "clearpass-portal", data=portal_data)

    # Cluster Database Synchronization
    async def sync_cluster_database(self, sync_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Synchronize a subscriber with the publisher."""
        return await self._make_request("POST", "cluster/db-sync", data=sync_data or {})

    # Data Filter Management (by name)
    async def update_data_filter_by_name(self, name: str, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a data filter by name."""
        return await self._make_request("PATCH", f"data-filter/name/{name}", data=filter_data)

    async def replace_data_filter_by_name(self, name: str, filter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace a data filter by name."""
        return await self._make_request("PUT", f"data-filter/name/{name}", data=filter_data)

    async def delete_data_filter_by_name(self, name: str) -> Dict[str, Any]:
        """Delete a data filter by name."""
        return await self._make_request("DELETE", f"data-filter/name/{name}")

    # Local User Password Policy (/local-user/password-policy)
    async def get_local_user_password_policy_settings(self) -> Dict[str, Any]:
        """Get the local user password policy."""
        return await self._make_request("GET", "local-user/password-policy")

    async def update_local_user_password_policy_settings(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Patch the local user password policy."""
        return await self._make_request("PATCH", "local-user/password-policy", data=policy_data)

    async def replace_local_user_password_policy_settings(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Put the local user password policy."""
        return await self._make_request("PUT", "local-user/password-policy", data=policy_data)

    # Operator Profile Management (by name)
    async def update_operator_profile_by_name(self, name: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an operator profile by name."""
        return await self._make_request("PATCH", f"operator-profile/name/{name}", data=profile_data)

    async def replace_operator_profile_by_name(self, name: str, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an operator profile by name."""
        return await self._make_request("PUT", f"operator-profile/name/{name}", data=profile_data)

    async def delete_operator_profile_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an operator profile by name."""
        return await self._make_request("DELETE", f"operator-profile/name/{name}")

    # SNMP Trap Receiver Management (by name)
    async def update_snmp_trap_receiver_by_name(self, name: str, receiver_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update some fields of an SNMP trap receiver by name."""
        return await self._make_request("PATCH", f"snmp-trap-receiver/name/{name}", data=receiver_data)

    async def replace_snmp_trap_receiver_by_name(self, name: str, receiver_data: Dict[str, Any]) -> Dict[str, Any]:
        """Replace an SNMP trap receiver by name."""
        return await self._make_request("PUT", f"snmp-trap-receiver/name/{name}", data=receiver_data)

    async def delete_snmp_trap_receiver_by_name(self, name: str) -> Dict[str, Any]:
        """Delete an SNMP trap receiver by name."""
        return await self._make_request("DELETE", f"snmp-trap-receiver/name/{name}")