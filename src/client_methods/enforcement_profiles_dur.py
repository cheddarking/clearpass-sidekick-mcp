"""
Client methods for ClearPass Downloadable User Role (DUR) enforcement-profile objects.

A Downloadable User Role is assembled from per-product building blocks that live under
``/enforcement-profile-dur/<resource>/{product_name}`` — session and stateless ACLs, MAC and
ethertype ACLs, QoS/policer/VoIP profiles, NAT pools, net destinations and services, DUR
classes, policies, time ranges and captive-portal profiles. Every one of them is scoped by
``product_name`` (the Aruba product the role is downloaded to) and is addressable both by
numeric id and by name.

This mixin also carries the two PUT (replace) operations on the base ``/enforcement-profile``
resource, which the enforcement-profile mixin does not implement.
"""

from typing import Any, Dict, Optional


class EnforcementProfileDurMethodsMixin:
    """Mixin providing Downloadable User Role (DUR) enforcement-profile API methods."""

    # ====================================================================
    # Internal helpers
    # ====================================================================

    @staticmethod
    def _dur_list_params(
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Build the standard ClearPass list query string for a DUR collection."""
        params: Dict[str, Any] = {}
        if filter_str is not None:
            params["filter"] = filter_str
        if sort is not None:
            params["sort"] = sort
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        if calculate_count is not None:
            params["calculate_count"] = calculate_count
        return params

    # ====================================================================
    # Captive Portal Profiles — /enforcement-profile-dur/captive-portal-profile/{product_name}
    # ====================================================================

    async def dur_list_captive_portal_profiles(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Captive Portal Profiles for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/captive-portal-profile/{product_name}", params=params)

    async def dur_create_captive_portal_profile(
        self, product_name: str, captive_portal_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Captive Portal Profile for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/captive-portal-profile/{product_name}", data=captive_portal_profile_data)

    async def dur_get_captive_portal_profile_by_id(
        self, product_name: str, captive_portal_profile_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Captive Portal Profile by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}")

    async def dur_update_captive_portal_profile_by_id(
        self, product_name: str, captive_portal_profile_id: str, captive_portal_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Captive Portal Profile by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}", data=captive_portal_profile_data
        )

    async def dur_replace_captive_portal_profile_by_id(
        self, product_name: str, captive_portal_profile_id: str, captive_portal_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Captive Portal Profile by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}", data=captive_portal_profile_data
        )

    async def dur_delete_captive_portal_profile_by_id(
        self, product_name: str, captive_portal_profile_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Captive Portal Profile by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/captive-portal-profile/{product_name}/{captive_portal_profile_id}")

    async def dur_get_captive_portal_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Captive Portal Profile by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}")

    async def dur_update_captive_portal_profile_by_name(
        self, product_name: str, name: str, captive_portal_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Captive Portal Profile by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}", data=captive_portal_profile_data
        )

    async def dur_replace_captive_portal_profile_by_name(
        self, product_name: str, name: str, captive_portal_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Captive Portal Profile by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}", data=captive_portal_profile_data
        )

    async def dur_delete_captive_portal_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Captive Portal Profile by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/captive-portal-profile/{product_name}/name/{name}")

    # ====================================================================
    # DUR Classes — /enforcement-profile-dur/dur-class/{product_name}
    # ====================================================================

    async def dur_list_dur_classes(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR DUR Classes for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/dur-class/{product_name}", params=params)

    async def dur_create_dur_class(
        self, product_name: str, dur_class_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR DUR Class for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/dur-class/{product_name}", data=dur_class_data)

    async def dur_get_dur_class_by_id(
        self, product_name: str, dur_class_id: str
    ) -> Dict[str, Any]:
        """Get a DUR DUR Class by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}")

    async def dur_update_dur_class_by_id(
        self, product_name: str, dur_class_id: str, dur_class_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR DUR Class by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}", data=dur_class_data
        )

    async def dur_replace_dur_class_by_id(
        self, product_name: str, dur_class_id: str, dur_class_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR DUR Class by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}", data=dur_class_data
        )

    async def dur_delete_dur_class_by_id(
        self, product_name: str, dur_class_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR DUR Class by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/dur-class/{product_name}/{dur_class_id}")

    async def dur_get_dur_class_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR DUR Class by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/dur-class/{product_name}/name/{name}")

    async def dur_update_dur_class_by_name(
        self, product_name: str, name: str, dur_class_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR DUR Class by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/dur-class/{product_name}/name/{name}", data=dur_class_data
        )

    async def dur_replace_dur_class_by_name(
        self, product_name: str, name: str, dur_class_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR DUR Class by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/dur-class/{product_name}/name/{name}", data=dur_class_data
        )

    async def dur_delete_dur_class_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR DUR Class by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/dur-class/{product_name}/name/{name}")

    # ====================================================================
    # Ethertype Access Control Lists — /enforcement-profile-dur/ethertype-access-control-list/{product_name}
    # ====================================================================

    async def dur_list_ethertype_access_control_lists(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Ethertype Access Control Lists for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}", params=params)

    async def dur_create_ethertype_access_control_list(
        self, product_name: str, ethertype_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Ethertype Access Control List for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}", data=ethertype_access_control_list_data)

    async def dur_get_ethertype_access_control_list_by_id(
        self, product_name: str, ethertype_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Ethertype Access Control List by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}")

    async def dur_update_ethertype_access_control_list_by_id(
        self, product_name: str, ethertype_access_control_list_id: str, ethertype_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Ethertype Access Control List by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}", data=ethertype_access_control_list_data
        )

    async def dur_replace_ethertype_access_control_list_by_id(
        self, product_name: str, ethertype_access_control_list_id: str, ethertype_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Ethertype Access Control List by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}", data=ethertype_access_control_list_data
        )

    async def dur_delete_ethertype_access_control_list_by_id(
        self, product_name: str, ethertype_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Ethertype Access Control List by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/{ethertype_access_control_list_id}")

    async def dur_get_ethertype_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Ethertype Access Control List by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}")

    async def dur_update_ethertype_access_control_list_by_name(
        self, product_name: str, name: str, ethertype_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Ethertype Access Control List by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}", data=ethertype_access_control_list_data
        )

    async def dur_replace_ethertype_access_control_list_by_name(
        self, product_name: str, name: str, ethertype_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Ethertype Access Control List by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}", data=ethertype_access_control_list_data
        )

    async def dur_delete_ethertype_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Ethertype Access Control List by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/ethertype-access-control-list/{product_name}/name/{name}")

    # ====================================================================
    # MAC Access Control Lists — /enforcement-profile-dur/mac-access-control-list/{product_name}
    # ====================================================================

    async def dur_list_mac_access_control_lists(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR MAC Access Control Lists for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/mac-access-control-list/{product_name}", params=params)

    async def dur_create_mac_access_control_list(
        self, product_name: str, mac_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR MAC Access Control List for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/mac-access-control-list/{product_name}", data=mac_access_control_list_data)

    async def dur_get_mac_access_control_list_by_id(
        self, product_name: str, mac_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Get a DUR MAC Access Control List by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}")

    async def dur_update_mac_access_control_list_by_id(
        self, product_name: str, mac_access_control_list_id: str, mac_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR MAC Access Control List by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}", data=mac_access_control_list_data
        )

    async def dur_replace_mac_access_control_list_by_id(
        self, product_name: str, mac_access_control_list_id: str, mac_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR MAC Access Control List by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}", data=mac_access_control_list_data
        )

    async def dur_delete_mac_access_control_list_by_id(
        self, product_name: str, mac_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR MAC Access Control List by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/mac-access-control-list/{product_name}/{mac_access_control_list_id}")

    async def dur_get_mac_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR MAC Access Control List by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}")

    async def dur_update_mac_access_control_list_by_name(
        self, product_name: str, name: str, mac_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR MAC Access Control List by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}", data=mac_access_control_list_data
        )

    async def dur_replace_mac_access_control_list_by_name(
        self, product_name: str, name: str, mac_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR MAC Access Control List by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}", data=mac_access_control_list_data
        )

    async def dur_delete_mac_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR MAC Access Control List by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/mac-access-control-list/{product_name}/name/{name}")

    # ====================================================================
    # NAT Pools — /enforcement-profile-dur/nat-pool/{product_name}
    # ====================================================================

    async def dur_list_nat_pools(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR NAT Pools for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/nat-pool/{product_name}", params=params)

    async def dur_create_nat_pool(
        self, product_name: str, nat_pool_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR NAT Pool for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/nat-pool/{product_name}", data=nat_pool_data)

    async def dur_get_nat_pool_by_id(
        self, product_name: str, nat_pool_id: str
    ) -> Dict[str, Any]:
        """Get a DUR NAT Pool by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}")

    async def dur_update_nat_pool_by_id(
        self, product_name: str, nat_pool_id: str, nat_pool_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR NAT Pool by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}", data=nat_pool_data
        )

    async def dur_replace_nat_pool_by_id(
        self, product_name: str, nat_pool_id: str, nat_pool_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR NAT Pool by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}", data=nat_pool_data
        )

    async def dur_delete_nat_pool_by_id(
        self, product_name: str, nat_pool_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR NAT Pool by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/nat-pool/{product_name}/{nat_pool_id}")

    async def dur_get_nat_pool_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR NAT Pool by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/nat-pool/{product_name}/name/{name}")

    async def dur_update_nat_pool_by_name(
        self, product_name: str, name: str, nat_pool_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR NAT Pool by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/nat-pool/{product_name}/name/{name}", data=nat_pool_data
        )

    async def dur_replace_nat_pool_by_name(
        self, product_name: str, name: str, nat_pool_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR NAT Pool by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/nat-pool/{product_name}/name/{name}", data=nat_pool_data
        )

    async def dur_delete_nat_pool_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR NAT Pool by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/nat-pool/{product_name}/name/{name}")

    # ====================================================================
    # Net Destinations — /enforcement-profile-dur/net-destination/{product_name}
    # ====================================================================

    async def dur_list_net_destinations(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Net Destinations for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/net-destination/{product_name}", params=params)

    async def dur_create_net_destination(
        self, product_name: str, net_destination_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Net Destination for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/net-destination/{product_name}", data=net_destination_data)

    async def dur_get_net_destination_by_id(
        self, product_name: str, net_destination_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Net Destination by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}")

    async def dur_update_net_destination_by_id(
        self, product_name: str, net_destination_id: str, net_destination_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Net Destination by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}", data=net_destination_data
        )

    async def dur_replace_net_destination_by_id(
        self, product_name: str, net_destination_id: str, net_destination_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Net Destination by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}", data=net_destination_data
        )

    async def dur_delete_net_destination_by_id(
        self, product_name: str, net_destination_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Net Destination by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/net-destination/{product_name}/{net_destination_id}")

    async def dur_get_net_destination_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Net Destination by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/net-destination/{product_name}/name/{name}")

    async def dur_update_net_destination_by_name(
        self, product_name: str, name: str, net_destination_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Net Destination by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/net-destination/{product_name}/name/{name}", data=net_destination_data
        )

    async def dur_replace_net_destination_by_name(
        self, product_name: str, name: str, net_destination_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Net Destination by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/net-destination/{product_name}/name/{name}", data=net_destination_data
        )

    async def dur_delete_net_destination_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Net Destination by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/net-destination/{product_name}/name/{name}")

    # ====================================================================
    # Net Services — /enforcement-profile-dur/net-service/{product_name}
    # ====================================================================

    async def dur_list_net_services(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Net Services for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/net-service/{product_name}", params=params)

    async def dur_create_net_service(
        self, product_name: str, net_service_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Net Service for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/net-service/{product_name}", data=net_service_data)

    async def dur_get_net_service_by_id(
        self, product_name: str, net_service_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Net Service by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/net-service/{product_name}/{net_service_id}")

    async def dur_update_net_service_by_id(
        self, product_name: str, net_service_id: str, net_service_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Net Service by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/net-service/{product_name}/{net_service_id}", data=net_service_data
        )

    async def dur_replace_net_service_by_id(
        self, product_name: str, net_service_id: str, net_service_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Net Service by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/net-service/{product_name}/{net_service_id}", data=net_service_data
        )

    async def dur_delete_net_service_by_id(
        self, product_name: str, net_service_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Net Service by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/net-service/{product_name}/{net_service_id}")

    async def dur_get_net_service_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Net Service by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/net-service/{product_name}/name/{name}")

    async def dur_update_net_service_by_name(
        self, product_name: str, name: str, net_service_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Net Service by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/net-service/{product_name}/name/{name}", data=net_service_data
        )

    async def dur_replace_net_service_by_name(
        self, product_name: str, name: str, net_service_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Net Service by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/net-service/{product_name}/name/{name}", data=net_service_data
        )

    async def dur_delete_net_service_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Net Service by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/net-service/{product_name}/name/{name}")

    # ====================================================================
    # Policer Profiles — /enforcement-profile-dur/policer-profile/{product_name}
    # ====================================================================

    async def dur_list_policer_profiles(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Policer Profiles for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/policer-profile/{product_name}", params=params)

    async def dur_create_policer_profile(
        self, product_name: str, policer_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Policer Profile for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/policer-profile/{product_name}", data=policer_profile_data)

    async def dur_get_policer_profile_by_id(
        self, product_name: str, policer_profile_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Policer Profile by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}")

    async def dur_update_policer_profile_by_id(
        self, product_name: str, policer_profile_id: str, policer_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Policer Profile by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}", data=policer_profile_data
        )

    async def dur_replace_policer_profile_by_id(
        self, product_name: str, policer_profile_id: str, policer_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Policer Profile by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}", data=policer_profile_data
        )

    async def dur_delete_policer_profile_by_id(
        self, product_name: str, policer_profile_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Policer Profile by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/policer-profile/{product_name}/{policer_profile_id}")

    async def dur_get_policer_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Policer Profile by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/policer-profile/{product_name}/name/{name}")

    async def dur_update_policer_profile_by_name(
        self, product_name: str, name: str, policer_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Policer Profile by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/policer-profile/{product_name}/name/{name}", data=policer_profile_data
        )

    async def dur_replace_policer_profile_by_name(
        self, product_name: str, name: str, policer_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Policer Profile by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/policer-profile/{product_name}/name/{name}", data=policer_profile_data
        )

    async def dur_delete_policer_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Policer Profile by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/policer-profile/{product_name}/name/{name}")

    # ====================================================================
    # Policies — /enforcement-profile-dur/policy/{product_name}
    # ====================================================================

    async def dur_list_policies(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Policies for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/policy/{product_name}", params=params)

    async def dur_create_policy(
        self, product_name: str, policy_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Policy for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/policy/{product_name}", data=policy_data)

    async def dur_get_policy_by_id(
        self, product_name: str, policy_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Policy by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/policy/{product_name}/{policy_id}")

    async def dur_update_policy_by_id(
        self, product_name: str, policy_id: str, policy_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Policy by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/policy/{product_name}/{policy_id}", data=policy_data
        )

    async def dur_replace_policy_by_id(
        self, product_name: str, policy_id: str, policy_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Policy by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/policy/{product_name}/{policy_id}", data=policy_data
        )

    async def dur_delete_policy_by_id(
        self, product_name: str, policy_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Policy by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/policy/{product_name}/{policy_id}")

    async def dur_get_policy_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Policy by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/policy/{product_name}/name/{name}")

    async def dur_update_policy_by_name(
        self, product_name: str, name: str, policy_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Policy by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/policy/{product_name}/name/{name}", data=policy_data
        )

    async def dur_replace_policy_by_name(
        self, product_name: str, name: str, policy_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Policy by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/policy/{product_name}/name/{name}", data=policy_data
        )

    async def dur_delete_policy_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Policy by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/policy/{product_name}/name/{name}")

    # ====================================================================
    # QoS Profiles — /enforcement-profile-dur/qos-profile/{product_name}
    # ====================================================================

    async def dur_list_qos_profiles(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR QoS Profiles for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/qos-profile/{product_name}", params=params)

    async def dur_create_qos_profile(
        self, product_name: str, qos_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR QoS Profile for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/qos-profile/{product_name}", data=qos_profile_data)

    async def dur_get_qos_profile_by_id(
        self, product_name: str, qos_profile_id: str
    ) -> Dict[str, Any]:
        """Get a DUR QoS Profile by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}")

    async def dur_update_qos_profile_by_id(
        self, product_name: str, qos_profile_id: str, qos_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR QoS Profile by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}", data=qos_profile_data
        )

    async def dur_replace_qos_profile_by_id(
        self, product_name: str, qos_profile_id: str, qos_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR QoS Profile by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}", data=qos_profile_data
        )

    async def dur_delete_qos_profile_by_id(
        self, product_name: str, qos_profile_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR QoS Profile by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/qos-profile/{product_name}/{qos_profile_id}")

    async def dur_get_qos_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR QoS Profile by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/qos-profile/{product_name}/name/{name}")

    async def dur_update_qos_profile_by_name(
        self, product_name: str, name: str, qos_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR QoS Profile by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/qos-profile/{product_name}/name/{name}", data=qos_profile_data
        )

    async def dur_replace_qos_profile_by_name(
        self, product_name: str, name: str, qos_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR QoS Profile by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/qos-profile/{product_name}/name/{name}", data=qos_profile_data
        )

    async def dur_delete_qos_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR QoS Profile by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/qos-profile/{product_name}/name/{name}")

    # ====================================================================
    # Session Access Control Lists — /enforcement-profile-dur/session-access-control-list/{product_name}
    # ====================================================================

    async def dur_list_session_access_control_lists(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Session Access Control Lists for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/session-access-control-list/{product_name}", params=params)

    async def dur_create_session_access_control_list(
        self, product_name: str, session_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Session Access Control List for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/session-access-control-list/{product_name}", data=session_access_control_list_data)

    async def dur_get_session_access_control_list_by_id(
        self, product_name: str, session_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Session Access Control List by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}")

    async def dur_update_session_access_control_list_by_id(
        self, product_name: str, session_access_control_list_id: str, session_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Session Access Control List by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}", data=session_access_control_list_data
        )

    async def dur_replace_session_access_control_list_by_id(
        self, product_name: str, session_access_control_list_id: str, session_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Session Access Control List by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}", data=session_access_control_list_data
        )

    async def dur_delete_session_access_control_list_by_id(
        self, product_name: str, session_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Session Access Control List by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/session-access-control-list/{product_name}/{session_access_control_list_id}")

    async def dur_get_session_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Session Access Control List by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}")

    async def dur_update_session_access_control_list_by_name(
        self, product_name: str, name: str, session_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Session Access Control List by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}", data=session_access_control_list_data
        )

    async def dur_replace_session_access_control_list_by_name(
        self, product_name: str, name: str, session_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Session Access Control List by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}", data=session_access_control_list_data
        )

    async def dur_delete_session_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Session Access Control List by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/session-access-control-list/{product_name}/name/{name}")

    # ====================================================================
    # Stateless Access Control Lists — /enforcement-profile-dur/stateless-access-control-list/{product_name}
    # ====================================================================

    async def dur_list_stateless_access_control_lists(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Stateless Access Control Lists for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/stateless-access-control-list/{product_name}", params=params)

    async def dur_create_stateless_access_control_list(
        self, product_name: str, stateless_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Stateless Access Control List for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/stateless-access-control-list/{product_name}", data=stateless_access_control_list_data)

    async def dur_get_stateless_access_control_list_by_id(
        self, product_name: str, stateless_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Stateless Access Control List by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}")

    async def dur_update_stateless_access_control_list_by_id(
        self, product_name: str, stateless_access_control_list_id: str, stateless_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Stateless Access Control List by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}", data=stateless_access_control_list_data
        )

    async def dur_replace_stateless_access_control_list_by_id(
        self, product_name: str, stateless_access_control_list_id: str, stateless_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Stateless Access Control List by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}", data=stateless_access_control_list_data
        )

    async def dur_delete_stateless_access_control_list_by_id(
        self, product_name: str, stateless_access_control_list_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Stateless Access Control List by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/{stateless_access_control_list_id}")

    async def dur_get_stateless_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Stateless Access Control List by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}")

    async def dur_update_stateless_access_control_list_by_name(
        self, product_name: str, name: str, stateless_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Stateless Access Control List by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}", data=stateless_access_control_list_data
        )

    async def dur_replace_stateless_access_control_list_by_name(
        self, product_name: str, name: str, stateless_access_control_list_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Stateless Access Control List by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}", data=stateless_access_control_list_data
        )

    async def dur_delete_stateless_access_control_list_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Stateless Access Control List by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/stateless-access-control-list/{product_name}/name/{name}")

    # ====================================================================
    # Time Ranges — /enforcement-profile-dur/time-range/{product_name}
    # ====================================================================

    async def dur_list_time_ranges(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR Time Ranges for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/time-range/{product_name}", params=params)

    async def dur_create_time_range(
        self, product_name: str, time_range_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR Time Range for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/time-range/{product_name}", data=time_range_data)

    async def dur_get_time_range_by_id(
        self, product_name: str, time_range_id: str
    ) -> Dict[str, Any]:
        """Get a DUR Time Range by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/time-range/{product_name}/{time_range_id}")

    async def dur_update_time_range_by_id(
        self, product_name: str, time_range_id: str, time_range_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Time Range by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/time-range/{product_name}/{time_range_id}", data=time_range_data
        )

    async def dur_replace_time_range_by_id(
        self, product_name: str, time_range_id: str, time_range_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Time Range by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/time-range/{product_name}/{time_range_id}", data=time_range_data
        )

    async def dur_delete_time_range_by_id(
        self, product_name: str, time_range_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR Time Range by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/time-range/{product_name}/{time_range_id}")

    async def dur_get_time_range_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR Time Range by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/time-range/{product_name}/name/{name}")

    async def dur_update_time_range_by_name(
        self, product_name: str, name: str, time_range_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR Time Range by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/time-range/{product_name}/name/{name}", data=time_range_data
        )

    async def dur_replace_time_range_by_name(
        self, product_name: str, name: str, time_range_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR Time Range by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/time-range/{product_name}/name/{name}", data=time_range_data
        )

    async def dur_delete_time_range_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR Time Range by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/time-range/{product_name}/name/{name}")

    # ====================================================================
    # VoIP Profiles — /enforcement-profile-dur/voip-profile/{product_name}
    # ====================================================================

    async def dur_list_voip_profiles(
        self,
        product_name: str,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Get a list of DUR VoIP Profiles for a product."""
        params = self._dur_list_params(filter_str, sort, offset, limit, calculate_count)
        return await self._make_request("GET", f"enforcement-profile-dur/voip-profile/{product_name}", params=params)

    async def dur_create_voip_profile(
        self, product_name: str, voip_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a DUR VoIP Profile for a product."""
        return await self._make_request("POST", f"enforcement-profile-dur/voip-profile/{product_name}", data=voip_profile_data)

    async def dur_get_voip_profile_by_id(
        self, product_name: str, voip_profile_id: str
    ) -> Dict[str, Any]:
        """Get a DUR VoIP Profile by numeric ID."""
        return await self._make_request("GET", f"enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}")

    async def dur_update_voip_profile_by_id(
        self, product_name: str, voip_profile_id: str, voip_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR VoIP Profile by numeric ID."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}", data=voip_profile_data
        )

    async def dur_replace_voip_profile_by_id(
        self, product_name: str, voip_profile_id: str, voip_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR VoIP Profile by numeric ID."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}", data=voip_profile_data
        )

    async def dur_delete_voip_profile_by_id(
        self, product_name: str, voip_profile_id: str
    ) -> Dict[str, Any]:
        """Delete a DUR VoIP Profile by numeric ID."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/voip-profile/{product_name}/{voip_profile_id}")

    async def dur_get_voip_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Get a DUR VoIP Profile by name."""
        return await self._make_request("GET", f"enforcement-profile-dur/voip-profile/{product_name}/name/{name}")

    async def dur_update_voip_profile_by_name(
        self, product_name: str, name: str, voip_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update some fields of a DUR VoIP Profile by name."""
        return await self._make_request(
            "PATCH", f"enforcement-profile-dur/voip-profile/{product_name}/name/{name}", data=voip_profile_data
        )

    async def dur_replace_voip_profile_by_name(
        self, product_name: str, name: str, voip_profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace a DUR VoIP Profile by name."""
        return await self._make_request(
            "PUT", f"enforcement-profile-dur/voip-profile/{product_name}/name/{name}", data=voip_profile_data
        )

    async def dur_delete_voip_profile_by_name(
        self, product_name: str, name: str
    ) -> Dict[str, Any]:
        """Delete a DUR VoIP Profile by name."""
        return await self._make_request("DELETE", f"enforcement-profile-dur/voip-profile/{product_name}/name/{name}")

    # ====================================================================
    # Base enforcement profile — full replace (PUT)
    # ====================================================================

    async def replace_enforcement_profile_by_id(
        self, enforcement_profile_id: int, profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an enforcement profile by numeric ID (full PUT)."""
        return await self._make_request(
            "PUT", f"enforcement-profile/{enforcement_profile_id}", data=profile_data
        )

    async def replace_enforcement_profile_by_name(
        self, name: str, profile_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Replace an enforcement profile by name (full PUT)."""
        return await self._make_request(
            "PUT", f"enforcement-profile/name/{name}", data=profile_data
        )
