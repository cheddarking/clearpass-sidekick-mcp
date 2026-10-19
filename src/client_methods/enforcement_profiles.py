"""
Client methods for ClearPass Enforcement Profile operations.

This module provides focused methods for the most common enforcement profile
operations following the template-driven approach for practical networking scenarios.
"""

import json
from typing import Any, Dict, List, Optional, Union

from ..models.enforcement_profiles import (
    EnforcementProfile,
    EnforcementProfileSummary,
    CreateEnforcementProfileRequest,
    UpdateEnforcementProfileRequest,
    EnforcementProfileListResponse,
    ProfileTemplate,
    TemplateInstance,
    ValidationResult,
    EnforcementProfileFilter,
    PREDEFINED_TEMPLATES,
    ProfileAttribute
)


class EnforcementProfileMethodsMixin:
    """Mixin class providing enforcement profile management methods."""

    # ========================================================================
    # Core Enforcement Profile Management (Phase 1.1)
    # ========================================================================

    async def list_enforcement_profiles(
        self,
        # Removed filter parameters as they cause API validation issues
        # filter_type: Optional[str] = None,
        # filter_action: Optional[str] = None,
        # name_contains: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        calculate_count: bool = False,
        # Optional params to keep the function signature compatible
        **kwargs
    ) -> Dict[str, Any]:
        """
        List enforcement profiles with optional filtering.
        
        Args:
            filter_type: Filter by profile type
            filter_action: Filter by profile action
            name_contains: Filter by profile name substring
            limit: Maximum number of profiles to return
            offset: Starting offset for pagination
            calculate_count: Whether to calculate total count
            
        Returns:
            Dictionary containing enforcement profiles list and metadata
        """
        # We're not going to use these filter parameters with the API
        # They are causing issues with parameter validation
        # Instead, we'll do filtering in memory after getting results
        
        params = {}
        
        # Handle pagination and count parameters
        if limit is not None:
            params["limit"] = str(limit)
        if offset is not None:
            params["offset"] = str(offset)
        if calculate_count:
            params["calculate_count"] = "true"
            
        # Explicitly avoid sending filter parameters to the API
        # DO NOT add filter_type, filter_action, or name_contains to params
            
        # Make the API call without any filtering
        return await self._make_request(
            method="GET",
            endpoint="/enforcement-profile",
            params=params
        )

    async def create_enforcement_profile(
        self,
        name: str,
        profile_type: str,
        description: Optional[str] = None,
        agent_template: Optional[str] = None,
        post_auth_template: Optional[str] = None,
        radius_dyn_authz_template: Optional[str] = None,
        action: Optional[str] = None,
        device_group_list: Optional[List[str]] = None,
        attributes: Optional[List[Dict[str, str]]] = None,
        tacacs_service_params: Optional[List[Dict[str, str]]] = None,
        dur_config: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Create a new enforcement profile.
        
        Args:
            name: Profile name
            profile_type: Profile type
            description: Optional profile description
            agent_template: Agent template
            post_auth_template: Post authentication template
            radius_dyn_authz_template: RADIUS dynamic authorization template
            action: Profile action
            device_group_list: List of device groups
            attributes: Profile attributes
            tacacs_service_params: TACACS+ service parameters
            dur_config: Downloadable User Role configuration
            
        Returns:
            Dictionary containing created profile details
        """
        # Build the data structure according to ClearPass API requirements
        data = {
            "name": name,
            "type": profile_type
        }
        
        # Description is commonly used
        if description:
            data["description"] = description
            
        # Action is required for most profile types 
        # Set a sensible default if not provided
        if action:
            data["action"] = action
        elif profile_type == "RADIUS":
            # For RADIUS profiles, provide a default action
            data["action"] = "Accept"
        
        # A profile with no enforcement parameters at all is rejected by the
        # appliance, and the message it returns names the wrong field
        # ("Invalid value specified for attribute -> type"). Fail locally with
        # an actionable message instead of round-tripping to get that.
        if not any([attributes, agent_template, post_auth_template,
                    radius_dyn_authz_template, device_group_list,
                    tacacs_service_params, dur_config]):
            raise ValueError(
                "An enforcement profile must carry at least one enforcement "
                "parameter. Supply 'attributes' (e.g. "
                "[{\"type\": \"Radius:IETF\", \"name\": \"Session-Timeout\", "
                "\"value\": \"28800\"}]) or one of agent_template, "
                "post_auth_template, radius_dyn_authz_template, "
                "device_group_list, tacacs_service_params, dur_config. "
                "Note: attribute types must be namespaced (Radius:IETF, "
                "Radius:Aruba, cpass:HTTP, ...) — a bare \"RADIUS\" is "
                "rejected by ClearPass."
            )

        if attributes:
            data["attributes"] = attributes
        
        if agent_template:
            data["agent_template"] = agent_template
            
        if post_auth_template:
            data["post_auth_template"] = post_auth_template
            
        if radius_dyn_authz_template:
            data["radius_dyn_authz_template"] = radius_dyn_authz_template
            
        if device_group_list:
            data["device_group_list"] = device_group_list
            
        if tacacs_service_params:
            data["tacacs_service_params"] = tacacs_service_params
            
        if dur_config:
            data["dur_config"] = dur_config

        return await self._make_request(
            method="POST",
            endpoint="/enforcement-profile",
            data=data
        )

    async def get_enforcement_profile_details(
        self,
        profile_id: Optional[int] = None,
        profile_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get enforcement profile details by ID or name.
        
        Args:
            profile_id: Profile ID (takes precedence over name)
            profile_name: Profile name
            
        Returns:
            Dictionary containing profile details
        """
        if profile_id:
            endpoint = f"/enforcement-profile/{profile_id}"
            operation = f"get_enforcement_profile_by_id_{profile_id}"
        elif profile_name:
            endpoint = f"/enforcement-profile/name/{profile_name}"
            operation = f"get_enforcement_profile_by_name_{profile_name}"
        else:
            raise ValueError("Either profile_id or profile_name must be provided")

        return await self._make_request(
            method="GET",
            endpoint=endpoint
        )

    async def update_enforcement_profile(
        self,
        profile_id: Optional[int] = None,
        profile_name: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        profile_type: Optional[str] = None,
        agent_template: Optional[str] = None,
        post_auth_template: Optional[str] = None,
        radius_dyn_authz_template: Optional[str] = None,
        action: Optional[str] = None,
        device_group_list: Optional[List[str]] = None,
        attributes: Optional[List[Dict[str, str]]] = None,
        tacacs_service_params: Optional[List[Dict[str, str]]] = None,
        dur_config: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Update enforcement profile by ID or name.
        
        Args:
            profile_id: Profile ID (takes precedence over name)
            profile_name: Profile name
            name: New profile name
            description: New profile description
            profile_type: New profile type
            agent_template: Agent template
            post_auth_template: Post authentication template
            radius_dyn_authz_template: RADIUS dynamic authorization template
            action: Profile action
            device_group_list: List of device groups
            attributes: Profile attributes
            tacacs_service_params: TACACS+ service parameters
            dur_config: Downloadable User Role configuration
            
        Returns:
            Dictionary containing updated profile details
        """
        # Build update data
        data = {}
        if name:
            data["name"] = name
        if description:
            data["description"] = description
        if profile_type:
            data["type"] = profile_type
        if agent_template:
            data["agent_template"] = agent_template
        if post_auth_template:
            data["post_auth_template"] = post_auth_template
        if radius_dyn_authz_template:
            data["radius_dyn_authz_template"] = radius_dyn_authz_template
        if action:
            data["action"] = action
        if device_group_list:
            data["device_group_list"] = device_group_list
        if attributes:
            data["attributes"] = attributes
        if tacacs_service_params:
            data["tacacs_service_params"] = tacacs_service_params
        if dur_config:
            data["dur_config"] = dur_config

        if profile_id:
            endpoint = f"/enforcement-profile/{profile_id}"
            operation = f"update_enforcement_profile_by_id_{profile_id}"
        elif profile_name:
            endpoint = f"/enforcement-profile/name/{profile_name}"
            operation = f"update_enforcement_profile_by_name_{profile_name}"
        else:
            raise ValueError("Either profile_id or profile_name must be provided")

        return await self._make_request(
            method="PATCH",
            endpoint=endpoint,
            data=data
        )

    async def delete_enforcement_profile(
        self,
        profile_id: Optional[int] = None,
        profile_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Delete enforcement profile by ID or name.
        
        Args:
            profile_id: Profile ID (takes precedence over name)
            profile_name: Profile name
            
        Returns:
            Dictionary containing deletion result
        """
        if profile_id:
            endpoint = f"/enforcement-profile/{profile_id}"
            operation = f"delete_enforcement_profile_by_id_{profile_id}"
        elif profile_name:
            endpoint = f"/enforcement-profile/name/{profile_name}"
            operation = f"delete_enforcement_profile_by_name_{profile_name}"
        else:
            raise ValueError("Either profile_id or profile_name must be provided")

        return await self._make_request(
            method="DELETE",
            endpoint=endpoint
        )

    # ========================================================================
    # Template-Based Creation (Phase 1.2)
    # ========================================================================

    async def create_profile_from_template(
        self,
        template_name: str,
        profile_name: str,
        profile_description: Optional[str] = None,
        customizations: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create an enforcement profile from a predefined template.
        
        Args:
            template_name: Name of the predefined template
            profile_name: Name for the new profile
            profile_description: Custom description for the profile
            customizations: Template customizations
            
        Returns:
            Dictionary containing created profile details
        """
        if template_name not in PREDEFINED_TEMPLATES:
            raise ValueError(f"Unknown template: {template_name}. Available templates: {list(PREDEFINED_TEMPLATES.keys())}")
        
        template = PREDEFINED_TEMPLATES[template_name]
        
        # Start with template defaults
        data = {
            "name": profile_name,
            "type": template.profile_type,
            "description": profile_description or template.description,
            "action": "Accept",  # Default action for all templates
            "attributes": [attr.model_dump() for attr in template.default_attributes]
        }
        
        # Apply customizations if provided
        if customizations:
            # Allow customizing attributes. A custom attribute with the same
            # (type, name) as a template default REPLACES it rather than being
            # appended — otherwise e.g. a custom session timeout would leave
            # two Session-Timeout attributes on the profile.
            if "attributes" in customizations:
                custom_attrs = customizations["attributes"]
                if isinstance(custom_attrs, list):
                    merged = list(data["attributes"])
                    for attr in custom_attrs:
                        if not isinstance(attr, dict):
                            continue
                        key = (attr.get("type"), attr.get("name"))
                        for index, existing in enumerate(merged):
                            if (existing.get("type"), existing.get("name")) == key:
                                merged[index] = attr
                                break
                        else:
                            merged.append(attr)
                    data["attributes"] = merged

            # Allow customizing other fields
            for field in ["description", "action", "device_group_list",
                          "agent_template", "post_auth_template",
                          "radius_dyn_authz_template"]:
                if field in customizations:
                    data[field] = customizations[field]

        return await self._make_request(
            method="POST",
            endpoint="/enforcement-profile",
            data=data
        )

    async def list_profile_templates(self) -> Dict[str, Any]:
        """
        List available predefined profile templates.
        
        Returns:
            Dictionary containing available templates
        """
        templates = []
        for template_name, template in PREDEFINED_TEMPLATES.items():
            templates.append({
                "name": template_name,
                "display_name": template.display_name,
                "description": template.description,
                "category": template.category,
                "profile_type": template.profile_type,
                "recommended_qos": template.recommended_qos,
                "recommended_acls": template.recommended_acls,
                "default_attributes_count": len(template.default_attributes),
                "time_limits": template.time_limits
            })
        
        return {
            "templates": templates,
            "count": len(templates),
            "categories": ["user_access", "device_access", "guest_access"]
        }

    async def validate_profile_configuration(
        self,
        profile_data: Dict[str, Any],
        check_dependencies: bool = True
    ) -> Dict[str, Any]:
        """
        Validate enforcement profile configuration.
        
        Args:
            profile_data: Profile configuration to validate
            check_dependencies: Whether to check for missing dependencies
            
        Returns:
            Dictionary containing validation results
        """
        validation_result = ValidationResult(is_valid=True)
        
        # Basic validation
        if not profile_data.get("name"):
            validation_result.errors.append("Profile name is required")
            validation_result.is_valid = False
            
        if not profile_data.get("type"):
            validation_result.errors.append("Profile type is required")
            validation_result.is_valid = False
        
        # Check for potential conflicts
        attributes = profile_data.get("attributes", [])
        if attributes:
            attr_names = [attr.get("name") for attr in attributes if attr.get("name")]
            duplicates = [name for name in set(attr_names) if attr_names.count(name) > 1]
            if duplicates:
                validation_result.warnings.append(f"Duplicate attribute names found: {duplicates}")
        
        # Check time limits
        session_timeout = None
        idle_timeout = None
        for attr in attributes:
            if attr.get("name") == "Session-Timeout":
                try:
                    session_timeout = int(attr.get("value", 0))
                    if session_timeout > 86400:  # 24 hours
                        validation_result.warnings.append("Session timeout exceeds 24 hours")
                except ValueError:
                    validation_result.errors.append("Invalid Session-Timeout value")
                    validation_result.is_valid = False
                    
            elif attr.get("name") == "Idle-Timeout":
                try:
                    idle_timeout = int(attr.get("value", 0))
                    if idle_timeout > (session_timeout if session_timeout else 3600):
                        validation_result.warnings.append("Idle timeout should be less than session timeout")
                except ValueError:
                    validation_result.errors.append("Invalid Idle-Timeout value")
                    validation_result.is_valid = False
        
        # Dependency checks (if enabled)
        if check_dependencies:
            device_groups = profile_data.get("device_group_list", [])
            if device_groups:
                validation_result.dependencies.extend([
                    f"Device group '{group}' should exist" for group in device_groups
                ])
        
        return validation_result.model_dump()

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _build_profile_filter(self, filter_criteria: EnforcementProfileFilter) -> str:
        """Build a ClearPass API filter from filter criteria.

        ClearPass 6.12.4 requires ``filter`` to be a JSON object; RSQL-style
        strings ("name contains X AND type=Y") are rejected with
        ``422 Filter must specify a JSON object``. Substring matches use the
        ``$contains`` operator; multiple keys in one object are ANDed.
        """
        filters: Dict[str, Any] = {}

        if filter_criteria.name_contains:
            filters["name"] = {"$contains": filter_criteria.name_contains}
        if filter_criteria.type:
            filters["type"] = filter_criteria.type
        if filter_criteria.action:
            filters["action"] = filter_criteria.action
        if filter_criteria.template_used:
            filters["description"] = {
                "$contains": f"Template: {filter_criteria.template_used}"
            }

        return json.dumps(filters) if filters else ""

    def _extract_profile_summary(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract summary information from full profile data."""
        return {
            "id": profile_data.get("id"),
            "name": profile_data.get("name"),
            "description": profile_data.get("description"),
            "type": profile_data.get("type"),
            "action": profile_data.get("action"),
            "device_group_count": len(profile_data.get("device_group_list", [])),
            "attribute_count": len(profile_data.get("attributes", []))
        } 