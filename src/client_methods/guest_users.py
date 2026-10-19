"""
Mixin class for ClearPassClient to manage guest user-related API calls.

Role namespaces
---------------
ClearPass has TWO unrelated role namespaces whose ids collide numerically:

* **Policy Manager roles** — ``GET /role``. On a stock appliance ``[Guest]``
  is id 3 and ``[Employee]`` is id 22.
* **Guest Manager roles** — the namespace a guest account's ``role_id`` field
  belongs to. On a stock appliance ``[Contractor]`` is 1, ``[Guest]`` is 2 and
  ``[Employee]`` is 3.

Submitting a Policy Manager role id as a guest ``role_id`` is a
privilege-escalation bug: ``[Guest]`` resolves to 3 in Policy Manager, which
means ``[Employee]`` to Guest Manager. The API accepts it, so the caller is
told the guest got ``[Guest]`` while the account actually carries employee-level
network access. Guest role names MUST be resolved with
:meth:`GuestUserMethodsMixin.get_guest_role_id_by_name`.
"""

import json
from typing import Dict, Any, Optional, Union

from ..exceptions import ClearPassAPIError

# A role_id that can never be valid. POST /guest with it is rejected at
# validation time (HTTP 422) *before* any record is created, and the rejection
# body enumerates the entire Guest Manager role namespace — see
# _probe_guest_manager_roles below.
_ROLE_PROBE_SENTINEL = -1

# Last-resort mapping, used ONLY if the live probe and the account scan both
# come back empty (e.g. a future firmware stops enumerating the options).
#
# !!! These are the Guest Manager (guest account) role ids, NOT Policy Manager
# !!! role ids. Do not "fix" them against GET /role — the two namespaces
# !!! collide numerically and swapping them silently grants guests employee
# !!! access. Verified on ClearPass 6.12.4.
_BUILTIN_GUEST_MANAGER_ROLES: Dict[str, int] = {
    "[Contractor]": 1,
    "[Guest]": 2,
    "[Employee]": 3,
}


def _error_body(error: Exception) -> Dict[str, Any]:
    """The structured error body carried by a ``ClearPassAPIError``.

    ``ClearPassClient._make_request`` always attaches the parsed body to
    ``response_data`` now. This helper used to re-parse the JSON back out of
    the exception *message* because the client's exception handler swallowed
    the body on every path; that workaround is gone.
    """
    data = getattr(error, "response_data", None)
    return data if isinstance(data, dict) else {}


class GuestUserMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for guest user management.
    """

    async def list_guest_users(
        self,
        filter_enabled: Optional[bool] = None,
        role_filter: Optional[str] = None,
        limit: int = 50
    ) -> Dict[str, Any]:
        """List guest users."""
        params = {"limit": limit}

        # Build JSON filter object if filters are provided
        filter_conditions = {}
        if filter_enabled is not None:
            filter_conditions["enabled"] = filter_enabled
        if role_filter:
            filter_conditions["role_name"] = role_filter

        if filter_conditions:
            params["filter"] = json.dumps(filter_conditions)

        return await self._make_request("GET", "guest", params=params)

    async def get_guest_user(self, user_id: Union[int, str]) -> Dict[str, Any]:
        """Get a specific guest user by ID."""
        return await self._make_request("GET", f"guest/{user_id}")

    async def get_guest_user_by_username(self, username: str) -> Dict[str, Any]:
        """Get a specific guest user by username."""
        return await self._make_request("GET", f"guest/username/{username}")

    # ------------------------------------------------------------------
    # Guest Manager role namespace
    # ------------------------------------------------------------------

    async def _probe_guest_manager_roles(self) -> Dict[str, int]:
        """Read the Guest Manager role namespace off the appliance.

        ClearPass exposes no list endpoint for guest roles (``GET /guest/role``
        is routed to ``GET /guest/<id>`` and 422s; ``/guestmanager/role`` 404s;
        the API Explorer catalogue for Identities-v1 / GuestConfiguration-v1
        contains no guest-role resource). The namespace *is* published in the
        validation error the appliance returns for an invalid ``role_id``::

            POST /guest {"role_id": -1}
            422 {"validation_messages": {"role_id": {
                    "error": "Invalid role_id",
                    "_options": {"1": "[Contractor]", "3": "[Employee]",
                                 "2": "[Guest]"}}}}

        The request carries no username and is rejected during validation, so
        it creates nothing (verified against the live appliance: the guest
        inventory is byte-identical before and after).
        """
        try:
            created = await self._make_request(
                "POST", "guest", data={"role_id": _ROLE_PROBE_SENTINEL})
        except ClearPassAPIError as exc:
            options = (
                _error_body(exc)
                .get("validation_messages", {})
                .get("role_id", {})
                .get("_options")
            )
            if not isinstance(options, dict):
                return {}
            roles: Dict[str, int] = {}
            for role_id, role_name in options.items():
                try:
                    roles[str(role_name)] = int(role_id)
                except (TypeError, ValueError):
                    continue
            return roles
        except Exception:
            return {}

        # Unreachable on a sane appliance: the sentinel is not a valid role.
        # If it somehow created a record, remove it rather than leave a
        # nameless guest account behind.
        stray_id = (created or {}).get("id")
        if stray_id is not None:
            try:
                await self.delete_guest_user(stray_id)
            except Exception:
                pass
        return {}

    async def _guest_manager_roles_from_accounts(self) -> Dict[str, int]:
        """Derive role name -> id pairs from existing guest accounts.

        Fallback only: covers whichever roles are actually in use.
        """
        try:
            response = await self.list_guest_users(limit=1000)
        except Exception:
            return {}
        items = response.get("_embedded", {}).get("items") or response.get("items", [])
        roles: Dict[str, int] = {}
        for item in items:
            if not isinstance(item, dict):
                continue
            name, role_id = item.get("role_name"), item.get("role_id")
            if isinstance(name, str) and isinstance(role_id, int):
                roles.setdefault(name, role_id)
        return roles

    async def list_guest_manager_roles(self, refresh: bool = False) -> Dict[str, int]:
        """Return ``{role_name: role_id}`` for the **Guest Manager** namespace.

        Cached on the client instance; pass ``refresh=True`` to re-read.
        """
        cached = getattr(self, "_guest_manager_roles_cache", None)
        if cached and not refresh:
            return dict(cached)

        roles = await self._probe_guest_manager_roles()
        if not roles:
            roles = await self._guest_manager_roles_from_accounts()
        if not roles:
            # Loud fallback: see the comment on _BUILTIN_GUEST_MANAGER_ROLES.
            roles = dict(_BUILTIN_GUEST_MANAGER_ROLES)

        self._guest_manager_roles_cache = dict(roles)
        return dict(roles)

    async def get_guest_role_id_by_name(self, role_name: str) -> Optional[int]:
        """Resolve a guest role NAME to its **Guest Manager** role id.

        This is the only correct resolver for a guest account's ``role_id``.
        Matching is exact first, then case-insensitive, then tolerant of the
        missing brackets around the ClearPass built-ins ("Guest" -> "[Guest]").
        """
        if not isinstance(role_name, str) or not role_name.strip():
            return None
        roles = await self.list_guest_manager_roles()

        if role_name in roles:
            return roles[role_name]

        wanted = role_name.strip().lower()
        lowered = {name.lower(): rid for name, rid in roles.items()}
        if wanted in lowered:
            return lowered[wanted]

        bracketed = f"[{wanted.strip('[]')}]"
        if bracketed in lowered:
            return lowered[bracketed]
        return None

    async def get_role_id_by_name(self, role_name: str) -> Optional[int]:
        """Get a **Policy Manager** role ID by role name (``GET /role``).

        WARNING: this is the Policy Manager namespace. It must NEVER be used to
        populate a guest account's ``role_id`` — the two namespaces collide
        numerically and doing so silently grants guests employee-level access.
        Use :meth:`get_guest_role_id_by_name` for guest accounts.
        """
        try:
            # Search for role by name using filter
            filter_json = json.dumps({"name": role_name})
            response = await self._make_request("GET", "role", params={"filter": filter_json})

            if "_embedded" in response and "items" in response["_embedded"]:
                roles = response["_embedded"]["items"]
            else:
                roles = response.get("items", [])

            if roles:
                return roles[0].get("id")
            return None
        except Exception:
            return None

    async def _apply_guest_role(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Translate a ``role_name`` in ``user_data`` into a Guest Manager id."""
        if "role_name" not in user_data or "role_id" in user_data:
            return user_data
        role_name = user_data.pop("role_name")
        role_id = await self.get_guest_role_id_by_name(role_name)
        if role_id is None:
            known = ", ".join(sorted(await self.list_guest_manager_roles()))
            raise ValueError(
                f"Role '{role_name}' not found in the ClearPass Guest Manager "
                f"role namespace. Available guest roles: {known}"
            )
        user_data["role_id"] = role_id
        return user_data

    async def create_guest_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new guest user."""
        user_data = await self._apply_guest_role(user_data)
        return await self._make_request("POST", "guest", data=user_data)

    async def update_guest_user(self, user_id: Union[int, str], user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing guest user by numeric ID."""
        user_data = await self._apply_guest_role(user_data)
        return await self._make_request("PATCH", f"guest/{user_id}", data=user_data)

    async def update_guest_user_by_username(self, username: str, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing guest user by username."""
        user_data = await self._apply_guest_role(user_data)
        return await self._make_request("PATCH", f"guest/username/{username}", data=user_data)

    async def delete_guest_user(self, user_id: Union[int, str]) -> Dict[str, Any]:
        """Delete a guest user by numeric ID."""
        return await self._make_request("DELETE", f"guest/{user_id}")

    async def delete_guest_user_by_username(self, username: str) -> Dict[str, Any]:
        """Delete a guest user by username."""
        return await self._make_request("DELETE", f"guest/username/{username}")
