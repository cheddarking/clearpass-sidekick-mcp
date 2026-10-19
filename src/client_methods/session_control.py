"""
Mixin class for ClearPassClient to manage session control API calls.

Note on the bulk/selector disconnect family
-------------------------------------------
ClearPass 6.12.4 **does** serve the ``session-action/disconnect[...]`` POST route
family -- at the unversioned ``/api`` root.

An earlier revision of this module recorded them as "not served", because the
client addressed the appliance at ``/api/v1`` and every one of those calls came
back as an HTTP 500 carrying the appliance's own ``/tips`` "Error 404: Page not
found" HTML page. That was the versioned mount misbehaving, not a missing route.
Re-measured by direct curl on 2026-07-30 (see ``_endpoint_url`` in
``src/clearpass_client.py`` for the full base-URL evidence):

* ``POST /api/v1/session-action/disconnect``, ``.../disconnect/mac/<mac>``,
  ``.../disconnect/ip/<ip>`` and ``.../disconnect/username/<user>`` -> HTML-bodied
  **500** on all four.
* The same four at ``POST /api/session-action/...`` -> structured
  **400 Bad Request** ("The request sent by the client was syntactically
  incorrect") for a synchronous call, and with ``?async=true`` a clean
  **200** returning ``{"action_id": "async_action_...", "status": "pending"}``.
  Polling ``GET /api/session-action/<action_id>`` for that probe (a username
  with no sessions) returned ``status: failed`` with
  ``"No Active Session found to disconnect."`` -- i.e. the route ran and reported
  a real result.

The client now builds every URL from ``/api``, so ``session_action_disconnect*``
below reaches the working handler.

``active-session/<mac>`` is a separate story and genuinely is **not** served on
6.12.4: ``GET`` and ``DELETE`` both answer a structured ``404 Page not found`` at
*both* roots, so ``*_active_session_by_mac_address`` remains unavailable here.

The four bulk/selector ``disconnect_sessions_*`` operations stay **composed**
from ``GET session`` + ``POST session/<id>/disconnect`` (both of which return
clean structured JSON, including a proper JSON 404 for an absent id). That path
is portable across appliance versions and needs no async polling, so it remains
the default. The native ``session_action_disconnect*`` wrappers are the direct
alternative: one request, no client-side scan, and full ``enforcement_profile``
support -- pass ``async_operation=True`` and poll ``get_session_action_status``.
"""

import json
import logging
import re
from typing import Dict, Any, Callable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Session payload keys that may carry each selector. ClearPass exposes these
# under different names depending on the access method (RADIUS / TACACS+ /
# web-login), so every candidate is checked rather than guessing one server-side
# filter field name.
_USERNAME_FIELDS: Tuple[str, ...] = (
    "username", "user_name", "visitor_name",
)
_MAC_FIELDS: Tuple[str, ...] = (
    "mac_address", "device_mac_address", "callingstationid",
    "calling_station_id", "mac",
)
_IP_FIELDS: Tuple[str, ...] = (
    "client_ip_address", "framedipaddress", "framed_ip_address",
    "ip_address", "ip",
)

# Hard ceilings for the scan that backs a composed bulk disconnect.
_SCAN_PAGE_SIZE = 1000
_SCAN_MAX_SESSIONS = 10000


def _normalize_mac(value: Any) -> str:
    """Reduce a MAC to bare lowercase hex so ``aa:bb:..``/``aa-bb-..``/``aabb..``
    all compare equal."""
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def _field_matches(session: Dict[str, Any], fields: Sequence[str],
                   wanted: str, normalizer: Optional[Callable[[Any], str]] = None) -> bool:
    norm = normalizer or (lambda v: str(v or "").strip().casefold())
    target = norm(wanted)
    if not target:
        return False
    return any(norm(session.get(f)) == target for f in fields if f in session)


def _session_digest(session: Dict[str, Any]) -> Dict[str, Any]:
    """The identifying fields echoed back for each affected session."""
    return {
        "session_id": session.get("id"),
        "username": session.get("username"),
        "mac_address": session.get("mac_address") or session.get("callingstationid"),
        "client_ip_address": (
            session.get("client_ip_address")
            or session.get("framedipaddress")
            or session.get("ip_address")
        ),
        "state": session.get("state"),
    }


class SessionControlMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for session control and management.
    """

    # Active Session Management
    async def list_active_sessions(
        self,
        filter_str: Optional[str] = None,
        sort: Optional[str] = None,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
        calculate_count: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Get a list of active sessions."""
        params = {k: v for k, v in locals().items() if k not in ['self'] and v is not None}
        if 'filter_str' in params:
            params['filter'] = params.pop('filter_str')
        return await self._make_request("GET", "session", params=params)

    async def get_active_session_by_id(self, session_id: str) -> Dict[str, Any]:
        """Get details of a specific active session by ID."""
        return await self._make_request("GET", f"session/{session_id}")

    # Session Disconnect Operations
    async def disconnect_session_by_id(self, session_id: str, confirm_disconnect: bool = True) -> Dict[str, Any]:
        """Disconnect a specific active session by ID."""
        data = {
            "id": session_id,
            "confirm_disconnect": confirm_disconnect
        }
        return await self._make_request("POST", f"session/{session_id}/disconnect", data=data)

    # Session Reauthorization Operations
    async def get_session_reauthorization_profiles(
        self, 
        session_id: str, 
        template_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get available reauthorization profiles for a session."""
        params = {}
        if template_type:
            params["template_type"] = template_type
        return await self._make_request("GET", f"session/{session_id}/reauthorize", params=params)

    async def reauthorize_session_by_id(
        self, 
        session_id: str, 
        reauthorize_profile: Optional[str] = None,
        confirm_reauthorize: bool = True
    ) -> Dict[str, Any]:
        """Reauthorize a specific active session by ID."""
        data = {
            "confirm_reauthorize": confirm_reauthorize
        }
        if reauthorize_profile:
            data["reauthorize_profile"] = reauthorize_profile
        return await self._make_request("POST", f"session/{session_id}/reauthorize", data=data)

    # ------------------------------------------------------------------
    # Bulk Session Actions
    #
    # Composed from `GET session` + `POST session/<id>/disconnect`. The native
    # `session-action/disconnect[...]` family IS served (at the unversioned
    # `/api` root -- see module docstring), but only usefully in async mode,
    # which forces the caller to poll an action_id. The composed path answers
    # synchronously with a full per-session result summary, so it stays the
    # default. Every one of these returns that summary.
    # ------------------------------------------------------------------

    async def _scan_sessions(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        match: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> Tuple[List[Dict[str, Any]], int, bool]:
        """Page through active sessions, returning ``(matched, scanned, truncated)``.

        ``filter_criteria`` is applied server-side (ClearPass takes the ``filter``
        query parameter as a JSON object). ``match`` is applied client-side, so a
        selector works regardless of which field name this appliance uses for it.
        """
        filter_str = json.dumps(filter_criteria) if filter_criteria else None

        matched: List[Dict[str, Any]] = []
        scanned = 0
        offset = 0
        truncated = False

        while True:
            page = await self.list_active_sessions(
                filter_str=filter_str,
                sort=sort,
                offset=offset,
                limit=_SCAN_PAGE_SIZE,
            )
            items = (page.get("_embedded") or {}).get("items") or []
            scanned += len(items)

            for session in items:
                if not isinstance(session, dict):
                    continue
                if match is None or match(session):
                    matched.append(session)

            if len(items) < _SCAN_PAGE_SIZE:
                break
            offset += len(items)
            if scanned >= _SCAN_MAX_SESSIONS:
                truncated = True
                break

        return matched, scanned, truncated

    async def _disconnect_matched_sessions(
        self,
        sessions: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Disconnect each session by id, one at a time, never raising.

        One failure never aborts the rest — each outcome is reported
        individually.
        """
        results: List[Dict[str, Any]] = []
        for session in sessions:
            entry = _session_digest(session)
            session_id = entry.get("session_id")
            if session_id is None:
                entry.update({
                    "disconnected": False,
                    "error": "session has no 'id' field; cannot disconnect it",
                })
                results.append(entry)
                continue
            try:
                entry["result"] = await self.disconnect_session_by_id(
                    str(session_id), confirm_disconnect=True
                )
                entry["disconnected"] = True
                entry["error"] = None
            except Exception as exc:  # noqa: BLE001 - reported per session
                logger.warning("Failed to disconnect session %s: %s", session_id, exc)
                entry["disconnected"] = False
                entry["error"] = str(exc)
            results.append(entry)
        return results

    @staticmethod
    def _unsupported_enforcement_profile(enforcement_profile: list) -> Dict[str, Any]:
        """`enforcement_profile` has no equivalent on `session/<id>/disconnect`."""
        return {
            "success": False,
            "supported": False,
            "message": (
                "enforcement_profile is not supported by the disconnect route "
                "available on this ClearPass version. Disconnects are performed "
                "via POST session/<id>/disconnect, which takes no enforcement "
                "profile. Use reauthorize_session (POST session/<id>/reauthorize) "
                "to apply a profile, or re-issue this call without "
                "enforcement_profile to disconnect the matching sessions."
            ),
            "unsupported_parameter": "enforcement_profile",
            "enforcement_profile": enforcement_profile,
            "matched_count": 0,
            "disconnected_count": 0,
            "failed_count": 0,
            "sessions": [],
        }

    async def _disconnect_sessions_matching(
        self,
        selector: Dict[str, Any],
        match: Optional[Callable[[Dict[str, Any]], bool]],
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False,
    ) -> Dict[str, Any]:
        """Shared body of the four bulk/selector disconnects."""
        if enforcement_profile:
            result = self._unsupported_enforcement_profile(enforcement_profile)
            result.update(selector)
            return result

        matched, scanned, truncated = await self._scan_sessions(
            filter_criteria=filter_criteria, sort=sort, match=match
        )

        summary: Dict[str, Any] = {
            "success": True,
            "matched_count": len(matched),
            "disconnected_count": 0,
            "failed_count": 0,
            "sessions_scanned": scanned,
            "truncated": truncated,
            "sessions": [],
            "failures": [],
            "method": (
                "composed: GET session + POST session/<id>/disconnect "
                "(synchronous; the native session-action/disconnect* routes "
                "are served but return an action_id to poll)"
            ),
        }
        summary.update(selector)
        if async_operation:
            summary["async_operation"] = False
            summary["async_note"] = (
                "async_operation is not available for the composed disconnect "
                "path; the operation ran synchronously and the full result is "
                "included here (no action_id to poll)."
            )

        if not matched:
            summary["message"] = "No active sessions matched; nothing was disconnected."
            return summary

        results = await self._disconnect_matched_sessions(matched)
        failures = [r for r in results if not r.get("disconnected")]

        summary["sessions"] = results
        summary["failures"] = failures
        summary["disconnected_count"] = len(results) - len(failures)
        summary["failed_count"] = len(failures)
        summary["success"] = not failures
        summary["message"] = (
            f"Disconnected {summary['disconnected_count']} of "
            f"{len(matched)} matching session(s)"
            + (f"; {len(failures)} failed" if failures else "")
        )
        return summary

    async def disconnect_sessions_bulk(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect every session matching ``filter_criteria``.

        With no filter this targets *all* active sessions.
        """
        return await self._disconnect_sessions_matching(
            selector={"filter_criteria": filter_criteria},
            match=None,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation,
        )

    async def disconnect_sessions_by_mac(
        self,
        mac_address: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect sessions whose MAC address matches ``mac_address``."""
        return await self._disconnect_sessions_matching(
            selector={"mac_address": mac_address},
            match=lambda s: _field_matches(s, _MAC_FIELDS, mac_address, _normalize_mac),
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation,
        )

    async def disconnect_sessions_by_username(
        self,
        username: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect sessions belonging to ``username``."""
        return await self._disconnect_sessions_matching(
            selector={"username": username},
            match=lambda s: _field_matches(s, _USERNAME_FIELDS, username),
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation,
        )

    async def disconnect_sessions_by_ip(
        self,
        client_ip_address: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect sessions whose client IP matches ``client_ip_address``."""
        return await self._disconnect_sessions_matching(
            selector={"client_ip_address": client_ip_address},
            match=lambda s: _field_matches(s, _IP_FIELDS, client_ip_address),
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation,
        )

    # ------------------------------------------------------------------
    # Native session-action/disconnect routes
    #
    # Verbatim wrappers over the routes pyclearpass documents. Unlike the
    # composed `disconnect_sessions_*` family above these issue a single request
    # and support `enforcement_profile`, but they are only served by appliances
    # that actually expose the route family (see module docstring).
    # ------------------------------------------------------------------

    @staticmethod
    def _session_action_body(
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build the shared `session-action/*` request body."""
        data: Dict[str, Any] = {}
        if filter_criteria is not None:
            data["filter"] = filter_criteria
        if enforcement_profile is not None:
            data["enforcement_profile"] = enforcement_profile
        if sort is not None:
            data["sort"] = sort
        return data

    @staticmethod
    def _async_params(async_operation: bool) -> Dict[str, Any]:
        """The `async` query parameter, present only when requested."""
        return {"async": "true"} if async_operation else {}

    async def session_action_disconnect(
        self,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect active sessions via the native bulk disconnect route."""
        return await self._make_request(
            "POST",
            "session-action/disconnect",
            data=self._session_action_body(filter_criteria, enforcement_profile, sort),
            params=self._async_params(async_operation),
        )

    async def session_action_disconnect_by_mac(
        self,
        mac_address: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect active sessions filtered by MAC via the native route."""
        return await self._make_request(
            "POST",
            f"session-action/disconnect/mac/{mac_address}",
            data=self._session_action_body(filter_criteria, enforcement_profile, sort),
            params=self._async_params(async_operation),
        )

    async def session_action_disconnect_by_ip(
        self,
        client_ip_address: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect active sessions filtered by client IP via the native route."""
        return await self._make_request(
            "POST",
            f"session-action/disconnect/ip/{client_ip_address}",
            data=self._session_action_body(filter_criteria, enforcement_profile, sort),
            params=self._async_params(async_operation),
        )

    async def session_action_disconnect_by_username(
        self,
        username: str,
        filter_criteria: Optional[Dict[str, Any]] = None,
        enforcement_profile: Optional[list] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Disconnect active sessions filtered by username via the native route."""
        return await self._make_request(
            "POST",
            f"session-action/disconnect/username/{username}",
            data=self._session_action_body(filter_criteria, enforcement_profile, sort),
            params=self._async_params(async_operation),
        )

    # ------------------------------------------------------------------
    # active-session/<mac> routes
    # ------------------------------------------------------------------

    async def get_active_session_by_mac_address(
        self,
        mac_address: str,
        interval: Optional[str] = None
    ) -> Dict[str, Any]:
        """List the enforcement profiles of the active session for a MAC."""
        params = {}
        if interval is not None:
            params["interval"] = interval
        return await self._make_request(
            "GET", f"active-session/{mac_address}", params=params
        )

    async def coa_active_session_by_mac_address(
        self,
        mac_address: str,
        enforcement_profile: str,
        interval: Optional[str] = None
    ) -> Dict[str, Any]:
        """Perform a Change of Authorization on the active session for a MAC."""
        params = {}
        if interval is not None:
            params["interval"] = interval
        return await self._make_request(
            "POST",
            f"active-session/{mac_address}",
            data={"enforcement_profile": enforcement_profile},
            params=params,
        )

    # Change of Authorization (CoA) Operations
    async def perform_coa_bulk(
        self,
        enforcement_profile: list,
        filter_criteria: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Perform bulk Change of Authorization (CoA) with filtering."""
        data = {
            "enforcement_profile": enforcement_profile
        }
        if filter_criteria:
            data["filter"] = filter_criteria
        if sort:
            data["sort"] = sort
        
        params = {}
        if async_operation:
            params["async"] = "true"
            
        return await self._make_request("POST", "session-action/coa", data=data, params=params)

    async def perform_coa_by_mac(
        self,
        mac_address: str,
        enforcement_profile: list,
        filter_criteria: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Perform CoA for sessions filtered by MAC address."""
        data = {
            "enforcement_profile": enforcement_profile
        }
        if filter_criteria:
            data["filter"] = filter_criteria
        if sort:
            data["sort"] = sort
        
        params = {}
        if async_operation:
            params["async"] = "true"
            
        return await self._make_request("POST", f"session-action/coa/mac/{mac_address}", data=data, params=params)

    async def perform_coa_by_username(
        self,
        username: str,
        enforcement_profile: list,
        filter_criteria: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Perform CoA for sessions filtered by username."""
        data = {
            "enforcement_profile": enforcement_profile
        }
        if filter_criteria:
            data["filter"] = filter_criteria
        if sort:
            data["sort"] = sort
        
        params = {}
        if async_operation:
            params["async"] = "true"
            
        return await self._make_request("POST", f"session-action/coa/username/{username}", data=data, params=params)

    async def perform_coa_by_ip(
        self,
        client_ip_address: str,
        enforcement_profile: list,
        filter_criteria: Optional[Dict[str, Any]] = None,
        sort: Optional[str] = None,
        async_operation: bool = False
    ) -> Dict[str, Any]:
        """Perform CoA for sessions filtered by client IP address."""
        data = {
            "enforcement_profile": enforcement_profile
        }
        if filter_criteria:
            data["filter"] = filter_criteria
        if sort:
            data["sort"] = sort
        
        params = {}
        if async_operation:
            params["async"] = "true"
            
        return await self._make_request("POST", f"session-action/coa/ip/{client_ip_address}", data=data, params=params)

    # Action Status Tracking
    async def get_session_action_status(
        self, 
        action_id: str, 
        offset: Optional[int] = None, 
        limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get the status of a session action by action ID."""
        params = {}
        if offset is not None:
            params["offset"] = offset
        if limit is not None:
            params["limit"] = limit
        return await self._make_request("GET", f"session-action/{action_id}", params=params) 