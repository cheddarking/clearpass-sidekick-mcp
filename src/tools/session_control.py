"""
MCP tools for Session Control operations.

Provides natural language automation for managing active network sessions,
performing disconnections, and executing Change of Authorization (CoA) operations.

Two disconnect families
-----------------------
* ``disconnect_sessions_*`` -- **composed**: ``GET session`` to find matching
  sessions, then ``POST session/<id>/disconnect`` per match. Answers
  synchronously with a per-session result summary. Portable and the default
  recommendation.
* ``session_action_disconnect*`` -- **native**: one request to the appliance's
  ``session-action/disconnect[...]`` routes, with ``enforcement_profile``
  support.

An earlier revision of this module documented the native family as unserved on
ClearPass 6.12.4 (HTTP 500 with an HTML body). That was a base-URL artefact: the
client addressed ``/api/v1``. Re-measured by direct curl on 2026-07-30 against
6.12.4, all four native routes ARE served at the unversioned ``/api`` root, which
is the only root the client uses now -- a synchronous call answers a structured
``400``, and ``async_operation=True`` answers ``200`` with an ``action_id`` whose
polled result is a real per-session outcome (the probe against a username with no
sessions reported ``"No Active Session found to disconnect."``). See the module
docstring of ``src/client_methods/session_control.py`` for the full measurement,
and ``_endpoint_url`` in ``src/clearpass_client.py`` for the base-URL evidence.

``active-session/<mac>`` is genuinely unserved on 6.12.4 -- structured ``404 Page
not found`` at both roots -- so ``*_active_session_by_mac_address`` still cannot
work here.
"""

import logging
from typing import Dict, Any, Optional, List, Union
from pydantic import Field
from fastmcp import Context

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


def _bulk_disconnect_response(summary: Dict[str, Any], **echo: Any) -> Dict[str, Any]:
    """Normalise a composed bulk-disconnect summary into the tool response.

    The client returns a per-session summary (matched / disconnected / failed)
    rather than a raw API envelope, because the bulk disconnect is composed from
    ``GET session`` + ``POST session/<id>/disconnect``. This keeps the top-level
    contract (``success`` / ``message``) intact while passing the detail through.
    """
    response: Dict[str, Any] = dict(summary or {})
    response.setdefault("success", False)
    response.setdefault("message", "Bulk disconnect returned no summary")
    for key, value in echo.items():
        response.setdefault(key, value)
    return response


# Active Session Management Tools

@operation(domain="session_control")
async def list_active_sessions(
    ctx: Context,
    filter_str: Optional[str] = Field(None, alias="filter", description="JSON filter expression (e.g., '{\"username\": \"user1\"}')."),
    sort: Optional[str] = Field(None, description="Sort ordering (e.g., '+id', '-timestamp')."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return (1-1000)."),
    calculate_count: Optional[bool] = Field(None, description="Whether to calculate the total item count.")
) -> Dict[str, Any]:
    """
    List active network sessions in ClearPass.
    
    This tool retrieves information about currently active sessions including
    usernames, MAC addresses, IP addresses, and session states.
    
    Examples:
    - "Show me all active sessions"
    - "List sessions for user 'jdoe'"
    - "Show active sessions from MAC address 'aa:bb:cc:dd:ee:ff'"
    """
    try:
        client = await get_clearpass_client()
        result = await client.list_active_sessions(
            filter_str=filter_str,
            sort=sort,
            offset=offset,
            limit=limit,
            calculate_count=calculate_count
        )

        # Enhanced response formatting
        if result.get("_embedded", {}).get("items"):
            sessions = result["_embedded"]["items"]
            session_count = len(sessions)
            total_count = result.get("count", session_count)

            summary = {
                "success": True,
                "message": f"Retrieved {session_count} active sessions",
                "total_count": total_count,
                "sessions": sessions
            }

            if session_count > 0:
                summary["sample_session"] = {
                    "username": sessions[0].get("username", "N/A"),
                    "mac_address": sessions[0].get("mac_address", "N/A"),
                    "client_ip_address": sessions[0].get("client_ip_address", "N/A"),
                    "state": sessions[0].get("state", "N/A")
                }

            return summary
        else:
            return {
                "success": True,
                "message": "No active sessions found",
                "total_count": 0,
                "sessions": []
            }

    except Exception as e:
        error_msg = f"Failed to list active sessions: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def get_active_session_details(
    ctx: Context,
    session_id: str = Field(..., description="ID of the active session to retrieve.")
) -> Dict[str, Any]:
    """
    Get detailed information about a specific active session.
    
    This tool retrieves comprehensive details about a single active session
    including all session attributes and enforcement profiles.
    
    Examples:
    - "Get details for session ID '12345'"
    - "Show me information about session abc-def-ghi"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_active_session_by_id(session_id)

        return {
            "success": True,
            "message": f"Successfully retrieved session details for ID: {session_id}",
            "session": result
        }

    except Exception as e:
        error_msg = f"Failed to get session details for ID {session_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# Session Disconnect Tools

@operation(domain="session_control")
async def disconnect_session(
    ctx: Context,
    session_id: str = Field(..., description="ID of the session to disconnect."),
    confirm: bool = Field(default=False, description="Confirm disconnection (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect a specific active session.
    
    This tool terminates an active network session by its ID.
    Requires confirmation for safety.
    
    Examples:
    - "Disconnect session ID '12345' with confirm=true"
    - "Terminate session abc-def-ghi"
    """
    if not confirm:
        return {
            "success": False,
            "message": "Session disconnection requires confirmation. Set confirm=true to proceed.",
            "session_id": session_id
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.disconnect_session_by_id(session_id, confirm_disconnect=True)

        return {
            "success": True,
            "message": f"Successfully initiated disconnection for session ID: {session_id}",
            "result": result
        }

    except Exception as e:
        error_msg = f"Failed to disconnect session {session_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def disconnect_sessions_bulk(
    ctx: Context,
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="JSON filter criteria for sessions to disconnect."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply during disconnect."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm bulk disconnection (required for safety).")
) -> Dict[str, Any]:
    """
    Perform bulk disconnection of sessions with filtering.

    This tool allows disconnecting multiple sessions based on filter criteria.
    Use with caution as it can affect many users simultaneously.
    With no filter_criteria it targets EVERY active session.

    It finds the matching sessions and disconnects each one individually,
    returning a per-session summary (matched / disconnected / failed).

    Examples:
    - "Disconnect all sessions with username starting with 'temp_'"
    - "Bulk disconnect sessions from VLAN 100"
    """
    if not confirm:
        return {
            "success": False,
            "message": "Bulk session disconnection requires confirmation. Set confirm=true to proceed.",
            "warning": "This operation can affect multiple users simultaneously."
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.disconnect_sessions_bulk(
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return _bulk_disconnect_response(result)

    except Exception as e:
        error_msg = f"Failed to perform bulk session disconnect: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def disconnect_sessions_by_username(
    ctx: Context,
    username: str = Field(..., description="Username to filter sessions for disconnection."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter criteria."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm disconnection (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect all sessions for a specific username.
    
    This tool disconnects all active sessions associated with a particular user.
    
    Examples:
    - "Disconnect all sessions for user 'jdoe'"
    - "Terminate sessions for username 'temp_user01'"
    """
    if not confirm:
        return {
            "success": False,
            "message": f"Session disconnection for username '{username}' requires confirmation. Set confirm=true to proceed.",
            "username": username
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.disconnect_sessions_by_username(
            username=username,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return _bulk_disconnect_response(result, username=username)

    except Exception as e:
        error_msg = f"Failed to disconnect sessions for username {username}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def disconnect_sessions_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address to filter sessions for disconnection."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter criteria."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm disconnection (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect all sessions for a specific MAC address.
    
    This tool disconnects all active sessions associated with a particular MAC address.
    
    Examples:
    - "Disconnect sessions for MAC 'aa:bb:cc:dd:ee:ff'"
    - "Terminate sessions for device with MAC '00-11-22-33-44-55'"
    """
    if not confirm:
        return {
            "success": False,
            "message": f"Session disconnection for MAC '{mac_address}' requires confirmation. Set confirm=true to proceed.",
            "mac_address": mac_address
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.disconnect_sessions_by_mac(
            mac_address=mac_address,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return _bulk_disconnect_response(result, mac_address=mac_address)

    except Exception as e:
        error_msg = f"Failed to disconnect sessions for MAC {mac_address}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def disconnect_sessions_by_ip(
    ctx: Context,
    client_ip_address: str = Field(..., description="Client IP address to filter sessions for disconnection."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter criteria."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm disconnection (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect all sessions for a specific client IP address.
    
    This tool disconnects all active sessions associated with a particular client IP.
    
    Examples:
    - "Disconnect sessions for IP '192.168.1.100'"
    - "Terminate sessions from client IP '10.0.0.50'"
    """
    if not confirm:
        return {
            "success": False,
            "message": f"Session disconnection for IP '{client_ip_address}' requires confirmation. Set confirm=true to proceed.",
            "client_ip_address": client_ip_address
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.disconnect_sessions_by_ip(
            client_ip_address=client_ip_address,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return _bulk_disconnect_response(result, client_ip_address=client_ip_address)

    except Exception as e:
        error_msg = f"Failed to disconnect sessions for IP {client_ip_address}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# Native session-action/disconnect Tools
#
# These drive the ClearPass `session-action/disconnect[...]` route family
# directly (one request, `enforcement_profile` supported) instead of the
# composed scan-and-disconnect path used by the `disconnect_sessions_*` tools
# above.
#
# ClearPass 6.12.4 serves this family at the unversioned `/api` root (the only
# root the client uses). A *synchronous* call answers a structured 400, so pass
# `async_operation=True` and poll `get_session_action_status` with the returned
# `action_id` for the real outcome. Prefer the composed `disconnect_sessions_*`
# tools when a synchronous, self-contained answer is wanted. (The historical
# "HTTP 500, route not served" note was an `/api/v1` mount artefact -- see the
# module docstring.)


@operation(domain="session_control")
async def session_action_disconnect(
    ctx: Context,
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="JSON filter expression selecting the sessions to disconnect (e.g., {\"username\": \"admin\"})."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply when performing CoA as part of the disconnect."),
    sort: Optional[str] = Field(None, description="Sort ordering for the matched session set (e.g., '-id')."),
    async_operation: bool = Field(default=False, description="Trigger the disconnect asynchronously and return an action ID to poll."),
    confirm: bool = Field(default=False, description="Confirm the disconnect (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect active sessions using the native bulk disconnect endpoint.

    Performs a synchronous or asynchronous session disconnect, filtering by any
    combination of fields. With no filter_criteria this targets EVERY active
    session.

    Maps to 'new_session_action_disconnect' in pyclearpass (POST /session-action/disconnect).
    """
    if not confirm:
        return {
            "success": False,
            "message": "Bulk session disconnection requires confirmation. Set confirm=true to proceed.",
            "warning": "This operation can affect multiple users simultaneously."
        }

    await ctx.info("Performing native bulk session disconnect...")
    try:
        client = await get_clearpass_client()
        response = await client.session_action_disconnect(
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return {
            "success": True,
            "async_operation": async_operation,
            "result": response,
            "message": "Successfully initiated native bulk session disconnect"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to perform native bulk session disconnect: {e}")
        return await format_api_error(e, "session action disconnect")
    except Exception as e:
        logger.error(f"Unexpected error performing native bulk session disconnect: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="session_control")
async def session_action_disconnect_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address whose active sessions should be disconnected."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter expression narrowing the matched sessions."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply when performing CoA as part of the disconnect."),
    sort: Optional[str] = Field(None, description="Sort ordering for the matched session set (e.g., '-id')."),
    async_operation: bool = Field(default=False, description="Trigger the disconnect asynchronously and return an action ID to poll."),
    confirm: bool = Field(default=False, description="Confirm the disconnect (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect active sessions for a MAC address using the native endpoint.

    Maps to 'new_session_action_disconnect_mac_by_mac_address' in pyclearpass (POST /session-action/disconnect/mac/{mac_address}).
    """
    if not confirm:
        return {
            "success": False,
            "message": f"Session disconnection for MAC '{mac_address}' requires confirmation. Set confirm=true to proceed.",
            "mac_address": mac_address
        }

    await ctx.info(f"Performing native session disconnect for MAC: {mac_address}")
    try:
        client = await get_clearpass_client()
        response = await client.session_action_disconnect_by_mac(
            mac_address=mac_address,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return {
            "success": True,
            "mac_address": mac_address,
            "async_operation": async_operation,
            "result": response,
            "message": f"Successfully initiated native session disconnect for MAC: {mac_address}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to disconnect sessions for MAC {mac_address}: {e}")
        return await format_api_error(e, f"session action disconnect for MAC {mac_address}")
    except Exception as e:
        logger.error(f"Unexpected error disconnecting sessions for MAC {mac_address}: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="session_control")
async def session_action_disconnect_by_ip(
    ctx: Context,
    client_ip_address: str = Field(..., description="Client IP address whose active sessions should be disconnected."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter expression narrowing the matched sessions."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply when performing CoA as part of the disconnect."),
    sort: Optional[str] = Field(None, description="Sort ordering for the matched session set (e.g., '-id')."),
    async_operation: bool = Field(default=False, description="Trigger the disconnect asynchronously and return an action ID to poll."),
    confirm: bool = Field(default=False, description="Confirm the disconnect (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect active sessions for a client IP using the native endpoint.

    Maps to 'new_session_action_disconnect_ip_by_client_ip_address' in pyclearpass (POST /session-action/disconnect/ip/{client_ip_address}).
    """
    if not confirm:
        return {
            "success": False,
            "message": f"Session disconnection for IP '{client_ip_address}' requires confirmation. Set confirm=true to proceed.",
            "client_ip_address": client_ip_address
        }

    await ctx.info(f"Performing native session disconnect for IP: {client_ip_address}")
    try:
        client = await get_clearpass_client()
        response = await client.session_action_disconnect_by_ip(
            client_ip_address=client_ip_address,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return {
            "success": True,
            "client_ip_address": client_ip_address,
            "async_operation": async_operation,
            "result": response,
            "message": f"Successfully initiated native session disconnect for IP: {client_ip_address}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to disconnect sessions for IP {client_ip_address}: {e}")
        return await format_api_error(e, f"session action disconnect for IP {client_ip_address}")
    except Exception as e:
        logger.error(f"Unexpected error disconnecting sessions for IP {client_ip_address}: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="session_control")
async def session_action_disconnect_by_username(
    ctx: Context,
    username: str = Field(..., description="Username whose active sessions should be disconnected."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter expression narrowing the matched sessions."),
    enforcement_profile: Optional[List[str]] = Field(None, description="Enforcement profiles to apply when performing CoA as part of the disconnect."),
    sort: Optional[str] = Field(None, description="Sort ordering for the matched session set (e.g., '-id')."),
    async_operation: bool = Field(default=False, description="Trigger the disconnect asynchronously and return an action ID to poll."),
    confirm: bool = Field(default=False, description="Confirm the disconnect (required for safety).")
) -> Dict[str, Any]:
    """
    Disconnect active sessions for a username using the native endpoint.

    Maps to 'new_session_action_disconnect_username_by_username' in pyclearpass (POST /session-action/disconnect/username/{username}).
    """
    if not confirm:
        return {
            "success": False,
            "message": f"Session disconnection for username '{username}' requires confirmation. Set confirm=true to proceed.",
            "username": username
        }

    await ctx.info(f"Performing native session disconnect for username: {username}")
    try:
        client = await get_clearpass_client()
        response = await client.session_action_disconnect_by_username(
            username=username,
            filter_criteria=filter_criteria,
            enforcement_profile=enforcement_profile,
            sort=sort,
            async_operation=async_operation
        )

        return {
            "success": True,
            "username": username,
            "async_operation": async_operation,
            "result": response,
            "message": f"Successfully initiated native session disconnect for username: {username}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to disconnect sessions for username {username}: {e}")
        return await format_api_error(e, f"session action disconnect for username {username}")
    except Exception as e:
        logger.error(f"Unexpected error disconnecting sessions for username {username}: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# Active-Session-by-MAC Tools


@operation(domain="session_control")
async def get_active_session_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address to look up the active session for."),
    interval: Optional[str] = Field(None, description="Interval over which to look for the active session.")
) -> Dict[str, Any]:
    """
    Get the enforcement profiles of the active session for a MAC address.

    Returns the enforcement profiles currently applied to the active session
    belonging to the given MAC address, which is what a subsequent Change of
    Authorization on that session would replace.

    Maps to 'get_active_session_by_mac_address' in pyclearpass (GET /active-session/{mac_address}).
    """
    await ctx.info(f"Retrieving active session for MAC: {mac_address}")
    try:
        client = await get_clearpass_client()
        response = await client.get_active_session_by_mac_address(
            mac_address=mac_address,
            interval=interval
        )

        return {
            "success": True,
            "mac_address": mac_address,
            "interval": interval,
            "active_session": response,
            "message": f"Retrieved active session details for MAC: {mac_address}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get active session for MAC {mac_address}: {e}")
        return await format_api_error(e, f"get active session by MAC {mac_address}")
    except Exception as e:
        logger.error(f"Unexpected error getting active session for MAC {mac_address}: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="session_control")
async def coa_active_session_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address whose active session should be reauthorized."),
    enforcement_profile: str = Field(..., description="Name of the enforcement profile to apply during the Change of Authorization."),
    interval: Optional[str] = Field(None, description="Interval over which to look for the active session."),
    confirm: bool = Field(default=False, description="Confirm the Change of Authorization (required for safety).")
) -> Dict[str, Any]:
    """
    Perform a Change of Authorization on the active session for a MAC address.

    Applies an enforcement profile to the active session belonging to the given
    MAC address, changing its authorization state in place.

    Maps to 'new_active_session_by_mac_address' in pyclearpass (POST /active-session/{mac_address}).
    """
    if not confirm:
        return {
            "success": False,
            "message": f"CoA on the active session for MAC '{mac_address}' requires confirmation. Set confirm=true to proceed.",
            "mac_address": mac_address
        }

    await ctx.info(f"Performing CoA on the active session for MAC: {mac_address}")
    try:
        client = await get_clearpass_client()
        response = await client.coa_active_session_by_mac_address(
            mac_address=mac_address,
            enforcement_profile=enforcement_profile,
            interval=interval
        )

        return {
            "success": True,
            "mac_address": mac_address,
            "enforcement_profile": enforcement_profile,
            "result": response,
            "message": f"Successfully initiated CoA on the active session for MAC: {mac_address}"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to perform CoA for MAC {mac_address}: {e}")
        return await format_api_error(e, f"CoA active session by MAC {mac_address}")
    except Exception as e:
        logger.error(f"Unexpected error performing CoA for MAC {mac_address}: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# Session Reauthorization Tools

@operation(domain="session_control")
async def get_session_reauthorization_profiles(
    ctx: Context,
    session_id: str = Field(..., description="ID of the session to get reauthorization profiles for."),
    template_type: Optional[str] = Field(None, description="Reauthorization profile type filter (Disconnect/CoA).")
) -> Dict[str, Any]:
    """
    Get available reauthorization profiles for a session.
    
    This tool retrieves the available reauthorization profiles that can be
    applied to a specific session for Change of Authorization operations.
    
    Examples:
    - "Get reauth profiles for session '12345'"
    - "Show available CoA profiles for session abc-def-ghi"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_session_reauthorization_profiles(
            session_id=session_id,
            template_type=template_type
        )
        
        return {
            "success": True,
            "message": f"Successfully retrieved reauthorization profiles for session: {session_id}",
            "session_id": session_id,
            "template_type": template_type,
            "profiles": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get reauthorization profiles for session {session_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def reauthorize_session(
    ctx: Context,
    session_id: str = Field(..., description="ID of the session to reauthorize."),
    reauthorize_profile: Optional[str] = Field(None, description="Name of the reauthorization profile to apply."),
    confirm: bool = Field(default=False, description="Confirm reauthorization (required for safety).")
) -> Dict[str, Any]:
    """
    Reauthorize a specific active session.
    
    This tool performs a Change of Authorization (CoA) operation on a session,
    optionally applying a specific reauthorization profile.
    
    Examples:
    - "Reauthorize session '12345' with profile 'RestrictedAccess'"
    - "Perform CoA on session abc-def-ghi"
    """
    if not confirm:
        return {
            "success": False,
            "message": "Session reauthorization requires confirmation. Set confirm=true to proceed.",
            "session_id": session_id
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.reauthorize_session_by_id(
            session_id=session_id,
            reauthorize_profile=reauthorize_profile,
            confirm_reauthorize=True
        )
        
        return {
            "success": True,
            "message": f"Successfully initiated reauthorization for session: {session_id}",
            "session_id": session_id,
            "reauthorize_profile": reauthorize_profile,
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to reauthorize session {session_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# Change of Authorization (CoA) Tools

@operation(domain="session_control")
async def perform_coa_bulk(
    ctx: Context,
    enforcement_profile: List[str] = Field(..., description="List of enforcement profiles to apply during CoA."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="JSON filter criteria for sessions to affect."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm CoA operation (required for safety).")
) -> Dict[str, Any]:
    """
    Perform bulk Change of Authorization (CoA) with filtering.
    
    This tool applies enforcement profiles to multiple sessions based on
    filter criteria, changing their authorization state.
    
    Examples:
    - "Apply CoA with 'RestrictedAccess' profile to all guest sessions"
    - "Perform bulk CoA with 'FullAccess' for sessions in Building A"
    """
    if not confirm:
        return {
            "success": False,
            "message": "Bulk CoA operation requires confirmation. Set confirm=true to proceed.",
            "warning": "This operation can affect multiple users simultaneously."
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.perform_coa_bulk(
            enforcement_profile=enforcement_profile,
            filter_criteria=filter_criteria,
            sort=sort,
            async_operation=async_operation
        )
        
        return {
            "success": True,
            "message": "Successfully initiated bulk CoA operation",
            "enforcement_profile": enforcement_profile,
            "async_operation": async_operation,
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to perform bulk CoA: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def perform_coa_by_username(
    ctx: Context,
    username: str = Field(..., description="Username to filter sessions for CoA."),
    enforcement_profile: List[str] = Field(..., description="List of enforcement profiles to apply."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter criteria."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm CoA operation (required for safety).")
) -> Dict[str, Any]:
    """
    Perform Change of Authorization for sessions by username.
    
    This tool applies enforcement profiles to all sessions associated with
    a specific username.
    
    Examples:
    - "Apply CoA with 'LimitedAccess' to user 'jdoe'"
    - "Change authorization for username 'guest01' to 'InternetOnly'"
    """
    if not confirm:
        return {
            "success": False,
            "message": f"CoA operation for username '{username}' requires confirmation. Set confirm=true to proceed.",
            "username": username
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.perform_coa_by_username(
            username=username,
            enforcement_profile=enforcement_profile,
            filter_criteria=filter_criteria,
            sort=sort,
            async_operation=async_operation
        )
        
        return {
            "success": True,
            "message": f"Successfully initiated CoA for username: {username}",
            "username": username,
            "enforcement_profile": enforcement_profile,
            "async_operation": async_operation,
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to perform CoA for username {username}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def perform_coa_by_mac(
    ctx: Context,
    mac_address: str = Field(..., description="MAC address to filter sessions for CoA."),
    enforcement_profile: List[str] = Field(..., description="List of enforcement profiles to apply."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter criteria."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm CoA operation (required for safety).")
) -> Dict[str, Any]:
    """
    Perform Change of Authorization for sessions by MAC address.
    
    This tool applies enforcement profiles to all sessions associated with
    a specific MAC address.
    
    Examples:
    - "Apply CoA with 'DeviceRestricted' to MAC 'aa:bb:cc:dd:ee:ff'"
    - "Change authorization for device '00-11-22-33-44-55' to 'Quarantine'"
    """
    if not confirm:
        return {
            "success": False,
            "message": f"CoA operation for MAC '{mac_address}' requires confirmation. Set confirm=true to proceed.",
            "mac_address": mac_address
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.perform_coa_by_mac(
            mac_address=mac_address,
            enforcement_profile=enforcement_profile,
            filter_criteria=filter_criteria,
            sort=sort,
            async_operation=async_operation
        )
        
        return {
            "success": True,
            "message": f"Successfully initiated CoA for MAC: {mac_address}",
            "mac_address": mac_address,
            "enforcement_profile": enforcement_profile,
            "async_operation": async_operation,
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to perform CoA for MAC {mac_address}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


@operation(domain="session_control")
async def perform_coa_by_ip(
    ctx: Context,
    client_ip_address: str = Field(..., description="Client IP address to filter sessions for CoA."),
    enforcement_profile: List[str] = Field(..., description="List of enforcement profiles to apply."),
    filter_criteria: Optional[Dict[str, Any]] = Field(None, description="Additional JSON filter criteria."),
    sort: Optional[str] = Field(None, description="Sort ordering for session selection."),
    async_operation: bool = Field(default=False, description="Perform operation asynchronously."),
    confirm: bool = Field(default=False, description="Confirm CoA operation (required for safety).")
) -> Dict[str, Any]:
    """
    Perform Change of Authorization for sessions by client IP address.
    
    This tool applies enforcement profiles to all sessions associated with
    a specific client IP address.
    
    Examples:
    - "Apply CoA with 'Restricted' to IP '192.168.1.100'"
    - "Change authorization for client '10.0.0.50' to 'BlockedAccess'"
    """
    if not confirm:
        return {
            "success": False,
            "message": f"CoA operation for IP '{client_ip_address}' requires confirmation. Set confirm=true to proceed.",
            "client_ip_address": client_ip_address
        }
    
    try:
        client = await get_clearpass_client()
        result = await client.perform_coa_by_ip(
            client_ip_address=client_ip_address,
            enforcement_profile=enforcement_profile,
            filter_criteria=filter_criteria,
            sort=sort,
            async_operation=async_operation
        )
        
        return {
            "success": True,
            "message": f"Successfully initiated CoA for IP: {client_ip_address}",
            "client_ip_address": client_ip_address,
            "enforcement_profile": enforcement_profile,
            "async_operation": async_operation,
            "result": result
        }
                
    except Exception as e:
        error_msg = f"Failed to perform CoA for IP {client_ip_address}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        }


# Action Status Tracking Tools

@operation(domain="session_control")
async def get_session_action_status(
    ctx: Context,
    action_id: str = Field(..., description="Action ID to check status for."),
    offset: Optional[int] = Field(None, description="Zero-based offset for pagination."),
    limit: Optional[int] = Field(default=25, description="Maximum number of items to return.")
) -> Dict[str, Any]:
    """
    Get the status of a session action operation.
    
    This tool checks the current status of a disconnect or CoA operation
    that was initiated asynchronously.
    
    Examples:
    - "Check status of action ID 'abc-123-def'"
    - "Get results for session action 'xyz-789-mno'"
    """
    try:
        client = await get_clearpass_client()
        result = await client.get_session_action_status(
            action_id=action_id,
            offset=offset,
            limit=limit
        )
        
        return {
            "success": True,
            "message": f"Successfully retrieved status for action: {action_id}",
            "action_id": action_id,
            "status": result
        }
                
    except Exception as e:
        error_msg = f"Failed to get status for action {action_id}: {str(e)}"
        logger.error(error_msg)
        return {
            "success": False,
            "message": error_msg,
            "error": str(e)
        } 