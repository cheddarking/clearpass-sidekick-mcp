"""
MCP tools for ClearPass API Operations (OAuth2).

Provides natural language automation for the ClearPass OAuth2 surface: inspecting the
authenticated API client or user, listing the privileges granted to that identity, and
requesting an access token directly for API-parity/diagnostic purposes.
"""

import logging
from typing import Dict, Any

from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


# ================================
# OAUTH2 IDENTITY
# ================================

@operation(domain="api_operations")
async def get_oauth_me(
    ctx: Context
) -> Dict[str, Any]:
    """
    Get information about the OAuth2 authenticated client or user.

    Useful for confirming which API client or operator identity the server is currently
    acting as before running privileged operations.

    Maps to 'get_oauth_me' in pyclearpass (GET /oauth/me).
    """
    await ctx.info("Retrieving OAuth2 identity information...")
    try:
        client = await get_clearpass_client()
        response = await client.get_oauth_me()

        return {
            "success": True,
            "identity": response,
            "message": "OAuth2 identity information retrieved successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get OAuth identity: {e}")
        return await format_api_error(e, "get oauth identity")
    except Exception as e:
        logger.error(f"Unexpected error getting OAuth identity: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="api_operations")
async def post_oauth_me_info(
    ctx: Context,
    me_data: Dict[str, Any] = Field(..., description=(
        "Identity request payload. Required: 'info' (defaults to the operator profile name) and "
        "'name' (defaults to the authenticated username). Additional properties may be returned "
        "for grant_type 'password' when defined in the OAuth API enforcement profile."
    ))
) -> Dict[str, Any]:
    """
    Get OAuth2 authenticated client or user information using a request body.

    This is the POST form of the identity endpoint; it accepts a body so additional
    identity properties defined in the OAuth API enforcement profile can be requested.

    Maps to 'new_oauth_me' in pyclearpass (POST /oauth/me).
    """
    await ctx.info("Retrieving OAuth2 identity information with request body...")
    try:
        client = await get_clearpass_client()
        response = await client.post_oauth_me_info(me_data)

        return {
            "success": True,
            "identity": response,
            "message": "OAuth2 identity information retrieved successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to post OAuth identity request: {e}")
        return await format_api_error(e, "post oauth identity")
    except Exception as e:
        logger.error(f"Unexpected error posting OAuth identity request: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="api_operations")
async def get_oauth_privileges(
    ctx: Context
) -> Dict[str, Any]:
    """
    List the privileges available to the authenticated OAuth2 user.

    Use this to check whether the current credentials are permitted to perform an
    operation before attempting it.

    Maps to 'get_oauth_privileges' in pyclearpass (GET /oauth/privileges).
    """
    await ctx.info("Retrieving OAuth2 privileges for the authenticated identity...")
    try:
        client = await get_clearpass_client()
        response = await client.get_oauth_privileges()

        return {
            "success": True,
            "privileges": response,
            "message": "OAuth2 privileges retrieved successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to get OAuth privileges: {e}")
        return await format_api_error(e, "get oauth privileges")
    except Exception as e:
        logger.error(f"Unexpected error getting OAuth privileges: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ================================
# OAUTH2 TOKEN
# ================================

@operation(domain="api_operations")
async def request_oauth_token(
    ctx: Context,
    token_request: Dict[str, Any] = Field(..., description=(
        "Token request payload. Required: 'grant_type' (OAuth2 authentication method) and "
        "'client_id'. Optional depending on grant type: 'client_secret', 'username', 'password', "
        "'scope', 'refresh_token'."
    ))
) -> Dict[str, Any]:
    """
    Obtain an OAuth2 access token for making ClearPass API calls.

    The server already authenticates automatically, so this is not required for normal
    use; it exists for API parity and diagnostics (for example verifying that a given
    client ID/secret or grant type works).

    Maps to 'new_oauth' in pyclearpass (POST /oauth).
    """
    await ctx.info("Requesting an OAuth2 access token (diagnostic)...")
    try:
        client = await get_clearpass_client()
        response = await client.request_oauth_token(token_request)

        return {
            "success": True,
            "token_response": response,
            "message": "OAuth2 token request completed"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to request OAuth token: {e}")
        return await format_api_error(e, "request oauth token")
    except Exception as e:
        logger.error(f"Unexpected error requesting OAuth token: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}
