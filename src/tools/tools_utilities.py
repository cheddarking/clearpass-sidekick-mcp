"""
MCP tools for ClearPass Tools and Utilities operations.

Provides natural language automation for the ClearPass guest tools and utilities:
generating random passwords and random MPSKs, and sending email and SMS messages.
"""

import logging
from typing import Dict, Any, Optional

from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..utils import format_api_error

logger = logging.getLogger(__name__)


# ================================
# RANDOM PASSWORD
# ================================

@operation(domain="tools_utilities")
async def get_random_password(
    ctx: Context
) -> Dict[str, Any]:
    """
    Generate a random password using the ClearPass default password options.

    Use this when you need a password without specifying a method or length.

    Maps to 'get_random_password' in pyclearpass (GET /random-password).
    """
    await ctx.info("Generating a random password with default options...")
    try:
        client = await get_clearpass_client()
        response = await client.get_random_password()

        return {
            "success": True,
            "random_password": response,
            "message": "Random password generated successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to generate random password: {e}")
        return await format_api_error(e, "get random password")
    except Exception as e:
        logger.error(f"Unexpected error generating random password: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="tools_utilities")
async def generate_random_password(
    ctx: Context,
    password_options: Optional[Dict[str, Any]] = Field(None, description=(
        "Password generation options: 'random_password_method' (see ClearPass documentation for "
        "allowed values), 'random_password_length' (desired length), and 'random_password_picture' "
        "(picture used for the 'nwa_picture_password' method)."
    ))
) -> Dict[str, Any]:
    """
    Generate a random password using specific password options.

    Use this when the password must follow a particular method (for example a
    picture-password pattern) or a specific length.

    Maps to 'new_random_password' in pyclearpass (POST /random-password).
    """
    await ctx.info("Generating a random password with the supplied options...")
    try:
        client = await get_clearpass_client()
        response = await client.generate_random_password(password_options)

        return {
            "success": True,
            "random_password": response,
            "message": "Random password generated successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to generate random password: {e}")
        return await format_api_error(e, "generate random password")
    except Exception as e:
        logger.error(f"Unexpected error generating random password: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ================================
# RANDOM MPSK
# ================================

@operation(domain="tools_utilities")
async def get_random_mpsk(
    ctx: Context
) -> Dict[str, Any]:
    """
    Generate a random MPSK (Multi Pre-Shared Key) using the ClearPass default options.

    Maps to 'get_random_mpsk' in pyclearpass (GET /random-mpsk).
    """
    await ctx.info("Generating a random MPSK with default options...")
    try:
        client = await get_clearpass_client()
        response = await client.get_random_mpsk()

        return {
            "success": True,
            "random_mpsk": response,
            "message": "Random MPSK generated successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to generate random MPSK: {e}")
        return await format_api_error(e, "get random mpsk")
    except Exception as e:
        logger.error(f"Unexpected error generating random MPSK: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="tools_utilities")
async def generate_random_mpsk(
    ctx: Context,
    mpsk_options: Optional[Dict[str, Any]] = Field(None, description=(
        "MPSK generation options: 'random_mpsk_method' (see ClearPass documentation for allowed "
        "values), 'random_mpsk_length' (desired length), and 'random_mpsk_picture' (picture used "
        "for the 'nwa_picture_password' method)."
    ))
) -> Dict[str, Any]:
    """
    Generate a random MPSK (Multi Pre-Shared Key) using specific options.

    Maps to 'new_random_mpsk' in pyclearpass (POST /random-mpsk).
    """
    await ctx.info("Generating a random MPSK with the supplied options...")
    try:
        client = await get_clearpass_client()
        response = await client.generate_random_mpsk(mpsk_options)

        return {
            "success": True,
            "random_mpsk": response,
            "message": "Random MPSK generated successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to generate random MPSK: {e}")
        return await format_api_error(e, "generate random mpsk")
    except Exception as e:
        logger.error(f"Unexpected error generating random MPSK: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


# ================================
# EMAIL / SMS DELIVERY
# ================================

@operation(domain="tools_utilities")
async def send_email(
    ctx: Context,
    email_data: Dict[str, Any] = Field(..., description=(
        "Email payload. Required: 'to' (list of recipient email addresses) and 'message' (email body). "
        "Optional: 'subject', 'cc_recipients', 'bcc_recipients', 'headers'."
    ))
) -> Dict[str, Any]:
    """
    Send an email through the ClearPass SMTP configuration.

    Sends a real email — never invoke against production recipients in testing.

    Maps to 'new_email_send' in pyclearpass (POST /email/send).
    """
    await ctx.info("Sending email via ClearPass...")
    try:
        client = await get_clearpass_client()
        response = await client.send_email(email_data)

        return {
            "success": True,
            "result": response,
            "message": "Email sent successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to send email: {e}")
        return await format_api_error(e, "send email")
    except Exception as e:
        logger.error(f"Unexpected error sending email: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}


@operation(domain="tools_utilities")
async def send_sms(
    ctx: Context,
    sms_data: Dict[str, Any] = Field(..., description=(
        "SMS payload. Required: 'recipient' (mobile telephone number in international format) and "
        "'message' (maximum 160 characters). Optional: 'handler' (SMS service to use) and 'carrier'."
    ))
) -> Dict[str, Any]:
    """
    Send an SMS message through the configured ClearPass SMS handler.

    Sends a real SMS — never invoke against production recipients in testing.

    Maps to 'new_sms_send' in pyclearpass (POST /sms/send).
    """
    await ctx.info("Sending SMS via ClearPass...")
    try:
        client = await get_clearpass_client()
        response = await client.send_sms(sms_data)

        return {
            "success": True,
            "result": response,
            "message": "SMS sent successfully"
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to send SMS: {e}")
        return await format_api_error(e, "send sms")
    except Exception as e:
        logger.error(f"Unexpected error sending SMS: {e}")
        return {"success": False, "error": str(e), "message": "An unexpected error occurred."}
