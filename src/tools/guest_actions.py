"""
MCP tools for Guest Actions.
Provides automated credential delivery and sponsor workflows.
"""

import logging
from typing import Dict, Any, Union, Optional
from fastmcp import Context
from pydantic import Field

from ..app_config import get_clearpass_client
from ..registry import operation

from ..exceptions import ClearPassAPIError
from ..models.guest_common import find_response_error
from ..utils import format_api_error

logger = logging.getLogger(__name__)


@operation(domain="guest_actions")
async def generate_guest_digital_pass(
    ctx: Context,
    guest_id: Union[int, str] = Field(..., description="Numeric ID of the guest account"),
    template_id: Union[int, str] = Field(..., description="Numeric ID of the digital pass template")
) -> Dict[str, Any]:
    """
    Generate digital pass for guest account (Apple Wallet/Google Pay).

    Creates a mobile wallet pass (pkpass format) for the specified guest account
    using the provided pass template. The pass can contain WiFi credentials,
    QR codes, and other guest information.

    Use cases:
    - Generate Apple Wallet passes for iOS guests
    - Create Google Pay passes for Android guests
    - Enable contactless credential delivery
    """
    await ctx.info(f"Generating digital pass for guest {guest_id} using template {template_id}")

    try:
        client = await get_clearpass_client()
        response = await client.generate_guest_digital_pass(guest_id, template_id)

        # The appliance answers HTTP 200 even when no pass was produced, e.g.
        # {"message": "Pass downloads have been disabled."} for ANY guest id
        # and ANY template id. A real pass carries `digital_pass`.
        body_error = find_response_error(
            response, expected_keys=("digital_pass",), subject="digital pass request")
        if body_error:
            return {
                "success": False,
                "error": body_error,
                "message": f"No digital pass was generated for guest {guest_id}",
                "error_type": "api_response_error",
                "response": response,
                "template_id": str(template_id)
            }

        return {
            "success": True,
            "message": f"Digital pass generated successfully for guest {guest_id}",
            "pass_data": response,
            "template_id": str(template_id)
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to generate digital pass: {e}")
        return await format_api_error(e, "generate digital pass")
    except Exception as e:
        logger.error(f"Unexpected error generating digital pass: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while generating the digital pass"
        }


@operation(domain="guest_actions")
async def generate_guest_receipt(
    ctx: Context,
    guest_id: Union[int, str] = Field(..., description="Numeric ID of the guest account"),
    template_id: Union[int, str] = Field(..., description="Numeric ID of the print template")
) -> Dict[str, Any]:
    """
    Generate printable receipt for guest account.

    Creates a formatted receipt (HTML or text) containing guest credentials
    and network access information using the specified print template.

    Use cases:
    - Generate PDF receipts for printing
    - Create HTML receipts for email
    - Produce text receipts for SMS
    """
    await ctx.info(f"Generating receipt for guest {guest_id} using template {template_id}")

    try:
        client = await get_clearpass_client()
        response = await client.generate_guest_receipt(guest_id, template_id)

        # A real receipt carries `guest_receipt`; anything else on an HTTP 200
        # is an error body, not a receipt.
        body_error = find_response_error(
            response, expected_keys=("guest_receipt",), subject="receipt request")
        if body_error:
            return {
                "success": False,
                "error": body_error,
                "message": f"No receipt was generated for guest {guest_id}",
                "error_type": "api_response_error",
                "response": response,
                "template_id": str(template_id)
            }

        return {
            "success": True,
            "message": f"Receipt generated successfully for guest {guest_id}",
            "receipt_data": response,
            "template_id": str(template_id)
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to generate receipt: {e}")
        return await format_api_error(e, "generate receipt")
    except Exception as e:
        logger.error(f"Unexpected error generating receipt: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while generating the receipt"
        }


@operation(domain="guest_actions")
async def send_guest_receipt_sms(
    ctx: Context,
    guest_id: Union[int, str] = Field(..., description="Numeric ID of the guest account"),
    confirm: bool = Field(default=False, description="Confirm sending receipt via SMS (required for safety)")
) -> Dict[str, Any]:
    """
    Send guest credentials via SMS.

    Resends the guest receipt containing network credentials to the phone number
    associated with the guest account. Requires confirmation to prevent accidental sends.

    Use cases:
    - Automated credential delivery via SMS
    - Resend credentials to lost/forgotten guests
    - Self-service credential retrieval

    Note: Guest account must have a valid phone number configured.
    """
    await ctx.info(f"Sending SMS receipt to guest {guest_id}")

    if not confirm:
        return {
            "success": False,
            "error": "SMS send requires confirmation",
            "message": "Set confirm=True to send the SMS receipt. This will send credentials to the guest's phone number.",
            "warning": "SMS messages may incur costs and cannot be recalled once sent."
        }

    try:
        client = await get_clearpass_client()
        response = await client.send_guest_receipt_sms(guest_id, confirm)

        await ctx.info(f"SMS receipt sent successfully to guest {guest_id}")

        return {
            "success": True,
            "message": f"SMS receipt sent successfully to guest {guest_id}",
            "delivery_status": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to send SMS receipt: {e}")
        return await format_api_error(e, "send SMS receipt")
    except Exception as e:
        logger.error(f"Unexpected error sending SMS receipt: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while sending the SMS receipt"
        }


@operation(domain="guest_actions")
async def send_guest_receipt_email(
    ctx: Context,
    guest_id: Union[int, str] = Field(..., description="Numeric ID of the guest account"),
    confirm: bool = Field(default=False, description="Confirm sending receipt via email (required for safety)")
) -> Dict[str, Any]:
    """
    Send guest credentials via email.

    Resends the guest receipt containing network credentials to the email address
    associated with the guest account. Requires confirmation to prevent accidental sends.

    Use cases:
    - Automated credential delivery via email
    - Send formatted HTML receipts with branding
    - Provide printable credentials to guests

    Note: Guest account must have a valid email address configured.
    """
    await ctx.info(f"Sending email receipt to guest {guest_id}")

    if not confirm:
        return {
            "success": False,
            "error": "Email send requires confirmation",
            "message": "Set confirm=True to send the email receipt. This will send credentials to the guest's email address.",
            "warning": "Email messages cannot be recalled once sent."
        }

    try:
        client = await get_clearpass_client()
        response = await client.send_guest_receipt_email(guest_id, confirm)

        await ctx.info(f"Email receipt sent successfully to guest {guest_id}")

        return {
            "success": True,
            "message": f"Email receipt sent successfully to guest {guest_id}",
            "delivery_status": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to send email receipt: {e}")
        return await format_api_error(e, "send email receipt")
    except Exception as e:
        logger.error(f"Unexpected error sending email receipt: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while sending the email receipt"
        }


@operation(domain="guest_actions")
async def process_guest_sponsor_action(
    ctx: Context,
    guest_id: Union[int, str] = Field(..., description="Numeric ID of the guest account"),
    token: str = Field(..., description="Registration token"),
    register_token: str = Field(..., description="Registration token"),
    gsr_id: Optional[str] = Field(None, description="Optional name of self-registration with sponsor confirmation"),
    register_reject: Optional[bool] = Field(None, description="Set to true to reject the sponsorship request"),
    role_id: Optional[int] = Field(None, description="Override the guest role"),
    modify_expire_time: Optional[str] = Field(None, description="Override the guest expiration time"),
    confirm_expire_time: Optional[str] = Field(None, description="Timestamp for new expiration (ISO 8601)")
) -> Dict[str, Any]:
    """
    Accept or reject a guest sponsorship request.

    Processes sponsor approval/rejection for guest accounts that require sponsor
    confirmation before network access is granted. Sponsors can approve, reject,
    or modify guest account parameters (role, expiration).

    Use cases:
    - Sponsor workflow automation
    - Approve guest access requests
    - Reject unauthorized guest requests
    - Override guest role or expiration during approval

    Workflow:
    1. Guest submits self-registration request
    2. Sponsor receives notification with tokens
    3. Sponsor calls this tool to approve/reject
    4. Guest account activated or denied
    """
    action = "rejecting" if register_reject else "approving"
    await ctx.info(f"Processing sponsor action ({action}) for guest {guest_id}")

    try:
        client = await get_clearpass_client()
        response = await client.process_guest_sponsor_action(
            guest_id=guest_id,
            token=token,
            register_token=register_token,
            gsr_id=gsr_id,
            register_reject=register_reject,
            role_id=role_id,
            modify_expire_time=modify_expire_time,
            confirm_expire_time=confirm_expire_time
        )

        status = "rejected" if register_reject else "approved"

        # The appliance answers HTTP 200 with a bare {"success": true} for an
        # invalid token and changes nothing, so a 200 alone is not evidence
        # that a sponsorship was processed. The documented
        # SponsorshipApprovalResponse carries the updated account
        # (`user` / `guest_receipt`) or an explicit `_confirm_*` flag; a body
        # with none of those is unverified and must not be reported as an
        # approval. A bare `message` is deliberately not accepted as proof.
        body_error = find_response_error(
            response,
            expected_keys=("guest_receipt", "user", "_confirm_success",
                           "_confirm_reject"),
            subject="sponsor action",
        )
        if body_error:
            await ctx.info(
                f"Sponsor action for guest {guest_id} could not be confirmed")
            return {
                "success": False,
                "error": body_error,
                "message": (
                    f"The sponsor action for guest {guest_id} could not be "
                    f"confirmed. The appliance returned HTTP 200 without the "
                    f"updated guest account, which is what it does for an "
                    f"invalid or expired token. The account was NOT {status}."
                ),
                "error_type": "unverified_response",
                "action": status,
                "response": response
            }

        await ctx.info(f"Guest sponsorship {status} successfully for guest {guest_id}")

        return {
            "success": True,
            "message": f"Guest sponsorship {status} successfully for guest {guest_id}",
            "action": status,
            "guest_data": response
        }
    except ClearPassAPIError as e:
        logger.error(f"Failed to process sponsor action: {e}")
        return await format_api_error(e, "process sponsor action")
    except Exception as e:
        logger.error(f"Unexpected error processing sponsor action: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "An unexpected error occurred while processing the sponsor action"
        }
