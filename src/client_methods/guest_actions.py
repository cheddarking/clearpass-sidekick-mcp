"""
Mixin class for ClearPassClient to manage guest action-related API calls.
"""

from typing import Dict, Any, Union, Optional


class GuestActionMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for guest actions.
    Includes digital pass generation, receipt generation, and credential delivery.
    """

    async def generate_guest_digital_pass(
        self,
        guest_id: Union[int, str],
        template_id: Union[int, str]
    ) -> Dict[str, Any]:
        """
        Generate digital pass for guest account based on template specified by ID.

        Args:
            guest_id: Numeric ID of the guest account
            template_id: Numeric ID of the digital pass template

        Returns:
            Dict containing the digital pass data (pkpass format)
        """
        return await self._make_request(
            "GET",
            f"guest/{guest_id}/pass/{template_id}"
        )

    async def generate_guest_receipt(
        self,
        guest_id: Union[int, str],
        template_id: Union[int, str]
    ) -> Dict[str, Any]:
        """
        Generate print template for guest account, using specified template ID.

        Args:
            guest_id: Numeric ID of the guest account
            template_id: Numeric ID of the print template

        Returns:
            Dict containing the receipt data (HTML or text)
        """
        return await self._make_request(
            "GET",
            f"guest/{guest_id}/receipt/{template_id}"
        )

    async def send_guest_receipt_sms(
        self,
        guest_id: Union[int, str],
        confirm: bool = False
    ) -> Dict[str, Any]:
        """
        Resend guest receipt for guest account, via SMS.

        Args:
            guest_id: Numeric ID of the guest account
            confirm: Flag to confirm sending guest receipt via SMS

        Returns:
            Dict containing the delivery status
        """
        data = {"confirm": confirm}
        return await self._make_request(
            "POST",
            f"guest/{guest_id}/sendreceipt/sms",
            data=data
        )

    async def send_guest_receipt_email(
        self,
        guest_id: Union[int, str],
        confirm: bool = False
    ) -> Dict[str, Any]:
        """
        Resend guest receipt for guest account, via SMTP (email).

        Args:
            guest_id: Numeric ID of the guest account
            confirm: Flag to confirm sending guest receipt via SMTP

        Returns:
            Dict containing the delivery status
        """
        data = {"confirm": confirm}
        return await self._make_request(
            "POST",
            f"guest/{guest_id}/sendreceipt/smtp",
            data=data
        )

    async def process_guest_sponsor_action(
        self,
        guest_id: Union[int, str],
        token: str,
        register_token: str,
        gsr_id: Optional[str] = None,
        register_reject: Optional[bool] = None,
        role_id: Optional[int] = None,
        modify_expire_time: Optional[str] = None,
        confirm_expire_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Accept or reject a guest sponsorship request.

        Args:
            guest_id: Numeric ID of the guest account
            token: Registration token
            register_token: Registration token
            gsr_id: Optional name of the self-registration with sponsor confirmation
            register_reject: Set to true to reject the sponsorship request
            role_id: Override the guest role
            modify_expire_time: Override the guest expiration time
            confirm_expire_time: Timestamp for new expiration; used if modify_expire_time is "expire_time"

        Returns:
            Dict containing the updated guest account data
        """
        # Build query params
        params = {}
        if gsr_id:
            params["gsr_id"] = gsr_id

        # Build request body
        data = {
            "token": token,
            "register_token": register_token
        }

        if register_reject is not None:
            data["register_reject"] = register_reject
        if role_id is not None:
            data["role_id"] = role_id
        if modify_expire_time:
            data["modify_expire_time"] = modify_expire_time
        if confirm_expire_time:
            data["confirm_expire_time"] = confirm_expire_time

        return await self._make_request(
            "POST",
            f"guest/{guest_id}/sponsor",
            params=params,
            data=data
        )
