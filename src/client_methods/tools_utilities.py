"""
Mixin class for ClearPassClient to manage Tools and Utilities API calls.

This module contains client methods for the ClearPass guest tools and utilities:
random password generation, random MPSK generation, and email/SMS delivery.
"""

from typing import Dict, Any, Optional


class ToolsUtilitiesMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for tools and utilities
    (random password, random MPSK, email and SMS sending).
    """

    # ================================
    # RANDOM PASSWORD
    # ================================

    async def get_random_password(self) -> Dict[str, Any]:
        """Generate a random password using the default password options."""
        return await self._make_request("GET", "random-password")

    async def generate_random_password(self, password_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a random password using the supplied password options."""
        return await self._make_request("POST", "random-password", data=password_options or {})

    # ================================
    # RANDOM MPSK
    # ================================

    async def get_random_mpsk(self) -> Dict[str, Any]:
        """Generate a random MPSK using the default MPSK options."""
        return await self._make_request("GET", "random-mpsk")

    async def generate_random_mpsk(self, mpsk_options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a random MPSK using the supplied MPSK options."""
        return await self._make_request("POST", "random-mpsk", data=mpsk_options or {})

    # ================================
    # EMAIL / SMS DELIVERY
    # ================================

    async def send_email(self, email_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send an email. This dispatches a real message via the ClearPass SMTP configuration."""
        return await self._make_request("POST", "email/send", data=email_data)

    async def send_sms(self, sms_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send an SMS message. This dispatches a real message via the configured SMS handler."""
        return await self._make_request("POST", "sms/send", data=sms_data)
