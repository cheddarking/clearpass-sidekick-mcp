"""
Mixin class for ClearPassClient to manage API client-related API calls.
"""

import json
from typing import Dict, Any, Optional, Union

class ApiClientMethodsMixin:
    """
    Mixin class for ClearPassClient providing methods for API client management.
    """

    async def list_api_clients(self, filter_enabled: Optional[bool] = None, limit: int = 50) -> Dict[str, Any]:
        """List API clients.

        The ClearPass 6.12.4 ``api-client`` endpoint requires ``filter`` to be a
        JSON object (``{"enabled": true}``). An RSQL-style string such as
        ``"enabled eq true"`` is rejected with
        ``422 Filter must specify a JSON object``.
        """
        params = {"limit": limit}
        if filter_enabled is not None:
            params["filter"] = json.dumps({"enabled": bool(filter_enabled)})

        return await self._make_request("GET", "api-client", params=params)
    
    async def get_api_client(self, client_id: Union[int, str]) -> Dict[str, Any]:
        """Get a specific API client."""
        return await self._make_request("GET", f"api-client/{client_id}")
    
    async def create_api_client(self, client_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new API client."""
        return await self._make_request("POST", "api-client", data=client_data)
    
    async def update_api_client(self, client_id: Union[int, str], client_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing API client."""
        return await self._make_request("PATCH", f"api-client/{client_id}", data=client_data)
    
    async def delete_api_client(self, client_id: Union[int, str]) -> Dict[str, Any]:
        """Delete an API client."""
        return await self._make_request("DELETE", f"api-client/{client_id}")