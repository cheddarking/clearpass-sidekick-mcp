"""
Custom exceptions for ClearPass Sidekick MCP Server.
"""

from typing import Dict, Optional, Any


class ClearPassAPIError(Exception):
    """Custom exception for ClearPass API errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict] = None):
        self.message = message
        self.status_code = status_code
        self.response_data = response_data
        super().__init__(self.message)