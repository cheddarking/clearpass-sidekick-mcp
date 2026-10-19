"""
Application configuration and shared instances for ClearPass Sidekick MCP Server.
"""

import os
import logging
from typing import Optional
from fastmcp import FastMCP

from .credentials import CredentialsManager, CredentialsError
from .clearpass_client import ClearPassClient
from .exceptions import ClearPassAPIError

# Configure logger
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("ClearPass Sidekick")

# Initialize credentials manager
credentials_manager = CredentialsManager()

# Load ClearPass configuration using credentials manager
try:
    clearpass_credentials = credentials_manager.load_credentials()
    CLEARPASS_CONFIG = {
        "host": clearpass_credentials.get("server", "").replace("/api", ""),  # Remove /api suffix if present
        "server": clearpass_credentials.get("server", ""),
        "client_id": clearpass_credentials.get("client_id", ""),
        "client_secret": clearpass_credentials.get("client_secret", ""),
        "api_token": clearpass_credentials.get("api_token", ""),
        "api_version": "v1",  # Default API version
        "verify_ssl": clearpass_credentials.get("verify_ssl", True)
    }
    logger.info("ClearPass credentials loaded successfully")
except CredentialsError as e:
    logger.warning(f"Failed to load ClearPass credentials: {e}")
    # Fallback to environment variables for backward compatibility
    server_url = os.getenv("CLEARPASS_SERVER", "")
    CLEARPASS_CONFIG = {
        "host": server_url.replace("/api", "") if server_url else "",  # Remove /api suffix if present
        "server": server_url,
        "client_id": os.getenv("CLEARPASS_CLIENT_ID", ""),
        "client_secret": os.getenv("CLEARPASS_CLIENT_SECRET", ""),
        "api_token": os.getenv("CLEARPASS_API_TOKEN", ""),
        "api_version": os.getenv("CLEARPASS_API_VERSION", "v1"),
        "verify_ssl": os.getenv("CLEARPASS_VERIFY_SSL", "true").lower() == "true"
    }

# Global ClearPass client instance for singleton pattern
_clearpass_client: Optional[ClearPassClient] = None


async def get_clearpass_client() -> ClearPassClient:
    """
    Get or create ClearPass client instance using singleton pattern.
    
    Returns:
        ClearPassClient: Initialized and authenticated client instance
        
    Raises:
        ValueError: If credentials are not properly configured
        ClearPassAPIError: If authentication fails
    """
    global _clearpass_client
    
    if _clearpass_client is None:
        # Validate that required credentials are configured
        if not CLEARPASS_CONFIG.get("host"):
            raise ValueError("ClearPass host not configured. Please set CLEARPASS_SERVER environment variable.")
        
        # Check for authentication method
        if not (CLEARPASS_CONFIG.get("client_id") and CLEARPASS_CONFIG.get("client_secret")):
            if not CLEARPASS_CONFIG.get("api_token"):
                raise ValueError("ClearPass credentials not configured. Please provide either client_id/client_secret or api_token.")
        
        logger.info("Initializing ClearPass client...")
        
        _clearpass_client = ClearPassClient(
            host=CLEARPASS_CONFIG["host"],
            client_id=CLEARPASS_CONFIG["client_id"],
            client_secret=CLEARPASS_CONFIG["client_secret"],
            api_version=CLEARPASS_CONFIG.get("api_version", "v1"),
            verify_ssl=CLEARPASS_CONFIG.get("verify_ssl", True)
        )
        
        # Test authentication to ensure the client is working
        try:
            await _clearpass_client.authenticate()
            logger.info("ClearPass client authenticated successfully")
        except Exception as e:
            logger.error(f"Failed to authenticate ClearPass client: {e}")
            _clearpass_client = None  # Reset so we can try again later
            raise ClearPassAPIError(f"Authentication failed: {str(e)}")
    
    return _clearpass_client