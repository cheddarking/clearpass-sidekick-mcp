"""
Secure credentials management for ClearPass API.

This module provides secure loading and handling of ClearPass API credentials
from environment variables, ensuring sensitive data is never exposed in logs
or standard output.
"""

import logging
import os
from typing import Dict, Optional, Union

from pyclearpass import ClearPassAPILogin

# Configure logger
logger = logging.getLogger(__name__)


class CredentialsError(Exception):
    """Base exception for credential-related errors."""
    pass


class CredentialsNotFoundError(CredentialsError):
    """Raised when no valid credentials are found."""
    pass


class InvalidCredentialsError(CredentialsError):
    """Raised when credentials are malformed or incomplete."""
    pass


class CredentialsManager:
    """
    Manages secure loading and validation of ClearPass API credentials.
    
    Supports loading credentials from environment variables only:
    - CLEARPASS_SERVER: ClearPass server URL (e.g., https://server.com:443/api)
    - CLEARPASS_CLIENT_ID: API client ID
    - CLEARPASS_CLIENT_SECRET: API client secret
    - CLEARPASS_API_TOKEN: Pre-generated API token (alternative to client_id/secret)
    - CLEARPASS_VERIFY_SSL: SSL verification (optional, defaults to True)
    """
    
    # Environment variable names
    ENV_SERVER = "CLEARPASS_SERVER"
    ENV_CLIENT_ID = "CLEARPASS_CLIENT_ID"
    ENV_CLIENT_SECRET = "CLEARPASS_CLIENT_SECRET"
    ENV_API_TOKEN = "CLEARPASS_API_TOKEN"
    ENV_VERIFY_SSL = "CLEARPASS_VERIFY_SSL"
    
    def __init__(self):
        """Initialize the credentials manager."""
        self._credentials: Optional[Dict[str, Union[str, bool]]] = None
    
    def load_credentials(self) -> Dict[str, Union[str, bool]]:
        """
        Load credentials from environment variables.
        
        Returns:
            Dictionary containing the loaded credentials
            
        Raises:
            CredentialsNotFoundError: If no valid credentials are found
            InvalidCredentialsError: If credentials are malformed
        """
        credentials = self._load_from_environment()
        if credentials:
            logger.info("Loaded credentials from environment variables")
            self._credentials = credentials
            return credentials
        
        # No credentials found
        raise CredentialsNotFoundError(
            f"No valid credentials found. Please set environment variables "
            f"({self.ENV_SERVER}, {self.ENV_CLIENT_ID}, {self.ENV_CLIENT_SECRET}) "
            f"or ({self.ENV_SERVER}, {self.ENV_API_TOKEN})"
        )
    
    def _load_from_environment(self) -> Optional[Dict[str, Union[str, bool]]]:
        """Load credentials from environment variables."""
        server = os.getenv(self.ENV_SERVER)
        api_token = os.getenv(self.ENV_API_TOKEN)
        client_id = os.getenv(self.ENV_CLIENT_ID)
        client_secret = os.getenv(self.ENV_CLIENT_SECRET)
        verify_ssl = os.getenv(self.ENV_VERIFY_SSL, "true").lower() in ("true", "1", "yes")
        
        # Check if we have either API token or client credentials
        has_token = bool(api_token)
        has_client_creds = bool(client_id and client_secret)
        
        if not server:
            logger.debug("CLEARPASS_SERVER environment variable not set")
            return None
        
        if not (has_token or has_client_creds):
            logger.debug("Neither API token nor client credentials found in environment")
            return None
        
        credentials = {
            "server": server,
            "verify_ssl": verify_ssl
        }
        
        if has_token:
            credentials["api_token"] = api_token
            logger.debug("Using API token authentication from environment")
        else:
            credentials["client_id"] = client_id
            credentials["client_secret"] = client_secret
            credentials["granttype"] = "client_credentials"
            logger.debug("Using client credentials authentication from environment")
        
        return credentials
    
    def validate_credentials(self, credentials: Optional[Dict[str, Union[str, bool]]] = None) -> bool:
        """
        Validate that credentials contain all required fields.
        
        Args:
            credentials: Optional credentials dict to validate. 
                        If None, uses previously loaded credentials.
                        
        Returns:
            True if credentials are valid
            
        Raises:
            InvalidCredentialsError: If credentials are invalid
        """
        if credentials is None:
            credentials = self._credentials
        
        if not credentials:
            raise InvalidCredentialsError("No credentials to validate")
        
        # Check required fields
        if not credentials.get("server"):
            raise InvalidCredentialsError("Missing 'server' field")
        
        # Validate server URL format
        server = credentials["server"]
        if not (server.startswith("http://") or server.startswith("https://")):
            raise InvalidCredentialsError("Server URL must start with http:// or https://")
        
        # Check authentication method
        has_token = bool(credentials.get("api_token"))
        has_client_creds = bool(credentials.get("client_id") and credentials.get("client_secret"))
        
        if not (has_token or has_client_creds):
            raise InvalidCredentialsError(
                "Credentials must contain either 'api_token' or both 'client_id' and 'client_secret'"
            )
        
        return True
    
    def get_clearpass_login(self) -> ClearPassAPILogin:
        """
        Create and return a configured ClearPassAPILogin object.
        
        Returns:
            Configured ClearPassAPILogin instance
            
        Raises:
            CredentialsNotFoundError: If no valid credentials are found
            InvalidCredentialsError: If credentials are invalid
        """
        if not self._credentials:
            self.load_credentials()
        
        self.validate_credentials()
        
        # Create login object based on authentication method
        if "api_token" in self._credentials:
            login = ClearPassAPILogin(
                server=self._credentials["server"],
                api_token=self._credentials["api_token"],
                verify_ssl=self._credentials.get("verify_ssl", True)
            )
            logger.info("Created ClearPass login with API token authentication")
        else:
            login = ClearPassAPILogin(
                server=self._credentials["server"],
                granttype=self._credentials["granttype"],
                clientid=self._credentials["client_id"],
                clientsecret=self._credentials["client_secret"],
                verify_ssl=self._credentials.get("verify_ssl", True)
            )
            logger.info("Created ClearPass login with client credentials authentication")
        
        return login
    
    def mask_sensitive_data(self, data: Dict) -> Dict:
        """
        Create a copy of data with sensitive fields masked for logging.
        
        Args:
            data: Dictionary that may contain sensitive data
            
        Returns:
            Dictionary with sensitive fields masked
        """
        sensitive_fields = {"client_secret", "api_token", "password"}
        masked_data = data.copy()
        
        for field in sensitive_fields:
            if field in masked_data and masked_data[field]:
                masked_data[field] = "***MASKED***"
        
        return masked_data