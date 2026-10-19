"""
ClearPass API Client

Handles OAuth2 authentication and API communication with Aruba ClearPass Policy Manager.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Any, Union
import httpx
from datetime import datetime, timedelta
import json
import time

# Import audit logging functionality
from .audit_logger import AuditLogger, get_audit_logger
from .exceptions import ClearPassAPIError

# Import mixin classes for modularized client methods
from .client_methods.api_clients import ApiClientMethodsMixin
from .client_methods.network_devices import NetworkDeviceMethodsMixin
from .client_methods.guest_users import GuestUserMethodsMixin
from .client_methods.guest_actions import GuestActionMethodsMixin
from .client_methods.guest_configuration import GuestConfigurationMethodsMixin
from .client_methods.certificates import CertificateMethodsMixin
from .client_methods.audit_logs import AuditLogsMethodsMixin
from .client_methods.local_server_config import LocalServerConfigMethodsMixin
from .client_methods.global_server_config import GlobalServerConfigMethodsMixin
from .client_methods.session_control import SessionControlMethodsMixin
from .client_methods.policy_elements import PolicyElementsMethodsMixin
from .client_methods.enforcement_profiles import EnforcementProfileMethodsMixin
from .client_methods.identities import IdentitiesMethodsMixin
from .client_methods.endpoint_visibility import EndpointVisibilityMethodsMixin
from .client_methods.integrations import IntegrationsMethodsMixin
from .client_methods.certificate_authority import CertificateAuthorityMethodsMixin
from .client_methods.tools_utilities import ToolsUtilitiesMethodsMixin
from .client_methods.api_operations import ApiOperationsMethodsMixin
from .client_methods.enforcement_profiles_dur import EnforcementProfileDurMethodsMixin

logger = logging.getLogger(__name__)


class ClearPassClient(
    ApiClientMethodsMixin,
    NetworkDeviceMethodsMixin,
    GuestUserMethodsMixin,
    GuestActionMethodsMixin,
    GuestConfigurationMethodsMixin,
    CertificateMethodsMixin,
    AuditLogsMethodsMixin,
    LocalServerConfigMethodsMixin,
    GlobalServerConfigMethodsMixin,
    SessionControlMethodsMixin,
    PolicyElementsMethodsMixin,
    EnforcementProfileMethodsMixin,
    IdentitiesMethodsMixin,
    EndpointVisibilityMethodsMixin,
    IntegrationsMethodsMixin,
    CertificateAuthorityMethodsMixin,
    ToolsUtilitiesMethodsMixin,
    ApiOperationsMethodsMixin,
    EnforcementProfileDurMethodsMixin
):
    """
    Async client for ClearPass Policy Manager REST API.
    
    Handles OAuth2 authentication, token management, and API requests.
    Inherits API-specific methods from mixin classes.
    """
    
    def __init__(
        self,
        host: str,
        client_id: str,
        client_secret: str,
        api_version: str = "v1",
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        self.host = host.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_version = api_version
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        
        # OAuth2 token management
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
        
        # HTTP client
        self.client = httpx.AsyncClient(
            verify=verify_ssl,
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )
        
        # API base URL.
        #
        # ClearPass is addressed at the UNVERSIONED ``/api`` root, not
        # ``/api/v1``. See ``_endpoint_url`` for the measurements behind that.
        # ``api_version`` is retained on the instance for callers/telemetry that
        # still report it, but it does not participate in URL construction.
        self.base_url = f"{self.host}/api"
        # Backwards-compatible alias: some callers/tests reference this name.
        self.unversioned_base_url = self.base_url

    async def __aenter__(self):
        """Async context manager entry."""
        await self.authenticate()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
        
    async def authenticate(self) -> str:
        """
        Authenticate with ClearPass using OAuth2 client credentials flow.
        
        Returns:
            str: Access token
            
        Raises:
            ClearPassAPIError: If authentication fails
        """
        if self.access_token and self.token_expires_at and datetime.now() < self.token_expires_at:
            return self.access_token
            
        logger.info("Authenticating with ClearPass...")
        
        auth_url = f"{self.host}/api/oauth"
        auth_data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        try:
            response = await self.client.post(
                auth_url,
                data=auth_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            response.raise_for_status()
            
            token_data = response.json()
            self.access_token = token_data["access_token"]
            
            # Calculate token expiration (subtract 60 seconds for safety)
            expires_in = token_data.get("expires_in", 3600)
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)
            
            # Update client headers with token
            self.client.headers["Authorization"] = f"Bearer {self.access_token}"
            
            logger.info("Successfully authenticated with ClearPass")
            return self.access_token
            
        except httpx.HTTPStatusError as e:
            error_msg = f"Authentication failed: {e.response.status_code}"
            try:
                error_data = e.response.json()
                error_msg += f" - {error_data.get('error_description', error_data.get('error', 'Unknown error'))}"
            except:
                error_msg += f" - {e.response.text}"
            raise ClearPassAPIError(error_msg, e.response.status_code)
            
        except Exception as e:
            raise ClearPassAPIError(f"Authentication error: {str(e)}")
    
    def _endpoint_url(self, endpoint: str) -> str:
        """Absolute URL for an endpoint, built from the unversioned ``/api`` root.

        Why unversioned, and why there is no per-endpoint exception list
        -----------------------------------------------------------------
        An earlier revision defaulted to ``/api/v1`` and carved out an
        ``_UNVERSIONED_PREFIXES`` exception list for ``oauth`` and
        ``enforcement-profile-dur``. That was backwards. Measured against a live
        ClearPass 6.12.4 appliance on 2026-07-30, ``/api`` is a strict superset
        of ``/api/v1``:

        * **56 GET endpoints** spanning every domain (network-device, role,
          enforcement-profile, guest, admin-user, fingerprint, syslog-target,
          session, cert-trust-list, cluster/server, endpoint, local-user,
          attribute, api-client, auth-source, posture-policy, ...) were fetched
          at both roots and the response bodies compared byte-for-byte after
          normalising the echoed ``_links.self.href``. **53 were identical.**
        * Of the 3 that differed, ``random-mpsk`` differs only because it mints
          a fresh random value per call. The other two are **regressions of the
          versioned mount**: ``GET /api/v1/alert`` and ``GET /api/v1/report``
          answer ``404 Object not found`` while ``GET /api/alert`` and
          ``GET /api/report`` return proper collections.
        * Writes match too: ``POST`` with an invalid body to network-device,
          role, admin-user, syslog-target, guest, enforcement-profile and
          cert-trust-list returns the identical structured 422 at both roots,
          as does ``PATCH network-device/999999`` (404).
        * Where the two roots diverge on writes, ``/api/v1`` is the broken one.
          It answers an HTML-wrapped **HTTP 500** for every
          ``enforcement-profile-dur/*`` write, for
          ``session-action/disconnect*``, and for the ``onguard-activity``
          message/notification POSTs -- all of which return clean structured
          4xx/2xx at ``/api``.
        * ``POST /api/v1/oauth`` answers ``404 Page not found``; ``POST
          /api/oauth`` mints the token (``authenticate()`` has always called it
          unversioned).

        No endpoint was found that ``/api/v1`` serves and ``/api`` does not, so
        the exception mechanism was deleted rather than inverted. This also
        matches pyclearpass, which builds every URL from the unversioned root.
        """
        return f"{self.base_url}/{endpoint.lstrip('/')}"

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Make an authenticated API request to ClearPass with integrated audit logging.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            data: Request body data
            params: Query parameters
            
        Returns:
            Dict: Response data
            
        Raises:
            ClearPassAPIError: If request fails
        """
        # Record start time for execution tracking
        start_time = time.time()
        
        # Extract metadata for audit logging
        audit_metadata = self._extract_request_metadata(method, endpoint, data, params)
        
        # Ensure we have a valid token
        await self.authenticate()
        
        url = self._endpoint_url(endpoint)

        # Body-less writes must still carry a body.
        #
        # ``self.client`` sets ``Content-Type: application/json`` on every
        # request. Passing ``json=None`` to httpx sends *no* body at all, so the
        # appliance sees a JSON content type with zero bytes and answers
        # ``400 - JSON decoding error: Syntax error, malformed JSON``. Every
        # body-less PATCH/POST/PUT the API defines (alert enable/disable,
        # report run, service start/stop, config/service enable/disable,
        # licence activation, agentless-onguard subnet-mapping enable/disable,
        # ...) hits this. Normalising ``None`` to ``{}`` centrally fixes them
        # all; the per-module ``data={}`` call sites remain valid and are simply
        # redundant now.
        #
        # DELETE and GET are deliberately excluded: they are legitimately
        # body-less and the appliance accepts them that way.
        request_body = data
        if request_body is None and method.upper() in ("PATCH", "POST", "PUT"):
            request_body = {}

        try:
            response = await self.client.request(
                method=method,
                url=url,
                json=request_body,
                params=params
            )
            response.raise_for_status()
            
            # Calculate execution time
            execution_time_ms = (time.time() - start_time) * 1000
            
            # Handle empty responses
            if response.status_code == 204 or not response.content:
                response_data = {"success": True}
            else:
                # Try to parse as JSON, but handle non-JSON responses
                try:
                    response_data = response.json()
                except Exception:
                    # For some endpoints (like license activation), the API returns HTML/text
                    # Check if this is a successful response despite not being JSON
                    if response.status_code in [200, 201, 202]:
                        response_data = {
                            "success": True,
                            "message": "Operation completed successfully (non-JSON response)",
                            "raw_response": response.text[:500] if response.text else None,
                            "content_type": response.headers.get("content-type", "unknown")
                        }
                    else:
                        raise
            
            # Log successful operation with metadata
            self._log_api_operation(
                audit_metadata=audit_metadata,
                status_code=response.status_code,
                response_data=response_data,
                execution_time_ms=execution_time_ms,
                outcome="success"
            )
            
            return response_data
            
        except httpx.HTTPStatusError as e:
            execution_time_ms = (time.time() - start_time) * 1000
            error_msg = f"API request failed: {method} {endpoint} - {e.response.status_code}"

            # The error body is parsed *outside* the raise path on purpose.
            # This block used to build the ClearPassAPIError (with response_data)
            # inside its own ``try:``, so the following ``except Exception``
            # caught it and re-raised a body-less copy -- every structured error
            # the appliance returned was silently lost to callers.
            parsed_body = None
            json_ok = False
            parse_error = None
            try:
                parsed_body = e.response.json()
                json_ok = True
            except Exception as exc:
                parse_error = exc

            if json_ok and isinstance(parsed_body, dict):
                error_data = parsed_body
                error_msg += f" - {error_data.get('detail', error_data.get('message', 'Unknown error'))}"
            else:
                # Non-JSON body (HTML error page, plain text, empty) or JSON
                # that is not an object. Normalise it so callers always receive
                # a dict and never raw HTML.
                error_data = self._structure_non_json_error_body(
                    e.response, parsed_body, json_ok)
                error_msg += f" - {error_data.get('message', '')}"

            error_details = error_msg
            if parse_error is not None:
                error_details = f"{error_msg} (Response parsing failed: {str(parse_error)})"

            # Log failed operation with error details
            self._log_api_operation(
                audit_metadata=audit_metadata,
                status_code=e.response.status_code,
                response_data=error_data,
                execution_time_ms=execution_time_ms,
                outcome="failure",
                error_details=error_details
            )

            raise ClearPassAPIError(error_msg, e.response.status_code, error_data)
                
        except Exception as e:
            execution_time_ms = (time.time() - start_time) * 1000
            error_msg = f"Request error: {str(e)}"
            
            # Log error operation
            self._log_api_operation(
                audit_metadata=audit_metadata,
                status_code=None,
                response_data=None,
                execution_time_ms=execution_time_ms,
                outcome="error",
                error_details=error_msg
            )
            
            raise ClearPassAPIError(error_msg)
    
    _HTML_BODY_HINTS = ("<html", "<!doctype html", "<body", "<h1", "<title")

    @staticmethod
    def _flatten_html_error(html: str) -> Dict[str, Any]:
        """Turn an HTML error page into a short structured summary.

        ClearPass answers some endpoints (e.g. ``POST report/<id>/run`` on a
        500) with a full HTML page. Handing that to a caller as an error string
        is useless, so extract the ``<title>`` and the visible text.
        """
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html,
                                re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""

        body = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
        body = re.sub(r"(?is)<head[^>]*>.*?</head>", " ", body)
        body = re.sub(r"(?s)<[^>]+>", " ", body)
        body = re.sub(r"&nbsp;?", " ", body)
        body = re.sub(r"\s+", " ", body).strip()

        summary = body or title
        return {"title": title, "text": summary[:500]}

    def _structure_non_json_error_body(
        self,
        response: Any,
        parsed_body: Any = None,
        json_ok: bool = False
    ) -> Dict[str, Any]:
        """Normalise a non-object error body into a dict.

        Guarantees ``ClearPassAPIError.response_data`` is always structured:
        HTML pages are flattened to a title + text summary, plain text is kept
        verbatim, an empty body is reported as such, and valid-but-not-object
        JSON (a bare list, a string) is carried through under ``body``.

        The ``message`` key is what gets appended to the exception message, so
        it preserves the historical ``... - <response text>`` format for plain
        text and empty bodies.
        """
        try:
            text = response.text or ""
        except Exception:  # pragma: no cover - defensive
            text = ""
        if not isinstance(text, str):
            text = str(text)

        try:
            content_type = str(response.headers.get("content-type", "") or "")
        except Exception:  # pragma: no cover - defensive
            content_type = ""

        if json_ok:
            return {
                "body_format": "json",
                "content_type": content_type,
                "message": text,
                "body": parsed_body,
            }

        stripped = text.strip()
        if not stripped:
            return {
                "body_format": "empty",
                "content_type": content_type,
                "message": "",
            }

        looks_html = (
            "html" in content_type.lower()
            or any(hint in stripped[:512].lower() for hint in self._HTML_BODY_HINTS)
        )

        if looks_html:
            flattened = self._flatten_html_error(stripped)
            return {
                "body_format": "html",
                "content_type": content_type,
                "title": flattened["title"],
                "message": flattened["text"],
            }

        return {
            "body_format": "text",
            "content_type": content_type,
            "message": text,
        }

    def _extract_request_metadata(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Extract metadata from API request for audit logging.
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            data: Request body data
            params: Query parameters
            
        Returns:
            Dict containing extracted metadata
        """
        try:
            # Build sanitized parameters for logging
            sanitized_params = {}
            
            if params:
                sanitized_params.update(params)
            
            if data:
                # Sanitize sensitive data in request body
                sanitized_data = self._sanitize_sensitive_data(data)
                sanitized_params["request_body"] = sanitized_data
            
            metadata = {
                "method": method.upper(),
                "endpoint": endpoint,
                "full_url": self._endpoint_url(endpoint),
                "parameters": sanitized_params,
                "timestamp": datetime.now().isoformat(),
                "client_host": self.host
            }
            
            return metadata
            
        except Exception as e:
            # Fallback metadata if extraction fails
            logger.warning(f"Failed to extract request metadata: {str(e)}")
            return {
                "method": method.upper(),
                "endpoint": endpoint,
                "parameters": {},
                "timestamp": datetime.now().isoformat(),
                "extraction_error": str(e)
            }
    
    def _sanitize_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize sensitive data from request parameters for audit logging.
        
        Args:
            data: Original data dictionary
            
        Returns:
            Sanitized data dictionary
        """
        if not isinstance(data, dict):
            return {"sanitized": str(type(data))}
        
        sensitive_fields = {
            "password", "secret", "token", "key", "credential", 
            "auth", "authorization", "client_secret"
        }
        
        sanitized = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(sensitive in key_lower for sensitive in sensitive_fields):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_sensitive_data(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _log_api_operation(
        self,
        audit_metadata: Dict[str, Any],
        status_code: Optional[int],
        response_data: Optional[Dict],
        execution_time_ms: float,
        outcome: str,
        error_details: Optional[str] = None
    ):
        """
        Log API operation with error handling and recovery mechanisms.
        
        Args:
            audit_metadata: Extracted request metadata
            status_code: HTTP response status code
            response_data: Response data (if any)
            execution_time_ms: Request execution time in milliseconds
            outcome: Operation outcome (success, failure, error)
            error_details: Error details (if any)
        """
        try:
            # Get audit logger instance
            audit_logger = get_audit_logger()
            
            # Prepare operation name
            operation = f"{audit_metadata.get('method', 'UNKNOWN')} {audit_metadata.get('endpoint', 'unknown')}"
            
            # Prepare response summary
            response_summary = None
            if response_data:
                if isinstance(response_data, dict):
                    # Create a brief summary of the response
                    if "success" in response_data:
                        response_summary = f"Success: {response_data.get('success')}"
                    elif "_embedded" in response_data:
                        # Handle paginated responses
                        embedded = response_data["_embedded"]
                        if embedded:
                            first_key = next(iter(embedded.keys()))
                            count = len(embedded[first_key]) if isinstance(embedded[first_key], list) else 1
                            response_summary = f"Retrieved {count} {first_key} items"
                    elif "id" in response_data:
                        response_summary = f"Resource ID: {response_data['id']}"
                    else:
                        response_summary = f"Response with {len(response_data)} fields"
                else:
                    response_summary = str(response_data)[:100]  # Truncate long responses
            
            # Add status code to parameters
            enhanced_params = audit_metadata.get("parameters", {}).copy()
            if status_code:
                enhanced_params["status_code"] = status_code
            
            # Log the operation
            audit_logger.log_operation(
                operation=operation,
                parameters=enhanced_params,
                outcome=outcome,
                response_summary=response_summary,
                error_details=error_details,
                execution_time_ms=execution_time_ms
            )
            
            # Force flush the log handler to ensure immediate write for testing purposes
            for handler in audit_logger.logger.handlers:
                handler.flush()
            import time
            time.sleep(0.05) # Small delay to ensure file system write
            
        except Exception as logging_error:
            # Error handling for logging failures - implement recovery mechanism
            self._handle_logging_failure(
                logging_error=logging_error,
                audit_metadata=audit_metadata,
                status_code=status_code,
                outcome=outcome,
                error_details=error_details
            )
    
    def _handle_logging_failure(
        self,
        logging_error: Exception,
        audit_metadata: Dict[str, Any],
        status_code: Optional[int],
        outcome: str,
        error_details: Optional[str]
    ):
        """
        Handle logging failures with recovery mechanisms.
        
        Args:
            logging_error: The exception that occurred during logging
            audit_metadata: Original audit metadata
            status_code: HTTP status code
            outcome: Operation outcome
            error_details: Original error details
        """
        try:
            # Log to application logger as fallback
            fallback_msg = (
                f"AUDIT LOG FAILURE: {str(logging_error)} | "
                f"Original operation: {audit_metadata.get('method')} {audit_metadata.get('endpoint')} | "
                f"Status: {status_code} | Outcome: {outcome}"
            )
            
            if error_details:
                fallback_msg += f" | Error: {error_details}"
            
            logger.error(fallback_msg)
            
            # Attempt to store failed log entry for later retry
            self._store_failed_log_entry({
                "timestamp": datetime.now().isoformat(),
                "logging_error": str(logging_error),
                "audit_metadata": audit_metadata,
                "status_code": status_code,
                "outcome": outcome,
                "error_details": error_details
            })
            
        except Exception as recovery_error:
            # Last resort: log to application logger / stderr
            logger.critical(f"CRITICAL: Complete audit logging failure: {str(recovery_error)}")
    
    def _store_failed_log_entry(self, failed_entry: Dict[str, Any]):
        """
        Store failed log entries for later retry/analysis.
        
        Args:
            failed_entry: The log entry that failed to be written
        """
        try:
            import os
            from pathlib import Path
            
            # Create failed logs directory
            failed_logs_dir = Path("logs/failed")
            failed_logs_dir.mkdir(parents=True, exist_ok=True)
            
            # Write failed entry to a separate file
            failed_log_file = failed_logs_dir / f"failed_audit_{datetime.now().strftime('%Y%m%d')}.json"
            
            with open(failed_log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(failed_entry) + "\n")
                
        except Exception as storage_error:
            # If we can't even store the failed entry, log to application logger
            logger.critical(f"Failed to store failed audit log entry: {str(storage_error)}")

    async def test_connection(self) -> Dict[str, Any]:
        """Test the connection to ClearPass."""
        try:
            await self.authenticate()
            # Use server-version instead of system/health
            server_info = await self.get_system_health()
            return {
                "success": True,
                "message": "Successfully connected to ClearPass",
                "server_info": server_info
            }
        except ClearPassAPIError as e:
            return {
                "success": False,
                "message": f"Connection failed: {e.message}",
                "error_code": e.status_code
            }