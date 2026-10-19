"""
Utility functions for ClearPass Sidekick MCP Server.
"""

from typing import Dict, List, Optional, Any, Union
from .exceptions import ClearPassAPIError


async def format_api_error(error: ClearPassAPIError, operation: str) -> Dict[str, Any]:
    """
    Format ClearPassAPIError into user-friendly response schema.
    Args:
        error: The ClearPassAPIError that occurred
        operation: Description of the operation that failed

    Returns:
        Dict containing formatted error response
    """
    error_str = str(error)
    error_response = {
        "success": False,
        "operation": operation,
        "error": error_str,
        "error_type": "api_error"
    }

    # Specific guidance based on status code or error content
    if error.status_code == 401:
        msg = "Authentication failed. Check your ClearPass credentials in configuration and ensure they are valid and active."
    elif error.status_code == 403:
        msg = "Access forbidden. Your ClearPass API client lacks required permissions for this operation. Contact your ClearPass administrator to grant API access."
    elif error.status_code == 404:
        msg = f"The requested resource for '{operation}' was not found. Call search or list operations in this domain to verify valid IDs or names, then retry."
    elif error.status_code == 422:
        msg = f"Validation error for '{operation}'. Review response_data for specific field errors and retry with corrected parameters."
    elif error.status_code == 500:
        msg = "ClearPass server error. Verify server status and logs, or try again later."
    elif "connection" in error_str.lower() or "timeout" in error_str.lower():
        msg = "Network error connecting to ClearPass host. Check network connectivity, server host URL, or increase timeout setting."
    else:
        msg = f"API request failed for '{operation}'. Check operation parameters via describe_operations and try again."

    error_response["message"] = msg
    error_response["suggestion"] = msg

    if error.status_code:
        error_response["status_code"] = error.status_code

    # The appliance's own structured error body. ClearPassClient._make_request
    # used to lose it (the ClearPassAPIError carrying response_data was raised
    # inside a try: whose except re-raised a body-less copy), so the only way a
    # caller ever saw e.g. {"validation_errors": {"limit": "Cannot be less than
    # 1"}} was as raw text accidentally appended to the message. It is passed
    # through as data now. Key name deliberately not "detail"/"details":
    # those are scanned as free-text error keys by callers and the live harness.
    if isinstance(error.response_data, dict) and error.response_data:
        error_response["response_data"] = error.response_data

    return error_response


async def format_validation_error(
    error: Union[Exception, str],
    operation: str,
    suggestion: Optional[str] = None
) -> Dict[str, Any]:
    """
    Format a validation error into a 3-part schema with error_type: 'validation_error'.
    """
    err_str = str(error)
    msg = suggestion or f"Validation error for '{operation}': {err_str}. Review parameters and retry with corrected values."
    return {
        "success": False,
        "operation": operation,
        "error": err_str,
        "error_type": "validation_error",
        "message": msg,
        "suggestion": msg
    }


async def format_unexpected_error(
    error: Exception,
    operation: str,
    suggestion: Optional[str] = None
) -> Dict[str, Any]:
    """
    Format an unexpected error into a 3-part schema (error_type: 'value_error' or 'unexpected_error').
    """
    err_str = str(error)
    if isinstance(error, (ValueError, TypeError)):
        err_type = "value_error"
        default_msg = f"Parameter or type error for '{operation}': {err_str}. Check input types and arguments, then retry."
    else:
        err_type = "unexpected_error"
        default_msg = f"An unexpected error occurred while executing '{operation}': {err_str}. Verify server state and parameters, then retry."

    msg = suggestion or default_msg
    return {
        "success": False,
        "operation": operation,
        "error": err_str,
        "error_type": err_type,
        "message": msg,
        "suggestion": msg
    }


async def format_error(
    error: Exception,
    operation: str,
    suggestion: Optional[str] = None
) -> Dict[str, Any]:
    """
    Async helper that dispatches to format_api_error, format_validation_error, or format_unexpected_error.
    """
    if isinstance(error, ClearPassAPIError):
        return await format_api_error(error, operation)
    elif isinstance(error, (ValueError, TypeError)):
        return await format_unexpected_error(error, operation, suggestion=suggestion)
    elif isinstance(error, Exception):
        err_lower = str(error).lower()
        if "validation" in type(error).__name__.lower() or "invalid" in err_lower or "missing" in err_lower:
            return await format_validation_error(error, operation, suggestion=suggestion)
        return await format_unexpected_error(error, operation, suggestion=suggestion)
    else:
        return await format_unexpected_error(Exception(str(error)), operation, suggestion=suggestion)


async def format_clarification_needed(
    message: str,
    question: str,
    options: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Format a clarification needed response for the LLM.

    Args:
        message: A brief message explaining why clarification is needed.
        question: The specific question to ask the user.
        options: Optional list of suggested options for the user to choose from.

    Returns:
        Dict containing formatted clarification response.
    """
    response = {
        "success": False,
        "error_type": "clarification_needed",
        "message": message,
        "suggestion": message,
        "question": question
    }
    if options is not None:
        response["options"] = options
    return response
