"""
Audit Logging Module for ClearPass Sidekick MCP Server

This module provides structured audit logging for all API operations performed
through the MCP server. It maintains detailed logs of user actions, API calls,
parameters, and outcomes for compliance and debugging purposes.
"""

import json
import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, Optional, Union


class AuditLogValidationError(Exception):
    """Exception raised when audit log validation fails."""
    pass


class AuditLogValidator:
    """Validator for audit log entries to ensure data integrity and format compliance."""
    
    # Required fields for audit log entries
    REQUIRED_FIELDS = {
        "timestamp", "user", "operation", "parameters", "outcome"
    }
    
    # Valid outcome values
    VALID_OUTCOMES = {"success", "failure", "error"}
    
    # Field type validation
    FIELD_TYPES = {
        "timestamp": str,
        "user": str,
        "operation": str,
        "parameters": dict,
        "outcome": str,
        "response_summary": (str, type(None)),
        "error_details": (str, type(None)),
        "execution_time_ms": (int, float, type(None))
    }
    
    @classmethod
    def validate_audit_entry(cls, audit_entry: Dict[str, Any]) -> None:
        """
        Validate an audit log entry against the required schema.
        
        Args:
            audit_entry: The audit log entry to validate
            
        Raises:
            AuditLogValidationError: If validation fails
        """
        if not isinstance(audit_entry, dict):
            raise AuditLogValidationError("Audit entry must be a dictionary")
        
        # Check required fields
        missing_fields = cls.REQUIRED_FIELDS - set(audit_entry.keys())
        if missing_fields:
            raise AuditLogValidationError(
                f"Missing required fields: {', '.join(missing_fields)}"
            )
        
        # Validate field types
        for field, value in audit_entry.items():
            if field in cls.FIELD_TYPES:
                expected_type = cls.FIELD_TYPES[field]
                if not isinstance(value, expected_type):
                    raise AuditLogValidationError(
                        f"Field '{field}' must be of type {expected_type}, got {type(value)}"
                    )
        
        # Validate outcome value
        if audit_entry["outcome"] not in cls.VALID_OUTCOMES:
            raise AuditLogValidationError(
                f"Invalid outcome '{audit_entry['outcome']}'. "
                f"Must be one of: {', '.join(cls.VALID_OUTCOMES)}"
            )
        
        # Validate timestamp format (ISO 8601)
        try:
            datetime.fromisoformat(audit_entry["timestamp"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise AuditLogValidationError(
                f"Invalid timestamp format: {audit_entry['timestamp']}. "
                "Must be ISO 8601 format"
            )
        
        # Validate parameters is a dictionary
        if not isinstance(audit_entry["parameters"], dict):
            raise AuditLogValidationError("Parameters field must be a dictionary")
        
        # Validate execution_time_ms is non-negative if provided
        if (audit_entry.get("execution_time_ms") is not None and 
            audit_entry["execution_time_ms"] < 0):
            raise AuditLogValidationError("execution_time_ms must be non-negative")
    
    @classmethod
    def sanitize_parameters(cls, parameters: Any) -> Dict[str, Any]:
        """
        Sanitize parameters to ensure they are JSON serializable.
        
        Args:
            parameters: Parameters to sanitize
            
        Returns:
            Sanitized parameters dictionary
        """
        if parameters is None:
            return {}
        
        if not isinstance(parameters, dict):
            return {"value": str(parameters)}
        
        sanitized = {}
        for key, value in parameters.items():
            try:
                # Test JSON serialization
                json.dumps(value)
                sanitized[str(key)] = value
            except (TypeError, ValueError):
                # Convert non-serializable values to strings
                sanitized[str(key)] = str(value)
        
        return sanitized


class AuditLogger:
    """
    Structured audit logger for ClearPass API operations.
    
    Provides JSON-formatted logging with automatic rotation and archival.
    Separate from application logging for compliance and audit purposes.
    """
    
    def __init__(
        self,
        log_dir: str = "logs",
        log_filename: str = "clearpass_audit.log",
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
        log_level: int = logging.INFO,
        validate_entries: bool = True,
        logger_name: Optional[str] = None # New parameter for unique logger names in tests
    ):
        """
        Initialize the audit logger.
        
        Args:
            log_dir: Directory to store audit logs
            log_filename: Name of the audit log file
            max_bytes: Maximum size of log file before rotation (default: 10MB)
            backup_count: Number of backup files to keep (default: 5)
            log_level: Logging level (default: INFO)
            validate_entries: Whether to validate log entries before writing (default: True)
        """
        self.log_dir = Path(log_dir)
        self.log_filename = log_filename
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.validate_entries = validate_entries
        
        # Create logs directory if it doesn't exist
        self.log_dir.mkdir(exist_ok=True)
        
        # Set up the audit logger
        self.logger = logging.getLogger(logger_name or "clearpass_audit")
        self.logger.setLevel(log_level)
        
        # Prevent duplicate handlers (important for global logger, less so for unique test loggers)
        if not self.logger.handlers:
            self._setup_handler()
    
    def _setup_handler(self):
        """Set up the rotating file handler with JSON formatting."""
        log_path = self.log_dir / self.log_filename
        
        # Create rotating file handler
        handler = RotatingFileHandler(
            filename=str(log_path),
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        
        # Set up JSON formatter
        formatter = AuditJSONFormatter()
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def log_operation(
        self,
        operation: str,
        parameters: Optional[Dict[str, Any]] = None,
        outcome: str = "success",
        response_summary: Optional[str] = None,
        user: str = "mcp_client",
        error_details: Optional[str] = None,
        execution_time_ms: Optional[float] = None
    ):
        """
        Log an API operation with structured data.
        
        Args:
            operation: Name of the operation/tool being executed
            parameters: Parameters passed to the operation
            outcome: Result of the operation ("success", "failure", "error")
            response_summary: Brief summary of the response
            user: User or client performing the operation
            error_details: Error details if operation failed
            execution_time_ms: Execution time in milliseconds
        """
        # Sanitize and validate parameters
        sanitized_parameters = AuditLogValidator.sanitize_parameters(parameters)
        
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user": user,
            "operation": operation,
            "parameters": sanitized_parameters,
            "outcome": outcome,
            "response_summary": response_summary,
            "execution_time_ms": execution_time_ms
        }
        
        if error_details:
            audit_entry["error_details"] = error_details
        
        # Validate entry if validation is enabled
        if self.validate_entries:
            try:
                AuditLogValidator.validate_audit_entry(audit_entry)
            except AuditLogValidationError as e:
                # Log validation error to application logger
                app_logger = logging.getLogger(__name__)
                app_logger.error(f"Audit log validation failed: {e}")
                
                # Create a fallback entry for the validation error
                fallback_entry = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "user": user,
                    "operation": "audit_validation_error",
                    "parameters": {"original_operation": operation, "validation_error": str(e)},
                    "outcome": "error",
                    "response_summary": "Failed to validate audit log entry",
                    "error_details": str(e)
                }
                
                self.logger.info("", extra={"audit_data": fallback_entry})
                return
        
        self.logger.info("", extra={"audit_data": audit_entry})
    
    def log_authentication(
        self,
        outcome: str,
        user: str = "mcp_client",
        error_details: Optional[str] = None
    ):
        """
        Log authentication attempts.
        
        Args:
            outcome: Result of authentication ("success", "failure")
            user: User attempting authentication
            error_details: Error details if authentication failed
        """
        self.log_operation(
            operation="authenticate",
            outcome=outcome,
            user=user,
            error_details=error_details,
            response_summary=f"Authentication {outcome}"
        )
    
    def log_api_call(
        self,
        endpoint: str,
        method: str,
        status_code: Optional[int] = None,
        response_size: Optional[int] = None,
        execution_time_ms: Optional[float] = None,
        error_details: Optional[str] = None
    ):
        """
        Log direct API calls to ClearPass.
        
        Args:
            endpoint: API endpoint called
            method: HTTP method used
            status_code: HTTP status code returned
            response_size: Size of response in bytes
            execution_time_ms: Execution time in milliseconds
            error_details: Error details if call failed
        """
        outcome = "success" if status_code and 200 <= status_code < 300 else "failure"
        
        parameters = {
            "endpoint": endpoint,
            "method": method,
            "status_code": status_code,
            "response_size_bytes": response_size
        }
        
        response_summary = f"{method} {endpoint} -> {status_code}"
        
        self.log_operation(
            operation="api_call",
            parameters=parameters,
            outcome=outcome,
            response_summary=response_summary,
            error_details=error_details,
            execution_time_ms=execution_time_ms
        )


class AuditJSONFormatter(logging.Formatter):
    """Custom JSON formatter for audit logs."""
    
    def format(self, record):
        """Format log record as JSON."""
        if hasattr(record, 'audit_data'):
            return json.dumps(record.audit_data, ensure_ascii=False, separators=(',', ':'))
        else:
            # Fallback for non-audit messages
            return json.dumps({
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "message": record.getMessage(),
                "module": record.module
            }, ensure_ascii=False, separators=(',', ':'))


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_mcp_operation(
    operation: str,
    parameters: Optional[Dict[str, Any]] = None,
    outcome: str = "success",
    response_summary: Optional[str] = None,
    error_details: Optional[str] = None,
    execution_time_ms: Optional[float] = None
):
    """
    Convenience function to log MCP operations.
    
    Args:
        operation: Name of the MCP tool/operation
        parameters: Parameters passed to the operation
        outcome: Result of the operation
        response_summary: Brief summary of the response
        error_details: Error details if operation failed
        execution_time_ms: Execution time in milliseconds
    """
    audit_logger = get_audit_logger()
    audit_logger.log_operation(
        operation=operation,
        parameters=parameters,
        outcome=outcome,
        response_summary=response_summary,
        error_details=error_details,
        execution_time_ms=execution_time_ms
    )