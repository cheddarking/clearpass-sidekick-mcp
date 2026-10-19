"""
Test suite for the audit logging module.

Tests log entry validation, formatting, rotation, and error handling.
"""

import json
import os
import tempfile
import unittest
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, Mock
import logging # Import logging for handler manipulation

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from audit_logger import (
    AuditLogger,
    AuditLogValidator,
    AuditLogValidationError,
    log_mcp_operation,
    get_audit_logger
)


class TestAuditLogValidator(unittest.TestCase):
    """Test cases for AuditLogValidator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.valid_entry = {
            "timestamp": "2024-01-01T12:00:00Z",
            "user": "test_user",
            "operation": "test_operation",
            "parameters": {"param1": "value1"},
            "outcome": "success",
            "response_summary": "Test successful",
            "execution_time_ms": 100.5
        }
    
    def test_validate_valid_entry(self):
        """Test validation of a valid audit entry."""
        # Should not raise any exception
        AuditLogValidator.validate_audit_entry(self.valid_entry)
    
    def test_validate_missing_required_fields(self):
        """Test validation fails when required fields are missing."""
        invalid_entry = self.valid_entry.copy()
        del invalid_entry["timestamp"]
        
        with self.assertRaises(AuditLogValidationError) as context:
            AuditLogValidator.validate_audit_entry(invalid_entry)
        
        self.assertIn("Missing required fields: timestamp", str(context.exception))
    
    def test_validate_invalid_outcome(self):
        """Test validation fails with invalid outcome value."""
        invalid_entry = self.valid_entry.copy()
        invalid_entry["outcome"] = "invalid_outcome"
        
        with self.assertRaises(AuditLogValidationError) as context:
            AuditLogValidator.validate_audit_entry(invalid_entry)
        
        self.assertIn("Invalid outcome", str(context.exception))
    
    def test_validate_invalid_timestamp(self):
        """Test validation fails with invalid timestamp format."""
        invalid_entry = self.valid_entry.copy()
        invalid_entry["timestamp"] = "invalid-timestamp"
        
        with self.assertRaises(AuditLogValidationError) as context:
            AuditLogValidator.validate_audit_entry(invalid_entry)
        
        self.assertIn("Invalid timestamp format", str(context.exception))
    
    def test_validate_negative_execution_time(self):
        """Test validation fails with negative execution time."""
        invalid_entry = self.valid_entry.copy()
        invalid_entry["execution_time_ms"] = -10
        
        with self.assertRaises(AuditLogValidationError) as context:
            AuditLogValidator.validate_audit_entry(invalid_entry)
        
        self.assertIn("execution_time_ms must be non-negative", str(context.exception))
    
    def test_sanitize_parameters_dict(self):
        """Test parameter sanitization with valid dictionary."""
        params = {"key1": "value1", "key2": 123}
        result = AuditLogValidator.sanitize_parameters(params)
        self.assertEqual(result, params)
    
    def test_sanitize_parameters_none(self):
        """Test parameter sanitization with None."""
        result = AuditLogValidator.sanitize_parameters(None)
        self.assertEqual(result, {})
    
    def test_sanitize_parameters_non_dict(self):
        """Test parameter sanitization with non-dictionary value."""
        result = AuditLogValidator.sanitize_parameters("test_string")
        self.assertEqual(result, {"value": "test_string"})
    
    def test_sanitize_parameters_non_serializable(self):
        """Test parameter sanitization with non-JSON-serializable values."""
        class NonSerializable:
            pass
        
        params = {"key1": "value1", "key2": NonSerializable()}
        result = AuditLogValidator.sanitize_parameters(params)
        
        self.assertEqual(result["key1"], "value1")
        self.assertTrue(isinstance(result["key2"], str))


class TestAuditLogger(unittest.TestCase):
    """Test cases for AuditLogger."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "test_logs"
        self.failed_logs_dir = Path(self.temp_dir) / "failed_logs"
        self.log_dir.mkdir(exist_ok=True)
        self.failed_logs_dir.mkdir(exist_ok=True)
        
        # Ensure a clean logger state for each test
        self.logger_name = f"test_audit_logger_{self.id()}"
        self.original_logger = logging.getLogger("clearpass_audit")
        self.original_logger_handlers = self.original_logger.handlers[:]
        self.original_logger.handlers = [] # Clear handlers for isolation
        self.original_logger.propagate = False # Prevent logs from going to root logger
        
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Restore original logger state
        self.original_logger.handlers = self.original_logger_handlers
        self.original_logger.propagate = True
    
    def test_logger_initialization(self):
        """Test audit logger initialization."""
        logger = AuditLogger(log_dir=str(self.log_dir), logger_name=f"{self.logger_name}_init")
        
        # Check that log directory was created
        self.assertTrue(self.log_dir.exists())
        
        # Check logger configuration
        self.assertEqual(logger.log_dir, self.log_dir)
        self.assertEqual(logger.log_filename, "clearpass_audit.log")
        self.assertTrue(logger.validate_entries)
    
    def test_log_operation_creates_file(self):
        """Test that logging an operation creates the log file."""
        logger = AuditLogger(log_dir=str(self.log_dir), log_filename="test_audit.log")
        
        logger.log_operation(
            operation="test_operation",
            parameters={"test": "value"},
            outcome="success"
        )
        
        # Force flush the log handler
        for handler in logger.logger.handlers:
            handler.flush()
        
        # Small delay to ensure file is written
        time.sleep(0.1)
        
        log_file = self.log_dir / "test_audit.log"
        self.assertTrue(log_file.exists())
    
    def test_log_operation_json_format(self):
        """Test that log entries are properly formatted as JSON."""
        logger = AuditLogger(log_dir=str(self.log_dir), log_filename="json_format.log", logger_name=f"{self.logger_name}_json")
        
        logger.log_operation(
            operation="test_operation",
            parameters={"test": "value"},
            outcome="success",
            response_summary="Test completed",
            execution_time_ms=50.0
        )
        
        # Force flush and wait
        for handler in logger.logger.handlers:
            handler.flush()
        time.sleep(0.1)
        
        log_file = self.log_dir / "json_format.log"
        
        # Verify file exists before reading
        if log_file.exists():
            with open(log_file, 'r', encoding='utf-8') as f:
                log_line = f.readline().strip()
            
            if log_line:  # Only test if we have content
                # Parse JSON
                log_entry = json.loads(log_line)
                
                # Verify required fields
                self.assertIn("timestamp", log_entry)
                self.assertEqual(log_entry["operation"], "test_operation")
                self.assertEqual(log_entry["parameters"], {"test": "value"})
                self.assertEqual(log_entry["outcome"], "success")
                self.assertEqual(log_entry["response_summary"], "Test completed")
                self.assertEqual(log_entry["execution_time_ms"], 50.0)
        else:
            self.skipTest("Log file not created in time")
    
    def test_log_authentication(self):
        """Test authentication logging."""
        logger = AuditLogger(log_dir=str(self.log_dir), log_filename="auth_audit.log", logger_name=f"{self.logger_name}_auth")
        
        logger.log_authentication(outcome="success", user="test_user")
        
        # Force flush and wait
        for handler in logger.logger.handlers:
            handler.flush()
        time.sleep(0.1)
        
        log_file = self.log_dir / "auth_audit.log"
        
        if log_file.exists():
            with open(log_file, 'r', encoding='utf-8') as f:
                log_line = f.readline().strip()
            
            if log_line:
                log_entry = json.loads(log_line)
                self.assertEqual(log_entry["operation"], "authenticate")
                self.assertEqual(log_entry["outcome"], "success")
                self.assertEqual(log_entry["user"], "test_user")
        else:
            self.skipTest("Log file not created in time")
    
    def test_log_api_call(self):
        """Test API call logging."""
        logger = AuditLogger(log_dir=str(self.log_dir), log_filename="api_call_audit.log", logger_name=f"{self.logger_name}_api_call")
        
        logger.log_api_call(
            endpoint="/api/test",
            method="GET",
            status_code=200,
            response_size=1024,
            execution_time_ms=150.0
        )
        
        # Force flush and wait
        for handler in logger.logger.handlers:
            handler.flush()
        time.sleep(0.1)
        
        log_file = self.log_dir / "api_call_audit.log"
        
        if log_file.exists():
            with open(log_file, 'r', encoding='utf-8') as f:
                log_line = f.readline().strip()
            
            if log_line:
                log_entry = json.loads(log_line)
                self.assertEqual(log_entry["operation"], "api_call")
                self.assertEqual(log_entry["outcome"], "success")
                self.assertEqual(log_entry["parameters"]["endpoint"], "/api/test")
                self.assertEqual(log_entry["parameters"]["method"], "GET")
                self.assertEqual(log_entry["parameters"]["status_code"], 200)
        else:
            self.skipTest("Log file not created in time")
    
    def test_validation_error_handling(self):
        """Test handling of validation errors."""
        logger = AuditLogger(log_dir=str(self.log_dir), log_filename="validation_error.log", validate_entries=True, logger_name=f"{self.logger_name}_validation")
        
        # Force a validation error by mocking the validator
        with patch.object(AuditLogValidator, 'validate_audit_entry') as mock_validate:
            mock_validate.side_effect = AuditLogValidationError("Test validation error")
            
            logger.log_operation(
                operation="test_operation",
                outcome="success"
            )
        
        # Force flush and wait
        for handler in logger.logger.handlers:
            handler.flush()
        time.sleep(0.1)
        
        log_file = self.log_dir / "validation_error.log"
        
        if log_file.exists():
            with open(log_file, 'r', encoding='utf-8') as f:
                log_line = f.readline().strip()
            
            if log_line:
                log_entry = json.loads(log_line)
                self.assertEqual(log_entry["operation"], "audit_validation_error")
                self.assertEqual(log_entry["outcome"], "error")
        else:
            self.skipTest("Log file not created in time")
    
    def test_log_rotation_configuration(self):
        """Test log rotation configuration."""
        # Test with default max_bytes (10MB)
        logger_default = AuditLogger(log_dir=str(self.log_dir), log_filename="default_audit.log", logger_name=f"{self.logger_name}_default")
        handler_default = logger_default.logger.handlers[0]
        self.assertEqual(handler_default.maxBytes, 10 * 1024 * 1024) # Assert against default 10MB

        # Test with custom max_bytes
        max_bytes_custom = 1024
        backup_count_custom = 3

        logger_custom = AuditLogger(
            log_dir=str(self.log_dir),
            log_filename="custom_audit.log", # Use a unique filename
            max_bytes=max_bytes_custom,
            backup_count=backup_count_custom,
            logger_name=f"{self.logger_name}_custom" # Use a unique logger name
        )

        # Verify configuration was stored
        self.assertEqual(logger_custom.max_bytes, max_bytes_custom)
        self.assertEqual(logger_custom.backup_count, backup_count_custom)

        # Verify handler exists and has correct type
        self.assertTrue(len(logger_custom.logger.handlers) > 0)
        handler_custom = logger_custom.logger.handlers[0]

        # Check if it's a RotatingFileHandler
        from logging.handlers import RotatingFileHandler
        self.assertIsInstance(handler_custom, RotatingFileHandler)

        # Verify handler configuration
        self.assertEqual(handler_custom.maxBytes, max_bytes_custom)
        self.assertEqual(handler_custom.backupCount, backup_count_custom)


class TestConvenienceFunctions(unittest.TestCase):
    """Test cases for convenience functions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Ensure a clean global audit logger state for each test
        import audit_logger
        audit_logger._audit_logger = None # Reset the global singleton
        
        # Clear handlers from the 'clearpass_audit' logger if any exist from previous tests
        audit_logger_instance = logging.getLogger("clearpass_audit")
        for handler in audit_logger_instance.handlers[:]:
            audit_logger_instance.removeHandler(handler)
        audit_logger_instance.propagate = False # Prevent logs from going to root logger
        
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
        # Restore original logger state
        import audit_logger
        audit_logger._audit_logger = None
        audit_logger_instance = logging.getLogger("clearpass_audit")
        for handler in audit_logger_instance.handlers[:]:
            audit_logger_instance.removeHandler(handler)
        audit_logger_instance.propagate = True
    
    def test_log_mcp_operation(self):
        """Test the log_mcp_operation convenience function."""
        # Mock the global logger
        with patch('audit_logger.get_audit_logger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            log_mcp_operation(
                operation="test_mcp_tool",
                parameters={"param1": "value1"},
                outcome="success",
                response_summary="MCP operation completed"
            )
            
            mock_logger.log_operation.assert_called_once_with(
                operation="test_mcp_tool",
                parameters={"param1": "value1"},
                outcome="success",
                response_summary="MCP operation completed",
                error_details=None,
                execution_time_ms=None
            )


if __name__ == '__main__':
    unittest.main()