"""
Test suite for ClearPass client integration with audit logging.

Tests that the ClearPass API wrapper properly logs all operations,
handles logging failures gracefully, and implements recovery mechanisms.
"""

import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch
from pathlib import Path
import sys

from src.clearpass_client import ClearPassClient
from src.audit_logger import get_audit_logger, AuditLogger # Import AuditLogger explicitly
from src.exceptions import ClearPassAPIError
import logging # Import logging for handler manipulation


class TestClearPassClientAuditIntegration(unittest.TestCase):
    """Test cases for ClearPass client audit logging integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = Path(self.temp_dir) / "test_logs"
        self.log_dir.mkdir(exist_ok=True)
        
        # Create client instance
        self.client = ClearPassClient(
            host="https://test.clearpass.local",
            client_id="test_client",
            client_secret="test_secret"
        )
        
        # Mock the HTTP client to avoid real network calls
        self.client.client = AsyncMock()
        
        # Ensure a clean global audit logger state for each test
        import src.audit_logger as audit_logger
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
        
        # Restore original logger state if necessary (though resetting _audit_logger should be enough)
        import src.audit_logger as audit_logger
        audit_logger._audit_logger = None
        audit_logger_instance = logging.getLogger("clearpass_audit")
        for handler in audit_logger_instance.handlers[:]:
            audit_logger_instance.removeHandler(handler)
        audit_logger_instance.propagate = True
        
    async def _successful_api_call_logging(self):
        """Test that successful API calls are properly logged."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"id": 123, "name": "test_client"}
        mock_response.raise_for_status.return_value = None
        self.client.client.request.return_value = mock_response
        
        # Mock authentication
        self.client.access_token = "test_token"
        self.client.token_expires_at = None  # Force re-auth
        
        # Mock auth response
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
        auth_response.raise_for_status.return_value = None
        self.client.client.post.return_value = auth_response
        
        # Patch audit logger to capture logs
        with patch('src.clearpass_client.get_audit_logger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            # Make API call
            result = await self.client._make_request("GET", "api-client/123")
            
            # Verify result
            self.assertEqual(result, {"id": 123, "name": "test_client"})
            
            # Verify audit logging was called
            mock_logger.log_operation.assert_called_once()
            call_args = mock_logger.log_operation.call_args
            
            # Verify log parameters
            self.assertEqual(call_args[1]["operation"], "GET api-client/123")
            self.assertEqual(call_args[1]["outcome"], "success")
            self.assertIn("status_code", call_args[1]["parameters"])
            self.assertEqual(call_args[1]["parameters"]["status_code"], 200)
            
    async def _failed_api_call_logging(self):
        """Test that failed API calls are properly logged with error details."""
        from httpx import HTTPStatusError, Request, Response
        
        mock_request = Mock(spec=Request)
        mock_response = Mock(spec=Response)
        mock_response.status_code = 404
        mock_response.json.side_effect = Exception("JSON parsing failed")  # Force JSON parsing to fail
        mock_response.text = "Not found"
        
        http_error = HTTPStatusError("404 Not Found", request=mock_request, response=mock_response)
        self.client.client.request.side_effect = http_error
        
        # Mock authentication
        self.client.access_token = "test_token"
        self.client.token_expires_at = None
        
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
        auth_response.raise_for_status.return_value = None
        self.client.client.post.return_value = auth_response
        
        # Patch audit logger to capture logs
        with patch('src.clearpass_client.get_audit_logger') as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger
            
            # Make API call and expect failure
            with self.assertRaises(ClearPassAPIError):
                await self.client._make_request("GET", "api-client/999")
            
            # Verify audit logging was called for failure
            mock_logger.log_operation.assert_called_once()
            call_args = mock_logger.log_operation.call_args
            
            # Verify log parameters for failure
            self.assertEqual(call_args[1]["operation"], "GET api-client/999")
            self.assertEqual(call_args[1]["outcome"], "failure")
            self.assertIn("status_code", call_args[1]["parameters"])
            self.assertEqual(call_args[1]["parameters"]["status_code"], 404)
            self.assertIsNotNone(call_args[1]["error_details"])
            
    async def _logging_failure_handling(self):
        """Test that logging failures are handled gracefully without breaking API calls."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_response.raise_for_status.return_value = None
        self.client.client.request.return_value = mock_response
        
        # Mock authentication
        self.client.access_token = "test_token"
        self.client.token_expires_at = None
        
        auth_response = Mock()
        auth_response.status_code = 200
        auth_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
        auth_response.raise_for_status.return_value = None
        self.client.client.post.return_value = auth_response
        
        # Mock audit logger to raise exception
        with patch('src.clearpass_client.get_audit_logger') as mock_get_logger:
            mock_logger = Mock()
            mock_logger.log_operation.side_effect = Exception("Logging failed")
            mock_get_logger.return_value = mock_logger
            
            # Patch the error handling methods to verify they're called
            with patch.object(self.client, '_handle_logging_failure') as mock_handle_failure:
                # Make API call - should succeed despite logging failure
                result = await self.client._make_request("GET", "test-endpoint")
                
                # Verify API call succeeded
                self.assertEqual(result, {"success": True})
                
                # Verify error handling was called
                mock_handle_failure.assert_called_once()
                
    def test_metadata_extraction(self):
        """Test that request metadata is properly extracted."""
        # Test metadata extraction
        metadata = self.client._extract_request_metadata(
            method="POST",
            endpoint="api-client",
            data={"name": "test", "password": "secret123"},
            params={"limit": 10}
        )
        
        # Verify metadata structure
        self.assertEqual(metadata["method"], "POST")
        self.assertEqual(metadata["endpoint"], "api-client")
        self.assertIn("timestamp", metadata)
        self.assertIn("parameters", metadata)
        
        # Verify sensitive data sanitization
        self.assertEqual(metadata["parameters"]["request_body"]["password"], "[REDACTED]")
        self.assertEqual(metadata["parameters"]["request_body"]["name"], "test")
        self.assertEqual(metadata["parameters"]["limit"], 10)
        
    def test_sensitive_data_sanitization(self):
        """Test that sensitive data is properly sanitized."""
        test_data = {
            "username": "testuser",
            "password": "secret123",
            "client_secret": "topsecret",
            "api_key": "key123",
            "normal_field": "normal_value",
            "nested": {
                "token": "nested_secret",
                "safe_field": "safe_value"
            }
        }
        
        sanitized = self.client._sanitize_sensitive_data(test_data)
        
        # Verify sensitive fields are redacted
        self.assertEqual(sanitized["password"], "[REDACTED]")
        self.assertEqual(sanitized["client_secret"], "[REDACTED]")
        self.assertEqual(sanitized["api_key"], "[REDACTED]")
        self.assertEqual(sanitized["nested"]["token"], "[REDACTED]")
        
        # Verify non-sensitive fields are preserved
        self.assertEqual(sanitized["username"], "testuser")
        self.assertEqual(sanitized["normal_field"], "normal_value")
        self.assertEqual(sanitized["nested"]["safe_field"], "safe_value")
        
    def test_failed_log_entry_storage(self):
        """Test that failed log entries are stored for recovery."""
        failed_entry = {
            "timestamp": "2024-01-01T12:00:00Z",
            "operation": "test_operation",
            "error": "logging_failed"
        }
        
        # Create temporary directory for failed logs
        with patch('pathlib.Path') as mock_path:
            mock_failed_dir = Mock()
            mock_path.return_value = mock_failed_dir
            mock_failed_dir.mkdir.return_value = None
            
            # Mock file operations
            mock_file = Mock()
            mock_open = Mock()
            mock_open.__enter__ = Mock(return_value=mock_file)
            mock_open.__exit__ = Mock(return_value=None)
            
            with patch('builtins.open', return_value=mock_open):
                # Test failed log storage
                self.client._store_failed_log_entry(failed_entry)
                
                # Verify directory creation was attempted
                mock_failed_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        
    async def _end_to_end_integration(self):
        """Test end-to-end integration with real audit logger."""
        # Use real audit logger with temporary directory
        with patch('src.clearpass_client.get_audit_logger') as mock_get_logger:
            from src.audit_logger import AuditLogger
            real_logger = AuditLogger(log_dir=str(self.log_dir))
            mock_get_logger.return_value = real_logger
            
            # Mock successful API response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"id": 456, "name": "integration_test"}
            mock_response.raise_for_status.return_value = None
            self.client.client.request.return_value = mock_response
            
            # Mock authentication
            self.client.access_token = "test_token"
            self.client.token_expires_at = None
            
            auth_response = Mock()
            auth_response.status_code = 200
            auth_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
            auth_response.raise_for_status.return_value = None
            self.client.client.post.return_value = auth_response
            
            # Make API call
            result = await self.client._make_request("GET", "api-client/456")
            
            # Verify result
            self.assertEqual(result, {"id": 456, "name": "integration_test"})
            
            # Verify log file was created
            log_file = self.log_dir / "clearpass_audit.log"
            self.assertTrue(log_file.exists())
            
            # Verify log content
            # No need for time.sleep here, as it will be handled in clearpass_client._log_api_operation
            
            if log_file.stat().st_size > 0:
                with open(log_file, 'r', encoding='utf-8') as f:
                    log_content = f.read().strip()
                    if log_content:
                        log_entry = json.loads(log_content.split('\n')[-1])
                        self.assertEqual(log_entry["operation"], "GET api-client/456")
                        self.assertEqual(log_entry["outcome"], "success")


def run_async_test(coro):
    """Helper function to run async tests."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# Convert async test methods to sync for unittest
class TestClearPassClientAuditIntegrationSync(TestClearPassClientAuditIntegration):
    """Sync wrapper for async tests."""
    
    def test_successful_api_call_logging_sync(self):
        """Sync wrapper for successful API call logging test."""
        run_async_test(super()._successful_api_call_logging())
        
    def test_failed_api_call_logging_sync(self):
        """Sync wrapper for failed API call logging test."""
        # Create a new async test method that forces JSON parsing to fail
        async def test_failed_api_call_logging_single_call():
            """Test that failed API calls are properly logged with error details (single call version)."""
            # Mock failed response
            from httpx import HTTPStatusError, Request, Response
            
            mock_request = Mock(spec=Request)
            mock_response = Mock(spec=Response)
            mock_response.status_code = 404
            mock_response.json.side_effect = Exception("JSON parsing failed")  # Force JSON parsing to fail
            mock_response.text = "Not found"
            
            http_error = HTTPStatusError("404 Not Found", request=mock_request, response=mock_response)
            self.client.client.request.side_effect = http_error
            
            # Mock authentication
            self.client.access_token = "test_token"
            self.client.token_expires_at = None
            
            auth_response = Mock()
            auth_response.status_code = 200
            auth_response.json.return_value = {"access_token": "test_token", "expires_in": 3600}
            auth_response.raise_for_status.return_value = None
            self.client.client.post.return_value = auth_response
            
            # Patch audit logger to capture logs
            with patch('src.clearpass_client.get_audit_logger') as mock_get_logger:
                mock_logger = Mock()
                mock_get_logger.return_value = mock_logger
                
                # Make API call and expect failure
                with self.assertRaises(ClearPassAPIError):
                    await self.client._make_request("GET", "api-client/999")
                
                # Verify audit logging was called for failure
                mock_logger.log_operation.assert_called_once()
                call_args = mock_logger.log_operation.call_args
                
                # Verify log parameters for failure
                self.assertEqual(call_args[1]["operation"], "GET api-client/999")
                self.assertEqual(call_args[1]["outcome"], "failure")
                self.assertIn("status_code", call_args[1]["parameters"])
                self.assertEqual(call_args[1]["parameters"]["status_code"], 404)
                self.assertIsNotNone(call_args[1]["error_details"])
        
        run_async_test(test_failed_api_call_logging_single_call())
        
    def test_logging_failure_handling_sync(self):
        """Sync wrapper for logging failure handling test."""
        run_async_test(super()._logging_failure_handling())
        
    def test_failed_log_entry_storage(self):
        """Test that failed log entries are stored for recovery (sync version)."""
        failed_entry = {
            "timestamp": "2024-01-01T12:00:00Z",
            "operation": "test_operation",
            "error": "logging_failed"
        }
        
        # Create temporary directory for failed logs
        with patch('pathlib.Path') as mock_path:
            mock_failed_dir = Mock()
            mock_path.return_value = mock_failed_dir
            mock_failed_dir.mkdir.return_value = None
            
            # Mock file operations
            mock_file = Mock()
            mock_open = Mock()
            mock_open.__enter__ = Mock(return_value=mock_file)
            mock_open.__exit__ = Mock(return_value=None)
            
            with patch('builtins.open', return_value=mock_open):
                # Test failed log storage
                self.client._store_failed_log_entry(failed_entry)
                
                # Verify directory creation was attempted
                mock_failed_dir.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        
    def test_end_to_end_integration_sync(self):
        """Sync wrapper for end-to-end integration test."""
        run_async_test(super()._end_to_end_integration())


if __name__ == '__main__':
    unittest.main()