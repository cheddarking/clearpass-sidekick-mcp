"""
Test suite for Feedback and Error Reporting Formatting (Task 13).

Tests the implementation of user-friendly error messages and success summaries.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

# Import the modules we're testing
from src.utils import format_api_error, format_validation_error, format_unexpected_error, format_error
from src.exceptions import ClearPassAPIError
from fastmcp import Context

class TestFeedbackErrorFormatting:
    """Test suite for feedback and error reporting formatting"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock FastMCP context"""
        context = Mock(spec=Context)
        context.info = AsyncMock()
        return context

    @pytest.mark.asyncio
    async def test_format_api_error_401(self):
        """Test API error formatting for 401 Unauthorized."""
        error = ClearPassAPIError("Authentication failed", status_code=401)
        formatted = await format_api_error(error, "test_operation")
        assert formatted["success"] is False
        assert formatted["operation"] == "test_operation"
        assert formatted["error_type"] == "api_error"
        assert formatted["status_code"] == 401
        assert "credentials" in formatted["suggestion"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_api_error_403(self):
        """Test API error formatting for 403 Forbidden."""
        error = ClearPassAPIError("Permission denied", status_code=403)
        formatted = await format_api_error(error, "test_operation")
        assert formatted["success"] is False
        assert formatted["status_code"] == 403
        assert "permission" in formatted["suggestion"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_api_error_404(self):
        """Test API error formatting for 404 Not Found."""
        error = ClearPassAPIError("Resource not found", status_code=404)
        formatted = await format_api_error(error, "test_operation")
        assert formatted["success"] is False
        assert formatted["status_code"] == 404
        assert "not found" in formatted["suggestion"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_api_error_500(self):
        """Test API error formatting for 500 Internal Server Error."""
        error = ClearPassAPIError("Internal server error", status_code=500)
        formatted = await format_api_error(error, "test_operation")
        assert formatted["success"] is False
        assert formatted["status_code"] == 500
        assert "server error" in formatted["suggestion"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_api_error_connection_timeout(self):
        """Test API error formatting for connection timeout."""
        error = ClearPassAPIError("Connection timeout occurred")
        formatted = await format_api_error(error, "test_operation")
        assert formatted["success"] is False
        assert "network connectivity" in formatted["suggestion"].lower()
        assert "timeout" in formatted["suggestion"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_api_error_generic(self):
        """Test API error formatting for a generic error."""
        error = ClearPassAPIError("Something unexpected happened", status_code=400)
        formatted = await format_api_error(error, "test_operation")
        assert formatted["success"] is False
        assert formatted["status_code"] == 400
        assert "parameters" in formatted["suggestion"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_validation_error(self):
        """Test validation error formatting."""
        formatted = await format_validation_error("Invalid value", "test_operation")
        assert formatted["success"] is False
        assert formatted["error_type"] == "validation_error"
        assert formatted["error"] == "Invalid value"
        assert "validation error" in formatted["message"].lower()
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_unexpected_error(self):
        """Test unexpected / value error formatting."""
        err = ValueError("bad value")
        formatted = await format_unexpected_error(err, "test_operation")
        assert formatted["success"] is False
        assert formatted["error_type"] == "value_error"
        assert "bad value" in formatted["error"]
        assert formatted["message"] == formatted["suggestion"]

    @pytest.mark.asyncio
    async def test_format_error_dispatcher(self):
        """Test format_error dispatching logic."""
        api_err = ClearPassAPIError("Auth fail", status_code=401)
        res1 = await format_error(api_err, "op")
        assert res1["error_type"] == "api_error"

        val_err = ValueError("invalid input")
        res2 = await format_error(val_err, "op")
        assert res2["error_type"] == "value_error"

        gen_err = RuntimeError("boom")
        res3 = await format_error(gen_err, "op")
        assert res3["error_type"] == "unexpected_error"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
