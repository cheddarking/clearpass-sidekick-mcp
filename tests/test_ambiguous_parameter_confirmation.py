"""
Test suite for Ambiguous Parameter Confirmation Logic (Task 14).

Tests the implementation of the format_clarification_needed helper function.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock
from typing import Dict, Any, Optional, List

# Import the modules we're testing
from src.utils import format_clarification_needed
from fastmcp import Context

class TestAmbiguousParameterConfirmation:
    """Test suite for ambiguous parameter confirmation logic"""

    @pytest.fixture
    def mock_context(self):
        """Create a mock FastMCP context"""
        context = Mock(spec=Context)
        context.info = AsyncMock()
        return context

    @pytest.mark.asyncio
    async def test_format_clarification_needed_basic(self):
        """Test basic clarification needed formatting without options."""
        message = "Missing required parameter."
        question = "What is the client ID?"
        
        formatted = await format_clarification_needed(message, question)
        
        assert formatted["success"] is False
        assert formatted["error_type"] == "clarification_needed"
        assert formatted["message"] == message
        assert formatted["question"] == question
        assert "options" not in formatted

    @pytest.mark.asyncio
    async def test_format_clarification_needed_with_options(self):
        """Test clarification needed formatting with options."""
        message = "Ambiguous device name."
        question = "Which device do you mean?"
        options = ["device-1", "device-2", "device-3"]
        
        formatted = await format_clarification_needed(message, question, options)
        
        assert formatted["success"] is False
        assert formatted["error_type"] == "clarification_needed"
        assert formatted["message"] == message
        assert formatted["question"] == question
        assert formatted["options"] == options

    @pytest.mark.asyncio
    async def test_format_clarification_needed_empty_options(self):
        """Test clarification needed formatting with empty options list."""
        message = "No matching records found."
        question = "Please provide a different filter."
        options = []
        
        formatted = await format_clarification_needed(message, question, options)
        
        assert formatted["success"] is False
        assert formatted["error_type"] == "clarification_needed"
        assert formatted["message"] == message
        assert formatted["question"] == question
        assert formatted["options"] == []

    @pytest.mark.asyncio
    async def test_format_clarification_needed_long_message_question(self):
        """Test with long message and question to ensure handling."""
        long_message = "This is a very long message that explains in detail why clarification is needed for the current operation. It might exceed typical line limits but should still be handled correctly by the formatting function."
        long_question = "Could you please specify the exact identifier for the resource you are trying to modify, as there are multiple resources that match the partial information you provided, and we need to ensure we target the correct one?"
        
        formatted = await format_clarification_needed(long_message, long_question)
        
        assert formatted["success"] is False
        assert formatted["message"] == long_message
        assert formatted["question"] == long_question

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])