"""
Test suite for API Client MCP Tools

Tests the implementation of Task 9: API Client MCP Tools integration
with the ClearPass API client.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

# Import the modules we're testing
from src.app_config import get_clearpass_client, CLEARPASS_CONFIG
from src.utils import format_api_error
from src.exceptions import ClearPassAPIError
from src.tools.api_clients import list_api_clients, create_api_client, get_api_client, update_api_client, delete_api_client
from src.tools.server_utility import _test_clearpass_connection_tool
from fastmcp import Context

class TestApiClientTools:
    """Test suite for API Client MCP tools"""
    
    @pytest.fixture
    def mock_context(self):
        """Create a mock FastMCP context"""
        context = Mock(spec=Context)
        context.info = AsyncMock()
        return context
    
    @pytest.fixture
    def mock_clearpass_client(self):
        """Create a mock ClearPass client"""
        client = AsyncMock()
        client.authenticate = AsyncMock()
        client.list_api_clients = AsyncMock()
        client.create_api_client = AsyncMock()
        client.get_api_client = AsyncMock()
        client.update_api_client = AsyncMock()
        client.delete_api_client = AsyncMock()
        client.get_system_health = AsyncMock()
        return client
    
    @pytest.fixture
    def sample_api_client_response(self):
        """Sample API client response data"""
        return {
            "id": 123,
            "client_id": "test-client",
            "description": "Test API client",
            "enabled": True,
            "scope": "read write",
            "grant_types": ["client_credentials"],
            "created_at": "2024-01-15T10:30:00Z"
        }
    
    @pytest.fixture
    def sample_clients_list_response(self):
        """Sample API clients list response"""
        return {
            "_embedded": {
                "items": [
                    {
                        "id": 1,
                        "client_id": "automation-bot",
                        "description": "Automation API client",
                        "enabled": True,
                        "scope": "read write"
                    },
                    {
                        "id": 2,
                        "client_id": "monitoring-service",
                        "description": "Monitoring client",
                        "enabled": True,
                        "scope": "read"
                    }
                ]
            }
        }
    
    @pytest.mark.asyncio
    async def test_get_clearpass_client_success(self, mock_clearpass_client):
        """Test successful ClearPass client initialization"""
        with patch('src.app_config.ClearPassClient', return_value=mock_clearpass_client):
            with patch('src.app_config.CLEARPASS_CONFIG', {
                'host': 'test.clearpass.com',
                'client_id': 'test_id',
                'client_secret': 'test_secret',
                'api_version': 'v1',
                'verify_ssl': True
            }):
                # Reset the singleton
                import src.app_config
                src.app_config._clearpass_client = None
                
                client = await get_clearpass_client()
                
                assert client is not None
                mock_clearpass_client.authenticate.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_clearpass_client_missing_host(self):
        """Test client initialization with missing host"""
        with patch('src.app_config.CLEARPASS_CONFIG', {
            'host': '',
            'client_id': 'test_id',
            'client_secret': 'test_secret'
        }):
            # Reset the singleton
            import src.app_config
            src.app_config._clearpass_client = None
            
            with pytest.raises(ValueError, match="ClearPass host not configured"):
                await get_clearpass_client()
    
    @pytest.mark.asyncio
    async def test_get_clearpass_client_missing_credentials(self):
        """Test client initialization with missing credentials"""
        with patch('src.app_config.CLEARPASS_CONFIG', {
            'host': 'test.clearpass.com',
            'client_id': '',
            'client_secret': '',
            'api_token': ''
        }):
            # Reset the singleton
            import src.app_config
            src.app_config._clearpass_client = None
            
            with pytest.raises(ValueError, match="ClearPass credentials not configured"):
                await get_clearpass_client()
    
    @pytest.mark.asyncio
    async def test_format_api_error(self):
        """Test API error formatting"""
        error = ClearPassAPIError("Authentication failed", status_code=401)
        formatted = await format_api_error(error, "test operation")
        
        assert formatted["success"] is False
        assert formatted["operation"] == "test operation"
        assert formatted["error_type"] == "api_error"
        assert formatted["status_code"] == 401
        assert "credentials" in formatted["suggestion"].lower()
    
    @pytest.mark.asyncio
    async def test_list_api_clients_success(self, mock_context, mock_clearpass_client, sample_clients_list_response):
        """Test successful API clients listing"""
        mock_clearpass_client.list_api_clients.return_value = sample_clients_list_response
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_api_clients(mock_context, limit=50)
            
            assert result["success"] is True
            assert result["total_count"] == 2
            assert len(result["clients"]) == 2
            assert result["clients"][0]["client_id"] == "automation-bot"
            mock_clearpass_client.list_api_clients.assert_called_once_with(filter_enabled=None, limit=50)
    
    @pytest.mark.asyncio
    async def test_list_api_clients_with_filter(self, mock_context, mock_clearpass_client, sample_clients_list_response):
        """Test API clients listing with filter"""
        mock_clearpass_client.list_api_clients.return_value = sample_clients_list_response
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_api_clients(mock_context, filter_enabled=True, limit=25)
            
            assert result["success"] is True
            mock_clearpass_client.list_api_clients.assert_called_once_with(filter_enabled=True, limit=25)
    
    @pytest.mark.asyncio
    async def test_list_api_clients_api_error(self, mock_context, mock_clearpass_client):
        """Test API clients listing with API error"""
        error = ClearPassAPIError("Unauthorized", status_code=401)
        mock_clearpass_client.list_api_clients.side_effect = error
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_api_clients(mock_context, limit=50)
            
            assert result["success"] is False
            assert result["error_type"] == "api_error"
            assert result["status_code"] == 401
    
    @pytest.mark.asyncio
    async def test_create_api_client_success(self, mock_context, mock_clearpass_client, sample_api_client_response):
        """Test successful API client creation"""
        mock_clearpass_client.create_api_client.return_value = sample_api_client_response
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await create_api_client(
                mock_context,
                client_id="test-client",
                description="Test client",
                scope="read write",
                enabled=True
            )
            
            assert result["success"] is True
            assert "created successfully" in result["message"]
            assert result["client"]["client_id"] == "test-client"
            
            # Verify the API call was made with correct parameters
            call_args = mock_clearpass_client.create_api_client.call_args[0][0]
            assert call_args["client_id"] == "test-client"
            # ClearPass names the field client_description, not description
            assert call_args["client_description"] == "Test client"
            assert call_args["enabled"] is True
            # scope is not supported by the ClearPass API and is deliberately not sent
            assert "scope" not in call_args
    
    @pytest.mark.asyncio
    async def test_create_api_client_invalid_scope(self, mock_context):
        """Test API client creation with invalid scope"""
        result = await create_api_client(
            mock_context,
            client_id="test-client",
            description="Test client",
            scope="invalid-scope"
        )
        
        assert result["success"] is False
        assert "Invalid scope" in result["error"]
    
    @pytest.mark.asyncio
    async def test_get_api_client_success(self, mock_context, mock_clearpass_client, sample_api_client_response):
        """Test successful API client retrieval"""
        mock_clearpass_client.get_api_client.return_value = sample_api_client_response
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_api_client(mock_context, client_id="test-client")
            
            assert result["success"] is True
            assert result["client"]["client_id"] == "test-client"
            mock_clearpass_client.get_api_client.assert_called_once_with("test-client")
    
    @pytest.mark.asyncio
    async def test_get_api_client_not_found(self, mock_context, mock_clearpass_client):
        """Test API client retrieval with not found error"""
        error = ClearPassAPIError("Not found", status_code=404)
        mock_clearpass_client.get_api_client.side_effect = error
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_api_client(mock_context, client_id="nonexistent")
            
            assert result["success"] is False
            assert result["status_code"] == 404
            assert "not found" in result["suggestion"].lower()
    
    @pytest.mark.asyncio
    async def test_update_api_client_success(self, mock_context, mock_clearpass_client, sample_api_client_response):
        """Test successful API client update"""
        updated_response = sample_api_client_response.copy()
        updated_response["description"] = "Updated description"
        mock_clearpass_client.update_api_client.return_value = updated_response
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await update_api_client(
                mock_context,
                client_id="test-client",
                description="Updated description",
                enabled=False
            )
            
            assert result["success"] is True
            assert "updated successfully" in result["message"]
            assert "client_description" in result["updated_fields"]
            assert "enabled" in result["updated_fields"]
            
            # Verify the API call was made with correct parameters
            call_args = mock_clearpass_client.update_api_client.call_args
            assert call_args[0][0] == "test-client"  # client_id
            update_data = call_args[0][1]
            assert update_data["client_description"] == "Updated description"
            assert update_data["enabled"] is False
    
    @pytest.mark.asyncio
    async def test_update_api_client_no_parameters(self, mock_context, mock_clearpass_client):
        """Test API client update with no parameters"""
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await update_api_client(mock_context, client_id="test-client")
            
            assert result["success"] is False
            assert "No update parameters provided" in result["error"]
    
    @pytest.mark.asyncio
    async def test_update_api_client_invalid_scope(self, mock_context, mock_clearpass_client):
        """Test API client update with invalid scope"""
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await update_api_client(
                mock_context,
                client_id="test-client",
                scope="invalid-scope"
            )
            
            assert result["success"] is False
            assert "Invalid scope" in result["error"]
    
    @pytest.mark.asyncio
    async def test_delete_api_client_success(self, mock_context, mock_clearpass_client):
        """Test successful API client deletion"""
        mock_clearpass_client.delete_api_client.return_value = None
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            result = await delete_api_client(
                mock_context,
                client_id="test-client",
                confirm=True
            )
            
            assert result["success"] is True
            assert "deleted successfully" in result["message"]
            mock_clearpass_client.delete_api_client.assert_called_once_with("test-client")
    
    @pytest.mark.asyncio
    async def test_delete_api_client_no_confirmation(self, mock_context):
        """Test API client deletion without confirmation"""
        result = await delete_api_client(mock_context, client_id="test-client", confirm=False)
        
        assert result["success"] is False
        assert "requires confirmation" in result["error"].lower()
        assert "destructive operation" in result["message"]
    
    @pytest.mark.asyncio
    async def test_test_clearpass_connection_success(self, mock_context, mock_clearpass_client):
        """Test successful ClearPass connection test"""
        health_response = {"status": "healthy", "version": "6.12.0"}
        mock_clearpass_client.get_system_health.return_value = health_response
        
        with patch('src.tools.server_utility.get_clearpass_client', return_value=mock_clearpass_client):
            result = await _test_clearpass_connection_tool(mock_context)
            
            assert result["success"] is True
            assert "Successfully connected" in result["message"]
            assert result["health_status"] == health_response
            assert "connection_details" in result
    
    @pytest.mark.asyncio
    async def test_test_clearpass_connection_config_error(self, mock_context):
        """Test connection test with configuration error"""
        with patch('src.tools.server_utility.get_clearpass_client', side_effect=ValueError("Host not configured")):
            result = await _test_clearpass_connection_tool(mock_context)
            
            assert result["success"] is False
            assert "Host not configured" in result["error"]
            assert "configuration_status" in result

    @pytest.mark.asyncio
    async def test_full_api_client_lifecycle(self, mock_clearpass_client):
        """Test complete API client lifecycle: create, get, update, delete"""
        # Mock responses for different operations
        create_response = {
            "id": 123,
            "client_id": "lifecycle-test",
            "description": "Test lifecycle",
            "enabled": True,
            "scope": "read",
            "client_secret": "generated-secret"
        }
        
        get_response = create_response.copy()
        update_response = create_response.copy()
        update_response["description"] = "Updated description"
        
        mock_clearpass_client.create_api_client.return_value = create_response
        mock_clearpass_client.get_api_client.return_value = get_response
        mock_clearpass_client.update_api_client.return_value = update_response
        mock_clearpass_client.delete_api_client.return_value = None
        
        mock_context = Mock(spec=Context)
        mock_context.info = AsyncMock()
        
        with patch('src.tools.api_clients.get_clearpass_client', return_value=mock_clearpass_client):
            # Test create

            create_result = await create_api_client(
                mock_context,
                client_id="lifecycle-test",
                description="Test lifecycle",
                scope="read" # Explicitly pass scope to avoid Field object issue
            )
            assert create_result["success"] is True
            
            # Test get
            get_result = await get_api_client(mock_context, client_id=123)
            assert get_result["success"] is True
            
            # Test update
            update_result = await update_api_client(
                mock_context,
                client_id=123,
                description="Updated description"
            )
            assert update_result["success"] is True
            
            # Test delete
            delete_result = await delete_api_client(
                mock_context,
                client_id=123,
                confirm=True
            )
            assert delete_result["success"] is True

class TestErrorHandling:
    """Test error handling scenarios"""
    
    @pytest.mark.asyncio
    async def test_various_http_status_codes(self):
        """Test error formatting for various HTTP status codes"""
        test_cases = [
            (401, "credentials"),
            (403, "permission"),
            (404, "not found"),
            (500, "server error"),
        ]
        
        for status_code, expected_keyword in test_cases:
            error = ClearPassAPIError(f"Error {status_code}", status_code=status_code)
            formatted = await format_api_error(error, "test operation")
            
            assert formatted["status_code"] == status_code
            assert expected_keyword.lower() in formatted["suggestion"].lower()
    
    @pytest.mark.asyncio
    async def test_connection_error_formatting(self):
        """Test formatting of connection errors"""
        error = ClearPassAPIError("Connection timeout occurred")
        formatted = await format_api_error(error, "test operation")
        
        assert "connectivity" in formatted["suggestion"].lower()

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])
