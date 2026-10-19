"""
Test suite for Guest User MCP Tools

Tests the implementation of Task 11: Guest User MCP Tools integration
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
from src.tools.guest_users import list_guest_users, get_guest_user, create_guest_user, update_guest_user, delete_guest_user
from fastmcp import Context

class TestGuestUserTools:
    """Test suite for Guest User MCP tools"""

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
        client.list_guest_users = AsyncMock()
        client.get_guest_user = AsyncMock()
        client.create_guest_user = AsyncMock()
        client.update_guest_user = AsyncMock()
        client.delete_guest_user = AsyncMock()
        return client

    @pytest.fixture
    def sample_guest_user_response(self):
        """Sample guest user response data"""
        return {
            "id": 1,
            "username": "testuser",
            "role_name": "Guest",
            "enabled": True,
            "expire_time": "2025-12-31T23:59:59Z"
        }

    @pytest.fixture
    def sample_guest_users_list_response(self):
        """Sample guest users list response"""
        return {
            "_embedded": {
                "items": [
                    {
                        "id": 1,
                        "username": "guest1",
                        "role_name": "Guest",
                        "enabled": True
                    },
                    {
                        "id": 2,
                        "username": "guest2",
                        "role_name": "Visitor",
                        "enabled": False
                    }
                ]
            }
        }

    # Tests for list_guest_users
    @pytest.mark.asyncio
    async def test_list_guest_users_success(self, mock_context, mock_clearpass_client, sample_guest_users_list_response):
        """Test successful guest users listing"""
        mock_clearpass_client.list_guest_users.return_value = sample_guest_users_list_response
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_guest_users(mock_context, limit=50)
            assert result["success"] is True
            assert result["total_count"] == 2
            assert len(result["users"]) == 2
            mock_clearpass_client.list_guest_users.assert_called_once_with(filter_enabled=None, role_filter=None, limit=50)

    @pytest.mark.asyncio
    async def test_list_guest_users_with_filters(self, mock_context, mock_clearpass_client, sample_guest_users_list_response):
        """Test guest users listing with filters"""
        mock_clearpass_client.list_guest_users.return_value = sample_guest_users_list_response
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_guest_users(mock_context, filter_enabled=True, role_filter="Guest", limit=25)
            assert result["success"] is True
            mock_clearpass_client.list_guest_users.assert_called_once_with(filter_enabled=True, role_filter="Guest", limit=25)

    @pytest.mark.asyncio
    async def test_list_guest_users_api_error(self, mock_context, mock_clearpass_client):
        """Test guest users listing with API error"""
        error = ClearPassAPIError("Unauthorized", status_code=401)
        mock_clearpass_client.list_guest_users.side_effect = error
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_guest_users(mock_context, limit=50)
            assert result["success"] is False
            assert result["error_type"] == "api_error"
            assert result["status_code"] == 401

    # Tests for get_guest_user
    @pytest.mark.asyncio
    async def test_get_guest_user_success_by_id(self, mock_context, mock_clearpass_client, sample_guest_user_response):
        """A numeric user_id is routed to the by-id endpoint."""
        mock_clearpass_client.get_guest_user.return_value = sample_guest_user_response
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_guest_user(mock_context, user_id=1)
            assert result["success"] is True
            assert result["user"]["username"] == "testuser"
            mock_clearpass_client.get_guest_user.assert_called_once_with(1)
            mock_clearpass_client.get_guest_user_by_username.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_guest_user_success_by_username(self, mock_context, mock_clearpass_client, sample_guest_user_response):
        """A non-numeric user_id is routed to the by-username endpoint."""
        mock_clearpass_client.get_guest_user_by_username.return_value = sample_guest_user_response
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_guest_user(mock_context, user_id="testuser")
            assert result["success"] is True
            assert result["user"]["username"] == "testuser"
            mock_clearpass_client.get_guest_user_by_username.assert_called_once_with("testuser")
            mock_clearpass_client.get_guest_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_guest_user_not_found(self, mock_context, mock_clearpass_client):
        """Test guest user retrieval with not found error"""
        error = ClearPassAPIError("Not found", status_code=404)
        mock_clearpass_client.get_guest_user_by_username.side_effect = error
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_guest_user(mock_context, user_id="nonexistent")
            assert result["success"] is False
            assert result["error_type"] == "api_error"
            assert result["status_code"] == 404

    # Tests for create_guest_user
    @pytest.mark.asyncio
    async def test_create_guest_user_success(self, mock_context, mock_clearpass_client, sample_guest_user_response):
        """Test successful guest user creation"""
        mock_clearpass_client.create_guest_user.return_value = sample_guest_user_response
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await create_guest_user(
                mock_context,
                username="newguest",
                password="password123",
                role_name="Visitor",
                enabled=True,
                expire_time="2025-12-31T23:59:59Z"
            )
            assert result["success"] is True
            assert "created successfully" in result["message"]
            mock_clearpass_client.create_guest_user.assert_called_once()
            call_args = mock_clearpass_client.create_guest_user.call_args[0][0]
            assert call_args["username"] == "newguest"
            assert call_args["password"] == "password123"

    @pytest.mark.asyncio
    async def test_create_guest_user_api_error(self, mock_context, mock_clearpass_client):
        """Test guest user creation with API error"""
        error = ClearPassAPIError("Bad Request", status_code=400)
        mock_clearpass_client.create_guest_user.side_effect = error
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await create_guest_user(
                mock_context,
                username="invaliduser",
                password="pwd"
            )
            assert result["success"] is False
            assert result["status_code"] == 400

    # Tests for update_guest_user
    @pytest.mark.asyncio
    async def test_update_guest_user_success(self, mock_context, mock_clearpass_client, sample_guest_user_response):
        """Test successful guest user update"""
        updated_response = sample_guest_user_response.copy()
        updated_response["enabled"] = False
        mock_clearpass_client.update_guest_user_by_username.return_value = updated_response
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await update_guest_user(
                mock_context,
                user_id="testuser",
                enabled=False,
                role_name="Admin"
            )
            assert result["success"] is True
            assert "updated successfully" in result["message"]
            assert "enabled" in result["updated_fields"]
            assert "role_name" in result["updated_fields"]
            # A non-numeric user_id must be routed to the by-username endpoint;
            # PATCH guest/<username> is rejected with 422 "ID '<name>' is invalid".
            mock_clearpass_client.update_guest_user.assert_not_called()
            mock_clearpass_client.update_guest_user_by_username.assert_called_once()
            call_args = mock_clearpass_client.update_guest_user_by_username.call_args
            assert call_args[0][0] == "testuser"
            update_data = call_args[0][1]
            assert update_data["enabled"] is False
            assert update_data["role_name"] == "Admin"

    @pytest.mark.asyncio
    async def test_update_guest_user_no_parameters(self, mock_context, mock_clearpass_client):
        """Test guest user update with no parameters"""
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await update_guest_user(mock_context, user_id="testuser")
            assert result["success"] is False
            assert "No update parameters provided" in result["error"]

    # Tests for delete_guest_user
    @pytest.mark.asyncio
    async def test_delete_guest_user_success(self, mock_context, mock_clearpass_client):
        """A username is deleted through the by-username endpoint."""
        mock_clearpass_client.delete_guest_user_by_username.return_value = None
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await delete_guest_user(mock_context, user_id="testuser", confirm=True)
            assert result["success"] is True
            assert "deleted successfully" in result["message"]
            mock_clearpass_client.delete_guest_user_by_username.assert_called_once_with("testuser")
            mock_clearpass_client.delete_guest_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_guest_user_by_numeric_id(self, mock_context, mock_clearpass_client):
        """A numeric user_id is deleted through the by-id endpoint."""
        mock_clearpass_client.delete_guest_user.return_value = None
        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            result = await delete_guest_user(mock_context, user_id=42, confirm=True)
            assert result["success"] is True
            mock_clearpass_client.delete_guest_user.assert_called_once_with(42)
            mock_clearpass_client.delete_guest_user_by_username.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_guest_user_no_confirmation(self, mock_context):
        """Test guest user deletion without confirmation"""
        result = await delete_guest_user(mock_context, user_id="testuser", confirm=False)
        assert result["success"] is False
        assert "requires confirmation" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_full_guest_user_lifecycle(self, mock_clearpass_client):
        """Test complete guest user lifecycle: create, get, update, delete"""
        create_response = {
            "id": 100,
            "username": "lifecycle-guest",
            "role_name": "Guest",
            "enabled": True,
            "expire_time": "2025-12-31T23:59:59Z"
        }
        get_response = create_response.copy()
        update_response = create_response.copy()
        update_response["enabled"] = False

        mock_clearpass_client.create_guest_user.return_value = create_response
        mock_clearpass_client.get_guest_user.return_value = get_response
        mock_clearpass_client.update_guest_user.return_value = update_response
        mock_clearpass_client.delete_guest_user.return_value = None

        mock_context = Mock(spec=Context)
        mock_context.info = AsyncMock()

        with patch('src.tools.guest_users.get_clearpass_client', return_value=mock_clearpass_client):
            # Create
            create_result = await create_guest_user(
                mock_context,
                username="lifecycle-guest",
                password="lifecycle_password"
            )
            assert create_result["success"] is True

            # Get
            get_result = await get_guest_user(mock_context, user_id=100)
            assert get_result["success"] is True

            # Update
            update_result = await update_guest_user(
                mock_context,
                user_id=100,
                enabled=False
            )
            assert update_result["success"] is True

            # Delete
            delete_result = await delete_guest_user(
                mock_context,
                user_id=100,
                confirm=True
            )
            assert delete_result["success"] is True

class TestGuestManagerRoleNamespace:
    """A guest account's role_id belongs to the Guest Manager namespace.

    Resolving it against the Policy Manager /role namespace is a privilege
    escalation: "[Guest]" is 3 in Policy Manager, and 3 means "[Employee]" to
    Guest Manager, so every account created that way silently gets employee
    access while the caller is told it got "[Guest]".
    """

    def _client(self, options=None, raise_on=("POST", "guest")):
        from src.client_methods.guest_users import GuestUserMethodsMixin

        if options is None:
            options = {"1": "[Contractor]", "3": "[Employee]", "2": "[Guest]"}

        class FakeClient(GuestUserMethodsMixin):
            def __init__(self):
                self.calls = []

            async def _make_request(self, method, endpoint, data=None, params=None):
                self.calls.append((method, endpoint, data, params))
                if (method, endpoint) == raise_on and (data or {}).get("role_id") == -1:
                    # Shaped exactly like what ClearPassClient._make_request
                    # raises: message *and* the parsed body on response_data.
                    body = {"validation_messages": {"role_id": {
                        "error": "Invalid role_id", "_options": options}}}
                    raise ClearPassAPIError(
                        "API request failed: POST guest - 422 - Invalid role_id - "
                        + __import__("json").dumps(body),
                        422,
                        body,
                    )
                if method == "POST" and endpoint == "guest":
                    return {"id": 1, "username": data.get("username"),
                            "role_id": data.get("role_id")}
                if method == "GET" and endpoint == "role":
                    # Policy Manager namespace: the wrong answer.
                    return {"_embedded": {"items": [{"id": 3, "name": "[Guest]"}]}}
                return {}

        return FakeClient()

    @pytest.mark.asyncio
    async def test_role_namespace_is_read_from_the_appliance(self):
        client = self._client()
        roles = await client.list_guest_manager_roles()
        assert roles == {"[Contractor]": 1, "[Guest]": 2, "[Employee]": 3}
        # The probe must never reach the Policy Manager role endpoint.
        assert all(call[1] != "role" for call in client.calls)

    @pytest.mark.asyncio
    async def test_guest_role_resolves_to_the_guest_manager_id(self):
        client = self._client()
        assert await client.get_guest_role_id_by_name("[Guest]") == 2
        assert await client.get_guest_role_id_by_name("[Employee]") == 3
        # Unbracketed and mis-cased names still land on the right role.
        assert await client.get_guest_role_id_by_name("Guest") == 2
        assert await client.get_guest_role_id_by_name("[guest]") == 2

    @pytest.mark.asyncio
    async def test_create_submits_the_guest_manager_role_id(self):
        client = self._client()
        created = await client.create_guest_user(
            {"username": "u", "password": "p", "role_name": "[Guest]"})
        assert created["role_id"] == 2, "Policy Manager id 3 must never be submitted"

    @pytest.mark.asyncio
    async def test_unknown_role_fails_loudly(self):
        client = self._client()
        with pytest.raises(ValueError) as excinfo:
            await client.create_guest_user(
                {"username": "u", "password": "p", "role_name": "Nope"})
        assert "not found" in str(excinfo.value)
        assert "[Guest]" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_default_role_name_exists_on_a_stock_appliance(self):
        """create_guest_user's default must be a real ClearPass role."""
        import inspect

        from src.registry import registry
        import src.tools.guest_users  # noqa: F401

        spec = registry.get("create_guest_user")
        default = inspect.signature(spec.func).parameters["role_name"].default
        assert getattr(default, "default", default) == "[Guest]"
        client = self._client()
        assert await client.get_guest_role_id_by_name("[Guest]") == 2


class TestResponseBodyErrors:
    """HTTP 200 with an error body must not be reported as success."""

    def test_error_flag_in_body(self):
        from src.models.guest_common import find_response_error

        err = find_response_error(
            {"error": 1, "field": "id",
             "message": "There is no print template with ID %1"})
        assert err and "no print template" in err

    def test_missing_expected_payload(self):
        from src.models.guest_common import find_response_error

        err = find_response_error({"message": "Pass downloads have been disabled."},
                                  expected_keys=("digital_pass",))
        assert err == "Pass downloads have been disabled."

    def test_bare_acknowledgement_is_not_proof(self):
        from src.models.guest_common import find_response_error

        assert find_response_error({"success": True},
                                   expected_keys=("user", "guest_receipt"))

    def test_good_body_passes(self):
        from src.models.guest_common import find_response_error

        assert find_response_error({"digital_pass": "..."},
                                   expected_keys=("digital_pass",)) is None
        assert find_response_error({"id": 1, "name": "t", "error": 0}) is None
        assert find_response_error("not a dict") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])