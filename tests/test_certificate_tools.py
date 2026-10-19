"""
Test suite for Certificate MCP Tools

Tests the implementation of Task 12: Certificate MCP Tools integration
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
from src.tools.certificates import list_certificate_trust_list, get_certificate_trust_list_details, import_certificate_to_trust_list, list_client_certificates, get_client_certificate_by_id, list_server_certificates, get_server_certificate_details, list_service_certificates
from fastmcp import Context

class TestCertificateTools:
    """Test suite for Certificate MCP tools"""

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
        client.list_certificates = AsyncMock()
        client.get_certificate = AsyncMock()
        return client

    @pytest.fixture
    def sample_certificate_response(self):
        """Sample certificate response data"""
        return {
            "id": 1,
            "name": "test-cert",
            "issuer": "Test CA",
            "subject": "CN=test.example.com",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_to": "2025-01-01T00:00:00Z",
            "type": "Server",
            "status": "Valid"
        }

    @pytest.fixture
    def sample_certificates_list_response(self):
        """Sample certificates list response"""
        return {
            "_embedded": {
                "items": [
                    {
                        "id": 1,
                        "name": "cert-1",
                        "issuer": "CA-1",
                        "subject": "CN=host1",
                        "valid_from": "2024-01-01T00:00:00Z",
                        "valid_to": "2025-01-01T00:00:00Z",
                        "type": "Server",
                        "status": "Valid"
                    },
                    {
                        "id": 2,
                        "name": "cert-2",
                        "issuer": "CA-2",
                        "subject": "CN=host2",
                        "valid_from": "2024-02-01T00:00:00Z",
                        "valid_to": "2025-02-01T00:00:00Z",
                        "type": "Client",
                        "status": "Valid"
                    }
                ]
            }
        }

    # Tests for list_certificate_trust_list
    @pytest.mark.asyncio
    async def test_list_certificates_success(self, mock_context, mock_clearpass_client, sample_certificates_list_response):
        """Test successful certificate trust list listing"""
        mock_clearpass_client.list_certificate_trust_list.return_value = sample_certificates_list_response
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_certificate_trust_list(mock_context, limit=50)
            assert result["success"] is True
            assert result["returned_count"] == 2
            assert len(result["trust_list_entries"]) == 2
            # None-valued optional params are stripped before hitting the client
            mock_clearpass_client.list_certificate_trust_list.assert_called_once_with(limit=50)

    @pytest.mark.asyncio
    async def test_list_certificates_total_count_requires_calculate_count(
        self, mock_context, mock_clearpass_client, sample_certificates_list_response
    ):
        """total_count is only populated when calculate_count is requested."""
        mock_clearpass_client.list_certificate_trust_list.return_value = sample_certificates_list_response
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_certificate_trust_list(mock_context, limit=50, calculate_count=True)
            assert result["success"] is True
            assert result["total_count"] == 2
            mock_clearpass_client.list_certificate_trust_list.assert_called_once_with(
                limit=50, calculate_count=True
            )

    @pytest.mark.asyncio
    async def test_list_certificates_with_filter(self, mock_context, mock_clearpass_client, sample_certificates_list_response):
        """Test trust list listing with a JSON filter expression"""
        mock_clearpass_client.list_certificate_trust_list.return_value = sample_certificates_list_response
        json_filter = '{"cert_type": "Server"}'
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_certificate_trust_list(mock_context, filter_str=json_filter, limit=25)
            assert result["success"] is True
            mock_clearpass_client.list_certificate_trust_list.assert_called_once_with(
                limit=25, filter=json_filter
            )

    @pytest.mark.asyncio
    async def test_list_certificates_drops_non_json_filter(
        self, mock_context, mock_clearpass_client, sample_certificates_list_response
    ):
        """A non-JSON filter is dropped rather than forwarded to the API."""
        mock_clearpass_client.list_certificate_trust_list.return_value = sample_certificates_list_response
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_certificate_trust_list(mock_context, filter_str="type eq 'Server'", limit=25)
            assert result["success"] is True
            assert "filter" not in mock_clearpass_client.list_certificate_trust_list.call_args.kwargs

    @pytest.mark.asyncio
    async def test_list_certificates_api_error(self, mock_context, mock_clearpass_client):
        """Test trust list listing with API error"""
        error = ClearPassAPIError("Unauthorized", status_code=401)
        mock_clearpass_client.list_certificate_trust_list.side_effect = error
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await list_certificate_trust_list(mock_context, limit=50)
            assert result["success"] is False
            assert result["error_type"] == "api_error"
            assert result["status_code"] == 401

    # Tests for get_client_certificate_by_id
    @pytest.mark.asyncio
    async def test_get_certificate_success(self, mock_context, mock_clearpass_client, sample_certificate_response):
        """Test successful certificate retrieval"""
        mock_clearpass_client.get_client_certificate_by_id.return_value = sample_certificate_response
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_client_certificate_by_id(mock_context, client_cert_id=1)
            assert result["success"] is True
            assert result["client_certificate"]["name"] == "test-cert"
            mock_clearpass_client.get_client_certificate_by_id.assert_called_once_with(1)

    @pytest.mark.asyncio
    async def test_get_certificate_not_found(self, mock_context, mock_clearpass_client):
        """Test certificate retrieval with not found error"""
        error = ClearPassAPIError("Not found", status_code=404)
        mock_clearpass_client.get_client_certificate_by_id.side_effect = error
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await get_client_certificate_by_id(mock_context, client_cert_id=999)
            assert result["success"] is False
            assert result["error_type"] == "api_error"
            assert result["status_code"] == 404
            assert "not found" in result["suggestion"].lower()

    @pytest.mark.asyncio
    async def test_get_certificate_requires_id(self, mock_context, mock_clearpass_client):
        """Omitting a required Field(...) parameter raises, not silently passes FieldInfo."""
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            with pytest.raises(TypeError, match="client_cert_id"):
                await get_client_certificate_by_id(mock_context)

    # ------------------------------------------------------------------
    # cert_usage vocabulary
    #
    # ClearPass 6.12.4 accepts only its own usage names. The tool used to
    # normalise friendly input into invented constants ('TLS' -> 'OTHER_TLS',
    # 'HTTPS' -> 'HTTPS_SERVER'), every one of which the appliance rejects with
    # `422 Invalid Certificate usage "<x>" specified` -- so an LLM following the
    # docstring could never get a 200. The accepted set was read off the live
    # appliance (the distinct cert_usage values on its 51 trust-list objects)
    # and each candidate confirmed by POST probe.
    # ------------------------------------------------------------------

    APPLIANCE_USAGES = (
        "EAP", "Others", "SAML", "SMTP", "AD/LDAP Servers", "Aruba Services",
        "Aruba Infrastructure", "Endpoint Context Servers", "RadSec", "Database",
    )

    REJECTED_CONSTANTS = ("OTHER_TLS", "HTTPS_SERVER", "SAML_IDP", "RADIUS_PROXY_TLS")

    async def _imported_usage(self, mock_context, mock_clearpass_client, usages):
        """Run the import tool and return the cert_usage it actually sent."""
        mock_clearpass_client.import_certificate_to_trust_list.return_value = {"id": 1}
        with patch('src.tools.certificates.get_clearpass_client', return_value=mock_clearpass_client):
            result = await import_certificate_to_trust_list(
                mock_context, cert_file_content="-----BEGIN CERTIFICATE-----",
                cert_usage=list(usages), enabled=False)
        assert result["success"] is True
        payload = mock_clearpass_client.import_certificate_to_trust_list.call_args.args[0]
        return payload["cert_usage"]

    @pytest.mark.asyncio
    async def test_cert_usage_appliance_values_round_trip(self, mock_context, mock_clearpass_client):
        """Every real appliance value survives normalisation with its own spelling."""
        sent = await self._imported_usage(mock_context, mock_clearpass_client, self.APPLIANCE_USAGES)
        assert sent == list(self.APPLIANCE_USAGES)

    @pytest.mark.asyncio
    async def test_cert_usage_friendly_aliases_map_to_appliance_values(self, mock_context, mock_clearpass_client):
        """'TLS'/'other'/'HTTPS' become 'Others'; the other aliases map likewise."""
        aliases = {
            "TLS": "Others",
            "other": "Others",
            "OTHER_TLS": "Others",
            "HTTPS": "Others",
            "HTTPS_SERVER": "Others",
            "SAML_IDP": "SAML",
            "RADIUS_PROXY_TLS": "RadSec",
            "AD": "AD/LDAP Servers",
            "ldap": "AD/LDAP Servers",
            "ECS": "Endpoint Context Servers",
        }
        sent = await self._imported_usage(mock_context, mock_clearpass_client, aliases.keys())
        assert sent == list(aliases.values())

    @pytest.mark.asyncio
    async def test_cert_usage_never_emits_a_rejected_constant(self, mock_context, mock_clearpass_client):
        """No input may produce a value the appliance answers 422 for."""
        probes = list(self.APPLIANCE_USAGES) + list(self.REJECTED_CONSTANTS) + \
            ["TLS", "HTTPS", "other", "AD", "ldap", "ECS", "db"]
        sent = await self._imported_usage(mock_context, mock_clearpass_client, probes)
        for value in sent:
            assert value not in self.REJECTED_CONSTANTS
        assert set(sent) <= set(self.APPLIANCE_USAGES)

    @pytest.mark.asyncio
    async def test_cert_usage_case_insensitive(self, mock_context, mock_clearpass_client):
        """Any casing of a real value normalises to the appliance's own spelling."""
        sent = await self._imported_usage(
            mock_context, mock_clearpass_client,
            ["others", "OTHERS", "eap", "radsec", "aruba services"])
        assert sent == ["Others", "Others", "EAP", "RadSec", "Aruba Services"]

    @pytest.mark.asyncio
    async def test_cert_usage_unknown_value_passes_through(self, mock_context, mock_clearpass_client):
        """A vocabulary a newer ClearPass adds must not be silently rewritten."""
        sent = await self._imported_usage(
            mock_context, mock_clearpass_client, ["Some Future Usage"])
        assert sent == ["Some Future Usage"]

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])