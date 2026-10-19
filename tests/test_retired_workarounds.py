"""Offline regression tests for three defects fixed on 2026-07-31.

All three were measured by direct curl against the lab ClearPass 6.12.4
appliance at the unversioned ``/api`` root before being fixed here.

1. **Dead certificate path.** ``CertificateMethodsMixin`` carried a
   ``get_server_certificate_by_uuid_and_name`` that issued
   ``GET server-cert-name/{uuid}/{name}``. That path is not served and answered
   **404 unconditionally** (measured for both ``RADIUS`` and ``HTTPS(RSA)``),
   which meant the ``server_uuid`` + ``service_name`` branch of the
   ``get_server_certificate_details`` operation could never succeed. The real
   route is ``server-cert/name/{uuid}/{name}`` (**200** for both), already
   implemented by the sibling ``get_server_certificate_by_name``. The dead
   duplicate was removed and the operation repointed at the working sibling.

2. **Deprecated Pydantic API.** ``enforcement_profiles`` called ``.dict()`` on
   Pydantic models. That is deprecated in V2 and removed in V3. Both call sites
   passed no arguments, so plain ``.model_dump()`` is an exact behavioural
   match.

3. **Retired ``/api/v1`` workaround.** ``get_network_device_by_name`` resolved a
   name through a server-side filtered list, documented on the premise that
   "ClearPass exposes no ``network-device/name/<name>`` endpoint". The premise
   was false -- it was an artefact of the old ``/api/v1`` mount. At ``/api`` the
   native route answers **200** for a real device and a structured
   **404 "Object not found"** for an absent one, so the composed scan was
   removed in favour of the native call.
"""

import ast
import pathlib

import httpx
import pytest

from src.clearpass_client import ClearPassClient
from src.client_methods.certificates import CertificateMethodsMixin
from src.client_methods.network_devices import NetworkDeviceMethodsMixin

SRC = pathlib.Path(__file__).resolve().parent.parent / "src"


def _recording_client():
    """A ``ClearPassClient`` whose transport records the call instead of sending it."""
    client = ClearPassClient.__new__(ClearPassClient)
    client.host = "https://appliance"
    client.api_version = "v1"
    client.base_url = "https://appliance/api"
    client.unversioned_base_url = "https://appliance/api"

    calls = []

    async def authenticate():
        return None

    async def request(**kwargs):
        calls.append(kwargs)
        return httpx.Response(
            200,
            json={"service_id": 1, "service_name": "RADIUS"},
            request=httpx.Request(kwargs["method"], kwargs["url"]),
        )

    class _Transport:
        pass

    transport = _Transport()
    transport.request = request

    client.authenticate = authenticate
    client.client = transport
    client._log_api_operation = lambda **kwargs: None
    client._extract_request_metadata = lambda *args, **kwargs: {}
    return client, calls


# ---------------------------------------------------------------------------
# 1. dead certificate path
# ---------------------------------------------------------------------------

def test_dead_server_cert_name_method_is_gone():
    """The op that could only ever 404 must not be reachable on the client."""
    assert not hasattr(CertificateMethodsMixin, "get_server_certificate_by_uuid_and_name")


def test_working_server_cert_by_name_method_survives():
    assert hasattr(CertificateMethodsMixin, "get_server_certificate_by_name")


@pytest.mark.asyncio
async def test_server_cert_by_name_uses_the_served_path():
    """``server-cert/name/...`` (200), never ``server-cert-name/...`` (404)."""
    client, calls = _recording_client()

    await client.get_server_certificate_by_name("a2130c28-uuid", "RADIUS")

    url = calls[0]["url"]
    assert url == "https://appliance/api/server-cert/name/a2130c28-uuid/RADIUS"
    assert "server-cert-name/" not in url


def test_no_source_file_still_references_the_dead_path():
    """Guards against the 404-only path being reintroduced anywhere in src/."""
    offenders = [
        str(p.relative_to(SRC))
        for p in SRC.rglob("*.py")
        if 'f"server-cert-name/' in p.read_text() or '"server-cert-name/' in p.read_text()
    ]
    assert offenders == [], f"dead server-cert-name path reintroduced in: {offenders}"


# ---------------------------------------------------------------------------
# 2. deprecated Pydantic .dict()
# ---------------------------------------------------------------------------

def test_no_pydantic_dict_calls_remain_in_src():
    """``.dict()`` is removed in Pydantic V3 -- ``.model_dump()`` everywhere."""
    offenders = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "dict"
                and not node.args
                and not node.keywords
            ):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert offenders == [], f"deprecated Pydantic .dict() calls: {offenders}"


def test_validate_profile_configuration_returns_a_plain_dict():
    """``.model_dump()`` must still hand the tool layer a real dict."""
    from src.models.enforcement_profiles import ValidationResult

    dumped = ValidationResult(is_valid=True).model_dump()
    assert isinstance(dumped, dict)
    # The tool layer reads these keys off the result by name.
    assert set(dumped) == {"is_valid", "warnings", "errors", "conflicts", "dependencies"}


# ---------------------------------------------------------------------------
# 3. retired network-device by-name workaround
# ---------------------------------------------------------------------------

def test_filtered_list_by_name_workaround_is_gone():
    assert not hasattr(NetworkDeviceMethodsMixin, "get_network_device_by_name")


@pytest.mark.asyncio
async def test_network_device_name_uses_the_native_route():
    """One request to the native route -- no client-side filtered-list scan."""
    client, calls = _recording_client()

    await client.get_network_device_name("AOS-CX-6200")

    assert len(calls) == 1, "a name lookup must not fan out into a list scan"
    assert calls[0]["method"] == "GET"
    assert calls[0]["url"] == "https://appliance/api/network-device/name/AOS-CX-6200"
    # The retired workaround passed a `filter` param against the collection.
    assert not (calls[0].get("params") or {})


@pytest.mark.asyncio
async def test_get_network_device_tool_resolves_a_name_natively():
    """The name branch of the `get_network_device` operation uses the native route."""
    from unittest.mock import AsyncMock, Mock, patch

    from fastmcp import Context

    from src.tools.network_devices import get_network_device

    ctx = Mock(spec=Context)
    ctx.info = AsyncMock()

    client = AsyncMock()
    client.get_network_device_name = AsyncMock(return_value={"id": 3001, "name": "AOS-CX-6200"})

    with patch("src.tools.network_devices.get_clearpass_client", AsyncMock(return_value=client)):
        result = await get_network_device(ctx, device_id="AOS-CX-6200")

    assert result["success"] is True
    client.get_network_device_name.assert_awaited_once_with("AOS-CX-6200")


@pytest.mark.asyncio
async def test_get_network_device_still_uses_the_numeric_route_for_an_id():
    """`network-device/<id>` only accepts a numeric id, so the branch must stay."""
    from unittest.mock import AsyncMock, Mock, patch

    from fastmcp import Context

    from src.tools.network_devices import get_network_device

    ctx = Mock(spec=Context)
    ctx.info = AsyncMock()

    client = AsyncMock()
    client.get_network_device = AsyncMock(return_value={"id": 3001})

    with patch("src.tools.network_devices.get_clearpass_client", AsyncMock(return_value=client)):
        result = await get_network_device(ctx, device_id=3001)

    assert result["success"] is True
    client.get_network_device.assert_awaited_once_with(3001)
    client.get_network_device_name.assert_not_awaited()
