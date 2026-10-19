"""Offline regression tests for ``ClearPassClient._make_request`` URL + body shape.

Two behaviours are pinned here, both discovered against a live ClearPass 6.12.4
appliance and then fixed centrally in ``src/clearpass_client.py``:

1. **Body-less writes must still carry a body.** The shared ``httpx`` client sets
   ``Content-Type: application/json`` on every request. Handing httpx
   ``json=None`` sends *no* bytes, so the appliance reads a JSON content type
   with an empty body and answers
   ``400 - JSON decoding error: Syntax error, malformed JSON``. Every body-less
   PATCH/POST/PUT the API defines (alert enable/disable, report run, service
   start/stop, ``config/service`` enable/disable, licence activation,
   agentless-onguard subnet-mapping enable/disable, ...) hits this. Four modules
   used to carry local ``data={}`` workarounds; ``_make_request`` now normalises
   ``None`` to ``{}`` for those three verbs so no caller has to.

   GET and DELETE are excluded on purpose -- they are legitimately body-less and
   the appliance accepts them that way.

2. **Every URL is built from the unversioned ``/api`` root.** ``/api/v1`` is a
   strictly worse mount on this appliance (see the ``_endpoint_url`` docstring
   for the measurements): it 404s ``alert`` and ``report``, and answers
   HTML-wrapped 500s for the DUR writes, ``session-action/disconnect*`` and the
   ``onguard-activity`` POSTs. There is no per-endpoint exception list any more.
"""

import httpx
import pytest

from src.clearpass_client import ClearPassClient


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
            json={"ok": True},
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
# 1. body-less writes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("method", ["PATCH", "POST", "PUT"])
@pytest.mark.asyncio
async def test_bodyless_write_sends_empty_object_not_none(method):
    """``data=None`` on a write verb must reach httpx as ``json={}``, never ``None``."""
    client, calls = _recording_client()

    await client._make_request(method, "alert/zzz/enable")

    assert len(calls) == 1
    # ``{}`` serialises to b"{}" -- a real body. ``None`` would send nothing and
    # the appliance would answer 400 "malformed JSON".
    assert calls[0]["json"] == {}
    assert calls[0]["json"] is not None


@pytest.mark.parametrize("method", ["GET", "DELETE"])
@pytest.mark.asyncio
async def test_bodyless_read_and_delete_stay_bodyless(method):
    """GET/DELETE are legitimately body-less and must not gain a body."""
    client, calls = _recording_client()

    await client._make_request(method, "network-device/1")

    assert calls[0]["json"] is None


@pytest.mark.asyncio
async def test_lowercase_write_verb_is_also_normalised():
    """Verb matching is case-insensitive, so ``patch`` behaves like ``PATCH``."""
    client, calls = _recording_client()

    await client._make_request("patch", "config/service/1/enable")

    assert calls[0]["json"] == {}


@pytest.mark.asyncio
async def test_explicit_payload_is_never_overwritten():
    """A caller-supplied body passes through untouched."""
    client, calls = _recording_client()
    payload = {"name": "zzz-mcptest-1", "enabled": False}

    await client._make_request("POST", "role", data=payload)

    assert calls[0]["json"] == payload


@pytest.mark.asyncio
async def test_explicit_empty_dict_still_sends_empty_dict():
    """The legacy per-module ``data={}`` workaround remains valid and is a no-op."""
    client, calls = _recording_client()

    await client._make_request("PATCH", "alert/zzz/disable", data={})

    assert calls[0]["json"] == {}


# ---------------------------------------------------------------------------
# 2. unversioned base URL
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("endpoint", [
    "network-device",
    "role",
    "enforcement-profile",
    "alert",
    "report",
    "session-action/disconnect/username/zzz-mcptest-nosuchuser",
    "enforcement-profile-dur/dur-class/ArubaOS-Switch",
    "onguard-activity/message",
    "oauth",
])
def test_endpoint_url_is_always_unversioned(endpoint):
    """No endpoint -- versioned-era exception or not -- gets an ``/api/v1`` prefix."""
    client, _ = _recording_client()

    url = client._endpoint_url(endpoint)

    assert url == f"https://appliance/api/{endpoint}"
    assert "/api/v1/" not in url


def test_endpoint_url_tolerates_a_leading_slash():
    client, _ = _recording_client()

    assert client._endpoint_url("/role") == "https://appliance/api/role"


def test_unversioned_prefix_exception_mechanism_is_gone():
    """The old carve-out list must not come back: ``/api`` is universal now."""
    assert not hasattr(ClearPassClient, "_UNVERSIONED_PREFIXES")
