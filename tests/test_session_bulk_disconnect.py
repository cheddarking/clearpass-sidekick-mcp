"""Offline proof of the composed bulk/selector disconnect family.

The live appliance has 0 active sessions, so the path that actually *matches*
and disconnects something cannot be exercised there. These tests drive the
mixin against a fake ClearPass so the matching, per-session disconnect,
aggregation and failure-isolation behaviour is covered.

Background: ClearPass 6.12.4 does not serve ``session-action/disconnect[...]``
(it answers with an HTTP 500 wrapping its own "Error 404" HTML page), so the
four bulk/selector disconnects are composed from ``GET session`` +
``POST session/<id>/disconnect``.
"""

import asyncio
import json

import pytest

from src.client_methods.session_control import (
    SessionControlMethodsMixin,
    _normalize_mac,
)


SESSIONS = [
    {"id": 1, "username": "alice", "mac_address": "AA:BB:CC:DD:EE:01",
     "client_ip_address": "10.0.0.1", "state": "active"},
    {"id": 2, "username": "alice", "mac_address": "aabb-ccdd-ee02",
     "framedipaddress": "10.0.0.2", "state": "active"},
    {"id": 3, "username": "bob", "mac_address": "aa:bb:cc:dd:ee:01",
     "client_ip_address": "10.0.0.3", "state": "active"},
]


class FakeClient(SessionControlMethodsMixin):
    """Implements only the two routes the composition is allowed to use."""

    def __init__(self, sessions=None, failing_ids=()):
        self.sessions = list(SESSIONS if sessions is None else sessions)
        self.failing_ids = set(failing_ids)
        self.disconnected = []
        self.list_calls = []

    async def list_active_sessions(self, filter_str=None, sort=None, offset=None,
                                   limit=None, calculate_count=None):
        self.list_calls.append(filter_str)
        items = self.sessions
        if filter_str:
            criteria = json.loads(filter_str)
            items = [s for s in items
                     if all(s.get(k) == v for k, v in criteria.items())]
        start = offset or 0
        return {"_embedded": {"items": items[start:start + (limit or len(items))]}}

    async def disconnect_session_by_id(self, session_id, confirm_disconnect=True):
        if str(session_id) in {str(i) for i in self.failing_ids}:
            raise RuntimeError(f"API request failed: POST session/{session_id}"
                               f"/disconnect - 404 - Session ID not found")
        self.disconnected.append(str(session_id))
        return {"disconnected": True, "id": session_id}


def run(coro):
    return asyncio.run(coro)


def test_normalize_mac_equates_all_separators():
    assert (_normalize_mac("AA:BB:CC:DD:EE:01")
            == _normalize_mac("aabb-ccdd-ee01")
            == _normalize_mac("aabbccddee01"))


def test_by_username_disconnects_every_matching_session():
    c = FakeClient()
    result = run(c.disconnect_sessions_by_username("alice"))
    assert result["success"] is True
    assert result["matched_count"] == 2
    assert result["disconnected_count"] == 2
    assert result["failed_count"] == 0
    assert c.disconnected == ["1", "2"]
    assert {s["session_id"] for s in result["sessions"]} == {1, 2}


def test_by_mac_matches_across_separator_styles():
    c = FakeClient()
    result = run(c.disconnect_sessions_by_mac("aabb.ccdd.ee01"))
    # sessions 1 and 3 carry the same MAC in different notations
    assert result["matched_count"] == 2
    assert sorted(c.disconnected) == ["1", "3"]


def test_by_ip_matches_alternate_ip_field_names():
    c = FakeClient()
    assert run(c.disconnect_sessions_by_ip("10.0.0.2"))["matched_count"] == 1
    assert c.disconnected == ["2"]


def test_bulk_with_no_filter_targets_every_session():
    c = FakeClient()
    result = run(c.disconnect_sessions_bulk())
    assert result["matched_count"] == 3
    assert result["disconnected_count"] == 3


def test_bulk_filter_is_applied_server_side():
    c = FakeClient()
    result = run(c.disconnect_sessions_bulk(filter_criteria={"username": "bob"}))
    assert c.list_calls == [json.dumps({"username": "bob"})]
    assert result["matched_count"] == 1
    assert c.disconnected == ["3"]


@pytest.mark.parametrize("method,kwargs", [
    ("disconnect_sessions_bulk", {}),
    ("disconnect_sessions_by_username", {"username": "nobody"}),
    ("disconnect_sessions_by_mac", {"mac_address": "00:00:00:00:00:01"}),
    ("disconnect_sessions_by_ip", {"client_ip_address": "203.0.113.254"}),
])
def test_zero_matches_is_a_clean_structured_result(method, kwargs):
    c = FakeClient(sessions=[])
    result = run(getattr(c, method)(**kwargs))
    assert result["success"] is True
    assert result["matched_count"] == 0
    assert result["disconnected_count"] == 0
    assert result["sessions"] == []
    assert "no active sessions matched" in result["message"].lower()
    assert c.disconnected == []


def test_one_failure_does_not_abort_the_rest():
    c = FakeClient(failing_ids={1})
    result = run(c.disconnect_sessions_by_username("alice"))
    assert result["success"] is False
    assert result["matched_count"] == 2
    assert result["disconnected_count"] == 1
    assert result["failed_count"] == 1
    assert c.disconnected == ["2"]
    failure = result["failures"][0]
    assert failure["session_id"] == 1
    assert "404" in failure["error"]


def test_session_without_an_id_is_reported_not_raised():
    c = FakeClient(sessions=[{"username": "alice"}])
    result = run(c.disconnect_sessions_by_username("alice"))
    assert result["matched_count"] == 1
    assert result["failed_count"] == 1
    assert "no 'id'" in result["failures"][0]["error"]


@pytest.mark.parametrize("method,kwargs", [
    ("disconnect_sessions_bulk", {}),
    ("disconnect_sessions_by_username", {"username": "alice"}),
    ("disconnect_sessions_by_mac", {"mac_address": "AA:BB:CC:DD:EE:01"}),
    ("disconnect_sessions_by_ip", {"client_ip_address": "10.0.0.1"}),
])
def test_enforcement_profile_refuses_before_touching_anything(method, kwargs):
    c = FakeClient()
    result = run(getattr(c, method)(enforcement_profile=["Quarantine"], **kwargs))
    assert result["success"] is False
    assert result["supported"] is False
    assert result["unsupported_parameter"] == "enforcement_profile"
    assert c.disconnected == []
    assert c.list_calls == []


def test_no_bulk_disconnect_touches_the_unserved_route_family():
    """The composition must never reach ``_make_request`` directly."""
    c = FakeClient()

    async def _forbidden(*a, **kw):
        raise AssertionError(f"raw HTTP call attempted: {a} {kw}")

    c._make_request = _forbidden
    for method, kwargs in [
        ("disconnect_sessions_bulk", {}),
        ("disconnect_sessions_by_username", {"username": "alice"}),
        ("disconnect_sessions_by_mac", {"mac_address": "AA:BB:CC:DD:EE:01"}),
        ("disconnect_sessions_by_ip", {"client_ip_address": "10.0.0.1"}),
    ]:
        assert run(getattr(c, method)(**kwargs))["success"] is True
