"""Live validation of the 5 operations added to ``network_devices``.

``test_network_and_sessions.py`` treats the whole domain as read-only and
records every create/mutate operation as BLOCKED, for one reason: 7 real NADs
(including a live Aruba switch) are configured on this appliance,
``delete_network_device`` is denylisted, and network devices are not a sweepable
fixture family — so anything created there could never be removed.

The new ``delete_network_device_by_name`` operation changes that calculus. It is
*not* denylisted (only the by-id spelling is), it is name-keyed, and a name-keyed
delete is exactly what ``harness.assert_ours`` can vouch for. That makes a
fixture NAD safe for the first time, so this module runs one:

    create_network_device(zzz-mcptest-<runid>-nad)   [existing op]
      -> get_network_device_by_name                  [NEW]
      -> update_network_device_by_name               [NEW, PATCH]
      -> replace_network_device_by_name              [NEW, PUT]
      -> replace_network_device                      [NEW, PUT by id]
      -> delete_network_device_by_name               [NEW]

The 7 real NADs are never read into a write path, never named in a mutation and
never deleted. Every mutation is preceded by ``assert_ours`` on the name being
written, and by a re-read proving the name resolves to the id our own create
returned. The fixture IP is RFC 5737 TEST-NET-1, which no real device can hold,
and the RADIUS secret is a non-secret constant so nothing sensitive reaches the
run artifact.

``delete_network_device`` and ``bulk_update_network_devices`` stay denylisted and
are not touched here.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import PASS, assert_ours, classify, fixture_name

DOMAIN = "network_devices"
BLOCKED = "BLOCKED"

# RFC 5737 TEST-NET-1. Documented as non-routable; no real NAD can hold it.
FIXTURE_IP = "192.0.2.201"

# Deliberately not a secret: this device authenticates nothing. Named so that a
# reader of the artifact file can see it is fixture scaffolding.
FIXTURE_RADIUS_SECRET = "zzz-mcptest-not-a-real-secret"

NEW_OPERATIONS: List[str] = [
    "get_network_device_by_name",
    "update_network_device_by_name",
    "replace_network_device_by_name",
    "replace_network_device",
    "delete_network_device_by_name",
]


# --------------------------------------------------------------------------
# Dispatch wrapper (params as a dict; verdict override for bookkeeping)
# --------------------------------------------------------------------------


async def _invoke(operation: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if is_denylisted(operation):
        raise DenylistedOperation(operation)
    return await harness.invoke(operation, _params=params or {})


async def _run(recorder, operation: str, params: Optional[Dict[str, Any]] = None,
               tier: str = "read", expect_absent: bool = False,
               verdict: Optional[str] = None) -> Dict[str, Any]:
    start = time.perf_counter()
    result = await _invoke(operation, params)
    duration = (time.perf_counter() - start) * 1000.0
    final = verdict or classify(result, operation, expect_absent=expect_absent)
    err = None if final == PASS else (harness.deep_error_text(result).strip() or None)
    recorder.record(operation, DOMAIN, tier, final, params or {}, err, duration)
    return result


def _record_blocked(recorder, operation: str, reason: str) -> None:
    recorder.record(operation, DOMAIN, "blocked", BLOCKED, {}, reason, 0.0)


def _no_crash(result: Dict[str, Any], operation: str) -> None:
    marker = harness.deep_crash_marker(result)
    assert marker is None, f"{operation}: crash marker {marker!r} in {result}"


def _is_clarification(result: Dict[str, Any]) -> bool:
    return (result.get("success") is False
            and result.get("error_type") == "clarification_needed"
            and bool(result.get("question")))


def _assert_ok_or_structured(result: Dict[str, Any], operation: str) -> bool:
    _no_crash(result, operation)
    if result.get("success") is True:
        return True
    assert not harness.looks_like_html(harness.deep_error_text(result)), \
        f"{operation} returned an HTML body where JSON was promised: {result}"
    assert isinstance(result.get("status_code"), int) or _is_clarification(result), \
        f"{operation} returned an unstructured error: {result}"
    return False


def _device(result: Dict[str, Any]) -> Dict[str, Any]:
    device = result.get("device")
    return device if isinstance(device, dict) else {}


def _assert_is_our_fixture(device: Dict[str, Any], expected_name: str,
                           expected_id: Any) -> None:
    """Two rails before every mutation on the fixture NAD.

    1. the name the appliance reports must carry the fixture prefix, and
    2. it must resolve to the id our own create returned — otherwise the handle
       points at one of the 7 real NADs and the write is refused.
    """
    assert_ours(device.get("name"))
    assert device.get("name") == expected_name, (
        f"SAFETY GUARD: expected the fixture NAD {expected_name!r}, the "
        f"appliance returned {device.get('name')!r}"
    )
    if expected_id is not None:
        assert device.get("id") == expected_id, (
            f"SAFETY GUARD: {expected_name!r} resolves to id {device.get('id')!r}, "
            f"not the id {expected_id!r} this run created"
        )


def _strip_readonly(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in (obj or {}).items()
            if not str(k).startswith("_") and k not in ("id", "count", "links")}


# ==========================================================================
# Fixture NAD lifecycle
# ==========================================================================


def test_fixture_nad_by_name_lifecycle(run_async, recorder, run_id, cleanup):
    name = fixture_name(run_id, "nad")

    # Registered before the create so a mid-create explosion still cleans up.
    cleanup.add(lambda: _invoke("delete_network_device_by_name",
                                {"name": name, "confirm": True}))

    created = run_async(_run(recorder, "create_network_device", tier="create",
                             params={"name": name, "ip_address": FIXTURE_IP,
                                     "radius_secret": FIXTURE_RADIUS_SECRET,
                                     "description": name}))
    _no_crash(created, "create_network_device")
    if created.get("success") is not True:
        reason = (f"create_network_device was rejected by the appliance: "
                  f"{harness.deep_error_text(created).strip()[:300]}")
        for operation in NEW_OPERATIONS:
            _record_blocked(recorder, operation, reason)
        pytest.skip(reason)

    device_id = _device(created).get("id")
    assert device_id is not None, f"create_network_device returned no id: {created}"

    # --- GET by name -----------------------------------------------------
    fetched = run_async(_run(recorder, "get_network_device_by_name", {"name": name}))
    _no_crash(fetched, "get_network_device_by_name")
    assert classify(fetched, "get_network_device_by_name") == PASS, fetched
    _assert_is_our_fixture(_device(fetched), name, device_id)

    # --- PATCH by name ---------------------------------------------------
    _assert_is_our_fixture(_device(fetched), name, device_id)
    patched = run_async(_run(recorder, "update_network_device_by_name", tier="update",
                             params={"name": name,
                                     "device_data": {"description": name + "-patched"}}))
    _assert_ok_or_structured(patched, "update_network_device_by_name")

    # --- PUT by name (full body; name and ip preserved) ------------------
    base = _strip_readonly(_device(fetched))
    put_body = dict(base)
    put_body.update({"name": name, "ip_address": FIXTURE_IP,
                     "radius_secret": FIXTURE_RADIUS_SECRET,
                     "description": name + "-replaced-by-name"})
    assert_ours(put_body["name"])
    replaced_by_name = run_async(_run(recorder, "replace_network_device_by_name",
                                      tier="update",
                                      params={"name": name, "device_data": put_body}))
    _assert_ok_or_structured(replaced_by_name, "replace_network_device_by_name")

    # --- PUT by id -------------------------------------------------------
    recheck = run_async(_invoke("get_network_device_by_name", {"name": name}))
    if recheck.get("success") is True:
        _assert_is_our_fixture(_device(recheck), name, device_id)
    put_body_by_id = dict(put_body, description=name + "-replaced-by-id")
    assert_ours(put_body_by_id["name"])
    replaced_by_id = run_async(_run(recorder, "replace_network_device", tier="update",
                                    params={"device_id": device_id,
                                            "device_data": put_body_by_id}))
    _assert_ok_or_structured(replaced_by_id, "replace_network_device")

    # --- delete guard, then delete by name -------------------------------
    unconfirmed = run_async(_run(recorder, "delete_network_device_by_name",
                                 {"name": name}, tier="negative", verdict=PASS))
    _no_crash(unconfirmed, "delete_network_device_by_name")
    assert unconfirmed.get("success") is not True, \
        f"delete_network_device_by_name deleted without confirm=True: {unconfirmed}"
    assert "confirm" in str(unconfirmed).lower(), unconfirmed

    final_check = run_async(_invoke("get_network_device_by_name", {"name": name}))
    if final_check.get("success") is True:
        _assert_is_our_fixture(_device(final_check), name, device_id)

    assert_ours(name)
    deleted = run_async(_run(recorder, "delete_network_device_by_name", tier="delete",
                             params={"name": name, "confirm": True}))
    _no_crash(deleted, "delete_network_device_by_name")
    assert classify(deleted, "delete_network_device_by_name") == PASS, deleted

    gone = run_async(_run(recorder, "get_network_device_by_name", tier="negative",
                          params={"name": name}, expect_absent=True))
    _no_crash(gone, "get_network_device_by_name")
    assert gone.get("success") is not True, \
        f"the fixture NAD survived delete_network_device_by_name: {gone}"


def test_get_network_device_by_name_absent_returns_structured_404(run_async, recorder):
    """The read path against a name that provably does not exist. Kept separate
    from the lifecycle so it runs even if the create is rejected."""
    operation = "get_network_device_by_name"
    result = run_async(_run(recorder, operation,
                            {"name": "zzz-mcptest-nonexistent-nad"},
                            tier="negative", expect_absent=True))
    _no_crash(result, operation)
    assert result.get("success") is not True, result
    assert isinstance(result.get("status_code"), int), \
        f"{operation} returned an unstructured error: {result}"
    assert not harness.looks_like_html(harness.deep_error_text(result)), result


def test_denylisted_network_device_operations_still_never_dispatch(run_async, recorder):
    """The new by-name delete does NOT relax the denylist: the by-id delete and
    the bulk update stay unreachable."""
    for operation in ("delete_network_device", "bulk_update_network_devices"):
        assert operation in DENYLIST, f"{operation} must stay on the denylist"
        with pytest.raises(DenylistedOperation):
            run_async(_invoke(operation))


def test_zz_new_operation_coverage_is_complete(recorder):
    """All 5 newly added network_devices operations must carry a verdict.

    Also pins the domain size. ``test_network_and_sessions.py`` still asserts 30
    in-scope operations across network_devices + session_control; network_devices
    alone now holds 21, so that assertion is stale and is reported to triage
    rather than edited from here.
    """
    import json

    import src.main  # noqa: F401
    from src.registry import registry

    all_ops = {s.name for s in registry.search(domain=DOMAIN)}
    assert len(all_ops) == 21, f"expected 21 operations, found {len(all_ops)}"

    unknown = [n for n in NEW_OPERATIONS if registry.get(n) is None]
    assert not unknown, f"unknown operations: {unknown}"

    recorded = set()
    with recorder.path.open(encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("domain") == DOMAIN:
                recorded.add(rec["operation"])

    missing = sorted(set(NEW_OPERATIONS) - recorded)
    assert not missing, f"new operations with no live disposition: {missing}"
