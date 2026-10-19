"""Live validation of the ``network_devices`` (16) and ``session_control`` (14)
operation domains against the real ClearPass 6.12.4 appliance.

Scope note: the full-SDK-coverage expansion grew these domains to 21 and 20
operations. This module still owns exactly the original 30; the 11 additions
are covered by ``test_network_devices_expansion_live.py`` and
``test_dur_and_misc_live.py`` and are listed in ``EXPANSION_OPERATIONS`` near
the coverage guard at the bottom of this file.

Scope rules baked into this module
----------------------------------
``network_devices`` is treated as **read-only**. 7 real NADs (including a live
Aruba switch) exist on this appliance and network devices are *not* a sweepable
fixture family — anything created here could never be cleaned up, and the
inventory guard would fail the session. Every operation that would create or
mutate a device is therefore recorded as ``BLOCKED`` and never dispatched
against a real device id. Where a *non-existent* device id makes the call
provably incapable of mutating anything, an extra negative probe is run purely
to prove the code path executes (no ``FieldInfo`` leak, no ``TypeError``); that
probe never upgrades the operation out of ``BLOCKED``.

``session_control`` is the module whose ``async with get_clearpass_client()``
bug was just fixed — 7 of its 14 operations raised ``TypeError`` because the
singleton accessor is a coroutine, not an async context manager. Proving those
7 now execute is the highest-value assertion here. The appliance currently has
0 active sessions, so the disconnect family is exercised against deliberately
non-existent session ids / usernames / MACs / IPs. The active-session count is
re-checked immediately before every disconnect dispatch and the test aborts if
it is non-zero: disconnecting a real session kicks a real device off the
network.

All 4 ``perform_coa_*`` operations plus ``delete_network_device`` and
``bulk_update_network_devices`` are on the hard denylist and are asserted to
raise before the gateway is touched.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation
from .harness import EXPECTED_SKIP, FAIL, PASS, classify, expected_skip_reason

# --------------------------------------------------------------------------
# Deliberately non-existent targets (RFC 5737 TEST-NET-1 address, a
# locally-administered MAC, a fixture-namespaced username, absurd numeric ids).
# Nothing on this appliance can match any of these.
# --------------------------------------------------------------------------

NX_DEVICE_ID = 999999999
NX_SESSION_ID = "999999999"
NX_ACTION_ID = "999999999"
NX_USERNAME = "zzz-mcptest-nosuchuser"
NX_MAC = "02:00:5e:10:00:00"
NX_IP = "192.0.2.123"

BLOCKED = "BLOCKED"

# operation -> (verdict, note); filled in as tests run, asserted at the end.
COVERAGE: Dict[str, Any] = {}

# Bugs found during the run. Recorded, never fixed here — a later phase triages
# and fixes centrally. Printed in full by the final reconciliation test.
BUGS: List[Dict[str, Any]] = []


def _mark(operation: str, verdict: str, note: str = "") -> None:
    COVERAGE[operation] = {"verdict": verdict, "note": note}


def _crash_markers(result: Any) -> List[str]:
    text = str(result)
    return [m for m in harness._CRASH_MARKERS if m in text]


def _assert_no_crash(operation: str, result: Any) -> None:
    """The single most important assertion in this module.

    A known environment limitation, a 404 or a validation error must all
    present as a *structured* error dict. A Python-level explosion surfacing
    through the operation's generic ``except Exception`` (or through
    ``invoke_operation``'s catch) is always a bug.
    """
    markers = _crash_markers(result)
    assert not markers, (
        f"{operation}: Python-level crash surfaced through the error path "
        f"(markers {markers}): {result}"
    )
    assert isinstance(result, dict), f"{operation}: non-dict result {result!r}"


# --------------------------------------------------------------------------
# Shared read of the real NAD inventory
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_devices(run_async, recorder) -> List[Dict[str, Any]]:
    """The 7 real NADs. Read once; never mutated."""
    result = run_async(recorder.run("list_network_devices", tier="read"))
    assert classify(result, "list_network_devices") == PASS, result
    devices = result.get("devices") or []
    assert devices, f"no network devices returned: {result}"
    return devices


@pytest.fixture(scope="module")
def real_device_id(real_devices) -> int:
    return real_devices[0]["id"]


# ==========================================================================
# network_devices — reads
# ==========================================================================


def test_list_network_devices_no_params(real_devices):
    """All optional parameters omitted — the FieldInfo omission path."""
    _mark("list_network_devices", PASS, f"{len(real_devices)} NADs returned")
    assert "FieldInfo" not in str(real_devices)
    for d in real_devices:
        assert isinstance(d.get("id"), int), f"device without numeric id: {d}"


def test_list_network_devices_with_optionals(run_async, recorder, real_devices):
    """The fully-specified path, for contrast with the omission path."""
    result = run_async(recorder.run(
        "list_network_devices", tier="read",
        filter_coa_capable=True, vendor_filter="Aruba", limit=10,
    ))
    _assert_no_crash("list_network_devices", result)
    assert classify(result, "list_network_devices") == PASS, result


def test_get_network_device_by_id(run_async, recorder, real_device_id):
    result = run_async(recorder.run(
        "get_network_device", tier="read", device_id=real_device_id
    ))
    _assert_no_crash("get_network_device", result)
    verdict = classify(result, "get_network_device")
    _mark("get_network_device", verdict, f"device_id={real_device_id}")
    assert verdict == PASS, result
    assert result["device"].get("id") == real_device_id, result


def test_get_network_device_by_name(run_async, recorder, real_devices):
    """FIXED: `get_network_device` documents "ID or name" (Union[int, str]).

    It used to interpolate the value straight into ``GET network-device/<id>``
    with no name->id branch, so a name was rejected with
    ``422 ID '<name>' is invalid`` — the same asymmetry as the reported
    ``delete_guest_user`` bug. It now branches on the shape of the value the way
    ``get_guest_user`` does, resolving a name through a server-side filtered
    list (ClearPass exposes no ``network-device/name/<name>`` endpoint).

    Both spellings must resolve to the same device. This is a read.
    """
    device = real_devices[0]
    name, device_id = device.get("name"), device.get("id")

    by_name = run_async(recorder.run(
        "get_network_device", tier="read", device_id=name
    ))
    _assert_no_crash("get_network_device", by_name)
    assert by_name.get("success") is True, \
        f"lookup by name {name!r} failed: {harness._error_text(by_name)[:250]}"
    assert by_name["device"].get("id") == device_id, by_name
    assert by_name["device"].get("name") == name, by_name

    _mark("get_network_device", classify(by_name, "get_network_device"),
          f"resolved by name {name!r} -> id {device_id}")


def test_get_network_device_absent_name_is_structured(run_async, recorder):
    """The name branch must fail structurally, not explode, for an unknown name."""
    result = run_async(recorder.run(
        "get_network_device", tier="negative", expect_absent=True,
        device_id="zzz-mcptest-no-such-device"
    ))
    _assert_no_crash("get_network_device", result)
    assert result.get("success") is False, result
    assert result.get("status_code") == 404, result
    assert "zzz-mcptest-no-such-device" in str(result), result


def test_search_devices_advanced_no_params(run_async, recorder, real_devices):
    """Omission path on the operation with the most Field()-defaulted params."""
    result = run_async(recorder.run("search_devices_advanced", tier="read"))
    _assert_no_crash("search_devices_advanced", result)
    verdict = classify(result, "search_devices_advanced")
    _mark("search_devices_advanced", verdict,
          f"unfiltered -> {result.get('total_found')} devices")
    assert verdict == PASS, result
    assert result["total_found"] == len(real_devices), (
        f"unfiltered advanced search returned {result['total_found']} devices "
        f"but list_network_devices returned {len(real_devices)}"
    )


def test_search_devices_advanced_client_side_filters(run_async, recorder, real_devices):
    """Client-side filtering (RadSec / CoA / vendor / SNMP) was previously fixed;
    verify it still discriminates rather than returning everything.

    FIXED here: every filter that matched ZERO devices used to crash with
    ``'str' object has no attribute 'get'`` (see the root-cause note below).
    The extraction now keys off presence and type rather than truthiness, so a
    genuine zero-match search returns an empty device list.

    Findings are collected rather than asserted one at a time so the whole
    filter matrix is exercised in a single live pass and the bug report carries
    every affected combination.
    """
    total = len(real_devices)
    matrix = [
        ("radsec_enabled=True", {"radsec_enabled": True}),
        ("radsec_enabled=False", {"radsec_enabled": False}),
        ("coa_capable=True", {"coa_capable": True}),
        ("coa_capable=False", {"coa_capable": False}),
        ("vendor_name=<absent>", {"vendor_name": "zzz-no-such-vendor"}),
        ("has_snmp_configured=True", {"has_snmp_configured": True}),
        ("ip_subnet=TEST-NET-1", {"ip_subnet": "192.0.2.0/24"}),
    ]
    results: Dict[str, Dict[str, Any]] = {}
    crashed: List[str] = []
    for label, params in matrix:
        res = run_async(recorder.run(
            "search_devices_advanced", tier="read", **params
        ))
        results[label] = res
        if _crash_markers(res):
            crashed.append(f"{label} -> {harness._error_text(res).strip()[:160]}")

    if crashed:
        BUGS.append({
            "operation": "search_devices_advanced",
            "params": "any server-criteria filter that matches ZERO devices "
                      "(vendor_name / device_type / coa_capable / radsec_enabled "
                      "/ has_snmp_configured)",
            "error": "'str' object has no attribute 'get'",
            "root_cause":
                "src/tools/network_devices.py empty-result fallback chain: when "
                "search_devices_by_criteria legitimately matches nothing it "
                "returns {'_embedded': {'items': []}, 'total': 0}. "
                "`devices = result['_embedded']['items']` is [] (falsy), so the "
                "fallback runs and ends at `devices = result.get('_embedded', [])`, "
                "which is the truthy dict {'items': []}. The vendor-summary loop "
                "then iterates the dict's KEYS and calls .get() on the string "
                "'items'. Zero matches is indistinguishable from 'wrong response "
                "shape' in that chain. ip_subnet/custom_filter narrowing to zero "
                "is unaffected because it happens after the fallback.",
            "affected": crashed,
        })
        _mark("search_devices_advanced", FAIL, "; ".join(crashed)[:200])

    # Filtering itself is correct whenever the match set is non-empty.
    off_n = results["radsec_enabled=False"].get("total_found")
    assert off_n == total, (
        f"radsec_enabled=False should match all {total} devices (none have "
        f"RadSec on this appliance), got {off_n}"
    )
    coa_on = results["coa_capable=True"]
    if coa_on.get("success"):
        assert all(d.get("coa_capable") for d in coa_on["devices"]), \
            "coa_capable=True returned devices with coa_capable falsy"
        assert coa_on["total_found"] < total, \
            "coa_capable=True returned every device — filter is a no-op"
    subnet = results["ip_subnet=TEST-NET-1"]
    assert subnet.get("total_found") == 0, \
        f"TEST-NET-1 subnet filter matched real devices: {subnet}"

    assert not crashed, (
        "search_devices_advanced crashes on zero-match filters: "
        + " | ".join(crashed)
    )

    # The three filters that used to crash must now return a clean empty result.
    for label in ("radsec_enabled=True", "vendor_name=<absent>",
                  "has_snmp_configured=True"):
        res = results[label]
        assert res.get("success") is True, f"{label} -> {res}"
        assert res.get("total_found") == 0, f"{label} -> {res}"
        assert res.get("devices") == [], f"{label} -> {res}"
        assert res.get("vendor_summary") == {}, (
            f"{label} produced a vendor summary from a zero-match search "
            f"(the old '_embedded' dict leak): {res}"
        )


def test_get_device_statistics(run_async, recorder, real_device_id):
    result = run_async(recorder.run(
        "get_device_statistics", tier="read", device_id=real_device_id
    ))
    _assert_no_crash("get_device_statistics", result)
    verdict = classify(result, "get_device_statistics")
    _mark("get_device_statistics", verdict,
          harness._error_text(result).strip()[:160] or "ok")
    assert verdict == PASS, result


def test_test_device_connectivity(run_async, recorder, real_device_id):
    """Read-only diagnostic: reports reachability, changes no configuration."""
    result = run_async(recorder.run(
        "test_device_connectivity", tier="read", device_id=real_device_id
    ))
    _assert_no_crash("test_device_connectivity", result)
    verdict = classify(result, "test_device_connectivity")
    _mark("test_device_connectivity", verdict,
          harness._error_text(result).strip()[:160] or
          f"overall_status={result.get('overall_status')}")
    assert verdict == PASS, result


def test_validate_device_configuration(run_async, recorder):
    """Pure validation — takes a config dict, touches no live device."""
    config = {
        "name": "zzz-mcptest-validate-only",
        "ip_address": "192.0.2.10",
        "radius_secret": "not-a-real-secret",
        "vendor_name": "Aruba",
        "coa_capable": True,
    }
    result = run_async(recorder.run(
        "validate_device_configuration", tier="read", device_config=config
    ))
    _assert_no_crash("validate_device_configuration", result)
    verdict = classify(result, "validate_device_configuration")
    _mark("validate_device_configuration", verdict,
          f"validation_status={result.get('validation_status')}")
    assert verdict == PASS, result


# ==========================================================================
# network_devices — known 6.12.4 limitations
# ==========================================================================


@pytest.mark.parametrize("operation", [
    "configure_device_snmp_settings",
    "configure_device_radsec_settings",
    "configure_device_cli_settings",
])
def test_configure_device_settings_known_limitation(run_async, recorder, operation):
    """Documented limitation: these need a live *managed* device and return
    422/400 on this appliance.

    Dispatched against a NON-EXISTENT device id. That keeps all 7 real NADs
    (including the live Aruba switch) untouchable while still driving the full
    code path, so a FieldInfo leak or TypeError would still be caught. The
    known-limitation allowlist supplies the skip reason.
    """
    params: Dict[str, Any] = {"device_id": NX_DEVICE_ID}
    if operation == "configure_device_radsec_settings":
        params["radsec_enabled"] = False
    elif operation == "configure_device_cli_settings":
        params["cli_enabled"] = False

    result = run_async(recorder.run(operation, tier="negative", **params))
    _assert_no_crash(operation, result)

    reason = expected_skip_reason(operation)
    assert reason, f"{operation} is not on the known-limitation allowlist"

    verdict = classify(result, operation)
    _mark(operation, verdict, reason)
    assert verdict in (EXPECTED_SKIP, PASS), (
        f"{operation} produced neither a structured known-limitation error nor "
        f"a success: {result}"
    )
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"KNOWN LIMITATION — {reason} (op={operation})")


# ==========================================================================
# network_devices — BLOCKED (create / mutate)
# ==========================================================================


def test_create_and_mutate_operations_are_blocked():
    """Network devices are not a safe fixture family.

    There is no cleanup path: `delete_network_device` is denylisted (7 real
    NADs) and the inventory guard fails the session on any un-swept object. So
    every create/clone/template/mutate operation is recorded BLOCKED and never
    dispatched at a real device.
    """
    blocked = {
        "create_network_device":
            "creates a real NAD with no cleanup path (delete_network_device is "
            "denylisted, network_devices is not a sweepable fixture family)",
        "clone_network_device":
            "clones a real NAD into a new un-deletable device",
        "create_device_from_template":
            "creates a real NAD with no cleanup path",
        "update_network_device":
            "mutates a real production NAD (live Aruba switch in inventory)",
        "configure_device_onconnect_enforcement":
            "writes OnConnect enforcement to a real production NAD",
        "delete_network_device":
            f"DENYLISTED: {DENYLIST['delete_network_device']}",
        "bulk_update_network_devices":
            f"DENYLISTED: {DENYLIST['bulk_update_network_devices']}",
    }
    for operation, why in blocked.items():
        _mark(operation, BLOCKED, why)
    assert len(blocked) == 7


@pytest.mark.parametrize("operation,params", [
    ("update_network_device", {"device_id": NX_DEVICE_ID, "description": "probe"}),
    ("configure_device_onconnect_enforcement",
     {"device_id": NX_DEVICE_ID, "onconnect_enabled": False}),
])
def test_blocked_mutators_still_execute_cleanly_against_absent_device(
    run_async, recorder, operation, params
):
    """Code-path probe only — the operation stays BLOCKED.

    A non-existent device id makes these calls incapable of mutating anything,
    which lets the omission path be exercised safely. This proves no FieldInfo
    leak / TypeError, but does NOT constitute real coverage of the write.
    """
    result = run_async(recorder.run(operation, tier="negative", **params))
    _assert_no_crash(operation, result)
    assert result.get("success") is not True, (
        f"{operation} reported success against non-existent device "
        f"{NX_DEVICE_ID}: {result}"
    )


def test_network_device_denylist_rails_hold(run_async, recorder):
    for operation in ("delete_network_device", "bulk_update_network_devices"):
        with pytest.raises(DenylistedOperation) as excinfo:
            run_async(harness.invoke(operation, device_id=NX_DEVICE_ID))
        assert DENYLIST[operation] in str(excinfo.value)
        recorder.record(operation, "network_devices", "denylist", EXPECTED_SKIP,
                        {}, f"DENYLISTED: {DENYLIST[operation]}", 0.0)


# ==========================================================================
# session_control — reads
# ==========================================================================


def _active_session_count(run_async) -> int:
    """Authoritative live count. Called immediately before every disconnect."""
    result = run_async(harness.invoke("list_active_sessions"))
    assert result.get("success") is True, (
        f"cannot verify active session count, refusing to proceed: {result}"
    )
    return int(result.get("total_count") or len(result.get("sessions") or []))


@pytest.fixture
def zero_active_sessions(run_async):
    """Abort any disconnect test unless the appliance has 0 active sessions.

    Re-evaluated per test, immediately before dispatch. Disconnecting a real
    session kicks a real device off the network.
    """
    count = _active_session_count(run_async)
    if count != 0:
        pytest.skip(
            f"ABORT: {count} active session(s) on the appliance — refusing to "
            f"dispatch any disconnect operation."
        )
    return count


def test_list_active_sessions_no_params(run_async, recorder):
    """PREVIOUSLY BROKEN (async with TypeError). All optionals omitted."""
    result = run_async(recorder.run("list_active_sessions", tier="read"))
    _assert_no_crash("list_active_sessions", result)
    verdict = classify(result, "list_active_sessions")
    _mark("list_active_sessions", verdict,
          f"total_count={result.get('total_count')}")
    assert verdict == PASS, result
    assert result.get("total_count") == 0, (
        f"expected 0 active sessions on this appliance, got "
        f"{result.get('total_count')} — disconnect tests must not run"
    )


def test_list_active_sessions_with_optionals(run_async, recorder):
    result = run_async(recorder.run(
        "list_active_sessions", tier="read",
        sort="-id", offset=0, limit=5, calculate_count=True,
    ))
    _assert_no_crash("list_active_sessions", result)
    assert classify(result, "list_active_sessions") == PASS, result


def test_get_active_session_details_absent(run_async, recorder):
    """PREVIOUSLY BROKEN. 0 sessions exist, so a non-existent id is the only
    way to drive this — a structured not-found is the correct outcome."""
    result = run_async(recorder.run(
        "get_active_session_details", tier="negative",
        expect_absent=True, session_id=NX_SESSION_ID,
    ))
    _assert_no_crash("get_active_session_details", result)
    verdict = classify(result, "get_active_session_details", expect_absent=True)
    _mark("get_active_session_details", verdict,
          f"absent session id -> {harness._error_text(result).strip()[:160]}")
    assert verdict == PASS, (
        f"absent-session read should be success or a structured not-found, "
        f"got {result}"
    )


def test_get_session_action_status_absent(run_async, recorder):
    result = run_async(recorder.run(
        "get_session_action_status", tier="negative",
        expect_absent=True, action_id=NX_ACTION_ID,
    ))
    _assert_no_crash("get_session_action_status", result)
    verdict = classify(result, "get_session_action_status", expect_absent=True)
    _mark("get_session_action_status", verdict,
          harness._error_text(result).strip()[:160] or "ok")
    assert verdict == PASS, result


def test_get_session_reauthorization_profiles_absent(run_async, recorder):
    result = run_async(recorder.run(
        "get_session_reauthorization_profiles", tier="negative",
        expect_absent=True, session_id=NX_SESSION_ID,
    ))
    _assert_no_crash("get_session_reauthorization_profiles", result)
    verdict = classify(result, "get_session_reauthorization_profiles",
                       expect_absent=True)
    _mark("get_session_reauthorization_profiles", verdict,
          harness._error_text(result).strip()[:160] or "ok")
    assert verdict == PASS, result


# ==========================================================================
# session_control — confirmation guards (optionals omitted)
# ==========================================================================


@pytest.mark.parametrize("operation,params", [
    ("disconnect_session", {"session_id": NX_SESSION_ID}),
    ("disconnect_sessions_bulk", {}),
    ("disconnect_sessions_by_username", {"username": NX_USERNAME}),
    ("disconnect_sessions_by_mac", {"mac_address": NX_MAC}),
    ("disconnect_sessions_by_ip", {"client_ip_address": NX_IP}),
    ("reauthorize_session", {"session_id": NX_SESSION_ID}),
])
def test_confirmation_guard_blocks_when_confirm_omitted(
    run_async, recorder, operation, params
):
    """`confirm` is a Field(default=False). With it OMITTED it must evaluate
    falsy and short-circuit before any network call.

    Under the FieldInfo bug this guard was the *first* thing to misbehave: a
    raw FieldInfo is truthy, so `if not confirm` would fall through and the
    operation would dispatch for real. This is the safety-critical case of the
    omission path.
    """
    result = run_async(recorder.run(operation, tier="negative", **params))
    _assert_no_crash(operation, result)
    assert result.get("success") is False, (
        f"{operation} did NOT short-circuit on the confirmation guard with "
        f"confirm omitted — a raw FieldInfo default would be truthy and let a "
        f"real disconnect through: {result}"
    )
    assert "confirm" in str(result.get("message", "")).lower(), (
        f"{operation} failed for a reason other than the confirmation guard: "
        f"{result}"
    )


# ==========================================================================
# session_control — disconnect family against non-existent targets
# ==========================================================================


def test_disconnect_session_absent_id(run_async, recorder, zero_active_sessions):
    """PREVIOUSLY BROKEN. confirm=True is required to get past the guard and
    reach the client — that is the code that used to raise TypeError. The
    session id does not exist and the appliance has 0 active sessions."""
    result = run_async(recorder.run(
        "disconnect_session", tier="negative", expect_absent=True,
        session_id=NX_SESSION_ID, confirm=True,
    ))
    _assert_no_crash("disconnect_session", result)
    verdict = classify(result, "disconnect_session", expect_absent=True)
    _mark("disconnect_session", verdict,
          harness._error_text(result).strip()[:160] or "executed")
    assert verdict == PASS, result


def test_disconnect_sessions_bulk_non_matching_filter(
    run_async, recorder, zero_active_sessions
):
    """PREVIOUSLY BROKEN.

    Bulk disconnect with NO filter targets every session, so a non-matching
    filter is passed explicitly even though 0 sessions exist — belt and braces
    on top of the zero-session guard.
    """
    result = run_async(recorder.run(
        "disconnect_sessions_bulk", tier="negative", expect_absent=True,
        filter_criteria={"username": NX_USERNAME}, confirm=True,
    ))
    _assert_no_crash("disconnect_sessions_bulk", result)
    verdict = classify(result, "disconnect_sessions_bulk", expect_absent=True)
    _mark("disconnect_sessions_bulk", verdict,
          f"matched_count={result.get('matched_count')} (composed disconnect)")
    assert verdict == PASS, result
    assert result.get("matched_count") == 0, result
    assert result.get("disconnected_count") == 0, result
    assert _active_session_count(run_async) == 0


@pytest.mark.parametrize("operation,params", [
    ("disconnect_sessions_by_username", {"username": NX_USERNAME}),
    ("disconnect_sessions_by_mac", {"mac_address": NX_MAC}),
    ("disconnect_sessions_by_ip", {"client_ip_address": NX_IP}),
])
def test_disconnect_by_selector_absent_target(
    run_async, recorder, zero_active_sessions, operation, params
):
    """PREVIOUSLY BROKEN (all three).

    Targets are chosen so nothing can match: a fixture-namespaced username, a
    locally-administered MAC, and an RFC 5737 TEST-NET-1 address.
    """
    result = run_async(recorder.run(
        operation, tier="negative", expect_absent=True, confirm=True, **params
    ))
    _assert_no_crash(operation, result)
    verdict = classify(result, operation, expect_absent=True)
    _mark(operation, verdict,
          f"matched_count={result.get('matched_count')} (composed disconnect)")
    assert verdict == PASS, result
    assert result.get("matched_count") == 0, result
    assert result.get("disconnected_count") == 0, result
    assert _active_session_count(run_async) == 0


def test_bulk_disconnects_no_longer_hit_the_unserved_route_family(
    run_async, recorder, zero_active_sessions
):
    """Regression guard for the ``session-action/disconnect*`` finding.

    Original finding: every ``session-action/disconnect[...]`` POST answered an
    **HTTP 500 whose body was the HPE ``/tips`` "Error 404: Page not found" HTML
    page**, while ``POST session/<id>/disconnect`` returned a clean structured
    JSON 404 for an absent id.

    Corrected cause: that 500 was the ``/api/v1`` mount, not a missing route.
    Re-measured by direct curl on 2026-07-30, the same four routes at the
    unversioned ``/api`` root — which is the only root the client uses now —
    answer a structured 400 synchronously and a 200 with a pollable
    ``action_id`` under ``?async=true``. See ``ClearPassClient._endpoint_url``.

    The four bulk/selector disconnects stay composed from ``GET session`` +
    ``POST session/<id>/disconnect``: that path answers synchronously with a
    per-session summary and needs no polling. The guard below is unchanged and
    still load-bearing — none of them may ever produce a 500 or an HTML body,
    and the per-session control must still return its structured 404.
    """
    per_session = run_async(harness.invoke(
        "disconnect_session", session_id=NX_SESSION_ID, confirm=True))
    assert "404" in harness._error_text(per_session), per_session

    selectors = {
        "disconnect_sessions_bulk": {"filter_criteria": {"username": NX_USERNAME}},
        "disconnect_sessions_by_username": {"username": NX_USERNAME},
        "disconnect_sessions_by_mac": {"mac_address": NX_MAC},
        "disconnect_sessions_by_ip": {"client_ip_address": NX_IP},
    }
    for operation, params in selectors.items():
        assert _active_session_count(run_async) == 0
        result = run_async(harness.invoke(operation, confirm=True, **params))
        _assert_no_crash(operation, result)

        blob = harness.deep_error_text(result) or ""
        assert not harness.looks_like_html(blob), (
            f"{operation} still returns an HTML error body: {result}")
        assert "500" not in blob, (
            f"{operation} still returns an HTTP 500: {result}")
        assert result.get("success") is True, (
            f"{operation} should succeed cleanly with nothing matching: {result}")
        assert result.get("matched_count") == 0, result
        assert result.get("disconnected_count") == 0, result

    assert _active_session_count(run_async) == 0


def test_reauthorize_session_absent_id(run_async, recorder, zero_active_sessions):
    """Not on the broken-7 list, but the same confirm-gated dispatch path."""
    result = run_async(recorder.run(
        "reauthorize_session", tier="negative", expect_absent=True,
        session_id=NX_SESSION_ID, confirm=True,
    ))
    _assert_no_crash("reauthorize_session", result)
    verdict = classify(result, "reauthorize_session", expect_absent=True)
    _mark("reauthorize_session", verdict,
          harness._error_text(result).strip()[:160] or "executed")
    assert verdict == PASS, result


def test_coa_operations_are_denylisted(run_async, recorder):
    """All 4 perform_coa_* operations must raise before the gateway."""
    coa_ops = {
        "perform_coa_bulk": {"enforcement_profile": ["x"]},
        "perform_coa_by_username": {"username": NX_USERNAME,
                                    "enforcement_profile": ["x"]},
        "perform_coa_by_mac": {"mac_address": NX_MAC,
                               "enforcement_profile": ["x"]},
        "perform_coa_by_ip": {"client_ip_address": NX_IP,
                              "enforcement_profile": ["x"]},
    }
    for operation, params in coa_ops.items():
        with pytest.raises(DenylistedOperation) as excinfo:
            run_async(harness.invoke(operation, **params))
        assert DENYLIST[operation] in str(excinfo.value)
        recorder.record(operation, "session_control", "denylist", EXPECTED_SKIP,
                        {}, f"DENYLISTED: {DENYLIST[operation]}", 0.0)
        _mark(operation, BLOCKED, f"DENYLISTED: {DENYLIST[operation]}")


# ==========================================================================
# The headline assertion + coverage reconciliation
# ==========================================================================


PREVIOUSLY_BROKEN = [
    "list_active_sessions",
    "get_active_session_details",
    "disconnect_session",
    "disconnect_sessions_bulk",
    "disconnect_sessions_by_username",
    "disconnect_sessions_by_mac",
    "disconnect_sessions_by_ip",
]


def test_zz_previously_broken_seven_all_execute(run_async, recorder):
    """The single highest-value assertion in this scope.

    Each of the 7 operations that carried the broken
    ``async with get_clearpass_client()`` must now execute without TypeError.
    Re-dispatched here independently of the earlier tests so this assertion
    stands on its own evidence.
    """
    zero = _active_session_count(run_async)
    assert zero == 0, f"{zero} active sessions — aborting disconnect re-probe"

    probes = {
        "list_active_sessions": {},
        "get_active_session_details": {"session_id": NX_SESSION_ID},
        "disconnect_session": {"session_id": NX_SESSION_ID, "confirm": True},
        "disconnect_sessions_bulk": {"filter_criteria": {"username": NX_USERNAME},
                                     "confirm": True},
        "disconnect_sessions_by_username": {"username": NX_USERNAME, "confirm": True},
        "disconnect_sessions_by_mac": {"mac_address": NX_MAC, "confirm": True},
        "disconnect_sessions_by_ip": {"client_ip_address": NX_IP, "confirm": True},
    }
    failures = []
    for operation in PREVIOUSLY_BROKEN:
        result = run_async(recorder.run(
            operation, tier="negative", expect_absent=True, **probes[operation]
        ))
        markers = _crash_markers(result)
        if markers:
            failures.append((operation, markers,
                             harness._error_text(result).strip()[:300]))

    print("\n[live-harness] previously-broken session_control operations:")
    for operation in PREVIOUSLY_BROKEN:
        state = "CRASH" if any(f[0] == operation for f in failures) else "executes"
        print(f"   {state:9s} {operation}")

    assert not failures, (
        "the async-with TypeError fix did NOT hold for: "
        + "; ".join(f"{op} {markers} {err}" for op, markers, err in failures)
    )
    assert _active_session_count(run_async) == 0


# Operations added to these two domains by the full-SDK-coverage expansion.
# ``network_devices`` grew 16 -> 21 and ``session_control`` 14 -> 20; the 11 new
# operations are owned by ``test_network_devices_expansion_live.py`` and
# ``test_dur_and_misc_live.py`` respectively. This module keeps its original
# 30-operation scope and excludes them.
EXPANSION_OPERATIONS: List[str] = [
    # network_devices -> test_network_devices_expansion_live.py
    "delete_network_device_by_name",
    "get_network_device_by_name",
    "replace_network_device",
    "replace_network_device_by_name",
    "update_network_device_by_name",
    # session_control -> test_dur_and_misc_live.py
    "coa_active_session_by_mac",
    "get_active_session_by_mac",
    "session_action_disconnect",
    "session_action_disconnect_by_ip",
    "session_action_disconnect_by_mac",
    "session_action_disconnect_by_username",
]


def test_zz_coverage_is_complete_and_reported():
    """Every one of this module's 30 in-scope operations must carry a verdict.

    The two domains now hold 41 operations between them (21 + 20); the 11 in
    ``EXPANSION_OPERATIONS`` belong to the expansion modules. Anything else
    appearing in either domain falls into this module's scope and must carry a
    verdict, so a future addition cannot go unnoticed.
    """
    import src.main  # noqa: F401
    from src.registry import registry

    unknown = [n for n in EXPANSION_OPERATIONS if registry.get(n) is None]
    assert not unknown, f"unknown operations: {unknown}"

    in_scope = sorted(
        s.name for d in ("network_devices", "session_control")
        for s in registry.search(domain=d)
        if s.name not in EXPANSION_OPERATIONS
    )
    assert len(in_scope) == 30, f"expected 30 in-scope operations, got {len(in_scope)}"

    missing = [n for n in in_scope if n not in COVERAGE]
    tally: Dict[str, int] = {}
    print("\n[live-harness] network_devices + session_control verdicts")
    for name in in_scope:
        entry = COVERAGE.get(name, {"verdict": "NOT RUN", "note": ""})
        tally[entry["verdict"]] = tally.get(entry["verdict"], 0) + 1
        print(f"   {entry['verdict']:14s} {name:45s} {entry['note'][:90]}")
    print(f"[live-harness] tally: {tally}  (of {len(in_scope)})")

    if BUGS:
        print(f"\n[live-harness] {len(BUGS)} bug(s) found (reported, NOT fixed):")
        for i, bug in enumerate(BUGS, 1):
            print(f"  {i}. {bug['operation']}")
            print(f"     params     : {bug['params']}")
            print(f"     error      : {bug['error']}")
            print(f"     root cause : {bug['root_cause']}")
            for extra in bug.get("affected", []):
                print(f"     affected   : {extra}")

    assert not missing, f"operations with no recorded verdict: {missing}"
    assert tally.get(FAIL, 0) == 0, (
        "FAIL verdicts recorded: "
        + str({k: v for k, v in COVERAGE.items() if v["verdict"] == FAIL})
    )
