"""Live validation — ``integrations`` domain (80 operations).

Scope
-----
Every operation registered under ``@operation(domain="integrations")``:

===========================  ====  =======================================
family                        ops   how it is exercised
===========================  ====  =======================================
syslog-target                  10   fixture CRUD, identity = host_address
syslog-export-filter           10   fixture CRUD, identity = name
event-sources                  10   fixture CRUD, identity = name
context-server-action          10   fixture CRUD, identity = action_name
endpoint-context-server        12   fixture CRUD + 2 trigger-poll
ingress-event-dictionary       10   fixture CRUD or EXPECTED-LIMITATION
device-insight                  2   GET, plus a STRICT read-restore
extension (instance + store)   16   reads dispatched, lifecycle writes never
===========================  ====  =======================================

Calling style
-------------
Optional parameters are OMITTED by default (see tests/live/README.md); the
omission path is where the ``FieldInfo`` class of bug lives. Every dispatch goes
through ``harness.invoke`` so the gateway (name resolution, parameter
whitelisting, ``Context`` injection, error wrapping) is validated at the same
time as the operation.

Safety
------
* **Name-keyed families** (syslog export filters, event sources, context server
  actions, endpoint context servers, ingress event dictionaries) use
  ``harness.fixture_name`` and are guarded by ``harness.assert_ours()``
  immediately before every update/replace/delete.

* **Syslog targets cannot carry a ``zzz-mcptest-`` name.** ``host_address`` is
  the identity key and the appliance only accepts an address there, so the name
  prefix guard does not apply. Instead this module reserves a small block of
  **RFC 5737 documentation-range** addresses (``192.0.2.0/24`` — reserved by
  IANA for documentation, never routed, so it can never be a real syslog
  collector), derives them deterministically from the session ``run_id`` so two
  concurrent runs cannot collide, and records the block into the results
  artifact. ``Net.assert_ours`` is the syslog-target analogue of
  ``assert_ours``: it raises unless the address is *exactly* one of this run's
  reserved addresses, and it is called immediately before every syslog-target
  update/replace/delete.

* **Nothing outside the fixture namespace is ever written.** The session
  inventory guard in ``conftest.py`` snapshots none of the integrations families
  and ``harness.sweep_fixtures()`` cannot clean them either, so this module
  carries its own module-scoped sweep: at teardown it lists all six writable
  families and deletes anything carrying the fixture prefix or one of this run's
  reserved addresses — and nothing else.

* **Extension lifecycle writes are never dispatched.** Installing, reinstalling
  or upgrading an extension pulls an image from Aruba's online store and mutates
  appliance services; starting/stopping/restarting/reconfiguring or uninstalling
  one would disrupt whichever real integration it backs. No fixture extension
  instance can exist (one cannot be created without an install), so every such
  operation is either asserted to raise ``DenylistedOperation`` — when
  ``denylist.py`` carries it — or recorded ``BLOCKED`` without being dispatched.
  The choice is made at RUNTIME from ``denylist.DENYLIST`` so this module stays
  correct however the denylist evolves.

Verdicts beyond harness.classify
--------------------------------
``PASS-graceful``       a write that is *expected* to fail because the target is
                        unreachable (endpoint-context-server poll against a
                        documentation-range address). A structured error is the
                        correct answer; a traceback or an HTML body is a FAIL.
``EXPECTED-LIMITATION`` the appliance/environment cannot serve the operation
                        (the extension store needs outbound internet; the
                        ingress-event-dictionary schema may be rejected).
                        Recorded with the structured error so it can be triaged.
``BLOCKED``             deliberately not dispatched; the reason is recorded.
"""

from __future__ import annotations

import copy
import json
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, FAIL, PASS, assert_ours, fixture_name

DOMAIN = "integrations"

#: Extra verdicts this module writes into ``results-<runid>.jsonl``.
BLOCKED = "BLOCKED"
LIMITATION = "EXPECTED-LIMITATION"
GRACEFUL = "PASS-graceful"

#: Identities that provably do not exist. The name carries the fixture prefix so
#: it can never collide with production data, and is never created.
GHOST = "zzz-mcptest-ghost-0000"
GHOST_ID = 999999
#: Extension instance ids are opaque UUID strings. This one is well-formed but
#: all-zero, so it cannot be a real instance on any appliance.
GHOST_UUID = "00000000-0000-4000-8000-000000000000"

#: RFC 5737 TEST-NET-1: reserved for documentation, never routed.
DOC_NET = "192.0.2."


# ==========================================================================
# Documentation-range address reservation (the syslog-target safety rail)
# ==========================================================================


def _fixture_octet(run_id: str, n: int) -> int:
    """Deterministic, run-scoped host octet inside 192.0.2.0/24.

    Derived from the session run id so two concurrent runs get disjoint blocks,
    and clamped well inside the usable host range.
    """
    base = int(run_id[:4], 16) % 200 + 10  # 10..209
    octet = base + n
    if octet > 250:
        octet -= 200
    return octet


class Net:
    """This run's reserved documentation-range addresses.

    ``assert_ours`` is to syslog targets what ``harness.assert_ours`` is to
    named objects: the load-bearing guard called immediately before every
    update/replace/delete of an address-keyed object.
    """

    def __init__(self, run_id: str, count: int = 6) -> None:
        self.run_id = run_id
        self.ips: List[str] = [
            f"{DOC_NET}{_fixture_octet(run_id, n)}" for n in range(count)
        ]
        assert len(set(self.ips)) == count, self.ips
        for ip in self.ips:
            assert ip.startswith(DOC_NET), ip

    def __getitem__(self, n: int) -> str:
        return self.ips[n]

    def is_ours(self, address: Any) -> bool:
        return isinstance(address, str) and address in self.ips

    def assert_ours(self, address: Any) -> str:
        if not self.is_ours(address):
            raise AssertionError(
                f"SAFETY GUARD: refusing to write/delete syslog target "
                f"{address!r} — it is not one of this run's reserved "
                f"documentation-range addresses {self.ips}. The live harness "
                f"may only mutate objects it created."
            )
        return address


@pytest.fixture(scope="module")
def net(run_id: str) -> Net:
    n = Net(run_id)
    print(f"[live-harness] integrations reserved documentation addresses: {n.ips}")
    return n


# ==========================================================================
# Dispatch / classification helpers
# ==========================================================================


def _ok(result: Any) -> bool:
    return isinstance(result, dict) and result.get("success") is True


def verdict_for(
    result: Dict[str, Any],
    operation: str,
    *,
    expect_absent: bool = False,
    expect_guard: bool = False,
) -> str:
    """``harness.classify`` plus a guard-path allowance.

    ``expect_guard`` marks a deliberate call with a missing identifier: a
    structured refusal is the *correct* answer, so ``success: False`` with a
    guard-shaped message is a PASS.
    """
    if harness.deep_crash_marker(result) is not None:
        return FAIL

    base = harness.classify(result, operation, expect_absent=expect_absent)
    if base == PASS:
        return PASS

    if expect_guard and result.get("success") is False:
        text = harness.deep_error_text(result).lower()
        guard_words = (
            "missing required parameter", "must be provided", "please provide",
            "required", "not found", "cannot be empty", "confirm",
        )
        if any(w in text for w in guard_words):
            return PASS
    return base


def tolerant_verdict(
    result: Dict[str, Any],
    operation: str,
    label: str,
    *,
    expect_absent: bool = False,
) -> str:
    """PASS on success; ``label`` on a *structured* failure; FAIL on a crash.

    Used where the appliance may legitimately be unable to complete the call
    (unreachable poll target, no outbound internet, unsupported schema). A
    traceback, a ``FieldInfo`` leak or an HTML error body is still a FAIL — a
    known environment limit must present as a structured error, never as a
    Python-level explosion.
    """
    base = verdict_for(result, operation, expect_absent=expect_absent)
    if base in (PASS, EXPECTED_SKIP):
        return base
    if harness.deep_crash_marker(result) is not None:
        return FAIL
    if harness.looks_like_html(harness.deep_error_text(result)):
        return FAIL
    return label


def _record(
    recorder,
    operation: str,
    tier: str,
    verdict: str,
    params: Dict[str, Any],
    result: Dict[str, Any],
    duration_ms: float = 0.0,
) -> None:
    err = None
    if verdict != PASS:
        err = (harness.deep_error_text(result) or "").strip()[:600] or None
    recorder.record(operation, DOMAIN, tier, verdict, params, err, duration_ms)


def note(recorder, operation: str, verdict: str, tier: str, reason: str) -> None:
    """Record a verdict for an operation that is deliberately not dispatched."""
    recorder.record(operation, DOMAIN, tier, verdict, {}, reason, 0.0)


async def _call(
    recorder,
    operation: str,
    tier: str,
    *,
    expect_absent: bool = False,
    expect_guard: bool = False,
    **params: Any,
) -> Tuple[Dict[str, Any], str]:
    start = time.perf_counter()
    result = await harness.invoke(operation, _params=params)
    duration = (time.perf_counter() - start) * 1000.0
    verdict = verdict_for(
        result, operation, expect_absent=expect_absent, expect_guard=expect_guard
    )
    _record(recorder, operation, tier, verdict, params, result, duration)
    return result, verdict


async def _call_tolerant(
    recorder,
    operation: str,
    tier: str,
    label: str,
    *,
    expect_absent: bool = False,
    **params: Any,
) -> Tuple[Dict[str, Any], str]:
    start = time.perf_counter()
    result = await harness.invoke(operation, _params=params)
    duration = (time.perf_counter() - start) * 1000.0
    verdict = tolerant_verdict(result, operation, label, expect_absent=expect_absent)
    _record(recorder, operation, tier, verdict, params, result, duration)
    return result, verdict


def items_of(result: Any) -> List[Dict[str, Any]]:
    return harness._extract_items(result) if isinstance(result, dict) else []


def payload_of(result: Any) -> Dict[str, Any]:
    """The created/fetched object out of a ``{"success": True, "data": ...}``."""
    data = result.get("data") if isinstance(result, dict) else None
    return data if isinstance(data, dict) else {}


def strip_readonly(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Drop server-generated keys so a payload can be re-POSTed / re-PUT."""
    out = copy.deepcopy(obj) if isinstance(obj, dict) else {}
    for key in ("id", "_links", "_embedded", "href", "created_at", "updated_at"):
        out.pop(key, None)
    return out


async def find_id(list_op: str, field: str, value: Any) -> Optional[Any]:
    """Resolve an object's numeric id by listing the family and matching ``field``.

    Some create operations answer 201 with an empty body, so the id has to be
    looked up rather than read off the create result. Read-only.
    """
    listed = await harness.invoke(list_op, limit=1000)
    if not _ok(listed):
        return None
    for item in items_of(listed):
        if item.get(field) == value:
            return item.get("id")
    return None


def require_created(result: Dict[str, Any], operation: str) -> Dict[str, Any]:
    """Assert a fixture create succeeded, carrying the structured error if not."""
    assert harness.deep_crash_marker(result) is None, result
    assert _ok(result), (
        f"{operation} could not create its fixture, so the rest of the "
        f"lifecycle cannot run: {json.dumps(result, default=str)[:800]}"
    )
    return payload_of(result)


# ==========================================================================
# Module-scoped sweep — these families are covered by neither
# harness.sweep_fixtures() nor the session inventory guard.
# ==========================================================================

#: family -> (list op, identity field, delete-by-id op, id parameter)
_SWEEPABLE: Dict[str, Tuple[str, str, str, str]] = {
    "syslog_export_filters": ("list_syslog_export_filters", "name",
                              "delete_syslog_export_filter_by_id",
                              "syslog_export_filter_id"),
    "event_sources": ("list_event_sources", "name",
                      "delete_event_source_by_id", "event_sources_id"),
    "endpoint_context_servers": ("list_endpoint_context_servers", "server_name",
                                 "delete_endpoint_context_server_by_id",
                                 "endpoint_context_server_id"),
    "context_server_actions": ("list_context_server_actions", "action_name",
                               "delete_context_server_action_by_id",
                               "context_server_action_id"),
    "ingress_event_dictionaries": ("list_ingress_event_dictionaries", "format_name",
                                   "delete_ingress_event_dictionary_by_id",
                                   "ingress_event_dictionary_id"),
}


async def sweep_integrations(net: Net) -> List[Dict[str, Any]]:
    """Delete every surviving object this module could have created.

    Only objects whose identity carries the fixture prefix — or, for syslog
    targets, whose host address is one of this run's reserved
    documentation-range addresses — are ever touched, and the guard runs
    immediately before each delete.
    """
    swept: List[Dict[str, Any]] = []

    for family, (list_op, name_field, del_op, id_param) in _SWEEPABLE.items():
        if is_denylisted(del_op):
            continue
        try:
            listed = await harness.invoke(list_op, limit=1000)
        except Exception as exc:
            swept.append({"family": family, "error": f"list failed: {exc}"})
            continue
        if not _ok(listed):
            continue
        for item in items_of(listed):
            name = item.get(name_field)
            if not harness.is_ours(name):
                continue
            try:
                assert_ours(name)  # guard immediately before delete
                result = await harness.invoke(del_op, **{id_param: item.get("id")})
                swept.append({"family": family, "name": name,
                              "deleted": _ok(result)})
            except Exception as exc:
                swept.append({"family": family, "name": name, "deleted": False,
                              "detail": f"{type(exc).__name__}: {exc}"})

    # Syslog targets are keyed by address, not by name.
    try:
        listed = await harness.invoke("list_syslog_targets", limit=1000)
    except Exception as exc:
        swept.append({"family": "syslog_targets", "error": f"list failed: {exc}"})
        return swept
    if _ok(listed):
        for item in items_of(listed):
            address = item.get("host_address")
            if not net.is_ours(address):
                continue
            try:
                net.assert_ours(address)  # guard immediately before delete
                result = await harness.invoke("delete_syslog_target_by_id",
                                              syslog_target_id=item.get("id"))
                swept.append({"family": "syslog_targets", "host_address": address,
                              "deleted": _ok(result)})
            except Exception as exc:
                swept.append({"family": "syslog_targets", "host_address": address,
                              "deleted": False,
                              "detail": f"{type(exc).__name__}: {exc}"})
    return swept


@pytest.fixture(scope="module", autouse=True)
def integrations_sweep(run_async, net: Net):
    """Delete any surviving integrations fixture at module teardown."""
    try:
        yield
    finally:
        swept = run_async(sweep_integrations(net))
        if swept:
            print(f"[live-harness] integrations sweep touched {len(swept)} "
                  f"object(s):")
            for entry in swept:
                print(f"   - {entry}")
        else:
            print("[live-harness] integrations sweep: nothing left to remove")


# ==========================================================================
# Shapes harvested read-only from the appliance
# ==========================================================================
#
# Several create payloads need an enum value the operation docstrings do not
# spell out (context server type, endpoint auth method, event source vendor,
# syslog export template, ...). Rather than guessing, the first pre-existing
# object of the family is read and its value reused, with a documented fallback
# for an appliance where the family is empty. Nothing here mutates anything.


@pytest.fixture(scope="module")
def shapes(run_async) -> Dict[str, Dict[str, Any]]:
    async def _harvest() -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for key, op in [
            ("context_server_action", "list_context_server_actions"),
            ("endpoint_context_server", "list_endpoint_context_servers"),
            ("event_source", "list_event_sources"),
            ("syslog_export_filter", "list_syslog_export_filters"),
            ("ingress_event_dictionary", "list_ingress_event_dictionaries"),
            ("syslog_target", "list_syslog_targets"),
            ("extension_instance", "list_extension_instances"),
        ]:
            try:
                result = await harness.invoke(op, limit=1000)
            except Exception:
                out[key] = {}
                continue
            listed = items_of(result) if _ok(result) else []
            out[key] = listed[0] if listed else {}
        return out

    return run_async(_harvest())


def pick(shape: Dict[str, Any], field: str, fallback: Any) -> Any:
    """A live value for ``field`` if the appliance has one, else ``fallback``."""
    value = shape.get(field)
    if value in (None, "", [], {}):
        return fallback
    return value


# ==========================================================================
# 0. Scope guard — the domain must not drift under this file
# ==========================================================================

#: Every operation this module accounts for. Kept explicit so a new operation
#: landing in the domain fails here instead of silently going untested.
OPS_COVERED = {
    # --- context-server-action (10) ---
    "list_context_server_actions", "create_context_server_action",
    "get_context_server_action_by_id", "update_context_server_action_by_id",
    "replace_context_server_action_by_id", "delete_context_server_action_by_id",
    "get_context_server_action_by_name", "update_context_server_action_by_name",
    "replace_context_server_action_by_name", "delete_context_server_action_by_name",
    # --- device-insight (2) ---
    "get_device_insight_config", "update_device_insight_config",
    # --- endpoint-context-server (12) ---
    "list_endpoint_context_servers", "create_endpoint_context_server",
    "get_endpoint_context_server_by_name", "update_endpoint_context_server_by_name",
    "replace_endpoint_context_server_by_name",
    "delete_endpoint_context_server_by_name",
    "get_endpoint_context_server_by_id", "update_endpoint_context_server_by_id",
    "replace_endpoint_context_server_by_id", "delete_endpoint_context_server_by_id",
    "trigger_endpoint_context_server_poll_by_name",
    "trigger_endpoint_context_server_poll_by_id",
    # --- event-sources (10) ---
    "list_event_sources", "create_event_source", "get_event_source_by_name",
    "update_event_source_by_name", "replace_event_source_by_name",
    "delete_event_source_by_name", "get_event_source_by_id",
    "update_event_source_by_id", "replace_event_source_by_id",
    "delete_event_source_by_id",
    # --- extension instance + store (16) ---
    "list_extension_instances", "install_extension_instance",
    "get_extension_instance", "update_extension_instance_state",
    "uninstall_extension_instance", "get_extension_instance_config",
    "replace_extension_instance_config", "get_extension_instance_log",
    "reinstall_extension_instance", "restart_extension_instance",
    "start_extension_instance", "stop_extension_instance",
    "get_extension_upgrade_info", "upgrade_extension_instance",
    "list_extension_store", "get_extension_store_item",
    # --- ingress-event-dictionary (10) ---
    "list_ingress_event_dictionaries", "create_ingress_event_dictionary",
    "get_ingress_event_dictionary_by_format_name",
    "update_ingress_event_dictionary_by_format_name",
    "replace_ingress_event_dictionary_by_format_name",
    "delete_ingress_event_dictionary_by_format_name",
    "get_ingress_event_dictionary_by_id",
    "update_ingress_event_dictionary_by_id",
    "replace_ingress_event_dictionary_by_id",
    "delete_ingress_event_dictionary_by_id",
    # --- syslog-export-filter (10) ---
    "list_syslog_export_filters", "create_syslog_export_filter",
    "get_syslog_export_filter_by_name", "update_syslog_export_filter_by_name",
    "replace_syslog_export_filter_by_name", "delete_syslog_export_filter_by_name",
    "get_syslog_export_filter_by_id", "update_syslog_export_filter_by_id",
    "replace_syslog_export_filter_by_id", "delete_syslog_export_filter_by_id",
    # --- syslog-target (10) ---
    "list_syslog_targets", "create_syslog_target",
    "get_syslog_target_by_host_address", "update_syslog_target_by_host_address",
    "replace_syslog_target_by_host_address", "delete_syslog_target_by_host_address",
    "get_syslog_target_by_id", "update_syslog_target_by_id",
    "replace_syslog_target_by_id", "delete_syslog_target_by_id",
}


def test_scope_is_the_whole_integrations_domain():
    import src.main  # noqa: F401
    from src.registry import registry

    registered = {s.name for s in registry.search(domain=DOMAIN)}
    assert len(registered) == 80, f"integrations changed size: {len(registered)}"
    assert OPS_COVERED == registered, {
        "untested_new_operations": sorted(registered - OPS_COVERED),
        "covered_but_gone_from_registry": sorted(OPS_COVERED - registered),
    }


def test_reserved_documentation_addresses_are_recorded(recorder, net: Net):
    """Pin this run's syslog-target identity keys into the results artifact.

    A syslog target cannot carry the ``zzz-mcptest-`` name prefix — the identity
    key is an address — so the reserved block IS the fixture namespace for that
    family and must be reproducible from the artifact when triaging a run.
    """
    for ip in net.ips:
        assert ip.startswith(DOC_NET), ip
        assert net.is_ours(ip)
    with pytest.raises(AssertionError):
        net.assert_ours("10.0.0.1")
    recorder.record(
        "list_syslog_targets", DOMAIN, "fixture-namespace", PASS,
        {"reserved_documentation_addresses": net.ips}, None, 0.0,
    )


# ==========================================================================
# 1. List reads — every optional parameter OMITTED
# ==========================================================================

LIST_READS = [
    "list_context_server_actions",
    "list_endpoint_context_servers",
    "list_event_sources",
    "list_ingress_event_dictionaries",
    "list_syslog_export_filters",
    "list_syslog_targets",
]


@pytest.mark.parametrize("operation", LIST_READS)
def test_list_with_all_optionals_omitted(run_async, recorder, operation):
    """The omission path — where the FieldInfo class of bug lived."""
    result, verdict = run_async(_call(recorder, operation, "read"))
    assert verdict == PASS, f"{operation}() -> {json.dumps(result, default=str)[:600]}"
    assert harness.deep_crash_marker(result) is None


@pytest.mark.parametrize("operation", LIST_READS)
def test_list_with_paging_optionals_supplied(run_async, recorder, operation):
    """[+opt] the same lists with realistic paging/counting supplied."""
    result, verdict = run_async(
        _call(recorder, operation, "read", limit=5, offset=0, calculate_count=True)
    )
    assert verdict == PASS, f"{operation}(+opt) -> {result}"


# ==========================================================================
# 2. syslog-target — fixture CRUD keyed by a reserved documentation address
# ==========================================================================


def _syslog_payload(address: str, description: str) -> Dict[str, Any]:
    """Required body fields per the operation docstring: host_address, protocol,
    server_port."""
    return {
        "host_address": address,
        "description": description,
        "server_port": 514,
        "protocol": "UDP",
    }


def test_syslog_target_lifecycle_by_host_address(
    run_async, recorder, run_id, net: Net, cleanup
):
    """create -> get(address) -> get(id) -> update(address) -> replace(address)
    -> delete(address) -> confirm absent."""
    address = net[0]
    tag = fixture_name(run_id, "syslog-a")

    created, v_create = run_async(
        _call(recorder, "create_syslog_target", "create",
              target_data=_syslog_payload(address, f"{tag} live validation"))
    )
    obj = require_created(created, "create_syslog_target")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_syslog_target_by_host_address",
                                       host_address=net.assert_ours(address)))

    target_id = obj.get("id")
    if target_id is None:
        target_id = run_async(find_id("list_syslog_targets", "host_address", address))

    # --- read back by both handles ---------------------------------------
    fetched, v = run_async(
        _call(recorder, "get_syslog_target_by_host_address", "read",
              host_address=address)
    )
    assert v == PASS, fetched
    assert payload_of(fetched).get("host_address") == address, fetched

    assert target_id is not None, "the created syslog target has no resolvable id"
    by_id, v = run_async(
        _call(recorder, "get_syslog_target_by_id", "read", syslog_target_id=target_id)
    )
    assert v == PASS, by_id
    assert payload_of(by_id).get("host_address") == address, by_id

    # --- PATCH by address --------------------------------------------------
    net.assert_ours(address)
    patched, v = run_async(
        _call(recorder, "update_syslog_target_by_host_address", "update",
              host_address=address, target_data={"description": f"{tag} patched"})
    )
    assert v == PASS, patched

    # --- PUT (full replacement) by address ---------------------------------
    net.assert_ours(address)
    replaced, v = run_async(
        _call(recorder, "replace_syslog_target_by_host_address", "update",
              host_address=address,
              target_data=_syslog_payload(address, f"{tag} replaced"))
    )
    assert v == PASS, replaced

    # --- DELETE by address -------------------------------------------------
    net.assert_ours(address)
    deleted, v = run_async(
        _call(recorder, "delete_syslog_target_by_host_address", "delete",
              host_address=address)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_syslog_target_by_host_address", "negative",
              expect_absent=True, host_address=address)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_syslog_target_lifecycle_by_id(run_async, recorder, run_id, net: Net, cleanup):
    """The by-id half: update(id) -> replace(id) -> delete(id)."""
    address = net[1]
    tag = fixture_name(run_id, "syslog-b")

    created, v_create = run_async(
        _call(recorder, "create_syslog_target", "create",
              target_data=_syslog_payload(address, f"{tag} live validation"))
    )
    obj = require_created(created, "create_syslog_target")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_syslog_target_by_host_address",
                                       host_address=net.assert_ours(address)))

    target_id = obj.get("id")
    if target_id is None:
        target_id = run_async(find_id("list_syslog_targets", "host_address", address))
    assert target_id is not None, created

    net.assert_ours(address)
    patched, v = run_async(
        _call(recorder, "update_syslog_target_by_id", "update",
              syslog_target_id=target_id,
              target_data={"description": f"{tag} patched by id"})
    )
    assert v == PASS, patched

    net.assert_ours(address)
    replaced, v = run_async(
        _call(recorder, "replace_syslog_target_by_id", "update",
              syslog_target_id=target_id,
              target_data=_syslog_payload(address, f"{tag} replaced by id"))
    )
    assert v == PASS, replaced

    net.assert_ours(address)
    deleted, v = run_async(
        _call(recorder, "delete_syslog_target_by_id", "delete",
              syslog_target_id=target_id)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_syslog_target_by_id", "negative",
              expect_absent=True, syslog_target_id=target_id)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_syslog_target_guard_paths(run_async, recorder):
    """A required parameter omitted -> pre-dispatch refusal, never a TypeError.

    Contract (``src/tools/gateway.py::invoke_operation``): the gateway rejects
    the call before the operation body runs, naming the parameter. The absence
    of ``missing required argument`` is part of the assertion — that text would
    mean the operation was called and Python raised.
    """
    for operation, param in [
        ("get_syslog_target_by_host_address", "host_address"),
        ("get_syslog_target_by_id", "syslog_target_id"),
        ("create_syslog_target", "target_data"),
    ]:
        result, verdict = run_async(
            _call(recorder, operation, "negative", expect_guard=True)
        )
        blob = json.dumps(result, default=str)
        assert result.get("success") is False, result
        assert "Missing required parameter(s)" in str(result.get("error")), result
        assert f"'{param}'" in str(result.get("error")), result
        assert "missing required argument" not in blob, result
        assert "TypeError" not in blob, result
        assert verdict == PASS, result


# ==========================================================================
# 3. syslog-export-filter — fixture CRUD keyed by name
# ==========================================================================


def _export_filter_payload(
    name: str, shape: Dict[str, Any], syslog_server: str, description: str
) -> Dict[str, Any]:
    """Required body fields per the docstring: name, export_template,
    export_event_format_type, syslog_servers. The three enum values are taken
    from a pre-existing filter when the appliance has one.

    Two things the docstring does not say, both established against the
    appliance (2026-07-30):

    * ``local_facility_level`` is spelled ``local0``..``local7``, not the
      syslog C-macro name — ``LOG_LOCAL0`` is rejected with
      *"Local facility level LOG_LOCAL0 is invalid"*.
    * a filter is only accepted with rules: without ``custom_sql`` (or a
      ``data_filter`` that itself carries rules) the appliance answers
      *"You must specify rules for the data filter or custom filter SQL"*.
      ``SELECT 1`` is the minimal well-formed statement and the filter is
      created disabled, so it never exports anything.
    """
    return {
        "name": name,
        "description": description,
        "export_template": pick(shape, "export_template", "Session Logs"),
        "export_event_format_type": pick(shape, "export_event_format_type",
                                         "Standard"),
        "local_facility_level": pick(shape, "local_facility_level", "local0"),
        "syslog_servers": [syslog_server],
        "custom_sql": "SELECT 1",
        "enabled": False,
    }


def test_syslog_export_filter_lifecycle(
    run_async, recorder, run_id, net: Net, shapes, cleanup
):
    """A fixture syslog target is created first so the filter references our own
    documentation-range collector rather than a production one."""
    collector = net[2]
    target_created = run_async(harness.invoke(
        "create_syslog_target",
        target_data=_syslog_payload(collector,
                                    "zzz-mcptest export-filter collector")))
    if _ok(target_created):
        cleanup.add(lambda: harness.invoke(
            "delete_syslog_target_by_host_address",
            host_address=net.assert_ours(collector)))

    shape = shapes["syslog_export_filter"]
    name = fixture_name(run_id, "sxf-1")
    renamed = fixture_name(run_id, "sxf-1", "renamed")

    created, v_create = run_async(
        _call(recorder, "create_syslog_export_filter", "create",
              filter_data=_export_filter_payload(
                  name, shape, collector, "integrations live validation"))
    )
    obj = require_created(created, "create_syslog_export_filter")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_syslog_export_filter_by_name",
                                       name=assert_ours(name)))

    filter_id = obj.get("id")
    if filter_id is None:
        filter_id = run_async(find_id("list_syslog_export_filters", "name", name))
    assert filter_id is not None, created

    fetched, v = run_async(
        _call(recorder, "get_syslog_export_filter_by_name", "read", name=name)
    )
    assert v == PASS, fetched

    by_id, v = run_async(
        _call(recorder, "get_syslog_export_filter_by_id", "read",
              syslog_export_filter_id=filter_id)
    )
    assert v == PASS, by_id

    assert_ours(name)
    patched, v = run_async(
        _call(recorder, "update_syslog_export_filter_by_name", "update",
              name=name, filter_data={"description": "patched by name"})
    )
    assert v == PASS, patched

    assert_ours(name)
    patched, v = run_async(
        _call(recorder, "update_syslog_export_filter_by_id", "update",
              syslog_export_filter_id=filter_id,
              filter_data={"description": "patched by id"})
    )
    assert v == PASS, patched

    assert_ours(name)
    replaced, v = run_async(
        _call(recorder, "replace_syslog_export_filter_by_id", "update",
              syslog_export_filter_id=filter_id,
              filter_data=_export_filter_payload(
                  name, shape, collector, "replaced by id"))
    )
    assert v == PASS, replaced

    # PUT by name, renaming into a second fixture name.
    assert_ours(name)
    assert_ours(renamed)
    cleanup.add(lambda: harness.invoke("delete_syslog_export_filter_by_name",
                                       name=assert_ours(renamed)))
    replaced, v = run_async(
        _call(recorder, "replace_syslog_export_filter_by_name", "update",
              name=name,
              filter_data=_export_filter_payload(
                  renamed, shape, collector, "replaced by name"))
    )
    assert v == PASS, replaced

    survivor = renamed if _ok(replaced) else name
    assert_ours(survivor)
    deleted, v = run_async(
        _call(recorder, "delete_syslog_export_filter_by_name", "delete",
              name=survivor)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_syslog_export_filter_by_name", "negative",
              expect_absent=True, name=survivor)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_syslog_export_filter_delete_by_id(
    run_async, recorder, run_id, net: Net, shapes, cleanup
):
    """A second fixture so ``delete_syslog_export_filter_by_id`` is exercised."""
    name = fixture_name(run_id, "sxf-2")

    # The appliance rejects a filter whose syslog_servers entry is not an
    # existing syslog target, and the collector this run created for the
    # lifecycle test above was torn down with that test.
    collector = net[2]
    target_created = run_async(harness.invoke(
        "create_syslog_target",
        target_data=_syslog_payload(collector,
                                    "zzz-mcptest export-filter collector")))
    if _ok(target_created):
        cleanup.add(lambda: harness.invoke(
            "delete_syslog_target_by_host_address",
            host_address=net.assert_ours(collector)))

    created, v_create = run_async(
        _call(recorder, "create_syslog_export_filter", "create",
              filter_data=_export_filter_payload(
                  name, shapes["syslog_export_filter"], net[2],
                  "delete-by-id fixture"))
    )
    obj = require_created(created, "create_syslog_export_filter")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_syslog_export_filter_by_name",
                                       name=assert_ours(name)))

    filter_id = obj.get("id")
    if filter_id is None:
        filter_id = run_async(find_id("list_syslog_export_filters", "name", name))
    assert filter_id is not None, created

    assert_ours(name)
    deleted, v = run_async(
        _call(recorder, "delete_syslog_export_filter_by_id", "delete",
              syslog_export_filter_id=filter_id)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_syslog_export_filter_by_id", "negative",
              expect_absent=True, syslog_export_filter_id=filter_id)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


# ==========================================================================
# 4. event-sources — fixture CRUD keyed by name
# ==========================================================================


def _event_source_payload(
    name: str, address: str, shape: Dict[str, Any], description: str
) -> Dict[str, Any]:
    """Required body fields per the docstring: name, ipaddress, vendor, type.

    ``vendor`` is a closed appliance enum the docstring does not spell out. A
    pre-existing event source's value is reused when the appliance has one;
    otherwise "Palo Alto Networks" — established against the appliance
    (2026-07-30) as an accepted member, where "Aruba", "Aruba Networks",
    "ArubaOS" and "Juniper" are all rejected with *"Invalid Vendor name
    specified"*. The source is created disabled, so the vendor choice has no
    runtime effect.
    """
    return {
        "name": name,
        "description": description,
        "ipaddress": address,
        "vendor": pick(shape, "vendor", "Palo Alto Networks"),
        "type": pick(shape, "type", "Syslog"),
        "enable": False,
    }


def test_event_source_lifecycle_by_name(
    run_async, recorder, run_id, net: Net, shapes, cleanup
):
    shape = shapes["event_source"]
    name = fixture_name(run_id, "evs-1")
    address = net[3]

    created, v_create = run_async(
        _call(recorder, "create_event_source", "create",
              event_source_data=_event_source_payload(
                  name, address, shape, "integrations live validation"))
    )
    obj = require_created(created, "create_event_source")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_event_source_by_name",
                                       name=assert_ours(name)))

    source_id = obj.get("id")
    if source_id is None:
        source_id = run_async(find_id("list_event_sources", "name", name))
    assert source_id is not None, created

    fetched, v = run_async(
        _call(recorder, "get_event_source_by_name", "read", name=name)
    )
    assert v == PASS, fetched

    by_id, v = run_async(
        _call(recorder, "get_event_source_by_id", "read", event_sources_id=source_id)
    )
    assert v == PASS, by_id

    assert_ours(name)
    patched, v = run_async(
        _call(recorder, "update_event_source_by_name", "update",
              name=name, event_source_data={"description": "patched by name"})
    )
    assert v == PASS, patched

    assert_ours(name)
    replaced, v = run_async(
        _call(recorder, "replace_event_source_by_name", "update",
              name=name,
              event_source_data=_event_source_payload(
                  name, address, shape, "replaced by name"))
    )
    assert v == PASS, replaced

    assert_ours(name)
    deleted, v = run_async(
        _call(recorder, "delete_event_source_by_name", "delete", name=name)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_event_source_by_name", "negative",
              expect_absent=True, name=name)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_event_source_lifecycle_by_id(
    run_async, recorder, run_id, net: Net, shapes, cleanup
):
    shape = shapes["event_source"]
    name = fixture_name(run_id, "evs-2")
    address = net[4]

    created, v_create = run_async(
        _call(recorder, "create_event_source", "create",
              event_source_data=_event_source_payload(
                  name, address, shape, "by-id fixture"))
    )
    obj = require_created(created, "create_event_source")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_event_source_by_name",
                                       name=assert_ours(name)))

    source_id = obj.get("id")
    if source_id is None:
        source_id = run_async(find_id("list_event_sources", "name", name))
    assert source_id is not None, created

    assert_ours(name)
    patched, v = run_async(
        _call(recorder, "update_event_source_by_id", "update",
              event_sources_id=source_id,
              event_source_data={"description": "patched by id"})
    )
    assert v == PASS, patched

    assert_ours(name)
    replaced, v = run_async(
        _call(recorder, "replace_event_source_by_id", "update",
              event_sources_id=source_id,
              event_source_data=_event_source_payload(
                  name, address, shape, "replaced by id"))
    )
    assert v == PASS, replaced

    assert_ours(name)
    deleted, v = run_async(
        _call(recorder, "delete_event_source_by_id", "delete",
              event_sources_id=source_id)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_event_source_by_id", "negative",
              expect_absent=True, event_sources_id=source_id)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


# ==========================================================================
# 5. context-server-action — fixture CRUD; action_name carries the prefix
# ==========================================================================
#
# The by-name route is /context-server-action/{server_type}/action-name/{name},
# so the server type is part of the identity. It is an appliance enum the
# operation docstrings do not spell out, so a pre-existing action's server_type
# is reused when the appliance has one; "Generic HTTP Context Server" is the
# documented fallback (the built-in type used for plain HTTP context server
# actions — that is its exact spelling on the appliance).


def _action_payload(
    action_name: str, server_type: str, address: str, description: str
) -> Dict[str, Any]:
    """Required body fields per the docstring: server_type, action_name,
    http_method, url.

    Three constraints the docstring does not state, all established against the
    appliance (2026-07-30):

    * ``auth_method`` is a closed enum; ``"None"`` is rejected outright with
      *400 "The request sent by the client was syntactically incorrect"*.
      ``basic`` is what every built-in action on the appliance carries.
    * ``server_name`` may only be set when ``server_type`` is a Generic HTTP
      context server (*"Cannot set server name for Server types other than
      Generic HTTP"*), and even then it must name a context server that already
      exists (*"Context server <addr> does not exists"*). The fixture therefore
      omits it — which also means the action is bound to no server and can
      never fire.
    * ``url`` is a path relative to the context server's base URL, so the
      documentation-range host stays out of it.

    ``address`` is kept in the signature so the run's reserved address block
    still scopes the description; it is deliberately not put on the wire.
    """
    return {
        "server_type": server_type,
        "action_name": action_name,
        "description": description,
        "http_method": "GET",
        "auth_method": "basic",
        "url": f"/zzz-mcptest/{address}",
        "content_type": "JSON",
    }


@pytest.fixture(scope="module")
def action_server_type(shapes) -> str:
    return pick(shapes["context_server_action"], "server_type",
                "Generic HTTP Context Server")


def test_context_server_action_lifecycle(
    run_async, recorder, run_id, net: Net, action_server_type, cleanup
):
    action_name = fixture_name(run_id, "csa-1")
    address = net[0]
    server_type = action_server_type

    created, v_create = run_async(
        _call(recorder, "create_context_server_action", "create",
              action_data=_action_payload(action_name, server_type, address,
                                          "integrations live validation"))
    )
    obj = require_created(created, "create_context_server_action")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke(
        "delete_context_server_action_by_name",
        server_type=server_type, action_name=assert_ours(action_name)))

    action_id = obj.get("id")
    if action_id is None:
        action_id = run_async(
            find_id("list_context_server_actions", "action_name", action_name))
    assert action_id is not None, created

    fetched, v = run_async(
        _call(recorder, "get_context_server_action_by_name", "read",
              server_type=server_type, action_name=action_name)
    )
    assert v == PASS, fetched

    by_id, v = run_async(
        _call(recorder, "get_context_server_action_by_id", "read",
              context_server_action_id=action_id)
    )
    assert v == PASS, by_id

    assert_ours(action_name)
    patched, v = run_async(
        _call(recorder, "update_context_server_action_by_id", "update",
              context_server_action_id=action_id,
              action_data={"description": "patched by id"})
    )
    assert v == PASS, patched

    assert_ours(action_name)
    replaced, v = run_async(
        _call(recorder, "replace_context_server_action_by_id", "update",
              context_server_action_id=action_id,
              action_data=_action_payload(action_name, server_type, address,
                                          "replaced by id"))
    )
    assert v == PASS, replaced

    assert_ours(action_name)
    patched, v = run_async(
        _call(recorder, "update_context_server_action_by_name", "update",
              server_type=server_type, action_name=action_name,
              action_data={"description": "patched by name"})
    )
    assert v == PASS, patched

    assert_ours(action_name)
    replaced, v = run_async(
        _call(recorder, "replace_context_server_action_by_name", "update",
              server_type=server_type, action_name=action_name,
              action_data=_action_payload(action_name, server_type, address,
                                          "replaced by name"))
    )
    assert v == PASS, replaced

    assert_ours(action_name)
    deleted, v = run_async(
        _call(recorder, "delete_context_server_action_by_name", "delete",
              server_type=server_type, action_name=action_name)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_context_server_action_by_name", "negative",
              expect_absent=True, server_type=server_type, action_name=action_name)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_context_server_action_delete_by_id(
    run_async, recorder, run_id, net: Net, action_server_type, cleanup
):
    action_name = fixture_name(run_id, "csa-2")
    server_type = action_server_type

    created, v_create = run_async(
        _call(recorder, "create_context_server_action", "create",
              action_data=_action_payload(action_name, server_type, net[1],
                                          "delete-by-id fixture"))
    )
    obj = require_created(created, "create_context_server_action")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke(
        "delete_context_server_action_by_name",
        server_type=server_type, action_name=assert_ours(action_name)))

    action_id = obj.get("id")
    if action_id is None:
        action_id = run_async(
            find_id("list_context_server_actions", "action_name", action_name))
    assert action_id is not None, created

    assert_ours(action_name)
    deleted, v = run_async(
        _call(recorder, "delete_context_server_action_by_id", "delete",
              context_server_action_id=action_id)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_context_server_action_by_id", "negative",
              expect_absent=True, context_server_action_id=action_id)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


# ==========================================================================
# 6. endpoint-context-server — fixture CRUD + trigger-poll
# ==========================================================================


def _ecs_payload(
    server_name: str, address: str, shape: Dict[str, Any], description: str
) -> Dict[str, Any]:
    """Required body fields per the docstring: server_type, server_name,
    server_base_url, auth_method, validate_server, status, bypass_proxy."""
    return {
        "server_type": pick(shape, "server_type", "Generic HTTP"),
        "server_name": server_name,
        "server_base_url": f"https://{address}",
        "auth_method": pick(shape, "auth_method", "BASIC"),
        "username": "zzz-mcptest",
        # Not a credential: the host is an unroutable documentation address and
        # this literal is a placeholder, not a real secret.
        "password": "zzz-mcptest-not-a-secret",
        "description": description,
        "validate_server": False,
        "status": pick(shape, "status", "Disabled"),
        "bypass_proxy": False,
    }


def test_endpoint_context_server_lifecycle_by_name(
    run_async, recorder, run_id, net: Net, shapes, cleanup
):
    shape = shapes["endpoint_context_server"]
    server_name = fixture_name(run_id, "ecs-1")
    address = net[3]

    created, v_create = run_async(
        _call(recorder, "create_endpoint_context_server", "create",
              server_data=_ecs_payload(server_name, address, shape,
                                       "integrations live validation"))
    )
    obj = require_created(created, "create_endpoint_context_server")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_endpoint_context_server_by_name",
                                       server_name=assert_ours(server_name)))

    server_id = obj.get("id")
    if server_id is None:
        server_id = run_async(
            find_id("list_endpoint_context_servers", "server_name", server_name))
    assert server_id is not None, created

    fetched, v = run_async(
        _call(recorder, "get_endpoint_context_server_by_name", "read",
              server_name=server_name)
    )
    assert v == PASS, fetched

    by_id, v = run_async(
        _call(recorder, "get_endpoint_context_server_by_id", "read",
              endpoint_context_server_id=server_id)
    )
    assert v == PASS, by_id

    assert_ours(server_name)
    patched, v = run_async(
        _call(recorder, "update_endpoint_context_server_by_name", "update",
              server_name=server_name,
              server_data={"description": "patched by name"})
    )
    assert v == PASS, patched

    assert_ours(server_name)
    replaced, v = run_async(
        _call(recorder, "replace_endpoint_context_server_by_name", "update",
              server_name=server_name,
              server_data=_ecs_payload(server_name, address, shape,
                                       "replaced by name"))
    )
    assert v == PASS, replaced

    # --- trigger-poll, FIXTURE SERVER ONLY --------------------------------
    # The base URL is an RFC 5737 documentation address, so the poll cannot
    # reach anything and is expected to fail. A structured error is the correct
    # answer; a traceback or an HTML body is not.
    assert_ours(server_name)
    polled, v_poll = run_async(
        _call_tolerant(recorder, "trigger_endpoint_context_server_poll_by_name",
                       "write", GRACEFUL, server_name=server_name)
    )
    assert v_poll != FAIL, polled
    assert harness.deep_crash_marker(polled) is None, polled

    assert_ours(server_name)
    polled, v_poll = run_async(
        _call_tolerant(recorder, "trigger_endpoint_context_server_poll_by_id",
                       "write", GRACEFUL, endpoint_context_server_id=server_id)
    )
    assert v_poll != FAIL, polled
    assert harness.deep_crash_marker(polled) is None, polled

    assert_ours(server_name)
    deleted, v = run_async(
        _call(recorder, "delete_endpoint_context_server_by_name", "delete",
              server_name=server_name)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_endpoint_context_server_by_name", "negative",
              expect_absent=True, server_name=server_name)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_endpoint_context_server_lifecycle_by_id(
    run_async, recorder, run_id, net: Net, shapes, cleanup
):
    shape = shapes["endpoint_context_server"]
    server_name = fixture_name(run_id, "ecs-2")
    address = net[4]

    created, v_create = run_async(
        _call(recorder, "create_endpoint_context_server", "create",
              server_data=_ecs_payload(server_name, address, shape,
                                       "by-id fixture"))
    )
    obj = require_created(created, "create_endpoint_context_server")
    assert v_create == PASS, created
    cleanup.add(lambda: harness.invoke("delete_endpoint_context_server_by_name",
                                       server_name=assert_ours(server_name)))

    server_id = obj.get("id")
    if server_id is None:
        server_id = run_async(
            find_id("list_endpoint_context_servers", "server_name", server_name))
    assert server_id is not None, created

    assert_ours(server_name)
    patched, v = run_async(
        _call(recorder, "update_endpoint_context_server_by_id", "update",
              endpoint_context_server_id=server_id,
              server_data={"description": "patched by id"})
    )
    assert v == PASS, patched

    assert_ours(server_name)
    replaced, v = run_async(
        _call(recorder, "replace_endpoint_context_server_by_id", "update",
              endpoint_context_server_id=server_id,
              server_data=_ecs_payload(server_name, address, shape,
                                       "replaced by id"))
    )
    assert v == PASS, replaced

    assert_ours(server_name)
    deleted, v = run_async(
        _call(recorder, "delete_endpoint_context_server_by_id", "delete",
              endpoint_context_server_id=server_id)
    )
    assert v == PASS, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_endpoint_context_server_by_id", "negative",
              expect_absent=True, endpoint_context_server_id=server_id)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_endpoint_context_server_poll_is_never_aimed_at_a_real_server(
    run_async, recorder
):
    """Polling an identity that does not exist must 404, not fall through.

    Every other poll call in this module carries ``assert_ours(server_name)``,
    so no pre-existing endpoint context server on this appliance is ever named.
    """
    assert_ours(GHOST)
    result, verdict = run_async(
        _call(recorder, "trigger_endpoint_context_server_poll_by_name", "negative",
              expect_absent=True, server_name=GHOST)
    )
    assert result.get("success") is not True, result
    assert harness.deep_crash_marker(result) is None, result
    assert verdict == PASS, result


# ==========================================================================
# 7. ingress-event-dictionary — fixture CRUD, or EXPECTED-LIMITATION
# ==========================================================================
#
# Required body fields are vendor, format_name, prefix, filter, fields and
# generic_fields — a nested schema the operation docstring does not specify. A
# pre-existing dictionary is cloned (server-generated keys stripped, identity
# fields replaced with fixture values) to give the create the best chance of
# being accepted. If the appliance still rejects it, the family is recorded
# EXPECTED-LIMITATION carrying the structured error and every write operation is
# instead exercised against a ghost identity, so each is still proved not to
# crash without ever touching real data.

_IED_WRITE_OPS = [
    "get_ingress_event_dictionary_by_format_name",
    "update_ingress_event_dictionary_by_format_name",
    "replace_ingress_event_dictionary_by_format_name",
    "delete_ingress_event_dictionary_by_format_name",
    "get_ingress_event_dictionary_by_id",
    "update_ingress_event_dictionary_by_id",
    "replace_ingress_event_dictionary_by_id",
    "delete_ingress_event_dictionary_by_id",
]


def _ied_payload(format_name: str, run_id: str, shape: Dict[str, Any]) -> Dict[str, Any]:
    if shape:
        payload = strip_readonly(shape)
        payload["format_name"] = format_name
        payload["prefix"] = f"zzzmcp{run_id[:4]}"
        payload["description"] = "integrations live validation"
        return payload
    return {
        "vendor": "Aruba",
        "format_name": format_name,
        "prefix": f"zzzmcp{run_id[:4]}",
        "status": "Disabled",
        "description": "integrations live validation",
        "filter": {},
        "fields": [],
        "generic_fields": {},
    }


async def _ingress_ghost_probes(recorder) -> None:
    """Prove every ingress write op returns a structured 404, never a crash.

    Targets ``zzz-mcptest-ghost-0000`` / id 999999, so it is provably incapable
    of touching real data.
    """
    assert_ours(GHOST)
    probes = [
        ("get_ingress_event_dictionary_by_format_name", {"format_name": GHOST}),
        ("update_ingress_event_dictionary_by_format_name",
         {"format_name": GHOST, "dictionary_data": {"description": "x"}}),
        ("replace_ingress_event_dictionary_by_format_name",
         {"format_name": GHOST, "dictionary_data": {"description": "x"}}),
        ("delete_ingress_event_dictionary_by_format_name", {"format_name": GHOST}),
        ("get_ingress_event_dictionary_by_id",
         {"ingress_event_dictionary_id": GHOST_ID}),
        ("update_ingress_event_dictionary_by_id",
         {"ingress_event_dictionary_id": GHOST_ID,
          "dictionary_data": {"description": "x"}}),
        ("replace_ingress_event_dictionary_by_id",
         {"ingress_event_dictionary_id": GHOST_ID,
          "dictionary_data": {"description": "x"}}),
        ("delete_ingress_event_dictionary_by_id",
         {"ingress_event_dictionary_id": GHOST_ID}),
    ]
    for operation, params in probes:
        result, verdict = await _call(recorder, operation, "negative",
                                      expect_absent=True, **params)
        assert harness.deep_crash_marker(result) is None, (operation, result)
        assert verdict == PASS, (operation, result)


def test_ingress_event_dictionary_lifecycle_or_limitation(
    run_async, recorder, run_id, shapes, cleanup
):
    format_name = fixture_name(run_id, "ied-1")
    shape = shapes["ingress_event_dictionary"]

    created, v_create = run_async(
        _call_tolerant(recorder, "create_ingress_event_dictionary", "create",
                       LIMITATION,
                       dictionary_data=_ied_payload(format_name, run_id, shape))
    )
    assert v_create != FAIL, (
        "create_ingress_event_dictionary crashed rather than returning a "
        f"structured result: {json.dumps(created, default=str)[:800]}"
    )

    if not _ok(created):
        # Documented outcome: the appliance rejects the dictionary schema. No
        # fixture exists, so the family's write path is recorded with the
        # structured error and every operation is proved non-crashing instead.
        reason = (harness.deep_error_text(created) or "").strip()[:400]
        for operation in _IED_WRITE_OPS:
            note(recorder, operation, LIMITATION, "blocked",
                 f"no fixture dictionary could be created: {reason}")
        run_async(_ingress_ghost_probes(recorder))
        return

    cleanup.add(lambda: harness.invoke(
        "delete_ingress_event_dictionary_by_format_name",
        format_name=assert_ours(format_name)))

    dict_id = payload_of(created).get("id")
    if dict_id is None:
        dict_id = run_async(
            find_id("list_ingress_event_dictionaries", "format_name", format_name))
    assert dict_id is not None, created

    fetched, v = run_async(
        _call(recorder, "get_ingress_event_dictionary_by_format_name", "read",
              format_name=format_name)
    )
    assert v == PASS, fetched

    by_id, v = run_async(
        _call(recorder, "get_ingress_event_dictionary_by_id", "read",
              ingress_event_dictionary_id=dict_id)
    )
    assert v == PASS, by_id

    assert_ours(format_name)
    patched, v = run_async(
        _call(recorder, "update_ingress_event_dictionary_by_id", "update",
              ingress_event_dictionary_id=dict_id,
              dictionary_data={"description": "patched by id"})
    )
    assert v == PASS, patched

    assert_ours(format_name)
    replaced, v = run_async(
        _call(recorder, "replace_ingress_event_dictionary_by_id", "update",
              ingress_event_dictionary_id=dict_id,
              dictionary_data=_ied_payload(format_name, run_id, shape))
    )
    assert v == PASS, replaced

    assert_ours(format_name)
    patched, v = run_async(
        _call(recorder, "update_ingress_event_dictionary_by_format_name", "update",
              format_name=format_name,
              dictionary_data={"description": "patched by format name"})
    )
    assert v == PASS, patched

    assert_ours(format_name)
    replaced, v = run_async(
        _call(recorder, "replace_ingress_event_dictionary_by_format_name", "update",
              format_name=format_name,
              dictionary_data=_ied_payload(format_name, run_id, shape))
    )
    assert v == PASS, replaced

    assert_ours(format_name)
    deleted, v = run_async(
        _call(recorder, "delete_ingress_event_dictionary_by_format_name", "delete",
              format_name=format_name)
    )
    assert v == PASS, deleted

    # A second fixture so delete-by-id is exercised too.
    second = fixture_name(run_id, "ied-2")
    created2 = run_async(harness.invoke(
        "create_ingress_event_dictionary",
        dictionary_data=_ied_payload(second, run_id, shape)))
    if not _ok(created2):
        note(recorder, "delete_ingress_event_dictionary_by_id", LIMITATION,
             "blocked",
             "the second fixture dictionary could not be created: "
             + (harness.deep_error_text(created2) or "").strip()[:400])
        return

    cleanup.add(lambda: harness.invoke(
        "delete_ingress_event_dictionary_by_format_name",
        format_name=assert_ours(second)))
    second_id = payload_of(created2).get("id")
    if second_id is None:
        second_id = run_async(
            find_id("list_ingress_event_dictionaries", "format_name", second))
    assert second_id is not None, created2

    assert_ours(second)
    deleted, v = run_async(
        _call(recorder, "delete_ingress_event_dictionary_by_id", "delete",
              ingress_event_dictionary_id=second_id)
    )
    assert v == PASS, deleted


# ==========================================================================
# 8. device-insight — GET, plus a STRICT read-restore
# ==========================================================================
#
# `update_device_insight_config` writes the GLOBAL Device Insight integration
# configuration. There is no fixture namespace for it and no way to scope a
# write, so the only safe exercise is writing back exactly what was read. That
# is attempted only when the GET payload provably round-trips:
#
#   1. the GET must succeed and return a non-empty dict,
#   2. it must carry the shape marker `enable_device_insight`,
#   3. it must contain NO secret-shaped key — the API returns `activation_token`
#      masked, and writing a masked value back would destroy the real token,
#   4. every value must be a JSON scalar/list so the body is reproducible.
#
# If any check fails the write is recorded BLOCKED and never dispatched. Either
# way the configuration is re-read at the end and asserted unchanged.

_SECRETISH = ("token", "secret", "password", "passphrase", "credential")


def _round_trips(config: Dict[str, Any]) -> Optional[str]:
    """None when the payload can be written back verbatim, else why not."""
    if not isinstance(config, dict) or not config:
        return "the GET returned no usable configuration payload"
    if "enable_device_insight" not in config:
        return ("the GET payload does not carry 'enable_device_insight', so the "
                "read body is not the same shape as the write body")
    for key, value in config.items():
        low = str(key).lower()
        if any(marker in low for marker in _SECRETISH):
            return (f"the payload carries the secret-shaped key {key!r}; the API "
                    f"returns it masked, so writing it back would destroy the "
                    f"real value")
        if not isinstance(value, (str, int, float, bool, list, type(None))):
            return f"the value for {key!r} is not a reproducible JSON scalar/list"
    return None


def test_device_insight_config_read_and_strict_restore(run_async, recorder):
    before, v_read = run_async(
        _call_tolerant(recorder, "get_device_insight_config", "read", LIMITATION)
    )
    assert v_read != FAIL, before
    assert harness.deep_crash_marker(before) is None, before

    if not _ok(before):
        note(recorder, "update_device_insight_config", BLOCKED, "blocked",
             "the Device Insight configuration could not be read, so there is "
             "nothing to restore: "
             + (harness.deep_error_text(before) or "").strip()[:300])
        return

    config = strip_readonly(payload_of(before))
    reason = _round_trips(config)
    if reason is not None:
        note(recorder, "update_device_insight_config", BLOCKED, "blocked",
             "global Device Insight integration config: no fixture namespace "
             "exists and a read-restore is not provably safe because " + reason)
        return

    # Read-restore: the body is exactly what the appliance just returned.
    restored, v_restore = run_async(
        _call_tolerant(recorder, "update_device_insight_config", "update",
                       LIMITATION, device_insight_data=config)
    )
    assert v_restore != FAIL, restored
    assert harness.deep_crash_marker(restored) is None, restored

    # Whether or not the restore was accepted, the configuration must be
    # byte-identical to what it was before this test ran.
    after, v_after = run_async(_call(recorder, "get_device_insight_config", "read"))
    assert v_after == PASS, after
    assert strip_readonly(payload_of(after)) == config, {
        "before": config,
        "after": strip_readonly(payload_of(after)),
        "note": "the read-restore changed the global Device Insight configuration",
    }


# ==========================================================================
# 9. extension store — 2 GETs that may need outbound internet
# ==========================================================================


def test_extension_store_reads(run_async, recorder):
    """The store is Aruba-hosted. Without outbound internet from the appliance a
    structured error is an acceptable EXPECTED-LIMITATION; a crash is not."""
    listed, v_list = run_async(
        _call_tolerant(recorder, "list_extension_store", "read", LIMITATION)
    )
    assert v_list != FAIL, listed
    assert harness.deep_crash_marker(listed) is None, listed

    store_items = items_of(listed) if _ok(listed) else []
    store_id = store_items[0].get("id") if store_items else GHOST

    item, v_item = run_async(
        _call_tolerant(recorder, "get_extension_store_item", "read", LIMITATION,
                       expect_absent=not store_items, store_id=store_id)
    )
    assert v_item != FAIL, item
    assert harness.deep_crash_marker(item) is None, item


# ==========================================================================
# 10. extension instances — reads dispatched, lifecycle writes never
# ==========================================================================


@pytest.fixture(scope="module")
def extension_id(shapes) -> Optional[str]:
    """The id of a pre-existing extension instance, if the appliance has one."""
    value = shapes["extension_instance"].get("id")
    return value if isinstance(value, str) and value else None


def test_list_extension_instances(run_async, recorder):
    """Optionals omitted, then supplied. The extension service is separate from
    the main config API, so an environment failure is a limitation, not a bug —
    a crash still is."""
    listed, verdict = run_async(
        _call_tolerant(recorder, "list_extension_instances", "read", LIMITATION)
    )
    assert verdict != FAIL, listed
    assert harness.deep_crash_marker(listed) is None, listed

    paged, verdict = run_async(
        _call_tolerant(recorder, "list_extension_instances", "read", LIMITATION,
                       limit=5, offset=0)
    )
    assert verdict != FAIL, paged


def test_extension_instance_reads(run_async, recorder, extension_id):
    """get + get-config against a listed instance, or a not-found probe.

    Both are pure GETs: nothing is started, stopped or reconfigured.
    """
    target = extension_id or GHOST_UUID
    absent = extension_id is None

    for operation in ("get_extension_instance", "get_extension_instance_config"):
        result, verdict = run_async(
            _call_tolerant(recorder, operation, "read", LIMITATION,
                           expect_absent=absent, extension_id=target)
        )
        assert harness.deep_crash_marker(result) is None, result
        assert verdict != FAIL, f"{operation}({target!r}) -> {result}"
        if not absent:
            assert _ok(result), result


def test_extension_instance_log_on_a_nonexistent_id(run_async, recorder):
    """A well-formed UUID that cannot be a real instance -> structured error."""
    result, verdict = run_async(
        _call_tolerant(recorder, "get_extension_instance_log", "negative",
                       LIMITATION, expect_absent=True, extension_id=GHOST_UUID)
    )
    assert result.get("success") is not True, result
    assert harness.deep_crash_marker(result) is None, result
    assert verdict != FAIL, result


def test_extension_instance_log_guard_path(run_async, recorder):
    """extension_id omitted -> pre-dispatch refusal, never a TypeError."""
    result, verdict = run_async(
        _call(recorder, "get_extension_instance_log", "negative", expect_guard=True)
    )
    error = str(result.get("error", ""))
    blob = json.dumps(result, default=str)
    assert result.get("success") is False, result
    assert "Missing required parameter(s)" in error, result
    assert "'extension_id'" in error, result
    assert "missing required argument" not in blob, result
    assert verdict == PASS, result


# --- lifecycle writes: denylisted, or BLOCKED without dispatch -------------
#
# None of these can be exercised safely:
#
#   * install / reinstall / upgrade pull an image from Aruba's online extension
#     store and mutate appliance services,
#   * start / stop / restart / update-state / replace-config / uninstall would
#     disrupt whichever real integration the instance backs, and
#   * there is no fixture instance to aim them at — one cannot exist without an
#     install, which is itself the first entry on this list.
#
# Whether an operation is hard-denylisted in ``denylist.py`` is read at RUNTIME:
#   denylisted     -> the denylist is asserted to fire before the gateway is
#                     touched (nothing reaches the appliance),
#   not denylisted -> BLOCKED is recorded and nothing is dispatched at all.
#
# At the time of writing ``denylist.py`` carries three of the ten —
# install_extension_instance, reinstall_extension_instance and
# upgrade_extension_instance, the ones that pull from Aruba's online store. The
# split is deliberately NOT pinned here: the test reads DENYLIST live, so an
# entry landing (or being removed) later moves the operation between the two
# branches without editing this file, and neither branch ever dispatches.

EXTENSION_LIFECYCLE_WRITES: Dict[str, str] = {
    "install_extension_instance":
        "Pulls a container image from Aruba's online extension store and "
        "installs a new appliance service.",
    "reinstall_extension_instance":
        "Re-pulls from Aruba's online store and recreates the extension's "
        "container, dropping its state.",
    "upgrade_extension_instance":
        "Pulls a newer image from Aruba's online store and replaces the "
        "running extension.",
    "get_extension_upgrade_info":
        "Queries Aruba's online store for upgrade candidates on behalf of a "
        "real instance; part of the upgrade family and meaningless without a "
        "fixture instance, which cannot exist.",
    "uninstall_extension_instance":
        "Deletes a real extension instance; no fixture instance can exist "
        "because install is itself blocked.",
    "update_extension_instance_state":
        "PATCHes the run state of a real extension instance.",
    "replace_extension_instance_config":
        "PUTs a whole new configuration onto a real extension instance.",
    "start_extension_instance": "Starts a real appliance service.",
    "stop_extension_instance":
        "Stops a real appliance service and whatever integration depends on it.",
    "restart_extension_instance": "Restarts a real appliance service.",
}


@pytest.mark.parametrize("operation", sorted(EXTENSION_LIFECYCLE_WRITES))
def test_extension_lifecycle_write_is_denylisted_or_blocked(
    run_async, recorder, operation
):
    import src.main  # noqa: F401
    from src.registry import registry

    assert registry.get(operation) is not None, operation

    if is_denylisted(operation):
        # The denylist must fire BEFORE the gateway is reached — no parameters
        # are supplied precisely because none are ever meant to be sent.
        with pytest.raises(DenylistedOperation):
            run_async(harness.invoke(operation))
        note(recorder, operation, BLOCKED, "denylist", DENYLIST[operation])
        return

    note(recorder, operation, BLOCKED, "blocked",
         "write path not exercised: " + EXTENSION_LIFECYCLE_WRITES[operation])


def test_extension_lifecycle_writes_were_never_dispatched(recorder):
    """Belt and braces: no blocked operation may appear in this run's results
    under a tier that means it was actually sent to the appliance."""
    dispatched_tiers = {"read", "create", "update", "delete", "negative", "write"}
    offenders = []
    with recorder.path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if (rec.get("operation") in EXTENSION_LIFECYCLE_WRITES
                    and rec.get("tier") in dispatched_tiers):
                offenders.append(rec)
    assert not offenders, offenders


# ==========================================================================
# 11. Summary
# ==========================================================================


def test_zz_no_integrations_fixture_survives(run_async, recorder, net: Net):
    """Every fixture this module created must already be gone.

    The module sweep runs after this, as a net; if it finds anything, this test
    has already failed and named it.
    """
    survivors: List[Dict[str, Any]] = []

    for family, (list_op, name_field, _del, _idp) in _SWEEPABLE.items():
        listed = run_async(harness.invoke(list_op, limit=1000))
        if not _ok(listed):
            continue
        survivors += [
            {"family": family, "name": item.get(name_field)}
            for item in items_of(listed)
            if harness.is_ours(item.get(name_field))
        ]

    listed = run_async(harness.invoke("list_syslog_targets", limit=1000))
    if _ok(listed):
        survivors += [
            {"family": "syslog_targets", "host_address": item.get("host_address")}
            for item in items_of(listed)
            if net.is_ours(item.get("host_address"))
        ]

    print(f"[live-harness] integrations verdict tally so far: {recorder.counts}")
    assert not survivors, (
        "integrations fixtures survived their own lifecycle tests: " + repr(survivors)
    )
