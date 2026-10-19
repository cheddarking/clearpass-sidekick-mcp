"""Live validation — ``endpoint_visibility`` domain, part 2 of 2 (56 of 94 ops).

Scope of this module
--------------------
* ``agentless-onguard/settings`` — Agentless OnGuard settings (10 ops)
* ``agentless-onguard/subnet-mapping`` — subnet mappings incl. enable/disable (14)
* ``config/network-scan`` — discovery / subnet scan configuration (8)
* ``profiler-subnet-mapping`` — profiler scan-account subnet mappings (10)
* ``onguard/policy-manager-zones`` — OnGuard zone client-subnet bindings (10)
* ``onguard/global-settings`` and ``onguard/settings`` — GET + POST (4)

Part 1 (``test_endpoint_visibility_live.py``) covers the fingerprint dictionary,
the Windows hotfix database, OnGuard custom scripts, device fingerprints and
OnGuard activity.

Calling style
-------------
Everything dispatches through ``harness.invoke`` (i.e. through
``src.tools.gateway.invoke_operation``), so the progressive-disclosure path is
validated alongside each operation. Optional parameters are OMITTED by default.

Every network these tests write is inside documentation space
--------------------------------------------------------------
Four of the six families here are keyed on, or configured with, IP networks.
Writing a real subnet into a subnet mapping or a network-scan target would point
appliance machinery at production address space. Every network value this module
sends is therefore inside RFC 5737 documentation space — ``192.0.2.0/24``,
``198.51.100.0/24``, and the single documentation addresses ``192.0.2.51`` /
``192.0.2.52`` — which can never overlap a real network.
``assert_doc_network`` refuses anything else immediately before a write, and the
end-of-module sweep uses "the configured network is documentation space" as the
ownership rail for the two families that have no name field.

Network scans are additionally created with ``enabled: false`` so the appliance
never actually scans anything on our behalf; ``enable_network_scan_by_id`` is
exercised and the scan is disabled again before it is deleted.

Global-state singletons
-----------------------
``onguard/global-settings`` and ``onguard/settings`` are appliance-wide state
with no fixture namespace to hide in. Their POST is exercised as a **strict
read-restore**: GET the current payload, POST that identical payload straight
back, then GET again and assert nothing moved. Before dispatching, the payload
is checked for round-trip safety (no read-only fields, no HAL metadata, a plain
JSON object); if it does not round-trip cleanly the POST is recorded ``BLOCKED``
with the reason and **never dispatched** — an approximate restore of global
OnGuard state is worse than no coverage.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import pytest

from . import harness
from ._endpoint_visibility_common import (
    ABSENT_ID,
    DOC_NETWORKS,
    NOTES,
    PASS,
    assert_created_id,
    assert_doc_network,
    assert_ours,
    fixture_name,
    id_of,
    items_of,
    no_crash,
    note,
    obj_of,
    record_blocked,
    record_limitation,
    run_op,
    surviving_fixtures,
    sweep_named_family,
)

#: Documentation networks used as fixture values.
NET_A = "192.0.2.0/24"
NET_B = "198.51.100.0/24"
#: Single documentation addresses — used where a "/" in the value would be eaten
#: by the URL path (the profiler by-network route interpolates the network
#: straight into the path).
ADDR_A = "192.0.2.51"
ADDR_B = "192.0.2.52"

#: ClearPass ships exactly one Policy Manager zone called "default"; used only
#: as a fallback when the appliance lists none.
DEFAULT_PM_ZONE = "default"

PROFILER_SCAN_TYPE = "SNMP"

#: Fields ``GET /onguard/settings`` documents as read-only. Their presence in
#: the GET payload means the body cannot be POSTed straight back as an identity
#: write.
ONGUARD_SETTINGS_READ_ONLY = {
    "version", "agentLibraryVersion", "installer_modified_time",
    "installer_modified_time_formatted", "agent_installers",
    "agent_web_installers",
}
ONGUARD_GLOBAL_SETTINGS_READ_ONLY: set = set()

#: HAL/link metadata that a POST body must not carry back.
HAL_KEYS = {"_links", "_embedded", "href"}


# --------------------------------------------------------------------------
# Shared fixtures / helpers
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pm_zone(request, run_async, recorder) -> str:
    """The name of a real Policy Manager zone.

    Subnet mappings and network scans must reference an existing zone. The zone
    is only ever *referenced* — never written — so using a real name here cannot
    mutate it; the fixture identity of every object created stays its own
    prefixed name.
    """
    if not request.config.getoption("--live"):
        pytest.skip("live appliance test; pass --live to enable")
    result, _ = run_op(run_async, recorder, "onguard_list_policy_manager_zones",
                       tier="read")
    for item in items_of(result, "policy_manager_zones"):
        for key in ("policy_manager_zone_name", "zone_name", "name", "zone"):
            value = item.get(key)
            if isinstance(value, str) and value:
                return value
    note(f"pm_zone: the appliance listed no OnGuard Policy Manager zones; "
         f"falling back to {DEFAULT_PM_ZONE!r}")
    return DEFAULT_PM_ZONE


def _networks_of(value: Any) -> List[str]:
    """Normalise a mapping/scan network field into a list of network strings."""
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


def _is_doc_only(value: Any) -> bool:
    """True when every network in ``value`` is documentation space."""
    nets = _networks_of(value)
    return bool(nets) and all(n in DOC_NETWORKS for n in nets)


def _roundtrip_blockers(payload: Any, read_only: set) -> List[str]:
    """Reasons ``payload`` cannot be POSTed straight back as an identity write."""
    blockers: List[str] = []
    if not isinstance(payload, dict):
        return [f"the GET returned {type(payload).__name__}, not a JSON object, "
                f"so there is no body that can be POSTed back verbatim"]
    if not payload:
        return ["the GET returned an empty object; POSTing {} back is not an "
                "identity write"]
    present_ro = sorted(k for k in payload if k in read_only)
    if present_ro:
        blockers.append(
            f"the GET payload carries read-only field(s) {present_ro}; POSTing "
            f"them back is not an identity write and the appliance may reject "
            f"or silently drop them")
    hal = sorted(k for k in payload if k in HAL_KEYS)
    if hal:
        blockers.append(f"the GET payload carries HAL metadata {hal}")
    return blockers


# ==========================================================================
# 1. agentless-onguard/settings — 10 operations
# ==========================================================================


def _agentless_settings_body(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "description": "zzz-mcptest live-harness fixture",
        "client_os": "Windows",
        "working_dir": "C:\\zzz-mcptest",
        "action": "Scan",
        "servers": ["192.0.2.10"],
        "download_url": (
            "https://192.0.2.10/agent/AgentlessOnGuard/windows/"
            "AgentlessOnGuardWrapper.exe"),
        "validate_url_cert": False,
    }


def _delete_agentless_settings(name: str):
    assert_ours(name)
    return harness.invoke("delete_agentless_onguard_settings_by_name",
                          _params={"name": name})


def test_list_agentless_onguard_settings(run_async, recorder):
    """The operation takes no parameters at all — a pure omission path."""
    result, verdict = run_op(run_async, recorder,
                             "list_agentless_onguard_settings", tier="read")
    no_crash(result, "list_agentless_onguard_settings")
    assert verdict == PASS, f"list_agentless_onguard_settings -> {result}"
    assert "settings" in result, f"unexpected shape: {sorted(result)}"


def test_agentless_onguard_settings_lifecycle_by_name(run_async, recorder,
                                                      run_id, cleanup):
    """create -> get -> update -> replace -> delete on the name handle."""
    name = fixture_name(run_id, "ags1")
    cleanup.add(lambda: _delete_agentless_settings(name))

    created, verdict = run_op(
        run_async, recorder, "create_agentless_onguard_settings", tier="create",
        expect="lenient", settings_data=_agentless_settings_body(name))
    no_crash(created, "create_agentless_onguard_settings")
    if verdict != PASS:
        pytest.skip(f"create_agentless_onguard_settings refused: {created}")

    got, verdict = run_op(run_async, recorder,
                          "get_agentless_onguard_settings_by_name", tier="read",
                          name=name)
    assert verdict == PASS, f"get_agentless_onguard_settings_by_name -> {got}"
    assert obj_of(got, "setting").get("name") == name, got

    assert_ours(name)
    updated, verdict = run_op(
        run_async, recorder, "update_agentless_onguard_settings_by_name",
        tier="update", name=name,
        settings_data={"description": "zzz-mcptest fixture (patched)"})
    assert verdict == PASS, f"update_agentless_onguard_settings_by_name -> {updated}"

    assert_ours(name)
    replaced, verdict = run_op(
        run_async, recorder, "replace_agentless_onguard_settings_by_name",
        tier="update", name=name, settings_data=_agentless_settings_body(name))
    assert verdict == PASS, f"replace_agentless_onguard_settings_by_name -> {replaced}"

    assert_ours(name)
    deleted, verdict = run_op(
        run_async, recorder, "delete_agentless_onguard_settings_by_name",
        tier="delete", name=name)
    assert verdict == PASS, f"delete_agentless_onguard_settings_by_name -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_agentless_onguard_settings_by_name",
        tier="negative", expect="absent", name=name)
    assert verdict == PASS, f"deleted agentless setting still readable: {gone}"


def test_agentless_onguard_settings_lifecycle_by_id(run_async, recorder, run_id,
                                                    cleanup):
    """The numeric-id handle; the id comes from our own create only."""
    name = fixture_name(run_id, "ags2")
    cleanup.add(lambda: _delete_agentless_settings(name))

    created, verdict = run_op(
        run_async, recorder, "create_agentless_onguard_settings", tier="create",
        expect="lenient", settings_data=_agentless_settings_body(name))
    no_crash(created, "create_agentless_onguard_settings")
    if verdict != PASS:
        pytest.skip(f"create_agentless_onguard_settings refused: {created}")

    sid = id_of(obj_of(created, "setting"))
    if sid is None:
        readback, _ = run_op(run_async, recorder,
                             "get_agentless_onguard_settings_by_name",
                             tier="read", name=name)
        sid = id_of(obj_of(readback, "setting"))
    if sid is None:
        record_blocked(recorder, "delete_agentless_onguard_settings_by_id",
                       "the appliance returned no numeric id for our own "
                       "agentless-settings fixture, so no id can be proven ours")
        pytest.skip("no id available for the agentless setting we created")
    created_ids = [sid]

    got, verdict = run_op(run_async, recorder,
                          "get_agentless_onguard_settings_by_id", tier="read",
                          settings_id=sid)
    assert verdict == PASS, f"get_agentless_onguard_settings_by_id({sid}) -> {got}"
    assert_ours(obj_of(got, "setting").get("name"))

    assert_created_id(sid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "update_agentless_onguard_settings_by_id",
        tier="update", settings_id=sid,
        settings_data={"description": "zzz-mcptest fixture (patched)"})
    assert verdict == PASS, f"update_agentless_onguard_settings_by_id -> {updated}"

    assert_created_id(sid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "replace_agentless_onguard_settings_by_id",
        tier="update", settings_id=sid,
        settings_data=_agentless_settings_body(name))
    assert verdict == PASS, f"replace_agentless_onguard_settings_by_id -> {replaced}"

    assert_created_id(sid, created_ids)
    assert_ours(obj_of(got, "setting").get("name"))
    deleted, verdict = run_op(
        run_async, recorder, "delete_agentless_onguard_settings_by_id",
        tier="delete", settings_id=sid)
    assert verdict == PASS, f"delete_agentless_onguard_settings_by_id -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_agentless_onguard_settings_by_id",
        tier="negative", expect="absent", settings_id=sid)
    assert verdict == PASS, f"deleted agentless setting still readable: {gone}"


AGENTLESS_SETTINGS_NAME_OPS: List[Tuple[str, str]] = [
    ("get_agentless_onguard_settings_by_name", ""),
    ("delete_agentless_onguard_settings_by_name", ""),
    ("update_agentless_onguard_settings_by_name", "patch"),
    ("replace_agentless_onguard_settings_by_name", "full"),
]


@pytest.mark.parametrize("operation,body", AGENTLESS_SETTINGS_NAME_OPS,
                         ids=[o[0] for o in AGENTLESS_SETTINGS_NAME_OPS])
def test_agentless_onguard_settings_by_name_absent(run_async, recorder, run_id,
                                                   operation, body):
    name = assert_ours(fixture_name(run_id, "ags", "absent"))
    params: Dict[str, Any] = {}
    if body == "patch":
        params["settings_data"] = {"description": "zzz-mcptest absent probe"}
    elif body == "full":
        params["settings_data"] = _agentless_settings_body(name)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", name=name, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(absent {name!r}) -> {result}"


AGENTLESS_SETTINGS_ID_OPS: List[Tuple[str, str]] = [
    ("get_agentless_onguard_settings_by_id", ""),
    ("delete_agentless_onguard_settings_by_id", ""),
    ("update_agentless_onguard_settings_by_id", "patch"),
    ("replace_agentless_onguard_settings_by_id", "full"),
]


@pytest.mark.parametrize("operation,body", AGENTLESS_SETTINGS_ID_OPS,
                         ids=[o[0] for o in AGENTLESS_SETTINGS_ID_OPS])
def test_agentless_onguard_settings_by_id_absent(run_async, recorder, run_id,
                                                 operation, body):
    name = assert_ours(fixture_name(run_id, "ags", "absent"))
    params: Dict[str, Any] = {}
    if body == "patch":
        params["settings_data"] = {"description": "zzz-mcptest absent probe"}
    elif body == "full":
        params["settings_data"] = _agentless_settings_body(name)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", settings_id=ABSENT_ID, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(settings_id={ABSENT_ID}) -> {result}"


def test_create_agentless_onguard_settings_missing_body_is_rejected(run_async,
                                                                    recorder):
    result, verdict = run_op(
        run_async, recorder, "create_agentless_onguard_settings",
        tier="negative", expect="refusal",
        substrings=("missing required parameter", "settings_data"))
    no_crash(result, "create_agentless_onguard_settings")
    assert verdict == PASS, f"create_agentless_onguard_settings() -> {result}"


# ==========================================================================
# 2. agentless-onguard/subnet-mapping — 14 operations
# ==========================================================================


def _subnet_mapping_body(name: str, zone: str, network: str = NET_A,
                         enabled: bool = False) -> Dict[str, Any]:
    assert_doc_network(network)
    return {
        "name": name,
        "client_subnets": [network],
        "zone": zone,
        "client_scan_setting": "All",
        "enabled": enabled,
    }


def _delete_subnet_mapping(name: str):
    assert_ours(name)
    return harness.invoke("delete_agentless_onguard_subnet_mapping_by_name",
                          _params={"name": name})


def test_list_agentless_onguard_subnet_mappings_optionals_omitted(run_async,
                                                                  recorder):
    result, verdict = run_op(run_async, recorder,
                             "list_agentless_onguard_subnet_mappings",
                             tier="read")
    no_crash(result, "list_agentless_onguard_subnet_mappings")
    assert verdict == PASS, f"list_agentless_onguard_subnet_mappings -> {result}"
    assert "subnet_mappings" in result, f"unexpected shape: {sorted(result)}"


def test_list_agentless_onguard_subnet_mappings_with_optionals(run_async,
                                                               recorder):
    result, verdict = run_op(
        run_async, recorder, "list_agentless_onguard_subnet_mappings",
        tier="read", filter_str='{"enabled": true}', sort="+name", offset=0,
        limit=5, calculate_count=True)
    no_crash(result, "list_agentless_onguard_subnet_mappings")
    assert verdict == PASS, \
        f"list_agentless_onguard_subnet_mappings (optionals) -> {result}"


def test_agentless_subnet_mapping_lifecycle_by_name(run_async, recorder, run_id,
                                                    cleanup, pm_zone):
    """create -> get -> update -> replace -> enable -> disable -> delete.

    The mapping is created disabled and pointed at documentation space, then
    enabled and disabled again to exercise both toggles before it is removed.
    """
    name = fixture_name(run_id, "asm1")
    cleanup.add(lambda: _delete_subnet_mapping(name))

    created, verdict = run_op(
        run_async, recorder, "create_agentless_onguard_subnet_mapping",
        tier="create", expect="lenient",
        mapping_data=_subnet_mapping_body(name, pm_zone))
    no_crash(created, "create_agentless_onguard_subnet_mapping")
    if verdict != PASS:
        pytest.skip(f"create_agentless_onguard_subnet_mapping refused: {created}")

    got, verdict = run_op(run_async, recorder,
                          "get_agentless_onguard_subnet_mapping_by_name",
                          tier="read", name=name)
    assert verdict == PASS, f"get_agentless_onguard_subnet_mapping_by_name -> {got}"
    record = obj_of(got, "subnet_mapping")
    assert record.get("name") == name, got
    assert _is_doc_only(record.get("client_subnets")), \
        f"our own mapping is not confined to documentation space: {record}"

    assert_ours(name)
    updated, verdict = run_op(
        run_async, recorder, "update_agentless_onguard_subnet_mapping_by_name",
        tier="update", name=name,
        mapping_data={"client_subnets": [assert_doc_network(NET_B)]})
    assert verdict == PASS, \
        f"update_agentless_onguard_subnet_mapping_by_name -> {updated}"

    assert_ours(name)
    replaced, verdict = run_op(
        run_async, recorder, "replace_agentless_onguard_subnet_mapping_by_name",
        tier="update", name=name,
        mapping_data=_subnet_mapping_body(name, pm_zone))
    assert verdict == PASS, \
        f"replace_agentless_onguard_subnet_mapping_by_name -> {replaced}"

    assert_ours(name)
    enabled, verdict = run_op(
        run_async, recorder, "enable_agentless_onguard_subnet_mapping_by_name",
        tier="update", name=name)
    assert verdict == PASS, \
        f"enable_agentless_onguard_subnet_mapping_by_name -> {enabled}"

    assert_ours(name)
    disabled, verdict = run_op(
        run_async, recorder, "disable_agentless_onguard_subnet_mapping_by_name",
        tier="update", name=name)
    assert verdict == PASS, \
        f"disable_agentless_onguard_subnet_mapping_by_name -> {disabled}"

    assert_ours(name)
    deleted, verdict = run_op(
        run_async, recorder, "delete_agentless_onguard_subnet_mapping_by_name",
        tier="delete", name=name)
    assert verdict == PASS, \
        f"delete_agentless_onguard_subnet_mapping_by_name -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_agentless_onguard_subnet_mapping_by_name",
        tier="negative", expect="absent", name=name)
    assert verdict == PASS, f"deleted subnet mapping still readable: {gone}"


def test_agentless_subnet_mapping_lifecycle_by_id(run_async, recorder, run_id,
                                                  cleanup, pm_zone):
    """The numeric-id handle, including enable/disable by id."""
    name = fixture_name(run_id, "asm2")
    cleanup.add(lambda: _delete_subnet_mapping(name))

    created, verdict = run_op(
        run_async, recorder, "create_agentless_onguard_subnet_mapping",
        tier="create", expect="lenient",
        mapping_data=_subnet_mapping_body(name, pm_zone))
    no_crash(created, "create_agentless_onguard_subnet_mapping")
    if verdict != PASS:
        pytest.skip(f"create_agentless_onguard_subnet_mapping refused: {created}")

    mid = id_of(obj_of(created, "subnet_mapping"))
    if mid is None:
        readback, _ = run_op(run_async, recorder,
                             "get_agentless_onguard_subnet_mapping_by_name",
                             tier="read", name=name)
        mid = id_of(obj_of(readback, "subnet_mapping"))
    if mid is None:
        record_blocked(recorder,
                       "delete_agentless_onguard_subnet_mapping_by_id",
                       "the appliance returned no numeric id for our own subnet "
                       "mapping fixture, so no id can be proven ours")
        pytest.skip("no id available for the subnet mapping we created")
    created_ids = [mid]

    got, verdict = run_op(run_async, recorder,
                          "get_agentless_onguard_subnet_mapping_by_id",
                          tier="read", subnet_mapping_id=mid)
    assert verdict == PASS, \
        f"get_agentless_onguard_subnet_mapping_by_id({mid}) -> {got}"
    assert_ours(obj_of(got, "subnet_mapping").get("name"))

    assert_created_id(mid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "update_agentless_onguard_subnet_mapping_by_id",
        tier="update", subnet_mapping_id=mid,
        mapping_data={"client_subnets": [assert_doc_network(NET_B)]})
    assert verdict == PASS, \
        f"update_agentless_onguard_subnet_mapping_by_id -> {updated}"

    assert_created_id(mid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "replace_agentless_onguard_subnet_mapping_by_id",
        tier="update", subnet_mapping_id=mid,
        mapping_data=_subnet_mapping_body(name, pm_zone))
    assert verdict == PASS, \
        f"replace_agentless_onguard_subnet_mapping_by_id -> {replaced}"

    assert_created_id(mid, created_ids)
    enabled, verdict = run_op(
        run_async, recorder, "enable_agentless_onguard_subnet_mapping_by_id",
        tier="update", subnet_mapping_id=mid)
    assert verdict == PASS, \
        f"enable_agentless_onguard_subnet_mapping_by_id -> {enabled}"

    assert_created_id(mid, created_ids)
    disabled, verdict = run_op(
        run_async, recorder, "disable_agentless_onguard_subnet_mapping_by_id",
        tier="update", subnet_mapping_id=mid)
    assert verdict == PASS, \
        f"disable_agentless_onguard_subnet_mapping_by_id -> {disabled}"

    assert_created_id(mid, created_ids)
    assert_ours(obj_of(got, "subnet_mapping").get("name"))
    deleted, verdict = run_op(
        run_async, recorder, "delete_agentless_onguard_subnet_mapping_by_id",
        tier="delete", subnet_mapping_id=mid)
    assert verdict == PASS, \
        f"delete_agentless_onguard_subnet_mapping_by_id -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_agentless_onguard_subnet_mapping_by_id",
        tier="negative", expect="absent", subnet_mapping_id=mid)
    assert verdict == PASS, f"deleted subnet mapping still readable by id: {gone}"


SUBNET_MAPPING_NAME_OPS: List[Tuple[str, str]] = [
    ("get_agentless_onguard_subnet_mapping_by_name", ""),
    ("delete_agentless_onguard_subnet_mapping_by_name", ""),
    ("enable_agentless_onguard_subnet_mapping_by_name", ""),
    ("disable_agentless_onguard_subnet_mapping_by_name", ""),
    ("update_agentless_onguard_subnet_mapping_by_name", "patch"),
    ("replace_agentless_onguard_subnet_mapping_by_name", "full"),
]


@pytest.mark.parametrize("operation,body", SUBNET_MAPPING_NAME_OPS,
                         ids=[o[0] for o in SUBNET_MAPPING_NAME_OPS])
def test_agentless_subnet_mapping_by_name_absent(run_async, recorder, run_id,
                                                 pm_zone, operation, body):
    """Every by-name operation — including both toggles — against a fixture name
    that cannot exist."""
    name = assert_ours(fixture_name(run_id, "asm", "absent"))
    params: Dict[str, Any] = {}
    if body == "patch":
        params["mapping_data"] = {"client_subnets": [assert_doc_network(NET_B)]}
    elif body == "full":
        params["mapping_data"] = _subnet_mapping_body(name, pm_zone)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", name=name, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(absent {name!r}) -> {result}"


SUBNET_MAPPING_ID_OPS: List[Tuple[str, str]] = [
    ("get_agentless_onguard_subnet_mapping_by_id", ""),
    ("delete_agentless_onguard_subnet_mapping_by_id", ""),
    ("enable_agentless_onguard_subnet_mapping_by_id", ""),
    ("disable_agentless_onguard_subnet_mapping_by_id", ""),
    ("update_agentless_onguard_subnet_mapping_by_id", "patch"),
    ("replace_agentless_onguard_subnet_mapping_by_id", "full"),
]


@pytest.mark.parametrize("operation,body", SUBNET_MAPPING_ID_OPS,
                         ids=[o[0] for o in SUBNET_MAPPING_ID_OPS])
def test_agentless_subnet_mapping_by_id_absent(run_async, recorder, run_id,
                                               pm_zone, operation, body):
    """Every by-id operation against an id that cannot exist.

    Unlike the by-name family, ``agentless-onguard/subnet-mapping/<id>`` on
    6.12.4 does not resolve an unknown id to a 404: every verb answers HTTP 500
    with the structured JSON body ``["Error in processing request. Please
    retry..."]``. ``expect="absent_or_error"`` accepts that graceless-but-
    structured answer while still failing the two outcomes that would indicate
    a real defect — a crash/traceback, or ``success`` (the MCP inventing a
    record for an id no object has).
    """
    name = assert_ours(fixture_name(run_id, "asm", "absent"))
    params: Dict[str, Any] = {}
    if body == "patch":
        params["mapping_data"] = {"client_subnets": [assert_doc_network(NET_B)]}
    elif body == "full":
        params["mapping_data"] = _subnet_mapping_body(name, pm_zone)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent_or_error",
                             subnet_mapping_id=ABSENT_ID, **params)
    no_crash(result, operation)
    assert result.get("success") is not True, \
        f"{operation} invented a record for id {ABSENT_ID}: {result}"
    assert verdict == PASS, \
        f"{operation}(subnet_mapping_id={ABSENT_ID}) -> {result}"


# ==========================================================================
# 3. config/network-scan — 8 operations
# ==========================================================================


async def _delete_scan_ids(scan_ids: List[int]) -> None:
    """Cleanup factory body — remove every network scan this test created."""
    for scan_id in list(scan_ids):
        await harness.invoke("delete_network_scan_by_id",
                             _params={"scan_id": scan_id})


def _network_scan_body(zone: str, network: str = NET_A) -> Dict[str, Any]:
    assert_doc_network(network)
    return {
        "type": "SUBNET",
        "zone": zone,
        "seed_device_or_ip_subnet": network,
        "scan_frequency": "DAILY",
        "start_time": "03:15",
        # Created disabled: the appliance must never actually scan on our behalf.
        "enabled": False,
    }


def test_list_network_scans_optionals_omitted(run_async, recorder):
    result, verdict = run_op(run_async, recorder, "list_network_scans",
                             tier="read")
    no_crash(result, "list_network_scans")
    assert verdict == PASS, f"list_network_scans (no params) -> {result}"
    assert "network_scans" in result, f"unexpected shape: {sorted(result)}"


def test_list_network_scans_with_optionals(run_async, recorder):
    """``config/network-scan`` indexes on ``id`` only.

    Diagnosed live on 6.12.4 by dispatching each optional on its own:
    ``sort``/``offset``/``limit``/``calculate_count`` are all served, and so is
    ``filter`` — but only over ``id``. Any filter naming a body field
    (``type``, ``zone``, ``enabled``, ``scan_frequency``) is rejected 422
    ``err.general``, as is a sort on a non-id key such as ``+zone``. The SDK
    documents ``filter`` generically for the resource, so the narrower reality
    is recorded as an EXPECTED-LIMITATION rather than asserted away, and the
    supported optionals are still asserted to pass together.
    """
    result, verdict = run_op(
        run_async, recorder, "list_network_scans", tier="read",
        sort="+id", offset=0, limit=5, calculate_count=True)
    no_crash(result, "list_network_scans")
    assert verdict == PASS, f"list_network_scans (optionals) -> {result}"

    # The id-keyed filter the resource does serve, exercised for real.
    filtered, verdict = run_op(
        run_async, recorder, "list_network_scans", tier="read",
        filter_str='{"id": 1}', sort="+id", limit=5)
    no_crash(filtered, "list_network_scans")
    assert verdict == PASS, f"list_network_scans (filter on id) -> {filtered}"

    # And the documented-but-unserved combination, pinned so a firmware upgrade
    # that starts honouring it shows up as a change rather than passing silently.
    rejected, _ = run_op(
        run_async, recorder, "list_network_scans", tier="read",
        expect="lenient", filter_str='{"type": "SUBNET"}', sort="+id", offset=0,
        limit=5, calculate_count=True)
    no_crash(rejected, "list_network_scans")
    if rejected.get("success") is not True:
        record_limitation(
            recorder, "list_network_scans",
            "config/network-scan only indexes id: a filter on any body field "
            "(type/zone/enabled/scan_frequency), and a sort on any non-id key, "
            "are rejected 422 err.general on 6.12.4",
            {"filter_str": '{"type": "SUBNET"}'})


def test_network_scan_lifecycle(run_async, recorder, cleanup, pm_zone):
    """create(disabled) -> get -> update -> replace -> enable -> disable -> delete.

    ``config/network-scan`` has no name field, so ownership rests on two rails:
    the id must be the one our own create returned (``assert_created_id``), and
    the scan's configured target must be documentation space (verified on the
    read-back before every write). If the appliance requires a live seed device
    the create is recorded ``EXPECTED-LIMITATION`` carrying its error and the
    remaining operations are covered by the absent-id tests below.
    """
    created_ids: List[int] = []
    # The id is not known until the create returns; the closure sees the list.
    cleanup.add(lambda: _delete_scan_ids(created_ids))

    created, verdict = run_op(
        run_async, recorder, "create_network_scan", tier="create",
        expect="lenient", scan_data=_network_scan_body(pm_zone))
    no_crash(created, "create_network_scan")
    if verdict != PASS:
        note("create_network_scan: the appliance refused a SUBNET scan "
             "targeting documentation space — a live seed device or a "
             "different enum value may be required; recorded "
             "EXPECTED-LIMITATION with the appliance error")
        pytest.skip(f"create_network_scan refused: {created}")

    scan_id = id_of(obj_of(created, "network_scan"))
    if scan_id is None:
        record_blocked(recorder, "delete_network_scan_by_id",
                       "the appliance returned no numeric id for our own network "
                       "scan, so no id can be proven ours; the created scan is "
                       "removed by the documentation-network sweep instead")
        pytest.skip("no id available for the network scan we created")
    created_ids.append(scan_id)

    got, verdict = run_op(run_async, recorder, "get_network_scan_by_id",
                          tier="read", scan_id=scan_id)
    assert verdict == PASS, f"get_network_scan_by_id({scan_id}) -> {got}"
    record = obj_of(got, "network_scan")
    assert _is_doc_only(record.get("seed_device_or_ip_subnet")), \
        f"our own scan is not confined to documentation space: {record}"

    assert_created_id(scan_id, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "update_network_scan_by_id", tier="update",
        scan_id=scan_id,
        scan_data={"seed_device_or_ip_subnet": assert_doc_network(NET_B)})
    assert verdict == PASS, f"update_network_scan_by_id({scan_id}) -> {updated}"

    assert_created_id(scan_id, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "replace_network_scan_by_id", tier="update",
        scan_id=scan_id, scan_data=_network_scan_body(pm_zone))
    assert verdict == PASS, f"replace_network_scan_by_id({scan_id}) -> {replaced}"

    assert_created_id(scan_id, created_ids)
    enabled, verdict = run_op(run_async, recorder, "enable_network_scan_by_id",
                              tier="update", scan_id=scan_id)
    assert verdict == PASS, f"enable_network_scan_by_id({scan_id}) -> {enabled}"

    # Disabled again immediately: the scan must not be left armed for a moment
    # longer than the toggle test needs.
    assert_created_id(scan_id, created_ids)
    disabled, verdict = run_op(run_async, recorder, "disable_network_scan_by_id",
                               tier="update", scan_id=scan_id)
    assert verdict == PASS, f"disable_network_scan_by_id({scan_id}) -> {disabled}"

    assert_created_id(scan_id, created_ids)
    deleted, verdict = run_op(run_async, recorder, "delete_network_scan_by_id",
                              tier="delete", scan_id=scan_id)
    assert verdict == PASS, f"delete_network_scan_by_id({scan_id}) -> {deleted}"

    gone, verdict = run_op(run_async, recorder, "get_network_scan_by_id",
                           tier="negative", expect="absent", scan_id=scan_id)
    assert verdict == PASS, f"deleted network scan still readable: {gone}"


NETWORK_SCAN_ID_OPS: List[Tuple[str, str]] = [
    ("get_network_scan_by_id", ""),
    ("delete_network_scan_by_id", ""),
    ("enable_network_scan_by_id", ""),
    ("disable_network_scan_by_id", ""),
    ("update_network_scan_by_id", "patch"),
    ("replace_network_scan_by_id", "full"),
]


@pytest.mark.parametrize("operation,body", NETWORK_SCAN_ID_OPS,
                         ids=[o[0] for o in NETWORK_SCAN_ID_OPS])
def test_network_scan_by_id_absent(run_async, recorder, pm_zone, operation, body):
    params: Dict[str, Any] = {}
    if body == "patch":
        params["scan_data"] = {
            "seed_device_or_ip_subnet": assert_doc_network(NET_B)}
    elif body == "full":
        params["scan_data"] = _network_scan_body(pm_zone)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", scan_id=ABSENT_ID, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(scan_id={ABSENT_ID}) -> {result}"


def test_create_network_scan_missing_body_is_rejected(run_async, recorder):
    result, verdict = run_op(
        run_async, recorder, "create_network_scan", tier="negative",
        expect="refusal", substrings=("missing required parameter", "scan_data"))
    no_crash(result, "create_network_scan")
    assert verdict == PASS, f"create_network_scan() -> {result}"


# ==========================================================================
# 4. profiler-subnet-mapping — 10 operations
# ==========================================================================


def _profiler_body(network: str) -> Dict[str, Any]:
    assert_doc_network(network)
    return {"network": network, "scan_type": PROFILER_SCAN_TYPE,
            "ext_accounts": []}


def _delete_profiler_by_network(network: str):
    assert_doc_network(network)
    return harness.invoke("profiler_delete_subnet_mapping_by_network",
                          _params={"scan_type": PROFILER_SCAN_TYPE,
                                   "network": network})


def test_profiler_list_subnet_mappings(run_async, recorder):
    """The operation takes no parameters at all — a pure omission path."""
    result, verdict = run_op(run_async, recorder, "profiler_list_subnet_mappings",
                             tier="read")
    no_crash(result, "profiler_list_subnet_mappings")
    assert verdict == PASS, f"profiler_list_subnet_mappings -> {result}"
    assert "profiler_subnet_mappings" in result, \
        f"unexpected shape: {sorted(result)}"


def test_profiler_subnet_mapping_lifecycle_by_network(run_async, recorder,
                                                      cleanup):
    """create -> get -> update -> replace -> delete on the network handle.

    A single documentation *address* (192.0.2.51) is used rather than a CIDR:
    the by-network route interpolates the value straight into the URL path, so a
    "/" would split into an extra path segment. See
    ``test_profiler_by_network_cidr_is_unaddressable`` which pins that.
    """
    network = assert_doc_network(ADDR_A)
    cleanup.add(lambda: _delete_profiler_by_network(network))

    created, verdict = run_op(
        run_async, recorder, "profiler_create_subnet_mapping", tier="create",
        expect="lenient", mapping_data=_profiler_body(network))
    no_crash(created, "profiler_create_subnet_mapping")
    if verdict != PASS:
        pytest.skip(f"profiler_create_subnet_mapping refused: {created}")

    got, verdict = run_op(run_async, recorder,
                          "profiler_get_subnet_mapping_by_network", tier="read",
                          scan_type=PROFILER_SCAN_TYPE, network=network)
    assert verdict == PASS, f"profiler_get_subnet_mapping_by_network -> {got}"
    record = obj_of(got, "profiler_subnet_mapping")
    assert _is_doc_only(record.get("network")), \
        f"our own profiler mapping is not confined to documentation space: {record}"

    assert_doc_network(network)
    updated, verdict = run_op(
        run_async, recorder, "profiler_update_subnet_mapping_by_network",
        tier="update", scan_type=PROFILER_SCAN_TYPE, network=network,
        mapping_data={"ext_accounts": []})
    assert verdict == PASS, f"profiler_update_subnet_mapping_by_network -> {updated}"

    assert_doc_network(network)
    replaced, verdict = run_op(
        run_async, recorder, "profiler_replace_subnet_mapping_by_network",
        tier="update", scan_type=PROFILER_SCAN_TYPE, network=network,
        mapping_data=_profiler_body(network))
    assert verdict == PASS, \
        f"profiler_replace_subnet_mapping_by_network -> {replaced}"

    assert_doc_network(network)
    deleted, verdict = run_op(
        run_async, recorder, "profiler_delete_subnet_mapping_by_network",
        tier="delete", scan_type=PROFILER_SCAN_TYPE, network=network)
    assert verdict == PASS, \
        f"profiler_delete_subnet_mapping_by_network -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "profiler_get_subnet_mapping_by_network",
        tier="negative", expect="absent", scan_type=PROFILER_SCAN_TYPE,
        network=network)
    assert verdict == PASS, f"deleted profiler mapping still readable: {gone}"


def test_profiler_subnet_mapping_lifecycle_by_id(run_async, recorder, cleanup):
    """The numeric-id handle; the id comes from our own create only."""
    network = assert_doc_network(ADDR_B)
    cleanup.add(lambda: _delete_profiler_by_network(network))

    created, verdict = run_op(
        run_async, recorder, "profiler_create_subnet_mapping", tier="create",
        expect="lenient", mapping_data=_profiler_body(network))
    no_crash(created, "profiler_create_subnet_mapping")
    if verdict != PASS:
        pytest.skip(f"profiler_create_subnet_mapping refused: {created}")

    mid = id_of(obj_of(created, "profiler_subnet_mapping"))
    if mid is None:
        readback, _ = run_op(run_async, recorder,
                             "profiler_get_subnet_mapping_by_network",
                             tier="read", scan_type=PROFILER_SCAN_TYPE,
                             network=network)
        mid = id_of(obj_of(readback, "profiler_subnet_mapping"))
    if mid is None:
        record_blocked(recorder, "profiler_delete_subnet_mapping_by_id",
                       "the appliance returned no numeric id for our own "
                       "profiler subnet mapping, so no id can be proven ours")
        pytest.skip("no id available for the profiler mapping we created")
    created_ids = [mid]

    got, verdict = run_op(run_async, recorder,
                          "profiler_get_subnet_mapping_by_id", tier="read",
                          scan_type=PROFILER_SCAN_TYPE,
                          profiler_subnet_mapping_id=mid)
    assert verdict == PASS, f"profiler_get_subnet_mapping_by_id({mid}) -> {got}"
    assert _is_doc_only(obj_of(got, "profiler_subnet_mapping").get("network")), got

    assert_created_id(mid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "profiler_update_subnet_mapping_by_id",
        tier="update", scan_type=PROFILER_SCAN_TYPE,
        profiler_subnet_mapping_id=mid, mapping_data={"ext_accounts": []})
    assert verdict == PASS, f"profiler_update_subnet_mapping_by_id -> {updated}"

    assert_created_id(mid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "profiler_replace_subnet_mapping_by_id",
        tier="update", scan_type=PROFILER_SCAN_TYPE,
        profiler_subnet_mapping_id=mid, mapping_data=_profiler_body(network))
    assert verdict == PASS, f"profiler_replace_subnet_mapping_by_id -> {replaced}"

    assert_created_id(mid, created_ids)
    deleted, verdict = run_op(
        run_async, recorder, "profiler_delete_subnet_mapping_by_id",
        tier="delete", scan_type=PROFILER_SCAN_TYPE,
        profiler_subnet_mapping_id=mid)
    assert verdict == PASS, f"profiler_delete_subnet_mapping_by_id -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "profiler_get_subnet_mapping_by_id",
        tier="negative", expect="absent", scan_type=PROFILER_SCAN_TYPE,
        profiler_subnet_mapping_id=mid)
    assert verdict == PASS, f"deleted profiler mapping still readable by id: {gone}"


PROFILER_NETWORK_OPS: List[Tuple[str, str]] = [
    ("profiler_get_subnet_mapping_by_network", ""),
    ("profiler_delete_subnet_mapping_by_network", ""),
    ("profiler_update_subnet_mapping_by_network", "patch"),
    ("profiler_replace_subnet_mapping_by_network", "full"),
]


@pytest.mark.parametrize("operation,body", PROFILER_NETWORK_OPS,
                         ids=[o[0] for o in PROFILER_NETWORK_OPS])
def test_profiler_by_network_absent(run_async, recorder, operation, body):
    """A documentation address no mapping was ever created for."""
    network = assert_doc_network("198.51.100.51")
    params: Dict[str, Any] = {}
    if body == "patch":
        params["mapping_data"] = {"ext_accounts": []}
    elif body == "full":
        params["mapping_data"] = _profiler_body(network)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", scan_type=PROFILER_SCAN_TYPE,
                             network=network, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(network={network}) -> {result}"


PROFILER_ID_OPS: List[Tuple[str, str]] = [
    ("profiler_get_subnet_mapping_by_id", ""),
    ("profiler_delete_subnet_mapping_by_id", ""),
    ("profiler_update_subnet_mapping_by_id", "patch"),
    ("profiler_replace_subnet_mapping_by_id", "full"),
]


@pytest.mark.parametrize("operation,body", PROFILER_ID_OPS,
                         ids=[o[0] for o in PROFILER_ID_OPS])
def test_profiler_by_id_absent(run_async, recorder, operation, body):
    params: Dict[str, Any] = {}
    if body == "patch":
        params["mapping_data"] = {"ext_accounts": []}
    elif body == "full":
        params["mapping_data"] = _profiler_body(ADDR_A)
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", scan_type=PROFILER_SCAN_TYPE,
                             profiler_subnet_mapping_id=ABSENT_ID, **params)
    no_crash(result, operation)
    assert verdict == PASS, \
        f"{operation}(profiler_subnet_mapping_id={ABSENT_ID}) -> {result}"


def test_profiler_by_network_cidr_is_unaddressable(run_async, recorder):
    """Read-only probe documenting a route-shape limitation.

    ``profiler-subnet-mapping/{scan_type}/network/{network}`` interpolates the
    network straight into the URL path, so a CIDR value such as ``192.0.2.0/24``
    contributes an extra path segment and cannot address the mapping it names.
    Pinned as a structured, non-crashing outcome; the finding itself is recorded
    in the run notes.
    """
    result, verdict = run_op(
        run_async, recorder, "profiler_get_subnet_mapping_by_network",
        tier="negative", expect="graceful", scan_type=PROFILER_SCAN_TYPE,
        network=assert_doc_network(NET_A))
    no_crash(result, "profiler_get_subnet_mapping_by_network")
    assert verdict == PASS, f"CIDR probe must answer cleanly -> {result}"
    if result.get("success") is not True:
        note("profiler_get_subnet_mapping_by_network: a CIDR network cannot be "
             "addressed through the by-network route — the '/' is interpolated "
             "into the URL path unencoded -> "
             f"{harness.deep_error_text(result)[:200]}")


# ==========================================================================
# 5. onguard/policy-manager-zones — 10 operations
# ==========================================================================


def _zone_body(name: str, network: str = NET_A) -> Dict[str, Any]:
    assert_ours(name)
    assert_doc_network(network)
    return {"policy_manager_zone_name": name, "client_subnets": network}


def _delete_zone_by_name(name: str):
    assert_ours(name)
    return harness.invoke("onguard_delete_policy_manager_zone_by_name",
                          _params={"name": name})


def test_onguard_list_policy_manager_zones(run_async, recorder):
    """The operation takes no parameters at all — a pure omission path."""
    result, verdict = run_op(run_async, recorder,
                             "onguard_list_policy_manager_zones", tier="read")
    no_crash(result, "onguard_list_policy_manager_zones")
    assert verdict == PASS, f"onguard_list_policy_manager_zones -> {result}"
    assert "policy_manager_zones" in result, f"unexpected shape: {sorted(result)}"


def test_onguard_policy_manager_zone_lifecycle_by_name(run_async, recorder,
                                                       run_id, cleanup):
    """create -> get -> update -> replace -> delete on the name handle.

    ``onguard/policy-manager-zones`` binds client subnets to a Policy Manager
    zone, so the appliance may require the named zone to already exist in cluster
    topology. If the create is refused it is recorded ``EXPECTED-LIMITATION``
    with the appliance's own error and the remaining operations are covered by
    the absent-name tests. A **real** zone name is never the target of an
    update/delete here — ``assert_ours`` refuses anything without the fixture
    prefix, which is the rail that keeps this family safe.
    """
    name = fixture_name(run_id, "pmz1")
    cleanup.add(lambda: _delete_zone_by_name(name))

    created, verdict = run_op(
        run_async, recorder, "onguard_create_policy_manager_zone", tier="create",
        expect="lenient", zone_data=_zone_body(name))
    no_crash(created, "onguard_create_policy_manager_zone")
    if verdict != PASS:
        note("onguard_create_policy_manager_zone: the appliance refused a "
             "client-subnet binding for a zone that does not exist in cluster "
             "topology; creating the zone itself is out of scope because "
             "delete_server_policy_manager_zone is denylisted, so it could "
             "never be removed. Recorded EXPECTED-LIMITATION with the "
             "appliance error")
        pytest.skip(f"onguard_create_policy_manager_zone refused: {created}")

    got, verdict = run_op(run_async, recorder,
                          "onguard_get_policy_manager_zone_by_name", tier="read",
                          name=name)
    assert verdict == PASS, f"onguard_get_policy_manager_zone_by_name -> {got}"

    assert_ours(name)
    updated, verdict = run_op(
        run_async, recorder, "onguard_update_policy_manager_zone_by_name",
        tier="update", name=name,
        zone_data={"client_subnets": assert_doc_network(NET_B)})
    assert verdict == PASS, f"onguard_update_policy_manager_zone_by_name -> {updated}"

    assert_ours(name)
    replaced, verdict = run_op(
        run_async, recorder, "onguard_replace_policy_manager_zone_by_name",
        tier="update", name=name,
        zone_data={"client_subnets": assert_doc_network(NET_A)})
    assert verdict == PASS, \
        f"onguard_replace_policy_manager_zone_by_name -> {replaced}"

    assert_ours(name)
    deleted, verdict = run_op(
        run_async, recorder, "onguard_delete_policy_manager_zone_by_name",
        tier="delete", name=name)
    assert verdict == PASS, \
        f"onguard_delete_policy_manager_zone_by_name -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "onguard_get_policy_manager_zone_by_name",
        tier="negative", expect="absent", name=name)
    assert verdict == PASS, f"deleted zone binding still readable: {gone}"


def test_onguard_policy_manager_zone_lifecycle_by_id(run_async, recorder, run_id,
                                                     cleanup):
    """The numeric-id handle for the OnGuard zone-binding family."""
    name = fixture_name(run_id, "pmz2")
    cleanup.add(lambda: _delete_zone_by_name(name))

    created, verdict = run_op(
        run_async, recorder, "onguard_create_policy_manager_zone", tier="create",
        expect="lenient", zone_data=_zone_body(name))
    no_crash(created, "onguard_create_policy_manager_zone")
    if verdict != PASS:
        pytest.skip(f"onguard_create_policy_manager_zone refused: {created}")

    zid = id_of(obj_of(created, "policy_manager_zone"))
    if zid is None:
        readback, _ = run_op(run_async, recorder,
                             "onguard_get_policy_manager_zone_by_name",
                             tier="read", name=name)
        zid = id_of(obj_of(readback, "policy_manager_zone"))
    if zid is None:
        record_blocked(recorder, "onguard_delete_policy_manager_zone_by_id",
                       "the appliance returned no numeric id for our own zone "
                       "binding, so no id can be proven ours — and an id "
                       "harvested from the listing would be a REAL Policy "
                       "Manager zone")
        pytest.skip("no id available for the zone binding we created")
    created_ids = [zid]

    got, verdict = run_op(run_async, recorder,
                          "onguard_get_policy_manager_zone_by_id", tier="read",
                          policy_manager_zones_id=zid)
    assert verdict == PASS, f"onguard_get_policy_manager_zone_by_id({zid}) -> {got}"

    assert_created_id(zid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "onguard_update_policy_manager_zone_by_id",
        tier="update", policy_manager_zones_id=zid,
        zone_data={"client_subnets": assert_doc_network(NET_B)})
    assert verdict == PASS, f"onguard_update_policy_manager_zone_by_id -> {updated}"

    assert_created_id(zid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "onguard_replace_policy_manager_zone_by_id",
        tier="update", policy_manager_zones_id=zid,
        zone_data={"client_subnets": assert_doc_network(NET_A)})
    assert verdict == PASS, f"onguard_replace_policy_manager_zone_by_id -> {replaced}"

    assert_created_id(zid, created_ids)
    deleted, verdict = run_op(
        run_async, recorder, "onguard_delete_policy_manager_zone_by_id",
        tier="delete", policy_manager_zones_id=zid)
    assert verdict == PASS, f"onguard_delete_policy_manager_zone_by_id -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "onguard_get_policy_manager_zone_by_id",
        tier="negative", expect="absent", policy_manager_zones_id=zid)
    assert verdict == PASS, f"deleted zone binding still readable by id: {gone}"


ZONE_NAME_OPS: List[Tuple[str, str]] = [
    ("onguard_get_policy_manager_zone_by_name", ""),
    ("onguard_delete_policy_manager_zone_by_name", ""),
    ("onguard_update_policy_manager_zone_by_name", "patch"),
    ("onguard_replace_policy_manager_zone_by_name", "full"),
]


@pytest.mark.parametrize("operation,body", ZONE_NAME_OPS,
                         ids=[o[0] for o in ZONE_NAME_OPS])
def test_onguard_policy_manager_zone_by_name_absent(run_async, recorder, run_id,
                                                    operation, body):
    """Fixture-prefixed zone name that cannot exist — never a real zone."""
    name = assert_ours(fixture_name(run_id, "pmz", "absent"))
    params: Dict[str, Any] = {}
    if body in ("patch", "full"):
        params["zone_data"] = {"client_subnets": assert_doc_network(NET_A)}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", name=name, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(absent {name!r}) -> {result}"


ZONE_ID_OPS: List[Tuple[str, str]] = [
    ("onguard_get_policy_manager_zone_by_id", ""),
    ("onguard_delete_policy_manager_zone_by_id", ""),
    ("onguard_update_policy_manager_zone_by_id", "patch"),
    ("onguard_replace_policy_manager_zone_by_id", "full"),
]


@pytest.mark.parametrize("operation,body", ZONE_ID_OPS,
                         ids=[o[0] for o in ZONE_ID_OPS])
def test_onguard_policy_manager_zone_by_id_absent(run_async, recorder, operation,
                                                  body):
    params: Dict[str, Any] = {}
    if body in ("patch", "full"):
        params["zone_data"] = {"client_subnets": assert_doc_network(NET_A)}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent",
                             policy_manager_zones_id=ABSENT_ID, **params)
    no_crash(result, operation)
    assert verdict == PASS, \
        f"{operation}(policy_manager_zones_id={ABSENT_ID}) -> {result}"


# ==========================================================================
# 6. onguard/global-settings and onguard/settings — 4 operations
# ==========================================================================


def test_onguard_list_global_settings(run_async, recorder):
    result, verdict = run_op(run_async, recorder, "onguard_list_global_settings",
                             tier="read")
    no_crash(result, "onguard_list_global_settings")
    assert verdict == PASS, f"onguard_list_global_settings -> {result}"
    assert "global_settings" in result, f"unexpected shape: {sorted(result)}"


def test_onguard_list_settings(run_async, recorder):
    result, verdict = run_op(run_async, recorder, "onguard_list_settings",
                             tier="read")
    no_crash(result, "onguard_list_settings")
    assert verdict == PASS, f"onguard_list_settings -> {result}"
    assert "onguard_settings" in result, f"unexpected shape: {sorted(result)}"


@pytest.mark.parametrize(
    "read_op,write_op,payload_key,read_only",
    [
        ("onguard_list_global_settings", "onguard_update_global_settings",
         "global_settings", ONGUARD_GLOBAL_SETTINGS_READ_ONLY),
        ("onguard_list_settings", "onguard_update_settings",
         "onguard_settings", ONGUARD_SETTINGS_READ_ONLY),
    ],
    ids=["onguard_update_global_settings", "onguard_update_settings"])
def test_onguard_settings_strict_read_restore(run_async, recorder, read_op,
                                              write_op, payload_key, read_only):
    """Strict read-restore of an appliance-wide OnGuard settings singleton.

    There is no fixture namespace for global state, so the only write that can
    be justified is an identity write. Sequence:

    1. GET the current payload.
    2. Refuse to dispatch at all — recording ``BLOCKED`` with the reason — if the
       payload cannot be POSTed back verbatim (not a JSON object, empty, carries
       documented read-only fields, or carries HAL metadata). An approximate
       restore of global OnGuard state is worse than no coverage.
    3. POST the identical payload back.
    4. GET again and assert every key still holds its original value.
    """
    before, verdict = run_op(run_async, recorder, read_op, tier="read")
    no_crash(before, read_op)
    assert verdict == PASS, f"{read_op} -> {before}"
    payload = before.get(payload_key)

    blockers = _roundtrip_blockers(payload, read_only)
    if blockers:
        record_blocked(recorder, write_op,
                       "STRICT read-restore refused: " + "; ".join(blockers))
        pytest.skip(f"{write_op}: {'; '.join(blockers)}")

    original = dict(payload)
    restored, verdict = run_op(run_async, recorder, write_op, tier="update",
                               expect="lenient", settings_data=dict(original))
    no_crash(restored, write_op)
    if verdict != PASS:
        # The appliance refused its own payload; nothing was changed, so run_op
        # has already recorded EXPECTED-LIMITATION with the error. The re-read
        # below still proves no drift.
        note(f"{write_op}: the appliance refused an identity POST of its own "
             f"GET payload -> {harness.deep_error_text(restored)[:200]}")

    after, verdict = run_op(run_async, recorder, read_op, tier="read")
    assert verdict == PASS, f"{read_op} (after restore) -> {after}"
    now = after.get(payload_key)
    assert isinstance(now, dict), f"{read_op} shape changed after restore: {after}"
    drifted = {k: (v, now.get(k)) for k, v in original.items()
               if now.get(k) != v}
    assert not drifted, \
        f"{write_op} changed appliance-wide OnGuard state: {drifted}"


# ==========================================================================
# 7. End-of-module fixture sweep + drift check
# ==========================================================================


def test_fixture_sweep_part2(run_async, recorder):
    """Remove every surviving fixture object in this module's families.

    Two ownership rails are used, matching how each family is keyed:

    * name-keyed families (agentless settings, agentless subnet mappings,
      OnGuard zone bindings) — ``assert_ours`` on the ``zzz-mcptest-`` prefix;
    * network-keyed families (``config/network-scan``,
      ``profiler-subnet-mapping``) — the configured network must be entirely
      inside RFC 5737 documentation space, which no real object can be.
    """
    swept: List[Dict[str, Any]] = []
    swept += sweep_named_family(
        run_async, "list_agentless_onguard_settings", "settings", "name",
        "delete_agentless_onguard_settings_by_name", "name")
    swept += sweep_named_family(
        run_async, "list_agentless_onguard_subnet_mappings", "subnet_mappings",
        "name", "delete_agentless_onguard_subnet_mapping_by_name", "name",
        list_params={"limit": 1000})
    swept += sweep_named_family(
        run_async, "onguard_list_policy_manager_zones", "policy_manager_zones",
        "policy_manager_zone_name",
        "onguard_delete_policy_manager_zone_by_name", "name")

    scans = run_async(harness.invoke("list_network_scans",
                                     _params={"limit": 1000}))
    for item in items_of(scans, "network_scans"):
        if not _is_doc_only(item.get("seed_device_or_ip_subnet")):
            continue  # a real scan target — never ours, never touched
        scan_id = id_of(item)
        if scan_id is None:
            continue
        removed = run_async(harness.invoke("delete_network_scan_by_id",
                                           _params={"scan_id": scan_id}))
        swept.append({"family": "config/network-scan", "id": scan_id,
                      "target": item.get("seed_device_or_ip_subnet"),
                      "deleted": bool(removed.get("success"))})

    mappings = run_async(harness.invoke("profiler_list_subnet_mappings"))
    for item in items_of(mappings, "profiler_subnet_mappings"):
        network = item.get("network")
        if not _is_doc_only(network):
            continue
        for candidate in _networks_of(network):
            assert_doc_network(candidate)
        removed = run_async(harness.invoke(
            "profiler_delete_subnet_mapping_by_network",
            _params={"scan_type": item.get("scan_type") or PROFILER_SCAN_TYPE,
                     "network": network}))
        swept.append({"family": "profiler-subnet-mapping", "network": network,
                      "deleted": bool(removed.get("success"))})

    print(f"\n[endpoint_visibility-2] sweep removed {len(swept)} object(s)")
    for entry in swept:
        print(f"   - {entry}")

    leftovers: Dict[str, List[Any]] = {
        "agentless_settings": surviving_fixtures(
            run_async, "list_agentless_onguard_settings", "settings", "name"),
        "agentless_subnet_mappings": surviving_fixtures(
            run_async, "list_agentless_onguard_subnet_mappings",
            "subnet_mappings", "name", {"limit": 1000}),
        "onguard_policy_manager_zones": surviving_fixtures(
            run_async, "onguard_list_policy_manager_zones",
            "policy_manager_zones", "policy_manager_zone_name"),
    }
    remaining = {k: v for k, v in leftovers.items() if v}
    assert not remaining, f"fixture objects survived the sweep: {remaining}"

    scans_after = run_async(harness.invoke("list_network_scans",
                                           _params={"limit": 1000}))
    doc_scans = [i for i in items_of(scans_after, "network_scans")
                 if _is_doc_only(i.get("seed_device_or_ip_subnet"))]
    assert not doc_scans, f"documentation-network scans survived: {doc_scans}"

    mappings_after = run_async(harness.invoke("profiler_list_subnet_mappings"))
    doc_mappings = [i for i in items_of(mappings_after,
                                        "profiler_subnet_mappings")
                    if _is_doc_only(i.get("network"))]
    assert not doc_mappings, \
        f"documentation-network profiler mappings survived: {doc_mappings}"


def test_summary(recorder):
    """Scope tally; declared last so it runs last within the module."""
    print(f"\n[endpoint_visibility-2] verdict counts: {recorder.counts}")
    for entry in NOTES:
        print(f"[endpoint_visibility-2] note: {entry}")
