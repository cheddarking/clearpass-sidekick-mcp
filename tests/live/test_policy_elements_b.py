"""Live validation — ``policy_elements`` domain, SECOND HALF (56 operations).

Scope
-----
``sorted(registry.search(domain="policy_elements"))[56:]`` — the alphabetically
second half of the 112-operation domain, from ``get_device_group_statistics``
through ``validate_tacacs_service_dictionary_configuration``. The first half is
another agent's.

Calling style
-------------
Optional parameters are OMITTED by default (see tests/live/README.md). Where a
second call adds realistic optionals it is marked ``[+opt]``.

Safety
------
* The only write family in scope that can be cleaned up is **roles**
  (``create_role`` / ``delete_role`` are not denylisted). ``update_role`` gets a
  full create -> update-by-id -> update-by-name -> replace -> delete lifecycle
  on a ``zzz-mcptest-*`` fixture.
* Every other ``update_*`` / ``replace_*`` / ``reorder_*`` /
  ``manage_*`` operation in scope can only succeed against a pre-existing
  production object, so its **write path is recorded BLOCKED**; the operation is
  still exercised on its guard path (identifier omitted) and its
  object-not-found path (a ``zzz-mcptest-ghost-*`` name / an id of 999999),
  neither of which can touch real data.
* ``assert_ours()`` is called immediately before every real write.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

import pytest

from . import harness
from .denylist import DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, FAIL, PASS, assert_ours, fixture_name

DOMAIN = "policy_elements"

# A name that provably does not exist on the appliance: it carries the fixture
# prefix (so it can never collide with production data) but is never created.
GHOST = "zzz-mcptest-ghost-0000"
GHOST_ID = 999999


# --------------------------------------------------------------------------
# Dispatch shim
# --------------------------------------------------------------------------
#
# harness.invoke()'s first positional parameter is itself called ``name``, so
# ``harness.invoke("get_role_details", name="[Guest]")`` raises
# ``TypeError: invoke() got multiple values for argument 'name'`` before the
# gateway is reached. Thirteen operations in this half take a ``name``
# parameter, so the by-name branch is untestable through harness.invoke().
# This shim reproduces harness.invoke()'s contract (denylist check first, then
# gateway dispatch, dict-normalised result) under a non-colliding signature.
# Reported as a harness limitation, not fixed here.


async def _dispatch(_op: str, **params: Any) -> Dict[str, Any]:
    if is_denylisted(_op):
        raise DenylistedOperation(_op)

    import src.main  # noqa: F401  (registers all 757 operations)
    from src.tools.gateway import invoke_operation

    result = await invoke_operation(harness.StubContext(), _op, params or None)
    if not isinstance(result, dict):
        return {
            "success": False,
            "error": f"non-dict result: {type(result).__name__}",
            "message": "Operation returned a non-dict payload",
            "raw": result,
        }
    return result


# --------------------------------------------------------------------------
# Classification helpers
# --------------------------------------------------------------------------

# harness.classify only inspects top-level error/message/detail keys. Several
# operations in this half return ``success: True`` while burying a Python
# AttributeError deeper in the payload, so the whole serialised result is
# scanned for crash markers.
_DEEP_MARKERS = (
    "FieldInfo",
    "Traceback (most recent call last)",
    "TypeError:",
    "AttributeError:",
    "object has no attribute",
    "cannot access local variable",
    "annotation=",
)


def deep_crash_marker(result: Dict[str, Any]) -> Optional[str]:
    """Return the first crash marker found anywhere in the payload."""
    blob = json.dumps(result, default=str)
    for marker in _DEEP_MARKERS:
        if marker in blob:
            return marker
    return None


def assert_missing_required(
    result: Dict[str, Any], operation: str, param: str
) -> None:
    """Assert the gateway refused the call *before* dispatch, naming ``param``.

    Contract (``src/tools/gateway.py::invoke_operation``)::

        {"success": False,
         "error": "Missing required parameter(s) ['<param>'] for '<op>'",
         "message": "Required parameters: [...]. Call describe_operations(...)"}

    This replaced ``TypeError: <op>() missing required argument: '<param>'``,
    which was a *post*-dispatch crash caught by invoke_operation's generic
    handler. So the absence of that text is itself part of the assertion: the
    parameter must be validated up front, never by calling the operation and
    letting Python raise.
    """
    error = str(result.get("error", ""))
    assert result.get("success") is False, result
    assert "Missing required parameter(s)" in error, result
    assert f"'{param}'" in error, result
    assert f"for '{operation}'" in error, result
    # Pre-dispatch proof: no TypeError leaked out of the operation itself.
    blob = json.dumps(result, default=str)
    assert "missing required argument" not in blob, result
    assert "TypeError" not in blob, result


def verdict_for(
    result: Dict[str, Any],
    operation: str,
    *,
    expect_absent: bool = False,
    expect_guard: bool = False,
) -> str:
    """harness.classify plus a deep crash scan and a guard-path allowance.

    ``expect_guard`` marks a deliberate call with no identifier / no update
    fields / no confirmation: a structured refusal is the *correct* answer, so
    ``success: False`` with a guard-shaped message is a PASS.
    """
    crash = deep_crash_marker(result)
    if crash:
        return FAIL

    base = harness.classify(result, operation, expect_absent=expect_absent)
    if base == PASS:
        return PASS

    if expect_guard and result.get("success") is False:
        text = " ".join(
            str(result.get(k, ""))
            for k in ("error", "message", "error_details", "detail")
        ).lower()
        guard_words = (
            "must be provided", "please provide", "required", "no update",
            "not found", "cannot specify both", "not provide both",
            "confirmation", "confirm", "cannot be empty",
        )
        if any(w in text for w in guard_words):
            return PASS
    return base


def record(
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
        err = " ".join(
            str(result.get(k, ""))
            for k in ("error", "message", "error_details")
        ).strip()[:600] or None
    recorder.record(operation, DOMAIN, tier, verdict, params, err, duration_ms)


async def _call(
    recorder,
    operation: str,
    tier: str,
    *,
    expect_absent: bool = False,
    expect_guard: bool = False,
    **params: Any,
):
    import time

    start = time.perf_counter()
    result = await _dispatch(operation, **params)
    duration = (time.perf_counter() - start) * 1000.0
    verdict = verdict_for(
        result, operation, expect_absent=expect_absent, expect_guard=expect_guard
    )
    record(recorder, operation, tier, verdict, params, result, duration)
    return result, verdict


# --------------------------------------------------------------------------
# Scope guard — the split must not drift
# --------------------------------------------------------------------------


def test_scope_is_the_second_half_of_policy_elements():
    import src.main  # noqa: F401
    from src.registry import registry

    names = sorted(s.name for s in registry.search(domain=DOMAIN))
    assert len(names) == 112, f"policy_elements changed size: {len(names)}"
    mine = names[56:]
    assert len(mine) == 56
    assert mine[0] == "get_device_group_hierarchy"
    assert mine[-1] == "validate_tacacs_service_dictionary_configuration"


# --------------------------------------------------------------------------
# 1. Read operations, every optional parameter OMITTED
# --------------------------------------------------------------------------

# Operations whose whole optional-parameter set may legitimately be omitted and
# which must then return data (not a guard refusal).
READS_NO_PARAMS = [
    "get_device_group_hierarchy",
    "list_application_dictionaries",
    "list_authentication_methods",
    "list_authentication_sources",
    "list_configuration_services",
    "list_enforcement_policies",
    "list_network_device_groups",
    "list_posture_policies",
    "list_radius_dictionaries",
    "list_role_mappings",
    "list_roles",
    "list_tacacs_service_dictionaries",
    "search_device_groups_advanced",
    "search_posture_policies_advanced",
    "search_radius_dictionaries_advanced",
    "search_tacacs_service_dictionaries_advanced",
]


@pytest.mark.parametrize("operation", READS_NO_PARAMS)
def test_read_with_all_optionals_omitted(run_async, recorder, operation):
    """The omission path — where the FieldInfo bug lived."""
    result, verdict = run_async(_call(recorder, operation, "read"))
    assert verdict == PASS, f"{operation}() -> {json.dumps(result, default=str)[:600]}"
    assert deep_crash_marker(result) is None


# Proxy Target family. The earlier triage ("no implementation on 6.12.4") was
# wrong about the appliance and right about the code: the client methods called
# a generated-pyclearpass surface (get_proxy_target, new_proxy_target,
# *_by_proxy_target_id, *_name_by_name) that ClearPassClient never defined, so
# every call raised AttributeError.
#
# Verified live on this 6.12.4 appliance: the endpoints DO exist.
#   GET    /proxy-target                -> 200, {"_embedded": {"items": []}}
#   GET    /proxy-target/{id}           -> 404 "Object not found"
#   GET    /proxy-target/name/{name}    -> 404 "Object not found"
#   PATCH/PUT/DELETE on both            -> 404 "Object not found"
# No proxy target is configured, so the collection is legitimately empty.
PROXY_TARGET_READS = [
    "list_proxy_targets",
    "search_proxy_targets_advanced",
]


@pytest.mark.parametrize("operation", PROXY_TARGET_READS)
def test_proxy_target_reads_succeed(run_async, recorder, operation):
    result, verdict = run_async(_call(recorder, operation, "read"))
    blob = json.dumps(result, default=str)
    assert "object has no attribute" not in blob, result
    assert deep_crash_marker(result) is None, result
    assert result.get("success") is True, result
    assert verdict == PASS, result


# --------------------------------------------------------------------------
# 2. Detail reads: guard path, by-id path, by-name path
# --------------------------------------------------------------------------

# operation, id parameter, name parameter
DETAIL_READS = [
    ("get_enforcement_policy_details", "enforcement_policy_id", "name"),
    ("get_network_device_group_details", "device_group_id", "name"),
    ("get_posture_policy_details", "policy_id", "name"),
    ("get_radius_dictionary_details", "radius_dict_id", "vendor_name"),
    ("get_role_details", "role_id", "name"),
    ("get_role_mapping_details", "role_mapping_id", "name"),
    ("get_tacacs_service_dictionary_details", "tacacs_dict_id", "name"),
]


@pytest.mark.parametrize("operation,id_param,name_param", DETAIL_READS)
def test_detail_read_guard_path(run_async, recorder, operation, id_param, name_param):
    """Neither identifier supplied — must be a structured refusal, not a crash."""
    result, verdict = run_async(
        _call(recorder, operation, "negative", expect_guard=True)
    )
    assert result.get("success") is False
    assert verdict == PASS, f"{operation}() -> {result}"
    assert deep_crash_marker(result) is None


@pytest.fixture(scope="module")
def live_ids(run_async):
    """Real identifiers harvested read-only from the appliance."""

    async def _harvest():
        out: Dict[str, Any] = {}
        for key, op in [
            ("device_group", "list_network_device_groups"),
            ("posture_policy", "list_posture_policies"),
            ("enforcement_policy", "list_enforcement_policies"),
            ("role", "list_roles"),
            ("role_mapping", "list_role_mappings"),
            ("tacacs_dict", "list_tacacs_service_dictionaries"),
            ("auth_source", "list_authentication_sources"),
        ]:
            result = await _dispatch(op)
            items = harness._extract_items(result)
            out[key] = harness._identify(items[0]) if items else {}
        return out

    return run_async(_harvest())


_ID_KEY = {
    "get_enforcement_policy_details": "enforcement_policy",
    "get_network_device_group_details": "device_group",
    "get_posture_policy_details": "posture_policy",
    "get_role_details": "role",
    "get_role_mapping_details": "role_mapping",
    "get_tacacs_service_dictionary_details": "tacacs_dict",
}


@pytest.mark.parametrize(
    "operation,id_param,name_param",
    [d for d in DETAIL_READS if d[0] in _ID_KEY],
)
def test_detail_read_by_id_and_by_name(
    run_async, recorder, live_ids, operation, id_param, name_param
):
    """Both handles must resolve. This is the id-or-name asymmetry check."""
    ident = live_ids[_ID_KEY[operation]]
    assert ident.get("id") is not None, f"no live object to read for {operation}"

    by_id, v_id = run_async(
        _call(recorder, operation, "read", **{id_param: ident["id"]})
    )
    assert v_id == PASS, f"{operation}({id_param}=...) -> {by_id}"

    by_name, v_name = run_async(
        _call(recorder, operation, "read", **{name_param: ident["name"]})
    )
    assert v_name == PASS, f"{operation}({name_param}=...) -> {by_name}"


def test_radius_dictionary_details_by_vendor_name(run_async, recorder):
    result, verdict = run_async(
        _call(recorder, "get_radius_dictionary_details", "read",
              vendor_name="Radius:IETF")
    )
    assert verdict == PASS, result
    # Non-zero id resolves normally.
    result, verdict = run_async(
        _call(recorder, "get_radius_dictionary_details", "read", radius_dict_id=800)
    )
    assert verdict == PASS, result


def test_radius_dictionary_details_accepts_id_zero(run_async, recorder):
    """FIXED: the identifier guard now uses `is None`, so id 0 is a real id.

    Radius:IETF really is dictionary 0 on this appliance. The old
    `if not radius_dict_id and not vendor_name` guard treated it as absent and
    made the by-id branch unreachable; siblings that guard with `is None`
    always accepted it (see test_get_radius_dictionary_statistics /
    test_radius_dictionary_probe).
    """
    result, verdict = run_async(
        _call(recorder, "get_radius_dictionary_details", "read", radius_dict_id=0)
    )
    assert result.get("success") is True, result
    assert verdict == PASS, result
    blob = json.dumps(result, default=str)
    assert "Radius:IETF" in blob, result
    assert "must be provided" not in blob, result


def test_proxy_target_details_guard_and_by_name(run_async, recorder):
    """Guard path is a clean refusal; the by-name path now reaches the API.

    FIXED: the proxy-target client methods used to call a generated-pyclearpass
    surface (`get_proxy_target_name_by_name`, ...) that ClearPassClient never
    had, so every call raised AttributeError. They now issue real requests to
    ``GET /proxy-target/name/{name}``, which exists on this 6.12.4 appliance and
    answers a genuine 404 for an absent target.
    """
    result, verdict = run_async(
        _call(recorder, "get_proxy_target_details", "negative", expect_guard=True)
    )
    assert result.get("success") is False
    assert verdict == PASS, result

    result, verdict = run_async(
        _call(recorder, "get_proxy_target_details", "negative",
              expect_absent=True, name=GHOST)
    )
    blob = json.dumps(result, default=str)
    assert "get_proxy_target_name_by_name" not in blob, result
    assert deep_crash_marker(result) is None, result
    assert result.get("success") is False, result
    assert "404" in blob, result
    assert verdict == PASS, result


# --------------------------------------------------------------------------
# 3. Statistics reads (required id present, everything else omitted)
# --------------------------------------------------------------------------


def test_get_device_group_statistics(run_async, recorder, live_ids):
    gid = live_ids["device_group"].get("id")
    result, verdict = run_async(
        _call(recorder, "get_device_group_statistics", "read", group_id=gid)
    )
    assert verdict == PASS, result
    # [+opt]
    result, verdict = run_async(
        _call(recorder, "get_device_group_statistics", "read",
              group_id=gid, include_device_details=True, time_range="7d")
    )
    assert verdict == PASS, result


def test_get_posture_policy_statistics(run_async, recorder, live_ids):
    """FIXED: the success ``return`` was indented inside the bare ``except:``
    that guarded the policy-name lookup, so the happy path fell off the end of
    the function and the gateway saw ``None``."""
    pid = live_ids["posture_policy"].get("id")
    result, verdict = run_async(
        _call(recorder, "get_posture_policy_statistics", "read", policy_id=pid)
    )
    assert result.get("error") != "non-dict result: NoneType", result
    assert result.get("success") is True, result
    assert isinstance(result.get("statistics"), dict), result
    assert result["statistics"].get("policy_id") == pid, result
    assert verdict == PASS, result


def test_get_posture_policy_statistics_absent_is_404(run_async, recorder):
    """FIXED: an absent policy used to yield success=True with a zeroed payload,
    indistinguishable from "no activity". It now fails the existence check."""
    result, verdict = run_async(
        _call(recorder, "get_posture_policy_statistics", "negative",
              expect_absent=True, policy_id=GHOST_ID)
    )
    assert result.get("success") is False, result
    assert "404" in json.dumps(result, default=str), result
    assert deep_crash_marker(result) is None, result
    assert verdict == PASS, result


def test_get_radius_dictionary_statistics(run_async, recorder):
    result, verdict = run_async(
        _call(recorder, "get_radius_dictionary_statistics", "read", radius_dict_id=0)
    )
    assert verdict == PASS, result


def test_get_tacacs_service_dictionary_statistics(run_async, recorder, live_ids):
    tid = live_ids["tacacs_dict"].get("id")
    result, verdict = run_async(
        _call(recorder, "get_tacacs_service_dictionary_statistics", "read",
              tacacs_dict_id=tid)
    )
    assert verdict == PASS, result


def test_get_proxy_target_statistics(run_async, recorder):
    """Returns synthesised statistics without touching the (absent) endpoint."""
    result, verdict = run_async(
        _call(recorder, "get_proxy_target_statistics", "read", proxy_target_id=1)
    )
    assert verdict in (PASS, EXPECTED_SKIP), result
    assert deep_crash_marker(result) is None


# --------------------------------------------------------------------------
# 4. Searches and lists with realistic optionals supplied  [+opt]
# --------------------------------------------------------------------------

SEARCH_WITH_OPTIONALS = [
    ("search_device_groups_advanced", {"name_pattern": "test"}),
    ("search_posture_policies_advanced", {"host_os": "Windows", "limit": 5}),
    ("search_radius_dictionaries_advanced", {"enabled_only": True, "limit": 5}),
    ("search_tacacs_service_dictionaries_advanced", {"name_pattern": "shell"}),
    ("list_roles", {"limit": 5, "sort": "+name"}),
    ("list_enforcement_policies", {"limit": 5, "calculate_count": True}),
    ("list_configuration_services", {"limit": 5, "offset": 0}),
    ("list_application_dictionaries", {"limit": 5}),
    ("get_device_group_hierarchy", {"include_statistics": True}),
]


@pytest.mark.parametrize("operation,params", SEARCH_WITH_OPTIONALS)
def test_read_with_optionals_supplied(run_async, recorder, operation, params):
    result, verdict = run_async(_call(recorder, operation, "read", **params))
    assert verdict == PASS, f"{operation}({params}) -> {result}"


# --------------------------------------------------------------------------
# 5. validate_* — pure client-side validators, no appliance mutation
# --------------------------------------------------------------------------

VALIDATORS = [
    ("validate_application_dictionary_configuration", "app_dict_config",
     {"name": GHOST, "description": "live validation",
      "attributes": [{"attr_name": "A", "attr_type": "String"}]}),
    ("validate_auth_source_configuration", "auth_source_config",
     {"name": GHOST, "type": "Local", "description": "live validation"}),
    ("validate_device_group_configuration", "group_config",
     {"name": GHOST, "group_format": "list", "value": "10.255.255.1"}),
    ("validate_posture_policy_configuration", "policy_config",
     {"name": GHOST, "posture_agent": "WebAgent", "host_os": "Windows",
      "plugin_version": "2.0"}),
    ("validate_proxy_target_configuration", "proxy_target_config",
     {"name": GHOST, "host_name": "10.255.255.1", "proxy_type": "RADIUS",
      "authentication_port": 1812, "accounting_port": 1813}),
    ("validate_radius_dictionary_configuration", "radius_dict_config",
     {"vendor_name": GHOST, "vendor_id": 65000, "prefix": "ZZZ",
      "attributes": []}),
    ("validate_tacacs_service_dictionary_configuration", "tacacs_dict_config",
     {"name": GHOST, "tacacs_service": "shell", "tacacs_protocol": "ip",
      "attributes": []}),
]


@pytest.mark.parametrize("operation,param,config", VALIDATORS)
def test_validator_with_optionals_omitted(run_async, recorder, operation, param, config):
    """Required config supplied, strict/conflict flags omitted."""
    result, verdict = run_async(
        _call(recorder, operation, "read", **{param: config})
    )
    assert verdict == PASS, f"{operation} -> {result}"
    assert deep_crash_marker(result) is None


@pytest.mark.parametrize("operation,param,config", VALIDATORS)
def test_validator_rejects_omitted_required_config(
    run_async, recorder, operation, param, config
):
    """Omitting a genuinely-required Field(...) must be a structured rejection."""
    result, verdict = run_async(
        _call(recorder, operation, "negative", expect_guard=True)
    )
    assert_missing_required(result, operation, param)
    assert "Traceback" not in json.dumps(result, default=str)
    assert verdict == PASS


# --------------------------------------------------------------------------
# 6. test_* connectivity probes (read-only under the hood)
# --------------------------------------------------------------------------


def test_authentication_source_connection_probe(run_async, recorder, live_ids):
    """Client-side this is a plain GET of the auth-source object — no bind."""
    sid = live_ids["auth_source"].get("id")
    result, verdict = run_async(
        _call(recorder, "test_authentication_source_connection", "read",
              auth_source_id=sid)
    )
    assert verdict == PASS, result

    missing, v_missing = run_async(
        _call(recorder, "test_authentication_source_connection", "negative",
              expect_guard=True)
    )
    assert_missing_required(
        missing, "test_authentication_source_connection", "auth_source_id")
    assert v_missing == PASS


def test_radius_dictionary_probe(run_async, recorder):
    result, verdict = run_async(
        _call(recorder, "test_radius_dictionary", "read", radius_dict_id=0)
    )
    assert verdict == PASS, result

    missing, v_missing = run_async(
        _call(recorder, "test_radius_dictionary", "negative", expect_guard=True)
    )
    assert_missing_required(missing, "test_radius_dictionary", "radius_dict_id")
    assert v_missing == PASS


def test_proxy_target_connectivity_absent_target(run_async, recorder):
    """FIXED: used to answer success=True with an AttributeError buried in
    ``data.error`` — a false positive for a target that does not exist.

    No proxy target is configured on this appliance (``GET /proxy-target``
    returns an empty collection), so id 1 is genuinely absent and must be
    reported as such.
    """
    result, verdict = run_async(
        _call(recorder, "test_proxy_target_connectivity", "negative",
              expect_absent=True, proxy_target_id=1)
    )
    blob = json.dumps(result, default=str)
    assert "get_proxy_target_by_proxy_target_id" not in blob, result
    assert deep_crash_marker(result) is None, result
    assert result.get("success") is False, result
    assert "404" in blob, result
    assert verdict == PASS, result


# --------------------------------------------------------------------------
# 7. optimize_device_group_configuration (read-only analysis)
# --------------------------------------------------------------------------


def test_optimize_device_group_configuration(run_async, recorder, live_ids):
    """The client method only analyses; apply_recommendations is never honoured."""
    gid = live_ids["device_group"].get("id")
    result, verdict = run_async(
        _call(recorder, "optimize_device_group_configuration", "read", group_id=gid)
    )
    assert verdict == PASS, result
    assert result.get("applied_changes") is False, (
        "optimize now applies changes by default — this test is no longer safe"
    )

    missing, v_missing = run_async(
        _call(recorder, "optimize_device_group_configuration", "negative",
              expect_guard=True)
    )
    assert_missing_required(
        missing, "optimize_device_group_configuration", "group_id")
    assert v_missing == PASS


# --------------------------------------------------------------------------
# 8. update_role — the one safe full write lifecycle in this half
# --------------------------------------------------------------------------


def test_update_role_lifecycle(run_async, recorder, run_id, cleanup):
    name = fixture_name(run_id, "pe-b")
    renamed = fixture_name(run_id, "pe-b", "renamed")
    cleanup.add(lambda: harness.sweep_fixtures())

    created = run_async(_dispatch("create_role", name=name,
                                  description="policy_elements live validation"))
    assert created.get("success") is True, created
    role_id = (created.get("role") or {}).get("id")
    assert role_id is not None, created

    # --- update by id, everything else omitted ---------------------------
    assert_ours(name)
    result, verdict = run_async(
        _call(recorder, "update_role", "update",
              role_id=role_id, new_description="updated via id")
    )
    assert verdict == PASS, result
    assert result["role"]["description"] == "updated via id"

    # --- update by name (the id-or-name symmetry check) -------------------
    assert_ours(name)
    result, verdict = run_async(
        _call(recorder, "update_role", "update",
              role_name=name, new_description="updated via name")
    )
    assert verdict == PASS, result
    assert result["role"]["description"] == "updated via name"

    # --- replace_all=True (PUT) supplied as the optional  [+opt] ----------
    assert_ours(name)
    assert_ours(renamed)
    result, verdict = run_async(
        _call(recorder, "update_role", "update",
              role_name=name, new_name=renamed,
              new_description="replaced", replace_all=True)
    )
    assert verdict == PASS, result
    assert result["role"]["name"] == renamed

    # --- read back --------------------------------------------------------
    fetched, v_fetch = run_async(
        _call(recorder, "get_role_details", "read", role_id=role_id)
    )
    assert v_fetch == PASS, fetched
    assert fetched["role"]["name"] == renamed

    # --- delete -----------------------------------------------------------
    assert_ours(renamed)
    deleted = run_async(_dispatch("delete_role", role_name=renamed, confirm=True))
    assert deleted.get("success") is True, deleted

    gone, v_gone = run_async(
        _call(recorder, "get_role_details", "read", expect_absent=True,
              role_id=role_id)
    )
    assert gone.get("success") is not True, gone
    assert v_gone == PASS, gone


def test_update_role_guard_paths(run_async, recorder):
    """No identifier, and identifier with nothing to change."""
    result, verdict = run_async(
        _call(recorder, "update_role", "negative", expect_guard=True)
    )
    assert "role_id or role_name" in str(result.get("message"))
    assert verdict == PASS

    assert_ours(GHOST)
    result, verdict = run_async(
        _call(recorder, "update_role", "negative", expect_guard=True, role_name=GHOST)
    )
    assert "No update parameters provided" in str(result.get("error"))
    assert verdict == PASS


# --------------------------------------------------------------------------
# 9. Remaining write operations: guard path + object-not-found path
# --------------------------------------------------------------------------
#
# The success path of every operation below can only be reached by mutating a
# pre-existing production object, so it is recorded BLOCKED (see module
# docstring). Both paths exercised here are provably incapable of touching real
# data: the guard call supplies no identifier at all, and the not-found call
# targets `zzz-mcptest-ghost-0000` / id 999999.

# operation -> params identifying a non-existent object
NOT_FOUND_WRITES = [
    ("update_application_dictionary", {"app_dict_name": GHOST, "new_description": "x"}),
    ("update_authentication_method_by_id", {"auth_method_id": GHOST_ID, "description": "x"}),
    ("update_authentication_method_by_name", {"method_name": GHOST, "description": "x"}),
    ("update_configuration_service", {"service_name": GHOST, "description": "x"}),
    ("update_enforcement_policy", {"policy_name": GHOST, "new_description": "x"}),
    ("update_posture_policy", {"policy_name": GHOST, "new_description": "x"}),
    ("update_radius_dictionary", {"vendor_name": GHOST, "new_prefix": "ZZZ"}),
    ("replace_configuration_service", {"service_name": GHOST, "name": GHOST,
                                       "template": "RADIUS Enforcement",
                                       "enf_policy": GHOST}),
    ("manage_device_group_membership", {"group_id": GHOST_ID,
                                        "devices_to_add": ["10.255.255.1"]}),
]


@pytest.mark.parametrize("operation,params", NOT_FOUND_WRITES)
def test_write_against_absent_object_is_structured_404(
    run_async, recorder, operation, params
):
    for value in params.values():
        if isinstance(value, str) and value == GHOST:
            assert_ours(value)
    result, verdict = run_async(
        _call(recorder, operation, "negative", expect_absent=True, **params)
    )
    assert result.get("success") is False, result
    assert verdict == PASS, f"{operation}({params}) -> {result}"
    assert deep_crash_marker(result) is None


GUARD_WRITES = [
    ("update_application_dictionary", {}),
    ("update_authentication_method", {}),
    ("update_configuration_service", {}),
    ("update_enforcement_policy", {}),
    ("update_posture_policy", {}),
    ("update_proxy_target", {}),
    ("update_radius_dictionary", {}),
    ("update_tacacs_service_dictionary", {}),
    ("replace_configuration_service", {"name": GHOST, "template": "RADIUS Enforcement",
                                       "enf_policy": GHOST}),
]


@pytest.mark.parametrize("operation,params", GUARD_WRITES)
def test_write_without_identifier_is_structured_refusal(
    run_async, recorder, operation, params
):
    result, verdict = run_async(
        _call(recorder, operation, "negative", expect_guard=True, **params)
    )
    assert result.get("success") is False, result
    assert verdict == PASS, f"{operation}({params}) -> {result}"
    assert deep_crash_marker(result) is None


def test_reorder_configuration_services_confirmation_gate(run_async, recorder):
    """confirm omitted -> refuse before anything is read or written."""
    result, verdict = run_async(
        _call(recorder, "reorder_configuration_services", "negative",
              expect_guard=True, service_order=[GHOST_ID])
    )
    assert result.get("error") == "Confirmation required", result
    assert verdict == PASS

    # confirm=True but an id that does not exist -> refused before the write.
    result, verdict = run_async(
        _call(recorder, "reorder_configuration_services", "negative",
              expect_guard=True, service_order=[GHOST_ID], confirm=True)
    )
    assert result.get("success") is False, result
    assert f"Service ID {GHOST_ID} not found" in str(result.get("error")), result
    assert verdict == PASS


# --- confirmed defects on the write paths ---------------------------------


def test_update_authentication_method_reports_the_real_error(run_async, recorder):
    """FIXED: the except handler interpolated ``operation``, which was assigned
    only *after* the awaited call, so every API error (a plain 404 included)
    was replaced by an UnboundLocalError and the real error was lost."""
    for params in ({"auth_method_id": GHOST_ID, "new_description": "x"},
                   {"auth_method_name": GHOST, "new_description": "x"}):
        result, verdict = run_async(
            _call(recorder, "update_authentication_method", "negative",
                  expect_absent=True, **params)
        )
        blob = json.dumps(result, default=str)
        assert "cannot access local variable" not in blob, result
        assert deep_crash_marker(result) is None, result
        assert result.get("success") is False, result
        assert "404" in blob, result
        assert verdict == PASS, result


def test_update_proxy_target_by_name_reaches_the_api(run_async, recorder):
    """FIXED: used to call `update_proxy_target_name_by_name`, which does not
    exist on ClearPassClient. It now PATCHes ``/proxy-target/name/{name}``,
    which exists on 6.12.4 and 404s for an absent target."""
    assert_ours(GHOST)
    result, verdict = run_async(
        _call(recorder, "update_proxy_target", "negative", expect_absent=True,
              proxy_target_name=GHOST, new_description="x")
    )
    blob = json.dumps(result, default=str)
    assert "update_proxy_target_name_by_name" not in blob, result
    assert deep_crash_marker(result) is None, result
    assert result.get("success") is False, result
    assert "404" in blob, result
    assert verdict == PASS, result


def test_update_tacacs_service_dictionary_404_is_structured(run_async, recorder):
    """FIXED: the ClearPassAPIError handler re-raised for any non-405 status,
    and a sibling ``except Exception`` cannot catch that, so a 404 escaped to
    the gateway's generic catch. It is now returned structured, like siblings."""
    assert_ours(GHOST)
    result, verdict = run_async(
        _call(recorder, "update_tacacs_service_dictionary", "negative",
              expect_absent=True, tacacs_dict_name=GHOST, new_description="x")
    )
    assert "raised an unexpected error" not in str(result.get("message")), result
    assert result.get("success") is False, result
    assert "Failed to update TACACS+ service dictionary" in str(
        result.get("message")), result
    assert "404" in json.dumps(result, default=str), result
    assert deep_crash_marker(result) is None, result
    assert verdict == PASS


# --------------------------------------------------------------------------
# 10. BLOCKED write paths — recorded, never dispatched
# --------------------------------------------------------------------------

BLOCKED_WRITE_PATHS = {
    "manage_device_group_membership":
        "PUTs a new member list onto a real network device group; "
        "delete_network_device_group is denylisted so no fixture group can be "
        "created and cleaned up.",
    "reorder_configuration_services":
        "Reorders the 19 pre-existing configuration services appliance-wide; "
        "cannot be scoped to fixtures.",
    "replace_configuration_service":
        "Full PUT replacement of a real configuration service; no safe "
        "fixture family for services.",
    "update_configuration_service": "Same family — no safe fixture service.",
    "update_enforcement_policy":
        "16 pre-existing enforcement policies; delete_enforcement_policy is "
        "outside the approved fixture families.",
    "update_posture_policy": "2 pre-existing posture policies, no fixture family.",
    "update_application_dictionary": "3 pre-existing dictionaries, no fixture family.",
    "update_radius_dictionary": "25 pre-existing RADIUS dictionaries, no fixture family.",
    "update_tacacs_service_dictionary": "18 pre-existing TACACS+ dictionaries.",
    "update_authentication_method": "Auth methods back live services.",
    "update_authentication_method_by_id": "Auth methods back live services.",
    "update_authentication_method_by_name": "Auth methods back live services.",
    "update_proxy_target": "Proxy targets unimplemented and unremovable.",
}


def test_blocked_write_paths_are_recorded_not_dispatched(recorder):
    """Success paths that cannot be exercised safely. Nothing is dispatched."""
    import src.main  # noqa: F401
    from src.registry import registry

    for operation, reason in BLOCKED_WRITE_PATHS.items():
        assert registry.get(operation) is not None, operation
        recorder.record(operation, DOMAIN, "blocked", "BLOCKED", {},
                        f"write path not exercised: {reason}", 0.0)
