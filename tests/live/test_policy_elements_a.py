"""Live validation — policy_elements domain, FIRST HALF (alphabetical, through ``list_*``).

Scope: the 82 operations of the ``policy_elements`` domain that sort from
``assess_endpoint_compliance`` up to and including
``list_tacacs_service_dictionaries``. The remaining 30 (``manage_*`` onward)
belong to a second agent and are not touched here.

Calling style
-------------
Optional parameters are OMITTED by default; that is the path where the
``FieldInfo`` leak lived. Where an optional parameter is meaningful a second
call supplies it explicitly.

Safety
------
* The only family in this scope that can be created and cleaned up safely is
  ``roles`` (``create_role``/``delete_role`` are both live-safe and roles are
  swept by ``harness.sweep_fixtures``). Every other ``create_*``/``clone_*``
  is exercised only on a path that provably cannot create an object (absent
  source object, unknown template) and is otherwise recorded ``BLOCKED``.
* Every write/delete name carries the fixture prefix and is passed through
  ``assert_ours`` immediately before dispatch.
* ``delete_network_device_group`` is denylisted and is asserted to raise.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import (
    EXPECTED_SKIP,
    FAIL,
    PASS,
    assert_ours,
    expected_skip_reason,
    fixture_name,
)

DOMAIN = "policy_elements"
BLOCKED = "BLOCKED"

# An id that cannot exist on this appliance. Used for every negative /
# cannot-create path so no real object is ever the target of a write.
ABSENT_ID = 999999999

# Populated by run_op; surfaced in the final summary.
NOTES: List[str] = []

# Product bugs confirmed live in this scope. Each is recorded FAIL in the JSONL
# artifact (Phase 5 triages from that) but marked xfail here so the suite stays
# meaningful: a NEW regression still turns the run red.
KNOWN_BUGS: Dict[str, str] = {
    # The policy_elements defects previously listed here are FIXED and their
    # tests now assert correct behaviour. Do not re-add an entry to silence a
    # regression — this list may only shrink. Fixed in this pass:
    #   configure_auth_source_{backup_connections,filters,radius_attributes}
    #       _make_request(json=...) -> data=, plus the request bodies now carry
    #       only real ClearPass auth-source fields.
    #   get_application_dictionary_statistics
    #       include_usage_patterns is threaded through to the client method.
    #   get_posture_policy_statistics (+ :absent)
    #       success return de-indented out of the bare `except:`; the policy is
    #       verified to exist so an absent id is a structured 404.
    #   get_proxy_target_statistics:absent
    #       existence check added.
    #   delete_configuration_service:no-identifier
    #       identifier guard moved ahead of the confirmation guard.
    #   bulk_update_application_dictionaries
    #       confirm_operation is no longer forwarded, and the client fans the
    #       operation out per item (ClearPass has no /bulk-update endpoint).
    #   enable_disable_radius_dictionary:absent
    #       the PATCH now carries `{}` so ClearPass answers 404, not 400.
    #   create_role:missing-required
    #       a missing required parameter used to surface as a caught TypeError
    #       through invoke_operation's generic catch; the gateway now validates
    #       required parameters before dispatch and answers
    #       "Missing required parameter(s) ['name'] for 'create_role'", so the
    #       allowance is gone and the test is strict again.
}


def check(verdict: str, bug_key, message: str) -> None:
    """Assert PASS, or xfail with the confirmed root cause for a known bug."""
    keys = (bug_key,) if isinstance(bug_key, str) else tuple(bug_key)
    if verdict != PASS:
        for key in keys:
            if key in KNOWN_BUGS:
                pytest.xfail(
                    f"KNOWN BUG [{key}] {KNOWN_BUGS[key]} :: {message}")
    assert verdict == PASS, message


# --------------------------------------------------------------------------
# Dispatch + verdict helper
# --------------------------------------------------------------------------

_ERROR_KEYS = ("error", "message", "detail", "details", "error_details",
               "warning", "safety_warning")


def _text(result: Dict[str, Any]) -> str:
    return " ".join(str(result.get(k, "")) for k in _ERROR_KEYS)


def _deep_text(result: Dict[str, Any]) -> str:
    """Whole payload as text — bulk operations report per-item outcomes nested
    inside a success envelope, and that is where their 404s live."""
    return json.dumps(result, default=str)


def _crash_markers(text: str) -> List[str]:
    return [m for m in harness._CRASH_MARKERS if m in text]


_ABSENT_PAT = ("404", "not found", "does not exist", "no such", "not exist",
               "unknown template", "could not be found", "does not support")


def run_op(
    recorder,
    operation: str,
    tier: str = "read",
    expect: str = "success",
    substrings: Tuple[str, ...] = (),
    **params: Any,
) -> Tuple[Dict[str, Any], str]:
    """Invoke through the gateway, classify, record. Returns (result, verdict).

    ``expect``:
      ``success``  — the operation should work against real data.
      ``absent``   — a structured "not found" for a deliberately absent object.
      ``refusal``  — a structured guard refusal; ``substrings`` must appear.
    """
    import time

    start = time.perf_counter()
    result = harness_invoke_sync(operation, params)
    duration = (time.perf_counter() - start) * 1000.0

    text = _text(result)
    deep = _deep_text(result)
    crashes = _crash_markers(text)
    reason = expected_skip_reason(operation)
    success = result.get("success") is True

    # A per-item crash nested inside a success envelope (bulk operations) is
    # still a crash; for a known-limitation family it is the documented gap.
    if not crashes and _crash_markers(deep):
        if reason:
            NOTES.append(
                f"{operation}: known limitation ({reason}) reported per-item "
                f"inside a success envelope")
            recorder.record(operation, DOMAIN, tier, EXPECTED_SKIP, params,
                            deep[:400], duration)
            return result, EXPECTED_SKIP
        crashes = _crash_markers(deep)
        text = deep

    if crashes:
        # A known environment limitation that manifests only as a missing
        # pyclearpass client method is still the documented limitation, not a
        # regression — but record the fact that it surfaces as a raw Python
        # error string rather than a structured one.
        if reason and not success and "object has no attribute" in text:
            verdict = EXPECTED_SKIP
            NOTES.append(
                f"{operation}: known limitation ({reason}) surfaces as a raw "
                f"AttributeError string, not a structured error"
            )
        else:
            verdict = FAIL
    elif expect == "success":
        verdict = PASS if success else (EXPECTED_SKIP if reason else FAIL)
    elif expect == "absent":
        low = deep.lower()
        # An operation that reports the absent object per-item inside a success
        # envelope has still handled it correctly; an operation that reports
        # plain success with no trace of the absence has invented data.
        if any(p in low for p in _ABSENT_PAT):
            verdict = PASS
        elif success:
            verdict = FAIL
        else:
            verdict = EXPECTED_SKIP if reason else FAIL
    elif expect == "refusal":
        low = text.lower()
        if not success and any(s.lower() in low for s in substrings):
            verdict = PASS
        else:
            verdict = FAIL
    else:  # pragma: no cover
        raise ValueError(expect)

    err = None if verdict == PASS else (text.strip() or None)
    recorder.record(operation, DOMAIN, tier, verdict, params, err, duration)
    return result, verdict


# The conftest event loop is session-scoped and reached through run_async; a
# module-level shim keeps the call sites readable.
_RUN_ASYNC = None


def harness_invoke_sync(operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch through the gateway, exactly as ``harness.invoke`` does.

    NOTE: this cannot call ``harness.invoke`` directly. ``harness.invoke``'s
    first positional parameter is itself called ``name``, so any operation with
    a ``name`` parameter — 12 of the operations in this scope, including
    ``create_role`` and every ``get_*_details`` name branch — raises
    ``TypeError: invoke() got multiple values for argument 'name'`` before
    reaching the appliance. Reported as a harness defect; worked around here so
    the operations can actually be validated. The denylist rail, the stub
    Context and the non-dict guard are reproduced faithfully.
    """
    assert _RUN_ASYNC is not None, "loop shim not installed"
    if is_denylisted(operation):
        raise DenylistedOperation(operation)

    import src.main  # noqa: F401  (side effect: registers all operations)
    from src.tools.gateway import invoke_operation

    ctx = harness.StubContext()
    result = _RUN_ASYNC(invoke_operation(ctx, operation, dict(params) or None))
    if not isinstance(result, dict):
        return {
            "success": False,
            "error": f"non-dict result: {type(result).__name__}",
            "message": "Operation returned a non-dict payload",
            "raw": result,
        }
    return result


@pytest.fixture(autouse=True, scope="module")
def _install_loop(request):
    global _RUN_ASYNC
    if not request.config.getoption("--live"):
        yield
        return
    _RUN_ASYNC = request.getfixturevalue("run_async")
    yield
    _RUN_ASYNC = None


def record_blocked(recorder, operation: str, reason: str) -> None:
    recorder.record(operation, DOMAIN, "blocked", BLOCKED, {}, reason, 0.0)


# --------------------------------------------------------------------------
# Catalogue of existing objects (read once per session)
# --------------------------------------------------------------------------

# op -> key holding the item list in the response
LIST_OPS: Dict[str, str] = {
    "list_application_dictionaries": "dictionaries",
    "list_authentication_methods": "authentication_methods",
    "list_authentication_sources": "authentication_sources",
    "list_configuration_services": "services",
    "list_enforcement_policies": "enforcement_policies",
    "list_network_device_groups": "device_groups",
    "list_posture_policies": "posture_policies",
    "list_proxy_targets": "proxy_targets",
    "list_radius_dictionaries": "dictionaries",
    "list_role_mappings": "role_mappings",
    "list_roles": "roles",
    "list_tacacs_service_dictionaries": "tacacs_dictionaries",
}


def _items(result: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    for container in (result, result.get("data") or {}):
        if isinstance(container, dict) and isinstance(container.get(key), list):
            return [i for i in container[key] if isinstance(i, dict)]
    return []


@pytest.fixture(scope="module")
def catalog(request, recorder) -> Dict[str, List[Dict[str, Any]]]:
    """One pass over every list operation; the raw items keyed by list op."""
    if not request.config.getoption("--live"):
        pytest.skip("live only")
    out: Dict[str, List[Dict[str, Any]]] = {}
    for op, key in LIST_OPS.items():
        result, _ = run_op(recorder, op, tier="read")
        out[op] = _items(result, key)
    return out


def pick(catalog, list_op: str, name_key: str = "name"
         ) -> Optional[Tuple[Any, Any]]:
    """First (id, name) pair from a family, or None when the family is empty."""
    for item in catalog.get(list_op) or []:
        ident = item.get("id")
        name = item.get(name_key)
        if ident is not None or name is not None:
            return ident, name
    return None


# ==========================================================================
# 1. list_*  (12 operations) — every optional omitted
# ==========================================================================


@pytest.mark.parametrize("operation,key", sorted(LIST_OPS.items()))
def test_list_operations_no_params(recorder, operation, key):
    result, verdict = run_op(recorder, operation, tier="read")
    assert "FieldInfo" not in json.dumps(result, default=str), \
        f"{operation}: FieldInfo leaked into the response"
    if verdict == EXPECTED_SKIP:
        reason = expected_skip_reason(operation)
        assert reason, f"{operation} skipped without a known reason: {result}"
        pytest.skip(f"{operation}: {reason}")
    assert verdict == PASS, f"{operation} (no params) -> {result}"
    assert _items(result, key) or result.get("success") is True, \
        f"{operation}: no items key '{key}' in {sorted(result)}"


@pytest.mark.parametrize("operation", ["list_roles", "list_enforcement_policies",
                                       "list_authentication_sources"])
def test_list_operations_with_optionals(recorder, operation):
    """Second pass with realistic optional parameters supplied."""
    result, verdict = run_op(
        recorder, operation, tier="read",
        limit=5, offset=0, sort="+name", calculate_count=True,
    )
    assert verdict == PASS, f"{operation} (optionals supplied) -> {result}"


def test_list_filter_str_alias(recorder, catalog):
    """``filter_str`` carries alias="filter"; check the alias survives dispatch."""
    got = pick(catalog, "list_roles")
    assert got, "no roles on the appliance to filter for"
    _, name = got
    result, verdict = run_op(
        recorder, "list_roles", tier="read",
        filter_str=json.dumps({"name": name}),
    )
    assert verdict == PASS, f"list_roles(filter_str=...) -> {result}"
    names = [r.get("name") for r in _items(result, "roles")]
    assert names == [] or name in names, \
        f"filter for {name!r} returned {names}"


# ==========================================================================
# 2. get_*_details — id path, name path, and the missing-identifier guard
# ==========================================================================

# operation, id param, name param, source list op, name key in list payload
DETAIL_OPS: List[Tuple[str, str, str, str, str]] = [
    ("get_application_dictionary_details", "app_dict_id", "name",
     "list_application_dictionaries", "name"),
    ("get_authentication_method_details", "auth_method_id", "name",
     "list_authentication_methods", "name"),
    ("get_authentication_source_details", "auth_source_id", "name",
     "list_authentication_sources", "name"),
    ("get_configuration_service_details", "service_id", "name",
     "list_configuration_services", "name"),
    ("get_enforcement_policy_details", "enforcement_policy_id", "name",
     "list_enforcement_policies", "name"),
    ("get_network_device_group_details", "device_group_id", "name",
     "list_network_device_groups", "name"),
    ("get_posture_policy_details", "policy_id", "name",
     "list_posture_policies", "name"),
    ("get_proxy_target_details", "proxy_target_id", "name",
     "list_proxy_targets", "name"),
    ("get_radius_dictionary_details", "radius_dict_id", "vendor_name",
     "list_radius_dictionaries", "vendor_name"),
    ("get_role_details", "role_id", "name", "list_roles", "name"),
    ("get_role_mapping_details", "role_mapping_id", "name",
     "list_role_mappings", "name"),
    ("get_tacacs_service_dictionary_details", "tacacs_dict_id", "name",
     "list_tacacs_service_dictionaries", "name"),
]


@pytest.mark.parametrize(
    "operation,id_param,name_param,list_op,name_key",
    DETAIL_OPS, ids=[d[0] for d in DETAIL_OPS])
def test_get_details_by_id(recorder, catalog, operation, id_param,
                           name_param, list_op, name_key):
    got = pick(catalog, list_op, name_key)
    if not got or got[0] is None:
        record_blocked(recorder, operation,
                       f"no existing object with an id in {list_op}")
        pytest.skip(f"{operation}: no existing object to read")
    ident, _ = got
    result, verdict = run_op(recorder, operation, tier="read",
                             **{id_param: ident})
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    assert verdict == PASS, f"{operation}({id_param}={ident}) -> {result}"


@pytest.mark.parametrize(
    "operation,id_param,name_param,list_op,name_key",
    DETAIL_OPS, ids=[d[0] for d in DETAIL_OPS])
def test_get_details_by_name(recorder, catalog, operation, id_param,
                             name_param, list_op, name_key):
    """The id-or-name asymmetry hunt: does the name branch actually work?"""
    got = pick(catalog, list_op, name_key)
    if not got or got[1] is None:
        record_blocked(recorder, operation,
                       f"no existing named object in {list_op}")
        pytest.skip(f"{operation}: no existing named object to read")
    _, name = got
    result, verdict = run_op(recorder, operation, tier="read",
                             **{name_param: name})
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    assert verdict == PASS, \
        f"{operation}({name_param}={name!r}) -> {result}"


@pytest.mark.parametrize(
    "operation,id_param,name_param,list_op,name_key",
    DETAIL_OPS, ids=[d[0] for d in DETAIL_OPS])
def test_get_details_without_identifier(recorder, operation, id_param,
                                        name_param, list_op, name_key):
    """No parameters at all — the pure omission path. Must be a clean refusal."""
    result, verdict = run_op(
        recorder, operation, tier="negative", expect="refusal",
        substrings=("provide", "required", "missing", "either"),
    )
    assert verdict == PASS, \
        f"{operation}() with no identifier should refuse cleanly -> {result}"


def test_get_authentication_method_by_id(recorder, catalog):
    got = pick(catalog, "list_authentication_methods")
    assert got and got[0] is not None
    result, verdict = run_op(recorder, "get_authentication_method_by_id",
                             tier="read", auth_method_id=got[0])
    assert verdict == PASS, f"get_authentication_method_by_id -> {result}"


def test_get_authentication_method_by_name(recorder, catalog):
    got = pick(catalog, "list_authentication_methods")
    assert got and got[1] is not None
    result, verdict = run_op(recorder, "get_authentication_method_by_name",
                             tier="read", name=got[1])
    assert verdict == PASS, f"get_authentication_method_by_name -> {result}"


def test_get_device_group_hierarchy(recorder):
    result, verdict = run_op(recorder, "get_device_group_hierarchy", tier="read")
    assert verdict == PASS, f"get_device_group_hierarchy() -> {result}"


def test_get_device_group_hierarchy_with_optionals(recorder, catalog):
    got = pick(catalog, "list_network_device_groups")
    if not got or got[0] is None:
        pytest.skip("no device groups on the appliance")
    result, verdict = run_op(recorder, "get_device_group_hierarchy", tier="read",
                             root_group_id=got[0], include_statistics=True)
    assert verdict == PASS, f"get_device_group_hierarchy(optionals) -> {result}"


# ==========================================================================
# 3. statistics / status reads
# ==========================================================================

# operation, id param, source list op, name key
STAT_OPS: List[Tuple[str, str, str, str]] = [
    ("get_application_dictionary_statistics", "app_dict_id",
     "list_application_dictionaries", "name"),
    ("get_auth_source_connection_status", "auth_source_id",
     "list_authentication_sources", "name"),
    ("get_auth_source_statistics", "auth_source_id",
     "list_authentication_sources", "name"),
    ("get_device_group_statistics", "group_id",
     "list_network_device_groups", "name"),
    ("get_posture_policy_statistics", "policy_id",
     "list_posture_policies", "name"),
    ("get_proxy_target_statistics", "proxy_target_id",
     "list_proxy_targets", "name"),
    ("get_radius_dictionary_statistics", "radius_dict_id",
     "list_radius_dictionaries", "vendor_name"),
    ("get_tacacs_service_dictionary_statistics", "tacacs_dict_id",
     "list_tacacs_service_dictionaries", "name"),
]


@pytest.mark.parametrize("operation,id_param,list_op,name_key", STAT_OPS,
                         ids=[s[0] for s in STAT_OPS])
def test_statistics_with_optionals_omitted(recorder, catalog, operation,
                                           id_param, list_op, name_key):
    got = pick(catalog, list_op, name_key)
    if not got or got[0] is None:
        record_blocked(recorder, operation,
                       f"no existing object with an id in {list_op}")
        pytest.skip(f"{operation}: no object to gather statistics for")
    result, verdict = run_op(recorder, operation, tier="read",
                             **{id_param: got[0]})
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    check(verdict, operation, f"{operation}({id_param}={got[0]}) -> {result}")


@pytest.mark.parametrize("operation,id_param,list_op,name_key", STAT_OPS,
                         ids=[s[0] for s in STAT_OPS])
def test_statistics_for_absent_object(recorder, operation, id_param,
                                      list_op, name_key):
    result, verdict = run_op(recorder, operation, tier="negative",
                             expect="absent", **{id_param: ABSENT_ID})
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    check(verdict, (operation, f"{operation}:absent"),
          f"{operation}({id_param}={ABSENT_ID}) should be a structured 404 "
          f"-> {result}")


# ==========================================================================
# 4. delete_* — confirmation gate, then the absent-object id/name paths
# ==========================================================================

# operation, id param, name param
DELETE_OPS: List[Tuple[str, str, str]] = [
    ("delete_application_dictionary", "app_dict_id", "app_dict_name"),
    ("delete_authentication_method", "auth_method_id", "auth_method_name"),
    ("delete_authentication_source", "auth_source_id", "auth_source_name"),
    ("delete_configuration_service", "service_id", "service_name"),
    ("delete_enforcement_policy", "enforcement_policy_id", "policy_name"),
    ("delete_posture_policy", "policy_id", "policy_name"),
    ("delete_proxy_target", "proxy_target_id", "proxy_target_name"),
    ("delete_radius_dictionary", "radius_dict_id", "vendor_name"),
    ("delete_role", "role_id", "role_name"),
    ("delete_role_mapping", "role_mapping_id", "role_mapping_name"),
    ("delete_tacacs_service_dictionary", "tacacs_dict_id", "tacacs_dict_name"),
]


@pytest.mark.parametrize("operation,id_param,name_param", DELETE_OPS,
                         ids=[d[0] for d in DELETE_OPS])
def test_delete_confirmation_gate(recorder, run_id, operation, id_param,
                                  name_param):
    """``confirm`` omitted must refuse before any API call is made."""
    name = assert_ours(fixture_name(run_id, "absent"))
    result, verdict = run_op(
        recorder, operation, tier="negative", expect="refusal",
        substrings=("confirm", "confirmation"),
        **{name_param: name},
    )
    assert verdict == PASS, \
        f"{operation}({name_param}=..., confirm omitted) -> {result}"
    assert result.get("success") is not True


@pytest.mark.parametrize("operation,id_param,name_param", DELETE_OPS,
                         ids=[d[0] for d in DELETE_OPS])
def test_delete_absent_object_by_name(recorder, run_id, operation, id_param,
                                      name_param):
    """The name branch of every delete: absent fixture name + confirm=True.

    A structured 404 proves the by-name path is implemented. A type error or a
    "must supply id" message is the id-or-name asymmetry bug.
    """
    name = assert_ours(fixture_name(run_id, "absent"))
    result, verdict = run_op(
        recorder, operation, tier="negative", expect="absent",
        confirm=True, **{name_param: name},
    )
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    assert verdict == PASS, \
        f"{operation}({name_param}={name!r}, confirm=True) -> {result}"


@pytest.mark.parametrize("operation,id_param,name_param", DELETE_OPS,
                         ids=[d[0] for d in DELETE_OPS])
def test_delete_without_identifier(recorder, operation, id_param, name_param):
    result, verdict = run_op(
        recorder, operation, tier="negative", expect="refusal",
        substrings=("provide", "required", "missing", "either"),
    )
    check(verdict, f"{operation}:no-identifier",
          f"{operation}() with no identifier should refuse cleanly -> {result}")


def test_delete_network_device_group_is_denylisted(recorder):
    with pytest.raises(DenylistedOperation) as exc:
        harness_invoke_sync("delete_network_device_group", {"confirm": True})
    assert "delete_network_device_group" in str(exc.value)
    recorder.record("delete_network_device_group", DOMAIN, "denylist",
                    EXPECTED_SKIP, {},
                    f"DENYLISTED: {DENYLIST['delete_network_device_group']}", 0.0)


# ==========================================================================
# 5. roles — the one family in scope that can be created and cleaned up
# ==========================================================================


def test_role_lifecycle(recorder, run_id, cleanup):
    """create_role -> get_role_details (id + name) -> delete_role.

    ``description`` is omitted on create so the optional-omission path is the
    one under test; a second create supplies it.
    """
    name = fixture_name(run_id, "role1")
    cleanup.add(lambda: harness.sweep_fixtures())

    created, verdict = run_op(recorder, "create_role", tier="create", name=name)
    assert verdict == PASS, f"create_role(name only) -> {created}"

    role = created.get("role") or {}
    rid = role.get("id")
    assert rid is not None, f"create_role returned no id: {created}"

    by_id, verdict = run_op(recorder, "get_role_details", tier="read",
                            role_id=rid)
    assert verdict == PASS, f"get_role_details(role_id={rid}) -> {by_id}"
    assert (by_id.get("role") or {}).get("name") == name, \
        f"id {rid} does not belong to {name}: {by_id}"

    by_name, verdict = run_op(recorder, "get_role_details", tier="read",
                              name=name)
    assert verdict == PASS, f"get_role_details(name={name!r}) -> {by_name}"

    assert_ours((by_id.get("role") or {}).get("name"))
    deleted, verdict = run_op(recorder, "delete_role", tier="delete",
                              role_id=rid, confirm=True)
    assert verdict == PASS, f"delete_role(role_id={rid}) -> {deleted}"

    gone, verdict = run_op(recorder, "get_role_details", tier="negative",
                           expect="absent", role_id=rid)
    assert verdict == PASS, f"deleted role still readable: {gone}"


def test_role_delete_by_name(recorder, run_id, cleanup):
    """Delete a fixture role via the *name* branch — the asymmetry check."""
    name = fixture_name(run_id, "role2")
    cleanup.add(lambda: harness.sweep_fixtures())

    created, verdict = run_op(recorder, "create_role", tier="create",
                              name=name, description="zzz mcptest fixture")
    assert verdict == PASS, f"create_role(with description) -> {created}"

    assert_ours(name)
    deleted, verdict = run_op(recorder, "delete_role", tier="delete",
                              role_name=name, confirm=True)
    assert verdict == PASS, f"delete_role(role_name={name!r}) -> {deleted}"

    gone, verdict = run_op(recorder, "get_role_details", tier="negative",
                           expect="absent", name=name)
    assert verdict == PASS, f"deleted role still readable by name: {gone}"


def test_create_role_without_name_is_rejected(recorder):
    """Required parameter missing — the gateway must refuse, not explode."""
    result, verdict = run_op(
        recorder, "create_role", tier="negative", expect="refusal",
        substrings=("required", "missing", "name", "invalid"),
    )
    check(verdict, "create_role:missing-required", f"create_role() -> {result}")


# ==========================================================================
# 6. clone_* — absent source object, so nothing can be created
# ==========================================================================

# operation, source id param, extra required params (name params get the prefix)
CLONE_OPS: List[Tuple[str, str, Dict[str, Any]]] = [
    ("clone_application_dictionary", "source_app_dict_id", {"new_name": "@name"}),
    ("clone_authentication_source", "source_auth_source_id", {"new_name": "@name"}),
    ("clone_device_group", "source_group_id", {"new_name": "@name"}),
    ("clone_posture_policy", "source_policy_id", {"new_name": "@name"}),
    ("clone_proxy_target", "source_proxy_target_id",
     {"new_name": "@name", "new_host_name": "192.0.2.199"}),
    ("clone_radius_dictionary", "source_radius_dict_id",
     {"new_vendor_name": "@name", "new_vendor_id": 999999}),
    ("clone_tacacs_service_dictionary", "source_tacacs_dict_id",
     {"new_name": "@name"}),
]


@pytest.mark.parametrize("operation,src_param,extra", CLONE_OPS,
                         ids=[c[0] for c in CLONE_OPS])
def test_clone_from_absent_source(recorder, run_id, operation, src_param, extra):
    name = assert_ours(fixture_name(run_id, "clone"))
    params = {k: (name if v == "@name" else v) for k, v in extra.items()}
    params[src_param] = ABSENT_ID
    result, verdict = run_op(recorder, operation, tier="negative",
                             expect="absent", **params)
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    assert verdict == PASS, \
        f"{operation}({src_param}={ABSENT_ID}) -> {result}"
    assert result.get("success") is not True, \
        f"{operation} reported success cloning an absent source: {result}"


# ==========================================================================
# 7. bulk_update_* — confirmation gate and the absent-id path
# ==========================================================================

BULK_OPS: List[Tuple[str, str]] = [
    ("bulk_update_application_dictionaries", "app_dict_ids"),
    ("bulk_update_device_groups", "group_ids"),
    ("bulk_update_posture_policies", "policy_ids"),
    ("bulk_update_proxy_targets", "proxy_target_ids"),
    ("bulk_update_radius_dictionaries", "radius_dict_ids"),
    ("bulk_update_tacacs_service_dictionaries", "tacacs_dict_ids"),
]


@pytest.mark.parametrize("operation,ids_param", BULK_OPS,
                         ids=[b[0] for b in BULK_OPS])
def test_bulk_delete_requires_confirmation(recorder, operation, ids_param):
    """operation_type='delete' with ``confirm_operation`` omitted must refuse
    before the client is touched. This is the omission path that matters most
    for the destructive bulk operations."""
    result, verdict = run_op(
        recorder, operation, tier="negative", expect="refusal",
        substrings=("confirm", "confirmation"),
        operation_type="delete", operation_data={},
        **{ids_param: [ABSENT_ID]},
    )
    assert verdict == PASS, \
        f"{operation}(delete, confirm omitted) must refuse -> {result}"


@pytest.mark.parametrize("operation,ids_param", BULK_OPS,
                         ids=[b[0] for b in BULK_OPS])
def test_bulk_update_absent_ids(recorder, operation, ids_param):
    """operation_type='update' against an id that cannot exist."""
    result, verdict = run_op(
        recorder, operation, tier="negative", expect="absent",
        operation_type="update",
        operation_data={"description": "zzz-mcptest noop"},
        **{ids_param: [ABSENT_ID]},
    )
    if verdict == EXPECTED_SKIP:
        pytest.skip(f"{operation}: {expected_skip_reason(operation)}")
    # Bulk implementations legitimately report per-item failure inside a
    # success envelope; run_op's absent matching already searches the whole
    # payload, so a PASS here means the absent id was actually noticed.
    check(verdict, operation, f"{operation}(update, absent id) -> {result}")


def test_bulk_update_auth_source_timeouts_optionals_omitted(recorder):
    """Both optional timeouts omitted — pure FieldInfo-omission path."""
    result, verdict = run_op(
        recorder, "bulk_update_auth_source_timeouts", tier="negative",
        expect="refusal",
        substrings=("timeout", "provide", "no ", "nothing", "not found",
                    "404", "required"),
        auth_source_ids=[ABSENT_ID],
    )
    assert verdict == PASS, \
        f"bulk_update_auth_source_timeouts(no timeouts) -> {result}"


# ==========================================================================
# 8. configure_auth_source_* — absent source, so no real object is mutated
# ==========================================================================

CONFIGURE_OPS: List[Tuple[str, Dict[str, Any]]] = [
    # An EMPTY backup list is the only body this appliance accepts for
    # cppm_auth_source_connection_backups (see
    # test_configure_auth_source_backup_entry_shape_is_rejected below), so it
    # is what proves the absent-object 404 reaches the caller.
    ("configure_auth_source_backup_connections", {"backup_servers": []}),
    ("configure_auth_source_filters",
     {"filters": [{"filter_name": "zzz-mcptest", "filter_query": "(uid=%{x})"}]}),
    ("configure_auth_source_radius_attributes",
     {"radius_attributes": [{"attr_name": "Filter-Id", "attr_value": "zzz"}]}),
]


@pytest.mark.parametrize("operation,extra", CONFIGURE_OPS,
                         ids=[c[0] for c in CONFIGURE_OPS])
def test_configure_auth_source_absent(recorder, operation, extra):
    """FIXED: all three used to call ``_make_request(json=...)`` against a
    signature of ``(method, endpoint, data=None, params=None)``, so they raised
    TypeError and had never worked. They now issue a real PATCH and an absent
    auth source comes back as a structured 404."""
    result, verdict = run_op(recorder, operation, tier="negative",
                             expect="absent", auth_source_id=ABSENT_ID, **extra)
    assert "unexpected keyword argument" not in str(result.get("error")), result
    check(verdict, operation, f"{operation}(absent auth source) -> {result}")


def test_configure_auth_source_backup_entry_shape_is_rejected(recorder):
    """Documents a real, unresolved ClearPass 6.12.4 limitation.

    ``cppm_auth_source_connection_backups: []`` is accepted (the PATCH proceeds
    to a normal 404 for an absent id), but every non-empty entry shape probed
    against this appliance is answered 400 "syntactically incorrect":
    ``{host_name}``, ``{host_name, connection_port}``, a mapping of named
    backups, and ``{backup_host_name}``. The appliance serves no api-docs /
    swagger endpoint, so the sub-schema could not be determined.

    What this test pins is that the failure is now the APPLIANCE's structured
    400 surfaced cleanly — not a Python TypeError from the old ``json=`` call.
    """
    result, verdict = run_op(
        recorder, "configure_auth_source_backup_connections", tier="negative",
        expect="absent", auth_source_id=ABSENT_ID,
        backup_servers=[{"hostname": "192.0.2.200", "port": 389}],
    )
    assert result.get("success") is False, result
    text = str(result.get("error"))
    assert "unexpected keyword argument" not in text, result
    assert "Traceback" not in json.dumps(result, default=str), result
    assert "400" in text, result
    assert verdict != PASS  # the 400 is not an absent-object answer


# ==========================================================================
# 9. enable/disable — absent target only
# ==========================================================================


def test_enable_disable_configuration_service_confirmation_gate(recorder, run_id):
    """``confirm`` omitted — the pure omission path for this guard."""
    name = assert_ours(fixture_name(run_id, "svc"))
    result, verdict = run_op(
        recorder, "enable_disable_configuration_service", tier="negative",
        expect="refusal", substrings=("confirm",),
        action="enable", service_name=name,
    )
    assert verdict == PASS, \
        f"enable_disable_configuration_service(confirm omitted) -> {result}"


def test_enable_disable_configuration_service_absent(recorder, run_id):
    name = assert_ours(fixture_name(run_id, "svc"))
    result, verdict = run_op(
        recorder, "enable_disable_configuration_service", tier="negative",
        expect="absent", action="enable", service_name=name, confirm=True,
    )
    check(verdict, "enable_disable_configuration_service:absent",
          f"enable_disable_configuration_service(absent) -> {result}")


def test_enable_disable_configuration_service_bad_action(recorder, run_id):
    name = assert_ours(fixture_name(run_id, "svc"))
    result, verdict = run_op(
        recorder, "enable_disable_configuration_service", tier="negative",
        expect="refusal", substrings=("action", "enable", "invalid"),
        action="zzz-not-an-action", service_name=name,
    )
    assert verdict == PASS, \
        f"enable_disable_configuration_service(bad action) -> {result}"


def test_enable_disable_radius_dictionary_absent(recorder, run_id):
    name = assert_ours(fixture_name(run_id, "vendor"))
    result, verdict = run_op(
        recorder, "enable_disable_radius_dictionary", tier="negative",
        expect="absent", action="enable", vendor_name=name,
    )
    check(verdict, "enable_disable_radius_dictionary:absent",
          f"enable_disable_radius_dictionary(absent) -> {result}")


def test_enable_disable_radius_dictionary_no_identifier(recorder):
    result, verdict = run_op(
        recorder, "enable_disable_radius_dictionary", tier="negative",
        expect="refusal", substrings=("must be provided", "either", "missing"),
        action="enable",
    )
    assert verdict == PASS, \
        f"enable_disable_radius_dictionary(no identifier) -> {result}"


# ==========================================================================
# 10. template creators, posture deployment, compliance assessment
# ==========================================================================


def test_create_device_group_from_unknown_template(recorder, run_id):
    """Unknown template short-circuits before any create — safe to dispatch."""
    name = assert_ours(fixture_name(run_id, "dg"))
    result, verdict = run_op(
        recorder, "create_device_group_from_template", tier="negative",
        expect="absent", template_name="zzz-mcptest-no-such-template",
        group_name=name, device_values="192.0.2.0/24",
    )
    assert verdict == PASS, f"create_device_group_from_template -> {result}"
    assert result.get("available_templates"), \
        "unknown-template refusal should list the available templates"


def test_create_posture_policy_from_unknown_template(recorder, run_id):
    name = assert_ours(fixture_name(run_id, "pp"))
    result, verdict = run_op(
        recorder, "create_posture_policy_from_template", tier="negative",
        expect="absent", template_name="zzz-mcptest-no-such-template",
        policy_name=name, target_os="Windows",
    )
    assert verdict == PASS, f"create_posture_policy_from_template -> {result}"
    assert result.get("available_templates"), \
        "unknown-template refusal should list the available templates"


def test_deploy_posture_policies_absent_policies(recorder, run_id):
    """test_mode / rollback_enabled omitted; the policy ids cannot exist."""
    name = assert_ours(fixture_name(run_id, "deploy"))
    result, verdict = run_op(
        recorder, "deploy_posture_policies", tier="negative", expect="absent",
        deployment_name=name, policy_ids=[ABSENT_ID],
        target_groups=["zzz-mcptest-nonexistent-group"],
    )
    assert verdict == PASS, f"deploy_posture_policies(absent) -> {result}"


def test_assess_endpoint_compliance_absent_policy(recorder):
    result, verdict = run_op(
        recorder, "assess_endpoint_compliance", tier="negative", expect="absent",
        policy_id=ABSENT_ID,
        endpoint_attributes={"mac_address": "00:00:5e:00:53:00", "os": "Windows"},
    )
    assert verdict == PASS, f"assess_endpoint_compliance(absent) -> {result}"


def test_assess_endpoint_compliance_real_policy(recorder, catalog):
    got = pick(catalog, "list_posture_policies")
    if not got or got[0] is None:
        record_blocked(recorder, "assess_endpoint_compliance",
                       "no posture policy exists to assess against")
        pytest.skip("no posture policies on the appliance")
    result, verdict = run_op(
        recorder, "assess_endpoint_compliance", tier="read",
        policy_id=got[0],
        endpoint_attributes={"mac_address": "00:00:5e:00:53:00", "os": "Windows"},
    )
    assert verdict in (PASS, EXPECTED_SKIP), \
        f"assess_endpoint_compliance(policy {got[0]}) -> {result}"


# ==========================================================================
# 11. Operations that cannot be exercised safely — recorded, not skipped silently
# ==========================================================================

BLOCKED_CREATES: Dict[str, str] = {
    "create_application_dictionary":
        "application dictionaries are not a sweepable family; a created "
        "fixture could not be guaranteed cleaned up",
    "create_authentication_method":
        "authentication methods are not a sweepable family",
    "create_authentication_source":
        "authentication sources are not a sweepable family and are referenced "
        "by live services",
    "create_configuration_service":
        "configuration services are not a sweepable family and participate in "
        "live policy evaluation ordering",
    "create_enforcement_policy":
        "enforcement policies are not a sweepable family and are referenced by "
        "the 19 live configuration services",
    "create_network_device_group":
        "delete_network_device_group is denylisted, so a created device group "
        "could never be removed",
    "create_posture_policy":
        "posture policies are not a sweepable family",
    "create_proxy_target":
        "proxy target endpoints have no pyclearpass implementation",
    "create_radius_dictionary":
        "RADIUS dictionaries are not a sweepable family and are global "
        "vendor-attribute definitions",
    "create_role_mapping":
        "role mappings are not a sweepable family and are referenced by live "
        "services",
    "create_tacacs_service_dictionary":
        "TACACS service dictionaries are not a sweepable family",
}


@pytest.mark.parametrize("operation", sorted(BLOCKED_CREATES))
def test_unsafe_create_is_blocked(recorder, operation):
    """Recorded as BLOCKED with a reason rather than improvised."""
    record_blocked(recorder, operation, BLOCKED_CREATES[operation])


def test_summary(recorder):
    """Print the scope tally; always last alphabetically within the module."""
    print(f"\n[policy_elements-a] verdict counts: {recorder.counts}")
    for note in NOTES:
        print(f"[policy_elements-a] note: {note}")
