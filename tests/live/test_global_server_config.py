"""Live validation of the ``global_server_config`` domain (58 operations).

Scope note: the domain grew to 86 operations in the full-SDK-coverage
expansion. This module still owns exactly its original 58; the 28 added
operations are covered by ``test_global_config_expansion_live.py`` and are
listed in ``EXPANSION_OPERATIONS`` at the bottom of this file so the coverage
guard can exclude them.

This is the most dangerous domain in the catalogue — admin users, privileges,
licences, cluster configuration, backup servers, Policy Manager zones, SNMP and
messaging. **Nothing here creates, updates or deletes anything on the
appliance.** The only families safe to create fixtures in (guest users,
enforcement profiles, roles) are not in this domain, so every operation is
either

* validated read-only,
* validated only up to its *local* refusal guard (confirmation / clarification),
  which returns before any client call is made, or
* recorded as BLOCKED and never dispatched.

Calling style: optional parameters are OMITTED by default (that is the path the
``FieldInfo`` bug lived on); the fully-specified path is exercised second where
it is meaningful.

Harness note
------------
``harness.invoke(name, **params)`` cannot dispatch an operation that has its own
parameter called ``name`` — the operation's ``name`` collides with the
harness's positional ``name`` argument and Python raises
``TypeError: invoke() got multiple values for argument 'name'``. Six operations
in this domain take a ``name`` parameter, so this module dispatches through a
local params-dict wrapper (``_invoke``) that still goes through
``src.tools.gateway.invoke_operation`` and still honours the denylist. Reported
as a harness defect; not fixed here.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, FAIL, PASS, classify

DOMAIN = "global_server_config"


# --------------------------------------------------------------------------
# Dispatch wrapper (params as a dict — see module docstring)
# --------------------------------------------------------------------------


async def _invoke(operation: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if is_denylisted(operation):
        raise DenylistedOperation(operation)
    import src.main  # noqa: F401  (registers all 757 operations)
    from src.tools.gateway import invoke_operation

    result = await invoke_operation(harness.StubContext(), operation, params or None)
    if not isinstance(result, dict):
        return {"success": False, "error": f"non-dict result: {type(result).__name__}",
                "message": "Operation returned a non-dict payload"}
    return result


async def _run(recorder, operation: str, params: Optional[Dict[str, Any]] = None,
               tier: str = "read", expect_absent: bool = False,
               verdict: Optional[str] = None) -> Dict[str, Any]:
    """Invoke + classify + record. ``verdict`` overrides the classification for
    cases the generic classifier cannot express (a structured local refusal is a
    legitimately correct outcome, but it carries ``success: False``)."""
    start = time.perf_counter()
    result = await _invoke(operation, params)
    duration = (time.perf_counter() - start) * 1000.0
    computed = classify(result, operation, expect_absent=expect_absent)
    final = verdict or computed
    err = None if final == PASS else (
        " ".join(str(result.get(k, "")) for k in ("error", "message")).strip() or None
    )
    recorder.record(operation, DOMAIN, tier, final, params or {}, err, duration)
    return result


def _no_crash(result: Dict[str, Any], operation: str) -> None:
    """A known environment limit must present as a structured error, never as a
    Python-level explosion."""
    text = str(result)
    for marker in ("FieldInfo", "Traceback (most recent call last)", "annotation=",
                   "TypeError:", "AttributeError:", "UnboundLocalError",
                   "cannot access local variable"):
        assert marker not in text, f"{operation}: crash marker {marker!r} in {result}"


def _is_clarification(result: Dict[str, Any]) -> bool:
    return (result.get("success") is False
            and result.get("error_type") == "clarification_needed"
            and bool(result.get("question")))


# --------------------------------------------------------------------------
# 1. List operations — every optional parameter omitted
# --------------------------------------------------------------------------

LIST_OPERATIONS = [
    "list_admin_privileges",
    "list_admin_users",
    "list_application_licenses",
    "list_attributes",
    "list_data_filters",
    "list_file_backup_servers",
    "list_operator_profiles",
    "list_server_policy_manager_zones",
    "list_snmp_trap_receivers",
]


@pytest.mark.parametrize("operation", LIST_OPERATIONS)
def test_list_operations_with_all_optionals_omitted(run_async, recorder, operation):
    """The omission path: no parameters at all."""
    result = run_async(_run(recorder, operation))
    _no_crash(result, operation)
    assert classify(result, operation) == PASS, f"{operation} (no params) -> {result}"


@pytest.mark.parametrize("operation,params", [
    ("list_admin_users", {"limit": 1, "offset": 0, "calculate_count": True}),
    ("list_admin_privileges", {"limit": 1, "sort": "+id"}),
    ("list_attributes", {"filter_str": '{"entity_name":"Device"}', "limit": 2}),
    ("list_data_filters", {"limit": 5, "calculate_count": True}),
    ("list_operator_profiles", {"limit": 5, "offset": 0}),
    ("list_snmp_trap_receivers", {"limit": 5}),
    ("list_file_backup_servers", {"limit": 5}),
])
def test_list_operations_with_pagination_and_filters(run_async, recorder, operation, params):
    """Second pass with realistic optional parameters supplied."""
    result = run_async(_run(recorder, operation, params))
    _no_crash(result, operation)
    assert classify(result, operation) == PASS, f"{operation}({params}) -> {result}"


# --------------------------------------------------------------------------
# 2. Singleton read operations (no parameters at all)
# --------------------------------------------------------------------------


def test_get_cluster_parameters(run_async, recorder):
    result = run_async(_run(recorder, "get_cluster_parameters"))
    _no_crash(result, "get_cluster_parameters")
    assert classify(result, "get_cluster_parameters") == PASS, result
    assert isinstance(result.get("cluster_parameters"), dict)


def test_get_oauth_all_privileges_omitted_and_specified(run_async, recorder):
    omitted = run_async(_run(recorder, "get_oauth_all_privileges"))
    _no_crash(omitted, "get_oauth_all_privileges")
    assert classify(omitted, "get_oauth_all_privileges") == PASS, omitted

    for fmt in ("list", "tree"):
        r = run_async(_run(recorder, "get_oauth_all_privileges", {"format_type": fmt}))
        _no_crash(r, "get_oauth_all_privileges")
        assert classify(r, "get_oauth_all_privileges") == PASS, f"format_type={fmt} -> {r}"

    # Negative: the appliance only accepts list|tree; an invalid value must come
    # back as a structured 422, not an exception.
    bad = run_async(_run(recorder, "get_oauth_all_privileges", {"format_type": "json"},
                         tier="negative", verdict=PASS))
    _no_crash(bad, "get_oauth_all_privileges")
    assert bad.get("status_code") == 422, bad


def test_get_messaging_setup_unconfigured(run_async, recorder):
    """Messaging is not configured on this appliance; a structured 404 saying so
    is the legitimately correct answer, not a failure."""
    result = run_async(_run(recorder, "get_messaging_setup",
                            expect_absent=True, verdict=PASS))
    _no_crash(result, "get_messaging_setup")
    if result.get("success") is not True:
        assert result.get("status_code") == 404, result
        assert "not configured" in str(result.get("error")).lower(), result


# --------------------------------------------------------------------------
# 3. Known 6.12.4 limitations — asserted as *known* skips
# --------------------------------------------------------------------------


# 2026-07-31: the two tests that lived here — asserting a known 404 for
# `get_admin_password_policy` / `get_local_user_password_policy` and for
# `get_application_license_summary` — were removed together with the operations
# they exercised. curl against the appliance showed the 404s came from the
# wrong (hyphenated) resource paths, not from a missing feature:
# /admin-user/password-policy, /local-user/password-policy and
# /application-license/summary all answer 200 on this 6.12.4 appliance. The
# working operations against those paths are covered in
# test_global_config_expansion_live.py.


# --------------------------------------------------------------------------
# 4. Detail reads against real, pre-existing objects (never mutated)
# --------------------------------------------------------------------------


def test_get_admin_privilege_details_by_id_and_name(run_async, recorder):
    listing = run_async(_run(recorder, "list_admin_privileges"))
    assert classify(listing, "list_admin_privileges") == PASS, listing
    first = listing["admin_privileges"][0]

    by_id = run_async(_run(recorder, "get_admin_privilege_details",
                           {"admin_privilege_id": first["id"]}))
    _no_crash(by_id, "get_admin_privilege_details")
    assert classify(by_id, "get_admin_privilege_details") == PASS, by_id

    by_name = run_async(_run(recorder, "get_admin_privilege_details",
                             {"name": first["name"]}))
    _no_crash(by_name, "get_admin_privilege_details")
    assert classify(by_name, "get_admin_privilege_details") == PASS, by_name


def test_get_admin_user_details_by_id_and_name(run_async, recorder):
    """Read-only against the two pre-existing admin users. Neither is mutated."""
    listing = run_async(_run(recorder, "list_admin_users"))
    assert classify(listing, "list_admin_users") == PASS, listing
    items = listing["data"]["_embedded"]["items"]
    assert items, "no admin users returned"
    first = items[0]

    by_id = run_async(_run(recorder, "get_admin_user_details", {"user_id": first["id"]}))
    _no_crash(by_id, "get_admin_user_details")
    assert classify(by_id, "get_admin_user_details") == PASS, by_id

    by_name = run_async(_run(recorder, "get_admin_user_details",
                             {"user_name": first["user_id"]}))
    _no_crash(by_name, "get_admin_user_details")
    assert classify(by_name, "get_admin_user_details") == PASS, by_name


def test_get_attribute_details_by_id_and_by_entity_name(run_async, recorder):
    listing = run_async(_run(recorder, "list_attributes"))
    first = listing["data"]["_embedded"]["items"][0]

    by_id = run_async(_run(recorder, "get_attribute_details",
                           {"attribute_id": first["id"]}))
    _no_crash(by_id, "get_attribute_details")
    assert classify(by_id, "get_attribute_details") == PASS, by_id

    by_pair = run_async(_run(recorder, "get_attribute_details",
                             {"entity_name": first["entity_name"], "name": first["name"]}))
    _no_crash(by_pair, "get_attribute_details")
    assert classify(by_pair, "get_attribute_details") == PASS, by_pair


def test_get_data_filter_details_by_id_and_name(run_async, recorder):
    listing = run_async(_run(recorder, "list_data_filters"))
    first = listing["data"]["_embedded"]["items"][0]

    by_id = run_async(_run(recorder, "get_data_filter_details",
                           {"data_filter_id": first["id"]}))
    _no_crash(by_id, "get_data_filter_details")
    assert classify(by_id, "get_data_filter_details") == PASS, by_id

    by_name = run_async(_run(recorder, "get_data_filter_details", {"name": first["name"]}))
    _no_crash(by_name, "get_data_filter_details")
    assert classify(by_name, "get_data_filter_details") == PASS, by_name


def test_get_operator_profile_details_by_id_and_name(run_async, recorder):
    listing = run_async(_run(recorder, "list_operator_profiles"))
    first = listing["data"]["_embedded"]["items"][0]

    by_id = run_async(_run(recorder, "get_operator_profile_details",
                           {"profile_id": first["id"]}))
    _no_crash(by_id, "get_operator_profile_details")
    assert classify(by_id, "get_operator_profile_details") == PASS, by_id

    by_name = run_async(_run(recorder, "get_operator_profile_details",
                             {"name": first["name"]}))
    _no_crash(by_name, "get_operator_profile_details")
    assert classify(by_name, "get_operator_profile_details") == PASS, by_name


def test_get_application_license_details_by_id(run_async, recorder):
    listing = run_async(_run(recorder, "list_application_licenses"))
    assert classify(listing, "list_application_licenses") == PASS, listing
    first = listing["application_licenses"][0]

    by_id = run_async(_run(recorder, "get_application_license_details",
                           {"license_id": first["id"]}))
    _no_crash(by_id, "get_application_license_details")
    assert classify(by_id, "get_application_license_details") == PASS, by_id


def test_get_server_policy_manager_zone_details_by_name(run_async, recorder):
    listing = run_async(_run(recorder, "list_server_policy_manager_zones"))
    assert classify(listing, "list_server_policy_manager_zones") == PASS, listing
    first = listing["server_policy_manager_zones"][0]

    by_name = run_async(_run(recorder, "get_server_policy_manager_zone_details",
                             {"name": first["zone_name"]}))
    _no_crash(by_name, "get_server_policy_manager_zone_details")
    assert classify(by_name, "get_server_policy_manager_zone_details") == PASS, by_name


def test_get_file_backup_server_details_none_configured(run_async, recorder):
    """No file backup servers exist on this appliance, so the only read-only
    validation available is the absent-object path (structured 404)."""
    listing = run_async(_run(recorder, "list_file_backup_servers"))
    assert classify(listing, "list_file_backup_servers") == PASS, listing
    assert listing.get("file_backup_servers") == [], \
        "a file backup server now exists; extend this test to read it by id"

    absent = run_async(_run(recorder, "get_file_backup_server_details",
                            {"file_backup_server_id": 999999},
                            tier="negative", expect_absent=True))
    _no_crash(absent, "get_file_backup_server_details")
    assert classify(absent, "get_file_backup_server_details", expect_absent=True) == PASS, absent
    assert absent.get("status_code") == 404, absent


# --------------------------------------------------------------------------
# 5. Negative reads — absent objects must return a structured 404
# --------------------------------------------------------------------------


@pytest.mark.parametrize("operation,params", [
    ("get_admin_privilege_details", {"admin_privilege_id": 999999}),
    ("get_application_license_details", {"license_id": 999999}),
    ("get_server_policy_manager_zone_details", {"zone_id": "999999"}),
])
def test_absent_object_reads_return_structured_404(run_async, recorder, operation, params):
    result = run_async(_run(recorder, operation, params, tier="negative",
                            expect_absent=True))
    _no_crash(result, operation)
    assert classify(result, operation, expect_absent=True) == PASS, result
    assert result.get("status_code") == 404, result


# (operation, params, human label the fixed handler must be able to render)
_HOISTED_IDENTIFIER_READS = [
    ("get_admin_user_details", {"user_id": 999999}, "ID 999999"),
    ("get_attribute_details", {"attribute_id": 999999}, "ID 999999"),
    ("get_data_filter_details", {"data_filter_id": 999999}, "ID 999999"),
    ("get_operator_profile_details", {"profile_id": 999999}, "ID 999999"),
    ("get_snmp_trap_receiver_details", {"snmp_trap_receiver_id": 999999}, "ID 999999"),
]


@pytest.mark.parametrize("operation,params,label",
                         _HOISTED_IDENTIFIER_READS,
                         ids=[o for o, _, _ in _HOISTED_IDENTIFIER_READS])
def test_absent_object_reads_must_not_raise_unboundlocalerror(run_async, recorder,
                                                              operation, params, label):
    """FIXED: these five operations used to assign their ``identifier`` log
    string *after* the awaited client call and then reference it from the
    ``except ClearPassAPIError`` handler. Any API error (a 404 on an absent
    object was the easy repro) therefore raised UnboundLocalError, which escaped
    through invoke_operation's generic catch as
    ``cannot access local variable 'identifier'`` — destroying the real error.

    The assignment is now hoisted above the ``try``. This asserts both halves of
    the fix: no UnboundLocalError, and the handler successfully renders the
    identifier it was always meant to render.
    """
    result = run_async(_run(recorder, operation, params, tier="negative",
                            expect_absent=True))
    _no_crash(result, operation)
    blob = str(result)
    assert "not associated with a value" not in blob, \
        f"{operation} still raises UnboundLocalError: {result}"
    assert "identifier" not in str(result.get("error", "")), result
    assert label in blob, \
        f"{operation} lost its identifier label in the error path: {result}"


@pytest.mark.parametrize("operation,params", [
    ("get_admin_user_details", {"user_id": 999999}),
    ("get_attribute_details", {"attribute_id": 999999}),
    ("get_data_filter_details", {"data_filter_id": 999999}),
    ("get_operator_profile_details", {"profile_id": 999999}),
])
def test_hoisted_identifier_reads_now_classify_as_structured_404(run_async, recorder,
                                                                operation, params):
    """With the handler no longer exploding, the real appliance response is
    visible: a structured 404 for an absent object.

    ``get_snmp_trap_receiver_details`` is deliberately excluded — see
    ``test_snmp_trap_receiver_absent_id_is_a_422_on_this_appliance``.
    """
    result = run_async(_run(recorder, operation, params, tier="negative",
                            expect_absent=True))
    _no_crash(result, operation)
    assert classify(result, operation, expect_absent=True) == PASS, result
    assert result.get("status_code") == 404, result


def test_snmp_trap_receiver_absent_id_is_a_422_on_this_appliance(run_async, recorder):
    """APPLIANCE BEHAVIOUR (not a code defect), only visible once the
    UnboundLocalError was fixed: ``GET snmp-trap-receiver/<id>`` answers
    ``422 Unprocessable Entity`` (``validation_messages: [null]``) for an id that
    does not exist, where every sibling family answers 404. Verified directly
    against the appliance for ids 999, 99999 and 999999; the *name* branch
    (``snmp-trap-receiver/name/<name>``) does return a proper 404.

    Recorded so the 422 is not mistaken for a regression in the operation.
    """
    result = run_async(_run(recorder, "get_snmp_trap_receiver_details",
                            {"snmp_trap_receiver_id": 999999},
                            tier="negative", verdict=PASS))
    _no_crash(result, "get_snmp_trap_receiver_details")
    assert result.get("status_code") == 422, result
    assert "ID 999999" in str(result), result


def test_get_snmp_trap_receiver_details_absent_by_name(run_async, recorder):
    """The name branch of the same operation — a structured 404, and the
    identifier label survives the (formerly UnboundLocalError) error path. No
    receivers exist on this appliance, so this is the only clean 404 path."""
    listing = run_async(_run(recorder, "list_snmp_trap_receivers"))
    assert listing["data"]["_embedded"]["items"] == [], \
        "an SNMP trap receiver now exists; extend this test to read it"

    result = run_async(_run(recorder, "get_snmp_trap_receiver_details",
                            {"name": "zzz-does-not-exist"},
                            tier="negative", expect_absent=True))
    _no_crash(result, "get_snmp_trap_receiver_details")
    assert classify(result, "get_snmp_trap_receiver_details", expect_absent=True) == PASS, result
    assert "name 'zzz-does-not-exist'" in str(result), result


def test_zone_id_zero_is_a_valid_identifier(run_async, recorder):
    """FIXED: ``get_server_policy_manager_zone_details`` used to guard with
    ``if not zone_id``, so the integer 0 — the id of the *only* zone on this
    appliance ("default") — was rejected as a missing identifier. The string
    "0" always worked, proving the lookup itself was fine; the guard now uses
    ``is None``, and ``zone_id`` is annotated ``Optional[Union[int, str]]``
    because the API itself returns an int.

    Both spellings must now reach the appliance and return the same zone.
    """
    as_string = run_async(_run(recorder, "get_server_policy_manager_zone_details",
                               {"zone_id": "0"}))
    assert classify(as_string, "get_server_policy_manager_zone_details") == PASS, as_string

    as_int = run_async(_run(recorder, "get_server_policy_manager_zone_details",
                            {"zone_id": 0}))
    _no_crash(as_int, "get_server_policy_manager_zone_details")
    assert not _is_clarification(as_int), \
        f"zone_id=0 was rejected as a missing identifier: {as_int}"
    assert classify(as_int, "get_server_policy_manager_zone_details") == PASS, as_int
    assert as_int.get("server_policy_manager_zone_details") == \
        as_string.get("server_policy_manager_zone_details"), \
        f"zone_id=0 and zone_id='0' resolved differently: {as_int} vs {as_string}"


# --------------------------------------------------------------------------
# 6. Clarification guards on identifier-less calls (no network, no mutation)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("operation", [
    "get_admin_privilege_details",
    "get_admin_user_details",
    "get_attribute_details",
    "get_data_filter_details",
    "get_operator_profile_details",
    "get_server_policy_manager_zone_details",
    "get_snmp_trap_receiver_details",
    "get_file_backup_server_details",
])
def test_identifier_less_read_returns_structured_clarification(run_async, recorder, operation):
    """Called with every parameter omitted, a lookup operation must ask for an
    identifier rather than explode. This is a purely local path."""
    result = run_async(_run(recorder, operation, tier="negative", verdict=PASS))
    _no_crash(result, operation)
    assert _is_clarification(result), f"{operation}() -> {result}"


@pytest.mark.parametrize("operation", [
    "update_file_backup_server",
    "update_server_policy_manager_zone",
])
def test_identifier_less_update_refuses_locally(run_async, recorder, operation):
    """MUTATING operation invoked with everything omitted. Safe because the
    clarification guard returns before any client call is made — verified in
    source. Nothing is written.

    The destructive path of these operations is deliberately NOT exercised
    (see the BLOCKED list in the phase report).
    """
    result = run_async(_run(recorder, operation, tier="negative", verdict=PASS))
    _no_crash(result, operation)
    assert _is_clarification(result), f"{operation}() -> {result}"


@pytest.mark.parametrize("operation", [
    "update_admin_privilege",
    "update_admin_user",
    "update_attribute",
    "update_data_filter",
    "update_operator_profile",
    "update_snmp_trap_receiver",
])
def test_required_param_omission_returns_structured_error_not_typeerror(
        run_async, recorder, operation):
    """BUG: these operations declare their identifier as a required
    ``Field(...)`` parameter. The gateway does not validate required
    parameters, so omitting one produces a raw
    ``TypeError: <op>() missing required argument: '<x>'`` that surfaces through
    invoke_operation's generic catch as an unstructured error string.

    Safe: the call never reaches the ClearPass client, so nothing is written.
    Fails today; must pass once the gateway validates required parameters.
    """
    result = run_async(_run(recorder, operation, tier="negative"))
    assert "missing required argument" not in str(result), \
        f"{operation}() leaked a raw TypeError: {result}"
    _no_crash(result, operation)


def test_get_application_license_details_required_param_omission(run_async, recorder):
    """Same required-parameter gap on a read operation (``license_id``)."""
    result = run_async(_run(recorder, "get_application_license_details",
                            tier="negative"))
    assert "missing required argument" not in str(result), \
        f"get_application_license_details() leaked a raw TypeError: {result}"
    _no_crash(result, "get_application_license_details")


# --------------------------------------------------------------------------
# 7. Deletion confirmation guards (local refusal, nothing dispatched)
# --------------------------------------------------------------------------

# Targets are deliberately non-existent ids: if the confirmation guard were ever
# to regress (e.g. `confirm` arriving as a truthy FieldInfo), the call would hit
# an object that does not exist rather than a real one.
_DELETE_GUARDS = [
    ("delete_admin_privilege", {"admin_privilege_id": 999999}),
    ("delete_attribute", {"attribute_id": 999999}),
    ("delete_data_filter", {"data_filter_id": 999999}),
    ("delete_operator_profile", {"profile_id": 999999}),
    ("delete_snmp_trap_receiver", {"snmp_trap_receiver_id": 999999}),
    ("delete_messaging_setup", {}),
]


@pytest.mark.parametrize("operation,params", _DELETE_GUARDS)
def test_delete_requires_explicit_confirmation(run_async, recorder, operation, params):
    """``confirm`` omitted must produce a structured refusal *before* any client
    call. This is also the single most valuable FieldInfo assertion in the
    domain: if an omitted ``confirm`` arrived as a truthy ``FieldInfo`` the
    guard would fall through and the delete would proceed.

    The actual deletion path is never exercised — see BLOCKED in the report.
    """
    result = run_async(_run(recorder, operation, params, tier="negative", verdict=PASS))
    _no_crash(result, operation)
    assert _is_clarification(result), \
        f"{operation} did not refuse without confirm=True: {result}"
    assert "confirm" in str(result).lower(), result


# --------------------------------------------------------------------------
# 8. Denylist — never dispatched
# --------------------------------------------------------------------------

DOMAIN_DENYLISTED = [
    "activate_application_license_online",
    "activate_application_license_offline",
    "delete_admin_user",
    "delete_application_license",
    "delete_file_backup_server",
    "delete_server_policy_manager_zone",
]


@pytest.mark.parametrize("operation", DOMAIN_DENYLISTED)
def test_denylisted_domain_operations_never_dispatch(run_async, recorder, operation):
    assert operation in DENYLIST, f"{operation} must stay on the denylist"
    with pytest.raises(DenylistedOperation):
        run_async(_invoke(operation))
    recorder.record(operation, DOMAIN, "denylist", EXPECTED_SKIP, {},
                    f"DENYLISTED: {DENYLIST[operation]}", 0.0)


# --------------------------------------------------------------------------
# 9. BLOCKED inventory — recorded, never dispatched
# --------------------------------------------------------------------------

BLOCKED: Dict[str, str] = {
    # -- creates: no safe fixture family exists in this domain -----------------
    "create_admin_privilege": "Creates a real admin privilege; no sweepable family and no delete path that is safe to rely on.",
    "create_admin_user": "Creates a real administrative account; delete_admin_user is denylisted so it could not be removed.",
    "create_application_license": "Installs a real vendor licence onto the appliance.",
    "create_attribute": "Creates a global attribute definition referenced by policy; no sweep support.",
    "create_data_filter": "Creates a global data filter used by Insight/session views; no sweep support.",
    "create_file_backup_server": "Writes real backup-target configuration; delete_file_backup_server is denylisted.",
    "create_messaging_setup": "Configures the appliance SMTP relay — a live outbound-messaging path.",
    "create_operator_profile": "Creates a real operator profile granting GUI privileges; no sweep support.",
    "create_server_policy_manager_zone": "Cluster-wide topology change; delete_server_policy_manager_zone is denylisted.",
    "create_snmp_trap_receiver": "Configures a real SNMP trap destination.",
    # -- writes with no local guard: they reach the appliance immediately ------
    "update_cluster_parameters": "Rewrites cluster-wide parameters (admin session timeouts, TACACS servers). No read-only path and no safe value to write.",
    "update_application_license": "Rewrites a real licence entry; recovery may require vendor action.",
    # -- denylisted -----------------------------------------------------------
    "activate_application_license_online": DENYLIST["activate_application_license_online"],
    "activate_application_license_offline": DENYLIST["activate_application_license_offline"],
    "delete_admin_user": DENYLIST["delete_admin_user"],
    "delete_application_license": DENYLIST["delete_application_license"],
    "delete_file_backup_server": DENYLIST["delete_file_backup_server"],
    "delete_server_policy_manager_zone": DENYLIST["delete_server_policy_manager_zone"],
}


def test_blocked_operations_are_recorded_and_not_dispatched(recorder):
    """Record every operation this phase refused to exercise, with its reason."""
    import src.main  # noqa: F401
    from src.registry import registry

    for operation, reason in BLOCKED.items():
        assert registry.get(operation) is not None, f"unknown operation {operation}"
        recorder.record(operation, DOMAIN, "blocked", "BLOCKED", {}, reason, 0.0)


# The 28 operations added to this domain by the full-SDK-coverage expansion.
# They are exercised (or BLOCKED) by ``test_global_config_expansion_live.py``,
# which owns them and pins the same list; this module deliberately keeps its
# original 58-operation scope and excludes them here rather than pretending to
# cover them.
EXPANSION_OPERATIONS: List[str] = [
    "create_clearpass_portal",
    "delete_admin_privilege_by_name",
    "delete_admin_user_by_user_id",
    "delete_attribute_by_entity_and_name",
    "delete_data_filter_by_name",
    "delete_operator_profile_by_name",
    "delete_snmp_trap_receiver_by_name",
    "get_admin_user_password_policy",
    "get_application_license_summary_detail",
    "get_clearpass_portal",
    "get_local_user_password_policy_settings",
    "replace_admin_privilege_by_name",
    "replace_admin_user_by_user_id",
    "replace_admin_user_password_policy",
    "replace_attribute_by_entity_and_name",
    "replace_data_filter_by_name",
    "replace_local_user_password_policy_settings",
    "replace_operator_profile_by_name",
    "replace_snmp_trap_receiver_by_name",
    "sync_cluster_database",
    "update_admin_privilege_by_name",
    "update_admin_user_by_user_id",
    "update_admin_user_password_policy",
    "update_attribute_by_entity_and_name",
    "update_data_filter_by_name",
    "update_local_user_password_policy_settings",
    "update_operator_profile_by_name",
    "update_snmp_trap_receiver_by_name",
]


def test_domain_coverage_accounts_for_every_operation(recorder):
    """Every one of this module's 58 operations must be exercised or BLOCKED.

    The domain itself now holds 81 operations (86 after the expansion, minus the
    5 dead hyphen-path operations removed on 2026-07-31). The 28 in ``EXPANSION_OPERATIONS``
    belong to ``test_global_config_expansion_live.py``; anything *else* that
    appears in the domain lands in this module's scope and must be accounted
    for here, so a future addition cannot slip through unnoticed.
    """
    import src.main  # noqa: F401
    from src.registry import registry

    unknown = [n for n in EXPANSION_OPERATIONS if registry.get(n) is None]
    assert not unknown, f"unknown operations: {unknown}"

    all_ops = ({s.name for s in registry.search(domain=DOMAIN)}
               - set(EXPANSION_OPERATIONS))
    # 58 originally, minus get/update_admin_password_policy,
    # get/update_local_user_password_policy and get_application_license_summary
    # (removed 2026-07-31: their hyphenated resource paths 404 on 6.12.4 and
    # working slash-path siblings already existed).
    assert len(all_ops) == 53, f"expected 53 operations, found {len(all_ops)}"

    recorded = set()
    with recorder.path.open(encoding="utf-8") as fh:
        import json
        for line in fh:
            rec = json.loads(line)
            if rec.get("domain") == DOMAIN:
                recorded.add(rec["operation"])

    missing = sorted(all_ops - recorded - set(BLOCKED))
    assert not missing, f"operations neither exercised nor BLOCKED: {missing}"
