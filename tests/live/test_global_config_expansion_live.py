"""Live validation of the 28 operations added to ``global_server_config``.

The domain grew from 58 to 86 operations in this branch. ``test_global_server_config.py``
covers the original 58 and is not touched here; this module covers exactly the
28 new ones:

* **by-name PATCH / PUT / DELETE** for five families — admin-privilege,
  attribute, data-filter, operator-profile, snmp-trap-receiver (15 ops). Each
  gets a *real* fixture lifecycle: the object is created with the pre-existing
  create operation, mutated and deleted through the new by-name operations, and
  cleaned up whatever happens. The original module recorded these creates as
  BLOCKED because no delete path could be relied on; the new
  ``delete_*_by_name`` operations are that path, which is what makes the
  lifecycle safe now.
* **admin-user by-user-id writes** (3 ops) — BLOCKED. The lifecycle would need
  a fixture admin user, and ``create_admin_user`` is itself BLOCKED in the
  existing module (``delete_admin_user`` is denylisted, so an account created
  here could not be removed). Mutating one of the two *real* admin accounts
  risks administrative lockout.
* **password policies** (6 ops) — GET both resources; the two PATCHes are run
  under **strict read-restore**: read the live policy, then write one field back
  at exactly the value it already holds, so the request is provably a no-op.
  The two PUTs are BLOCKED: a full replacement resets every omitted field, and
  a no-op PUT cannot be proven from the read alone.
* **clearpass-portal** (2 ops) — GET yes, POST BLOCKED (global portal state).
* **application-license/summary** (1 op) — GET.
* **cluster/db-sync** (1 op) — BLOCKED and never dispatched: a cluster-wide,
  disruptive operation. It is being added to the hard denylist separately;
  this module does not edit ``denylist.py``.

2026-07-31: the section that exercised the **legacy hyphen-path**
password-policy operations (``get_admin_password_policy``,
``get_local_user_password_policy``, ``update_local_user_password_policy``) has
been deleted along with the operations themselves. curl against the lab
appliance settled the dead-code question: ``/admin-user-password-policy``,
``/local-user-password-policy`` and ``/application-license-summary`` all
answer 404, while the slash spellings ``/admin-user/password-policy``,
``/local-user/password-policy`` and ``/application-license/summary`` all answer
200. The hyphen-path operations could never succeed and duplicated names that
already worked, so they were removed rather than repointed.

Verdicts
--------
PASS / EXPECTED_SKIP / FAIL come from ``harness.classify``; a fourth
bookkeeping verdict, ``BLOCKED``, is recorded directly for operations that were
deliberately never dispatched.

Assertion policy for the by-name writes: the *hard* assertions are the ones
that catch bugs — no crash marker, no HTML body where JSON was promised, no
unstructured error, and the safety guard fires before every mutation. A body
the appliance rejects on schema grounds is recorded with its real (FAIL)
verdict for triage rather than aborting the lifecycle before its cleanup.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

from . import harness
from .denylist import DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, PASS, assert_ours, classify, fixture_name

DOMAIN = "global_server_config"
BLOCKED = "BLOCKED"

# RFC 5737 TEST-NET-1 — routable nowhere, so a fixture SNMP trap destination
# cannot emit traffic to anything real.
TEST_NET_HOST = "192.0.2.10"

# Entity used for the fixture attribute. "Device" is the entity the existing
# module already filters on, so it is known to exist on this appliance.
ATTRIBUTE_ENTITY = "Device"


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
    """Success, or a refusal an LLM can act on. Returns True when it succeeded.

    A rejected body is a legitimate (recorded) finding; an HTML error page, a
    status-code-less error blob or a crash never is.
    """
    _no_crash(result, operation)
    if result.get("success") is True:
        return True
    assert not harness.looks_like_html(harness.deep_error_text(result)), \
        f"{operation} returned an HTML body where JSON was promised: {result}"
    assert isinstance(result.get("status_code"), int) or _is_clarification(result), \
        f"{operation} returned an unstructured error: {result}"
    return False


def _strip_readonly(obj: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in (obj or {}).items()
            if not str(k).startswith("_") and k not in ("id", "count", "links")}


def _payload(result: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    for key in keys:
        value = result.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _skip_family(recorder, operations: Iterable[str], reason: str) -> None:
    for operation in operations:
        _record_blocked(recorder, operation, reason)
    pytest.skip(reason)


def _first_item(result: Dict[str, Any], *keys: str) -> Dict[str, Any]:
    """First object out of a list result, whichever envelope it arrived in."""
    for key in keys:
        value = result.get(key)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            return value[0]
    data = result.get("data")
    if isinstance(data, dict):
        items = data.get("_embedded", {}).get("items")
        if isinstance(items, list) and items and isinstance(items[0], dict):
            return items[0]
    return {}


def _extract_list(result: Dict[str, Any], *keys: str) -> List[Dict[str, Any]]:
    """Every object out of a list result, whichever envelope it arrived in."""
    for key in keys:
        value = result.get(key)
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
    data = result.get("data")
    if isinstance(data, dict):
        items = data.get("_embedded", {}).get("items")
        if isinstance(items, list):
            return [v for v in items if isinstance(v, dict)]
    for value in result.values():
        if isinstance(value, list) and all(isinstance(v, dict) for v in value):
            return list(value)
    return []


# ==========================================================================
# 1. admin-privilege — fixture lifecycle through the new by-name operations
# ==========================================================================

_ADMIN_PRIVILEGE_OPS = ["update_admin_privilege_by_name",
                        "replace_admin_privilege_by_name",
                        "delete_admin_privilege_by_name"]


def test_admin_privilege_by_name_lifecycle(run_async, recorder, run_id, cleanup):
    """create (existing op) -> PATCH by name -> PUT by name -> DELETE by name.

    ``cppm_privileges`` is copied from a pre-existing privilege rather than
    invented: the appliance's own vocabulary is the only authority on what a
    valid privilege map looks like. The pre-existing object is only read.
    """
    name = fixture_name(run_id, "advpriv")
    cleanup.add(lambda: _invoke("delete_admin_privilege_by_name",
                                {"name": name, "confirm": True}))

    # NOT copied from the listing. The first record the appliance returns is
    # "Super Administrator", whose task set the API refuses to reproduce on a
    # new privilege — that is what made this create FAIL before 2026-07-31, and
    # it was the *test payload*, never the tool: `create_admin_privilege`
    # builds its body from the `AdminPrivilege` model, whose field names
    # (name/description/access_type/cppm_privileges/insight_privileges/
    # allow_passwords/allow_security_configs) match the API exactly, verified
    # by a raw curl POST that returned 201. A minimal read-only monitoring
    # grant is both accepted and the least privilege a fixture can carry.
    cppm_privileges = {"mon": "R"}

    created = run_async(_run(recorder, "create_admin_privilege", tier="create",
                             params={"name": name,
                                     "cppm_privileges": cppm_privileges,
                                     "description": name}))
    _no_crash(created, "create_admin_privilege")
    if created.get("success") is not True:
        _skip_family(recorder, _ADMIN_PRIVILEGE_OPS,
                     f"create_admin_privilege was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    base = _payload(created, "created_privilege", "data")

    assert_ours(name)
    patched = run_async(_run(recorder, "update_admin_privilege_by_name", tier="update",
                             params={"name": name,
                                     "privilege_data": {"description": name + "-patched"}}))
    _assert_ok_or_structured(patched, "update_admin_privilege_by_name")

    put_body = dict(_strip_readonly(base))
    put_body.update({"name": name, "cppm_privileges": cppm_privileges,
                     "description": name + "-replaced"})
    assert_ours(name)
    replaced = run_async(_run(recorder, "replace_admin_privilege_by_name", tier="update",
                              params={"name": name, "privilege_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_admin_privilege_by_name")

    # The confirmation guard is the single most valuable FieldInfo assertion on
    # a delete: an omitted `confirm` arriving as a truthy FieldInfo would let
    # the guard fall through.
    unconfirmed = run_async(_run(recorder, "delete_admin_privilege_by_name",
                                 {"name": name}, tier="negative", verdict=PASS))
    _no_crash(unconfirmed, "delete_admin_privilege_by_name")
    assert _is_clarification(unconfirmed), \
        f"delete_admin_privilege_by_name proceeded without confirm=True: {unconfirmed}"

    assert_ours(name)
    deleted = run_async(_run(recorder, "delete_admin_privilege_by_name", tier="delete",
                             params={"name": name, "confirm": True}))
    _no_crash(deleted, "delete_admin_privilege_by_name")
    assert classify(deleted, "delete_admin_privilege_by_name") == PASS, deleted


# ==========================================================================
# 2. attribute — fixture lifecycle through the new entity+name operations
# ==========================================================================

_ATTRIBUTE_OPS = ["update_attribute_by_entity_and_name",
                  "replace_attribute_by_entity_and_name",
                  "delete_attribute_by_entity_and_name"]


def test_attribute_by_entity_and_name_lifecycle(run_async, recorder, run_id, cleanup):
    name = fixture_name(run_id, "attr")
    cleanup.add(lambda: _invoke("delete_attribute_by_entity_and_name",
                                {"entity_name": ATTRIBUTE_ENTITY, "name": name,
                                 "confirm": True}))

    created = run_async(_run(recorder, "create_attribute", tier="create",
                             params={"entity_name": ATTRIBUTE_ENTITY, "name": name,
                                     "data_type": "String", "description": name}))
    _no_crash(created, "create_attribute")
    if created.get("success") is not True:
        _skip_family(recorder, _ATTRIBUTE_OPS,
                     f"create_attribute was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    base = _payload(created, "data", "attribute")

    assert_ours(name)
    patched = run_async(_run(recorder, "update_attribute_by_entity_and_name", tier="update",
                             params={"entity_name": ATTRIBUTE_ENTITY, "name": name,
                                     "attribute_data": {"mandatory": False}}))
    _assert_ok_or_structured(patched, "update_attribute_by_entity_and_name")

    put_body = dict(_strip_readonly(base))
    put_body.update({"name": name, "entity_name": ATTRIBUTE_ENTITY,
                     "data_type": base.get("data_type") or "String"})
    assert_ours(name)
    replaced = run_async(_run(recorder, "replace_attribute_by_entity_and_name", tier="update",
                              params={"entity_name": ATTRIBUTE_ENTITY, "name": name,
                                      "attribute_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_attribute_by_entity_and_name")

    unconfirmed = run_async(_run(recorder, "delete_attribute_by_entity_and_name",
                                 {"entity_name": ATTRIBUTE_ENTITY, "name": name},
                                 tier="negative", verdict=PASS))
    _no_crash(unconfirmed, "delete_attribute_by_entity_and_name")
    assert _is_clarification(unconfirmed), \
        f"delete_attribute_by_entity_and_name proceeded without confirm=True: {unconfirmed}"

    assert_ours(name)
    deleted = run_async(_run(recorder, "delete_attribute_by_entity_and_name", tier="delete",
                             params={"entity_name": ATTRIBUTE_ENTITY, "name": name,
                                     "confirm": True}))
    _no_crash(deleted, "delete_attribute_by_entity_and_name")
    assert classify(deleted, "delete_attribute_by_entity_and_name") == PASS, deleted


# ==========================================================================
# 3. data-filter — fixture lifecycle through the new by-name operations
# ==========================================================================

_DATA_FILTER_OPS = ["update_data_filter_by_name", "replace_data_filter_by_name",
                    "delete_data_filter_by_name"]


def test_data_filter_by_name_lifecycle(run_async, recorder, run_id, cleanup):
    """``create_data_filter`` used to send an invented body
    (``name``/``filter_expression``/``entity_name``) that the appliance always
    rejected with HTTP 422. It was rewritten on 2026-07-31 to the real schema —
    ``name``/``type``/``configuration_type`` plus either
    ``rule_eval_algo``+``rules`` or ``custom_sql`` — derived by GETting the 39
    data filters this appliance ships with. The create must now genuinely
    succeed, so its rejection is a hard failure rather than a family skip.
    """
    name = fixture_name(run_id, "datafilter")
    cleanup.add(lambda: _invoke("delete_data_filter_by_name",
                                {"name": name, "confirm": True}))

    created = run_async(_run(recorder, "create_data_filter", tier="create", params={
        "name": name,
        "type": "SESSION",
        "configuration_type": "attribute_rules",
        "rule_eval_algo": "OR",
        "rules": [{"match_type": "OR",
                   "condition": [{"type": "Common", "name": "Source",
                                  "oper": "EQUALS", "value": "RADIUS"}]}],
        "description": name,
    }))
    _no_crash(created, "create_data_filter")
    assert created.get("success") is True, (
        f"create_data_filter must succeed with the real schema, got: "
        f"{harness.deep_error_text(created).strip()[:300]}"
    )
    base = _payload(created, "data", "data_filter")

    # `configuration_type` *and* `type` must ride along on every PATCH: the
    # appliance reads an omitted `configuration_type` as unset rather than
    # unchanged and answers 422 "Cannot change configuration type", and
    # omitting `type` as well yields a bare 422. Verified by curl on
    # 2026-07-31. That is an API quirk, not a tool defect —
    # `update_data_filter_by_name` passes the caller's `filter_data` through
    # verbatim, which is exactly why it can satisfy the quirk.
    assert_ours(name)
    patched = run_async(_run(recorder, "update_data_filter_by_name", tier="update",
                             params={"name": name,
                                     "filter_data": {
                                         "description": name + "-patched",
                                         "configuration_type": "attribute_rules",
                                         "type": "SESSION"}}))
    assert classify(patched, "update_data_filter_by_name") == PASS, patched

    put_body = dict(_strip_readonly(base))
    put_body["name"] = name
    assert_ours(name)
    replaced = run_async(_run(recorder, "replace_data_filter_by_name", tier="update",
                              params={"name": name, "filter_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_data_filter_by_name")

    unconfirmed = run_async(_run(recorder, "delete_data_filter_by_name",
                                 {"name": name}, tier="negative", verdict=PASS))
    _no_crash(unconfirmed, "delete_data_filter_by_name")
    assert _is_clarification(unconfirmed), \
        f"delete_data_filter_by_name proceeded without confirm=True: {unconfirmed}"

    assert_ours(name)
    deleted = run_async(_run(recorder, "delete_data_filter_by_name", tier="delete",
                             params={"name": name, "confirm": True}))
    _no_crash(deleted, "delete_data_filter_by_name")
    assert classify(deleted, "delete_data_filter_by_name") == PASS, deleted


# ==========================================================================
# 4. operator-profile — fixture lifecycle through the new by-name operations
# ==========================================================================

_OPERATOR_PROFILE_OPS = ["update_operator_profile_by_name",
                         "replace_operator_profile_by_name",
                         "delete_operator_profile_by_name"]


def test_operator_profile_by_name_lifecycle(run_async, recorder, run_id, cleanup):
    name = fixture_name(run_id, "opprofile")
    cleanup.add(lambda: _invoke("delete_operator_profile_by_name",
                                {"name": name, "confirm": True}))

    created = run_async(_run(recorder, "create_operator_profile", tier="create",
                             params={"name": name, "description": name}))
    _no_crash(created, "create_operator_profile")
    if created.get("success") is not True:
        _skip_family(recorder, _OPERATOR_PROFILE_OPS,
                     f"create_operator_profile was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    base = _payload(created, "data", "operator_profile")

    assert_ours(name)
    patched = run_async(_run(recorder, "update_operator_profile_by_name", tier="update",
                             params={"name": name,
                                     "profile_data": {"description": name + "-patched"}}))
    _assert_ok_or_structured(patched, "update_operator_profile_by_name")

    put_body = dict(_strip_readonly(base))
    put_body["name"] = name
    assert_ours(name)
    replaced = run_async(_run(recorder, "replace_operator_profile_by_name", tier="update",
                              params={"name": name, "profile_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_operator_profile_by_name")

    unconfirmed = run_async(_run(recorder, "delete_operator_profile_by_name",
                                 {"name": name}, tier="negative", verdict=PASS))
    _no_crash(unconfirmed, "delete_operator_profile_by_name")
    assert _is_clarification(unconfirmed), \
        f"delete_operator_profile_by_name proceeded without confirm=True: {unconfirmed}"

    assert_ours(name)
    deleted = run_async(_run(recorder, "delete_operator_profile_by_name", tier="delete",
                             params={"name": name, "confirm": True}))
    _no_crash(deleted, "delete_operator_profile_by_name")
    assert classify(deleted, "delete_operator_profile_by_name") == PASS, deleted


# ==========================================================================
# 5. snmp-trap-receiver — fixture lifecycle through the new by-name operations
# ==========================================================================

_SNMP_OPS = ["update_snmp_trap_receiver_by_name",
             "replace_snmp_trap_receiver_by_name",
             "delete_snmp_trap_receiver_by_name"]


def test_snmp_trap_receiver_by_name_lifecycle(run_async, recorder, run_id, cleanup):
    """The trap destination is RFC 5737 TEST-NET-1, so the fixture receiver
    cannot forward anything anywhere while it briefly exists.

    2026-07-31: ``create_snmp_trap_receiver`` used to send ``version`` /
    ``community`` / ``port`` / ``name`` / ``enabled``. Only the first three had
    real counterparts, spelled ``snmp_version`` / ``community_string`` /
    ``server_port``; the appliance rejected every create with 422 "SNMP version
    must be specified". The tool now sends the real field names.

    **The resource has no ``name`` field** — ``host_address`` *is* the identity
    and the key the by-name routes use. That is why ``assert_ours`` cannot
    guard this family: no SNMP trap receiver can carry the ``zzz-mcptest-``
    prefix. The safety property instead comes from ``TEST_NET_HOST``, a
    dedicated RFC 5737 documentation address that no production receiver would
    ever use; the test refuses to run if one already exists there, and cleans
    up by both host address and numeric id.
    """
    key = TEST_NET_HOST

    listing = run_async(_invoke("list_snmp_trap_receivers", {"limit": 1000}))
    existing = [r for r in (_extract_list(listing) or [])
                if r.get("host_address") == key]
    assert not existing, (
        f"SAFETY: an SNMP trap receiver already exists at the fixture address "
        f"{key}; refusing to touch a pre-existing object: {existing}"
    )

    cleanup.add(lambda: _invoke("delete_snmp_trap_receiver_by_name",
                                {"name": key, "confirm": True}))

    created = run_async(_run(recorder, "create_snmp_trap_receiver", tier="create",
                             params={"host_address": key,
                                     "snmp_version": "V2C",
                                     "server_port": 162,
                                     "community_string": "zzz-mcptest-public"}))
    _no_crash(created, "create_snmp_trap_receiver")
    assert created.get("success") is True, (
        f"create_snmp_trap_receiver must succeed with the real schema, got: "
        f"{harness.deep_error_text(created).strip()[:300]}"
    )
    base = _payload(created, "data", "snmp_trap_receiver")
    receiver_id = base.get("id")
    if receiver_id is not None:
        cleanup.add(lambda: _invoke("delete_snmp_trap_receiver",
                                    {"snmp_trap_receiver_id": receiver_id,
                                     "confirm": True}))

    assert base.get("host_address") == key, (
        f"SAFETY: the created receiver is not at the fixture address {key}: {base}"
    )

    patched = run_async(_run(recorder, "update_snmp_trap_receiver_by_name", tier="update",
                             params={"name": key,
                                     "receiver_data": {"description": "zzz-mcptest-patched"}}))
    _assert_ok_or_structured(patched, "update_snmp_trap_receiver_by_name")

    put_body = dict(_strip_readonly(base))
    put_body.setdefault("host_address", key)
    put_body.setdefault("snmp_version", "V2C")
    put_body.setdefault("community_string", "zzz-mcptest-public")
    replaced = run_async(_run(recorder, "replace_snmp_trap_receiver_by_name", tier="update",
                              params={"name": key, "receiver_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_snmp_trap_receiver_by_name")

    unconfirmed = run_async(_run(recorder, "delete_snmp_trap_receiver_by_name",
                                 {"name": key}, tier="negative", verdict=PASS))
    _no_crash(unconfirmed, "delete_snmp_trap_receiver_by_name")
    assert _is_clarification(unconfirmed), \
        f"delete_snmp_trap_receiver_by_name proceeded without confirm=True: {unconfirmed}"

    deleted = run_async(_run(recorder, "delete_snmp_trap_receiver_by_name", tier="delete",
                             params={"name": key, "confirm": True}))
    _assert_ok_or_structured(deleted, "delete_snmp_trap_receiver_by_name")


# ==========================================================================
# 6. clearpass-portal
# ==========================================================================


def test_get_clearpass_portal(run_async, recorder):
    """Read-only. The POST counterpart rewrites appliance-wide portal state and
    is BLOCKED."""
    result = run_async(_run(recorder, "get_clearpass_portal"))
    _no_crash(result, "get_clearpass_portal")
    if _assert_ok_or_structured(result, "get_clearpass_portal"):
        assert isinstance(result.get("clearpass_portal"), (dict, list)), result


# ==========================================================================
# 7. application-license summary
# ==========================================================================


def test_get_application_license_summary_detail(run_async, recorder):
    """``GET /application-license/summary``.

    Verified by curl on 2026-07-31: this path answers **200** on 6.12.4. The
    404 recorded in docs/live_testing_plan_phase1.md:2340 belonged to the
    hyphen spelling ``/application-license-summary``, whose operation has since
    been removed. There is therefore no allowlist entry any more and this must
    genuinely pass.
    """
    operation = "get_application_license_summary_detail"
    result = run_async(_run(recorder, operation, tier="read"))
    _no_crash(result, operation)
    assert harness.expected_skip_reason(operation) is None, (
        f"{operation} must not be on the known-limitation allowlist: "
        f"/application-license/summary is served on this appliance"
    )
    assert classify(result, operation) == PASS, result


# ==========================================================================
# 8. Password policies — GET both, strict read-restore for the PATCHes
# ==========================================================================

# Fields safe to write back at their existing value. Chosen because they are
# scalars on the policy resource itself, not derived or server-owned.
_POLICY_ECHO_KEYS = (
    "password_minimum_length", "password_complexity", "password_expiry_days",
    "disable_after_days", "reminder_days", "disable_after_failed_attempts",
)


def _echo_field(policy: Dict[str, Any]) -> Optional[Tuple[str, Any]]:
    """Pick one field that can be written back at exactly its current value.

    Returns None when no such field can be identified — in which case the write
    cannot be proven to be a no-op and must be recorded BLOCKED instead.
    """
    for key in _POLICY_ECHO_KEYS:
        value = policy.get(key)
        if isinstance(value, (int, str, bool)) and not isinstance(value, type(None)):
            return key, value
    for key, value in policy.items():
        if str(key).startswith("_") or key in ("id", "links"):
            continue
        if isinstance(value, (int, str, bool)):
            return str(key), value
    return None


def test_admin_user_password_policy_get_and_noop_patch(run_async, recorder):
    """GET ``/admin-user/password-policy``, then PATCH one field back at the
    value it already holds.

    A no-op write is the only write that can be run against an appliance-wide
    security control. If the read does not yield a field that can be echoed,
    the PATCH is recorded BLOCKED rather than guessed at. The PUT is BLOCKED
    unconditionally: a full replacement resets every omitted field.
    """
    read = run_async(_run(recorder, "get_admin_user_password_policy"))
    ok = _assert_ok_or_structured(read, "get_admin_user_password_policy")
    if not ok:
        _record_blocked(recorder, "update_admin_user_password_policy",
                        "The policy could not be read "
                        f"(status {read.get('status_code')}), so no write can be "
                        "proven to be a no-op.")
        pytest.skip("admin-user/password-policy is not readable on this appliance")

    policy = _payload(read, "admin_user_password_policy")
    echo = _echo_field(policy)
    if echo is None:
        _record_blocked(recorder, "update_admin_user_password_policy",
                        "No scalar field on the policy could be echoed back "
                        "unchanged, so no provably no-op write exists.")
        pytest.skip("no echoable field on the admin user password policy")

    key, value = echo
    patched = run_async(_run(recorder, "update_admin_user_password_policy",
                             {"policy_data": {key: value}}, tier="update"))
    _assert_ok_or_structured(patched, "update_admin_user_password_policy")

    verify = run_async(_invoke("get_admin_user_password_policy"))
    if verify.get("success") is True:
        after = _payload(verify, "admin_user_password_policy")
        assert after.get(key) == value, (
            f"the no-op PATCH changed {key!r}: {value!r} -> {after.get(key)!r}"
        )


def test_local_user_password_policy_get_and_noop_patch(run_async, recorder):
    """Same strict read-restore contract against ``/local-user/password-policy``."""
    read = run_async(_run(recorder, "get_local_user_password_policy_settings"))
    ok = _assert_ok_or_structured(read, "get_local_user_password_policy_settings")
    if not ok:
        _record_blocked(recorder, "update_local_user_password_policy_settings",
                        "The policy could not be read "
                        f"(status {read.get('status_code')}), so no write can be "
                        "proven to be a no-op.")
        pytest.skip("local-user/password-policy is not readable on this appliance")

    policy = _payload(read, "local_user_password_policy")
    echo = _echo_field(policy)
    if echo is None:
        _record_blocked(recorder, "update_local_user_password_policy_settings",
                        "No scalar field on the policy could be echoed back "
                        "unchanged, so no provably no-op write exists.")
        pytest.skip("no echoable field on the local user password policy")

    key, value = echo
    patched = run_async(_run(recorder, "update_local_user_password_policy_settings",
                             {"policy_data": {key: value}}, tier="update"))
    _assert_ok_or_structured(patched, "update_local_user_password_policy_settings")

    verify = run_async(_invoke("get_local_user_password_policy_settings"))
    if verify.get("success") is True:
        after = _payload(verify, "local_user_password_policy")
        assert after.get(key) == value, (
            f"the no-op PATCH changed {key!r}: {value!r} -> {after.get(key)!r}"
        )


# ==========================================================================
# 10. BLOCKED inventory — recorded, never dispatched
# ==========================================================================

BLOCKED_OPERATIONS: Dict[str, str] = {
    # -- admin-user writes: no fixture admin user can exist -------------------
    "update_admin_user_by_user_id": (
        "Only 2 admin users exist on this appliance and both are real. A "
        "fixture admin user cannot be created: create_admin_user is BLOCKED in "
        "test_global_server_config.py because delete_admin_user is denylisted, "
        "so the account could never be removed. PATCHing a real admin account "
        "risks administrative lockout."
    ),
    "replace_admin_user_by_user_id": (
        "Same as update_admin_user_by_user_id, and worse: a PUT resets every "
        "omitted field (privilege_level, enabled, password), so a partial body "
        "against a real admin account is a lockout."
    ),
    "delete_admin_user_by_user_id": (
        "The by-user-id spelling of delete_admin_user, which is denylisted: "
        "only 2 admin users exist and no fixture admin user can be created to "
        "delete instead."
    ),
    # -- full-replacement password-policy writes ------------------------------
    "replace_admin_user_password_policy": (
        "A PUT resets every field omitted from the body, so it cannot be proven "
        "to be a no-op from a read alone; this is an appliance-wide security "
        "control. Only the no-op PATCH is exercised."
    ),
    "replace_local_user_password_policy_settings": (
        "A PUT resets every field omitted from the body, so it cannot be proven "
        "to be a no-op from a read alone; this is an appliance-wide security "
        "control. Only the no-op PATCH is exercised."
    ),
    # -- global portal state --------------------------------------------------
    "create_clearpass_portal": (
        "POST /clearpass-portal rewrites the appliance-wide landing page and "
        "redirect target for every user; there is no per-object namespace to "
        "scope it to and no delete operation to undo it."
    ),
    # -- cluster-wide ---------------------------------------------------------
    "sync_cluster_database": (
        "POST /cluster/db-sync forces a subscriber-to-publisher database "
        "synchronisation across the whole cluster — disruptive, long-running "
        "and un-scopeable. Never dispatched; being added to the hard denylist "
        "separately."
    ),
}


def test_blocked_operations_are_recorded_and_not_dispatched(recorder):
    import src.main  # noqa: F401
    from src.registry import registry

    for operation, reason in BLOCKED_OPERATIONS.items():
        assert registry.get(operation) is not None, f"unknown operation {operation}"
        _record_blocked(recorder, operation, reason)


# ==========================================================================
# 11. Coverage reconciliation over the 28 newly added operations
# ==========================================================================

NEW_OPERATIONS: List[str] = [
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


def test_zz_new_operation_coverage_is_complete(recorder):
    """All 28 newly added operations must be exercised or BLOCKED.

    Also pins the domain size. ``test_global_server_config.py`` still asserts
    ``len(all_ops) == 58``; the domain now holds 81, so that assertion is stale
    and is reported to triage rather than edited from here.

    81 = 86 after the expansion, minus the 5 dead hyphen-path operations
    removed on 2026-07-31 (get/update_admin_password_policy,
    get/update_local_user_password_policy, get_application_license_summary).
    """
    import json

    import src.main  # noqa: F401
    from src.registry import registry

    all_ops = {s.name for s in registry.search(domain=DOMAIN)}
    assert len(all_ops) == 81, f"expected 81 operations, found {len(all_ops)}"

    unknown = [n for n in NEW_OPERATIONS if registry.get(n) is None]
    assert not unknown, f"unknown operations: {unknown}"

    recorded = set()
    with recorder.path.open(encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("domain") == DOMAIN:
                recorded.add(rec["operation"])

    missing = sorted(set(NEW_OPERATIONS) - recorded - set(BLOCKED_OPERATIONS))
    assert not missing, f"new operations neither exercised nor BLOCKED: {missing}"
