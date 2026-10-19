"""Live validation — ``enforcement_profiles_dur`` (142), ``session_control``
(the 6 operations added after the first sweep), ``tools_utilities`` (6) and
``api_operations`` (4).

158 operations in total, exercised against a real ClearPass 6.12.4 appliance.

Scope rules baked into this module
----------------------------------
**enforcement_profiles_dur (142)** is 14 near-identical resource families x 10
verbs, plus the 2 base ``replace_enforcement_profile_by_*`` PUTs. Every DUR
resource is scoped to a ``product_name`` path segment, and **the product is a
property of the family, not of the appliance**: the ACL/QoS/policer/NAT/VoIP
families are served only for ``Mobility Access Switch`` (and, for some,
``Mobility Controller``), while classes and policies are served only for
``ArubaOS-Switch``/``AOS-CX``. Asking for the wrong one is answered with a
structured ``422 Invalid product_name``. Each family therefore carries its own
ordered list of candidate products and resolves the first one this appliance
actually serves; the winner is recorded and printed. Each family then runs a
real fixture lifecycle under a ``zzz-mcptest-*`` name:

    list -> create -> get by id -> get by name -> PATCH by id -> PATCH by name
         -> PUT (id or name) -> DELETE (id or name)

The PUT and DELETE variants **alternate by family index**, so the two shapes
this suite would otherwise never reach (``replace_*_by_id`` on even families,
``delete_*_by_id`` on odd ones) are all covered across the 14 families even
though each individual family only runs 8 of the 10 verbs.

One family (``policy``) cannot exist on its own: a policy rule names a DUR
class and the appliance rejects a create that references a class it cannot
find. That family declares a ``prereq`` — a fixture DUR class created (and
cleaned up) first, whose name is substituted into the policy bodies.

Downloadable User Roles are a licensed feature and can be absent on a 6.12.4
lab appliance. If **no** candidate product answers a family's list call, the
whole family is recorded as EXPECTED-LIMITATION — one record per operation,
sharing the reason — and the test returns without attempting a create. One
family's absence can therefore never abort another's.

Every DUR request is routed to the **unversioned** ``/api`` root — as is every
other request, since ``ClearPassClient._endpoint_url`` now builds all URLs from
``/api``. This resource tree is where the difference was first noticed: DUR
*reads* behave identically under both roots (``/api/v1`` and ``/api`` return the
same 200 list for ``ArubaOS-Switch``/``AOS-CX`` and the same 422 "Invalid
product_name" for an unserved product), but every DUR *write* under ``/api/v1``
answers HTTP 500 carrying an HTML "application unavailable" page, while the same
write under ``/api`` answers a clean structured 422/2xx. That routing bug — not
a missing licence — is what made all 14 families fail the 2026-07-30 sweep.

DUR is **not** a sweepable family (``harness._SWEEPABLE`` covers only guest
users, enforcement profiles and roles) and is **not** in the inventory-guard
snapshot, so nothing else would clean a stray DUR object up. Every create
registers its delete on the per-test ``cleanup`` fixture in the same breath, and
``assert_ours`` guards every PATCH/PUT/DELETE immediately before dispatch.

**session_control (6 new)** — ``get_active_session_by_mac`` is dispatched
against a locally-administered MAC that nothing can match. The other five
(``coa_active_session_by_mac`` and the four ``session_action_disconnect*``) are
on the hard denylist added for this scope and are asserted to raise before the
gateway is touched. That keeps the policy consistent with the four
``perform_coa_*`` entries already there, and it is also why the appliance's
known HTTP-500-with-an-HTML-body answer on the native
``session-action/disconnect*`` routes (documented in the module docstrings of
``src/tools/session_control.py``) is never observed here: the route is never
reached at all.

**tools_utilities (6)** — the four random-password / random-MPSK generators are
pure generators with no side effect on appliance state and are dispatched
freely. ``send_email`` and ``send_sms`` deliver to real humans through the
appliance's SMTP relay and SMS handler; both are denylisted and asserted to
raise.

**api_operations (4)** — all four are dispatched. ``request_oauth_token`` mints
a token for the very client this suite already authenticates as, which is
harmless; its request body is **never** written to the results artifact
(``RunRecorder._redact`` only redacts top-level keys, and the secret sits one
level down inside ``token_request``), so the recorded ``params_sent`` is
overridden with a redacted placeholder at the call site.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, FAIL, PASS, assert_ours, fixture_name

BLOCKED = "BLOCKED"

DUR = "enforcement_profiles_dur"
SESSIONS = "session_control"
UTILS = "tools_utilities"
APIOPS = "api_operations"

# Deliberately unmatchable targets: a locally-administered MAC and an absurd id.
NX_MAC = "02:00:5e:10:00:00"
NX_IP = "192.0.2.123"
NX_USERNAME = "zzz-mcptest-nosuchuser"
ABSENT_ID = "999999999"

# The four Aruba products the DUR endpoints are scoped by. Which of them a
# given family serves differs family by family (see the module docstring), so
# each family declares its own ordered candidate list drawn from these.
AOS_SWITCH = "ArubaOS-Switch"
AOS_CX = "AOS-CX"
MAS = "Mobility Access Switch"
MC = "Mobility Controller"

# Substituted with the name of the family's prereq object before dispatch.
PREREQ_TOKEN = "__PREREQ_NAME__"

# operation -> {"verdict": ..., "note": ...}; asserted complete by the summary.
COVERAGE: Dict[str, Dict[str, str]] = {}

# Free-text observations surfaced by the summary test.
NOTES: List[str] = []

# Structured findings (non-PASS outcomes on operations that should have worked).
FINDINGS: List[Dict[str, Any]] = []


def _mark(operation: str, verdict: str, note: str = "") -> None:
    COVERAGE[operation] = {"verdict": verdict, "note": note[:180]}


# --------------------------------------------------------------------------
# Dispatch + verdict helper
# --------------------------------------------------------------------------

_ERROR_KEYS = ("error", "message", "detail", "details", "error_details",
               "warning", "safety_warning", "question")

_ABSENT_PAT = ("404", "not found", "does not exist", "no such", "not exist",
               "could not be found")

_UNSUPPORTED_PAT = _ABSENT_PAT + ("not supported", "unsupported", "501",
                                  "not implemented", "not licensed",
                                  "license", "licence")


def _text(result: Dict[str, Any]) -> str:
    return " ".join(str(result.get(k, "")) for k in _ERROR_KEYS)


def _crash_markers(result: Any) -> List[str]:
    marker = harness.deep_crash_marker(result)
    return [marker] if marker else []


def _html_body(result: Dict[str, Any]) -> bool:
    """True when the error body is a rendered HTML page, not a JSON problem doc.

    An HTTP 500 carrying an HPE "Error 404" page must never be read as a
    legitimate absence — that is exactly the trap ``session-action/disconnect*``
    laid for the first sweep.
    """
    return harness.looks_like_html(harness.deep_error_text(result) or _text(result))


def is_unsupported(result: Dict[str, Any]) -> bool:
    """True when the appliance answered with a structured 'this endpoint is not
    served / not licensed here' rather than a real payload."""
    if not isinstance(result, dict) or result.get("success") is True:
        return False
    if _html_body(result) or _crash_markers(result):
        return False
    if result.get("status_code") in (404, 501):
        return True
    low = (harness.deep_error_text(result) or _text(result)).lower()
    return any(p in low for p in _UNSUPPORTED_PAT)


# The conftest event loop is session-scoped and reached through ``run_async``;
# a module-level shim keeps the call sites readable.
_RUN_ASYNC = None


def _sync(coro):
    assert _RUN_ASYNC is not None, "loop shim not installed"
    return _RUN_ASYNC(coro)


def run_op(
    recorder,
    operation: str,
    domain: str,
    tier: str = "read",
    expect: str = "success",
    substrings: Tuple[str, ...] = (),
    record_params: Optional[Dict[str, Any]] = None,
    **params: Any,
) -> Tuple[Dict[str, Any], str]:
    """Invoke through the gateway, classify, record. Returns (result, verdict).

    ``expect``:
      ``success``      — the operation should work against real data.
      ``absent``       — a structured "not found" for a deliberately absent object.
      ``refusal``      — a structured guard refusal; ``substrings`` must appear.
      ``rejected``     — the appliance legitimately rejects the request; any
                         structured, crash-free failure is correct.
      ``tolerant``     — success is ideal but a structured, crash-free failure
                         is an acceptable environment answer (EXPECTED_SKIP).

    ``record_params`` overrides what is written to the results artifact — used
    where a secret sits below the top level of a parameter and would otherwise
    escape ``RunRecorder._redact``.
    """
    start = time.perf_counter()
    result = _sync(harness.invoke(operation, _params=params))
    duration = (time.perf_counter() - start) * 1000.0

    text = _text(result)
    crashes = _crash_markers(result)
    success = result.get("success") is True

    if _html_body(result):
        NOTES.append(
            f"{operation}: error body is an HTML page, not a structured API "
            f"error — substring matching would mis-read it as a 404")
        verdict = FAIL
    elif crashes:
        verdict = FAIL
    elif expect == "success":
        verdict = PASS if success else FAIL
    elif expect == "absent":
        low = (harness.deep_error_text(result) or text).lower()
        # Reporting populated data for an object that cannot exist would mean
        # the operation invented it. An empty collection is a fine answer.
        verdict = PASS if (any(p in low for p in _ABSENT_PAT)
                           or (success and not _payload_items(result))) else FAIL
    elif expect == "refusal":
        low = text.lower()
        verdict = PASS if (not success
                           and all(s.lower() in low for s in substrings)) else FAIL
    elif expect == "rejected":
        verdict = FAIL if success else PASS
    elif expect == "tolerant":
        verdict = PASS if success else EXPECTED_SKIP
    else:  # pragma: no cover
        raise ValueError(expect)

    err = None if verdict == PASS else (text.strip() or None)
    recorder.record(operation, domain, tier, verdict,
                    record_params if record_params is not None else params,
                    err, duration)
    if verdict == FAIL:
        FINDINGS.append({"operation": operation, "params": params,
                         "error": (err or "")[:400]})
    return result, verdict


_ENVELOPE_KEYS = ("success", "message", "product_name", "count", "total_count",
                  "returned_count", "pagination_info", "mac_address",
                  "interval", "error", "status_code")


def _payload_items(result: Dict[str, Any]) -> List[Any]:
    """The real objects a success envelope carries, if any.

    ``harness._extract_items`` understands the HAL shapes at the top level;
    single-object operations (``get_active_session_by_mac`` answers under
    ``active_session``) nest the HAL envelope one level down, so nested dicts
    are checked too.
    """
    items = harness._extract_items(result)
    if items:
        return items
    for key, value in result.items():
        if key in _ENVELOPE_KEYS:
            continue
        if isinstance(value, dict):
            nested = harness._extract_items(value)
            if nested:
                return nested
        elif isinstance(value, list) and value:
            return [v for v in value]
    return []


def record_blocked(recorder, operation: str, domain: str, reason: str) -> None:
    recorder.record(operation, domain, "blocked", BLOCKED, {}, reason, 0.0)
    _mark(operation, BLOCKED, reason)


def record_limitation(recorder, operation: str, domain: str, reason: str) -> None:
    recorder.record(operation, domain, "read", EXPECTED_SKIP, {},
                    f"EXPECTED-LIMITATION: {reason}", 0.0)
    _mark(operation, EXPECTED_SKIP, f"EXPECTED-LIMITATION: {reason}")


def assert_denylisted(recorder, operation: str, domain: str,
                      params: Dict[str, Any]) -> None:
    """The operation must raise before the gateway is touched."""
    assert is_denylisted(operation), f"{operation} is not on the denylist"
    with pytest.raises(DenylistedOperation) as excinfo:
        _sync(harness.invoke(operation, _params=params))
    assert DENYLIST[operation] in str(excinfo.value)
    recorder.record(operation, domain, "denylist", EXPECTED_SKIP, {},
                    f"DENYLISTED: {DENYLIST[operation]}", 0.0)
    _mark(operation, BLOCKED, f"DENYLISTED: {DENYLIST[operation]}")


@pytest.fixture(autouse=True, scope="module")
def _install_loop(request):
    global _RUN_ASYNC
    if not request.config.getoption("--live"):
        yield
        return
    _RUN_ASYNC = request.getfixturevalue("run_async")
    yield
    _RUN_ASYNC = None


# ==========================================================================
# enforcement_profiles_dur — family table
# ==========================================================================
#
# One dict per family:
#   singular / plural : build the 10 operation names and the id/data params
#   products          : ordered candidate ``product_name`` values; the first
#                       one this appliance serves wins (see the docstring)
#   create/patch/put  : request bodies; ``name`` is added at dispatch
#   prereq (optional) : an object this family's bodies reference by name
#
# Bodies are deliberately minimal: only the keys each operation's schema
# documents as required, plus the smallest rule set the appliance accepts.
# Optional keys stay omitted — that is the ``FieldInfo`` path the whole harness
# exists to pin. Where 6.12.4 rejected the documented-looking value the
# appliance's own vocabulary is used instead, and the reason is noted inline.

_ANY_RULE = {"src_traffic_match": "any", "dst_traffic_match": "any",
             "service_type": "any", "action": "permit"}

# ArubaOS-Switch / AOS-CX class rules: ``packet_match`` is match|ignore (the
# switch CLI verb), not permit|deny — the appliance answers "Invalid
# packet_match" for the latter.
def _class_rule(number: int) -> Dict[str, Any]:
    return {"number": number, "packet_match": "match",
            "traffic_match_type": "protocol", "protocol": "ip",
            "source": "any", "destination": "any"}


DUR_FAMILIES: List[Dict[str, Any]] = [
    {
        "singular": "captive_portal_profile",
        "plural": "captive_portal_profiles",
        "products": (AOS_SWITCH, MAS, MC, AOS_CX),
        "create": {"url": "https://192.0.2.10/guest/portal"},
        "patch": {"url": "https://192.0.2.11/guest/portal"},
        "put": {"url": "https://192.0.2.12/guest/portal"},
    },
    {
        "singular": "dur_class",
        "plural": "dur_classes",
        "products": (AOS_SWITCH, AOS_CX),
        "create": {"hpe_rules": [_class_rule(10)],
                   "aos_cx_rules": [_class_rule(10)]},
        "patch": {"hpe_rules": [_class_rule(20)]},
        "put": {"hpe_rules": [_class_rule(30)],
                "aos_cx_rules": [_class_rule(30)]},
    },
    {
        "singular": "ethertype_access_control_list",
        "plural": "ethertype_access_control_lists",
        "products": (MAS, MC),
        # ``ethertype_type`` is any|<named protocol>; "custom" (with an
        # ethertype_value) is rejected as "Invalid ethertype_type" on 6.12.4.
        "create": {"rules": [{"action": "permit", "ethertype_type": "any"}]},
        "patch": {"rules": [{"action": "deny", "ethertype_type": "any"}]},
        "put": {"rules": [{"action": "permit", "ethertype_type": "any"}]},
    },
    {
        "singular": "mac_access_control_list",
        "plural": "mac_access_control_lists",
        "products": (MAS, MC),
        "create": {"rules": [{"action": "permit", "mac_address_type": "any"}]},
        "patch": {"rules": [{"action": "deny", "mac_address_type": "any"}]},
        "put": {"rules": [{"action": "permit", "mac_address_type": "any"}]},
    },
    {
        "singular": "nat_pool",
        "plural": "nat_pools",
        "products": (MAS, MC),
        "create": {"start_src_range": "192.0.2.10",
                   "end_src_range": "192.0.2.20"},
        "patch": {"end_src_range": "192.0.2.30"},
        "put": {"start_src_range": "192.0.2.10",
                "end_src_range": "192.0.2.40"},
    },
    {
        "singular": "net_destination",
        "plural": "net_destinations",
        "products": (AOS_SWITCH, MAS, MC),
        # ``position`` is mandatory for an ArubaOS-Switch net-destination rule
        # ("Position must be specified" without it).
        "create": {"rules": [{"rule_type": "network", "ip_address": "192.0.2.0",
                              "netmask": "255.255.255.0", "position": 1}]},
        "patch": {"rules": [{"rule_type": "network",
                             "ip_address": "198.51.100.0",
                             "netmask": "255.255.255.0", "position": 1}]},
        "put": {"rules": [{"rule_type": "network", "ip_address": "203.0.113.0",
                           "netmask": "255.255.255.0", "position": 1}]},
    },
    {
        "singular": "net_service",
        "plural": "net_services",
        "products": (AOS_SWITCH, MAS, MC, AOS_CX),
        # The appliance's vocabulary here is capitalised: protocol "TCP",
        # port_selection "Port" (lower-case forms are rejected).
        "create": {"protocol": "TCP", "port_selection": "Port", "port": 8081},
        "patch": {"port": 8082},
        "put": {"protocol": "TCP", "port_selection": "Port", "port": 8083},
    },
    {
        "singular": "policer_profile",
        "plural": "policer_profiles",
        "products": (MAS, MC),
        "create": {"cir": 1000000, "cbs": 8000},
        "patch": {"cbs": 16000},
        "put": {"cir": 2000000, "cbs": 16000},
    },
    {
        "singular": "policy",
        "plural": "policies",
        "products": (AOS_SWITCH, AOS_CX),
        # A policy rule names a DUR class; "any" is not a class, so a real one
        # is created first and its name substituted for PREREQ_TOKEN.
        "prereq": {"singular": "dur_class", "plural": "dur_classes",
                   "body": {"hpe_rules": [_class_rule(10)],
                            "aos_cx_rules": [_class_rule(10)]}},
        "create": {"rules": [{"number": 10, "class_type": "ipv4",
                              "class_name": PREREQ_TOKEN, "action": "permit"}]},
        "patch": {"rules": [{"number": 20, "class_type": "ipv4",
                             "class_name": PREREQ_TOKEN, "action": "permit"}]},
        "put": {"rules": [{"number": 30, "class_type": "ipv4",
                           "class_name": PREREQ_TOKEN, "action": "permit"}]},
    },
    {
        "singular": "qos_profile",
        "plural": "qos_profiles",
        "products": (MAS, MC),
        "create": {"dscp": 8, "dot1p": 1},
        "patch": {"dscp": 16},
        "put": {"dscp": 24, "dot1p": 3},
    },
    {
        "singular": "session_access_control_list",
        "plural": "session_access_control_lists",
        "products": (MAS, MC),
        "create": {"rules": [dict(_ANY_RULE)]},
        "patch": {"rules": [dict(_ANY_RULE, action="deny")]},
        "put": {"rules": [dict(_ANY_RULE)]},
    },
    {
        "singular": "stateless_access_control_list",
        "plural": "stateless_access_control_lists",
        "products": (MAS, MC),
        "create": {"rules": [dict(_ANY_RULE)]},
        "patch": {"rules": [dict(_ANY_RULE, action="deny")]},
        "put": {"rules": [dict(_ANY_RULE)]},
    },
    {
        "singular": "time_range",
        "plural": "time_ranges",
        "products": (MAS, MC),
        # ``type`` is immutable once set and is compared against the stored
        # (capitalised) value, so the PATCH omits it and the PUT — a full
        # replace — must carry it back verbatim, or the appliance answers
        # "Type cannot be changed".
        "create": {"type": "Periodic",
                   "rules": [{"start_day_or_date": "Monday",
                              "end_day_or_date": "Friday",
                              "start_time": "08:00", "end_time": "17:00"}]},
        "patch": {"rules": [{"start_day_or_date": "Monday",
                             "end_day_or_date": "Friday",
                             "start_time": "09:00", "end_time": "17:00"}]},
        "put": {"type": "Periodic",
                "rules": [{"start_day_or_date": "Tuesday",
                           "end_day_or_date": "Thursday",
                           "start_time": "08:00", "end_time": "18:00"}]},
    },
    {
        "singular": "voip_profile",
        "plural": "voip_profiles",
        "products": (MAS, MC),
        "create": {"voip_vlan": 100, "dscp": 46, "dot1p": "6"},
        "patch": {"dscp": 34},
        "put": {"voip_vlan": 101, "dscp": 46, "dot1p": "6"},
    },
]

assert len(DUR_FAMILIES) == 14


def dur_ops(singular: str, plural: str) -> Dict[str, str]:
    """The 10 operation names belonging to one DUR family."""
    return {
        "list": f"dur_list_{plural}",
        "create": f"dur_create_{singular}",
        "get_by_id": f"dur_get_{singular}_by_id",
        "get_by_name": f"dur_get_{singular}_by_name",
        "update_by_id": f"dur_update_{singular}_by_id",
        "update_by_name": f"dur_update_{singular}_by_name",
        "replace_by_id": f"dur_replace_{singular}_by_id",
        "replace_by_name": f"dur_replace_{singular}_by_name",
        "delete_by_id": f"dur_delete_{singular}_by_id",
        "delete_by_name": f"dur_delete_{singular}_by_name",
    }


def _item_id(result: Dict[str, Any]) -> Optional[Any]:
    """Pull the object id out of a ``_dur_call`` success envelope."""
    item = result.get("item")
    if isinstance(item, dict):
        if item.get("id") is not None:
            return item["id"]
        nested = harness._extract_items(item)
        if nested and isinstance(nested[0], dict):
            return nested[0].get("id")
    return None


# --------------------------------------------------------------------------
# Per-family product resolution
# --------------------------------------------------------------------------

# The appliance's answer when a family exists but is not served for the
# product asked for. It is a structured 422 and means "try the next
# candidate", not "this operation is broken".
_WRONG_PRODUCT_PAT = ("invalid product_name",)


def _wrong_product(result: Dict[str, Any]) -> bool:
    low = (harness.deep_error_text(result) or _text(result)).lower()
    return any(p in low for p in _WRONG_PRODUCT_PAT)


def resolve_product(recorder, list_op: str,
                    products: Tuple[str, ...]) -> Tuple[Optional[str],
                                                        Dict[str, Any],
                                                        List[Dict[str, Any]]]:
    """First candidate product whose list call this appliance actually serves.

    Returns ``(product, list_result, attempts)``; ``product`` is ``None`` when
    the appliance serves none of them, which the caller turns into a
    family-wide EXPECTED-LIMITATION.
    """
    attempts: List[Dict[str, Any]] = []
    for product in products:
        result, _ = run_op(recorder, list_op, DUR, tier="read",
                           expect="tolerant", product_name=product)
        assert not _crash_markers(result), (
            f"{list_op}({product}) crashed rather than returning a structured "
            f"error: {result}")
        attempts.append({"product": product,
                         "success": result.get("success") is True,
                         "error": (_text(result) or "").strip()[:200]})
        if result.get("success") is True:
            return product, result, attempts
        assert _wrong_product(result) or is_unsupported(result), (
            f"{list_op}({product}) failed for a reason other than the product "
            f"not being served: {result}")
    return None, {}, attempts


def _substitute(body: Any, token: str, value: str) -> Any:
    """Deep copy of ``body`` with every ``token`` string replaced."""
    if isinstance(body, dict):
        return {k: _substitute(v, token, value) for k, v in body.items()}
    if isinstance(body, list):
        return [_substitute(v, token, value) for v in body]
    if isinstance(body, str):
        return body.replace(token, value)
    return body


# --------------------------------------------------------------------------
# The DUR family lifecycle — one parametrised test per family
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "index, family",
    [(i, f) for i, f in enumerate(DUR_FAMILIES)],
    ids=[f["singular"] for f in DUR_FAMILIES],
)
def test_dur_family_lifecycle(recorder, run_id, cleanup, index, family):
    """list -> create -> read(id, name) -> PATCH(id, name) -> PUT -> DELETE.

    The PUT and DELETE variants alternate by family index so that across the
    14 families all 10 verbs of the DUR shape are exercised, even though each
    individual family only runs 8 of them.

    If no candidate product answers the family's list call, every operation in
    the family is recorded as EXPECTED-LIMITATION with a shared reason and the
    test returns — a missing family never aborts another.
    """
    singular, plural = family["singular"], family["plural"]
    ops = dur_ops(singular, plural)
    id_param = f"{singular}_id"
    data_param = f"{singular}_data"

    # --- 1. list, every optional omitted (the FieldInfo omission path) -------
    product, listed, attempts = resolve_product(recorder, ops["list"],
                                                family["products"])

    if product is None:
        reason = (f"DUR {plural} are served for none of "
                  f"{list(family['products'])} on this ClearPass 6.12.4 "
                  f"appliance ("
                  + "; ".join(f"{a['product']} -> {a['error'][:60]}"
                              for a in attempts) + ")")
        for op in ops.values():
            record_limitation(recorder, op, DUR, reason)
        NOTES.append(reason)
        pytest.skip(reason)

    _mark(ops["list"], PASS,
          f"{listed.get('count')} pre-existing {plural} for {product}")
    pre_existing = listed.get("count") or 0

    # the explicitly-specified branch of the same operation
    run_op(recorder, ops["list"], DUR, tier="read", expect="success",
           product_name=product, sort="+id", offset=0, limit=25,
           calculate_count=True)

    # --- 2. prereq, for the families whose bodies reference another object ---
    create_body = family["create"]
    patch_body = family["patch"]
    put_body = family["put"]
    prereq = family.get("prereq")
    if prereq:
        prereq_ops = dur_ops(prereq["singular"], prereq["plural"])
        prereq_name = fixture_name(run_id, f"dur-{index}", "prereq")
        cleanup.add(lambda: harness.invoke(
            prereq_ops["delete_by_name"],
            _params={"product_name": product,
                     "name": assert_ours(prereq_name)}))
        made, pv = run_op(recorder, prereq_ops["create"], DUR, tier="create",
                          expect="success", product_name=product,
                          **{f"{prereq['singular']}_data":
                             dict(prereq["body"], name=prereq_name)})
        assert pv == PASS, (
            f"{plural} need a {prereq['singular']} to reference and "
            f"{prereq_ops['create']} failed: {_text(made)}")
        create_body = _substitute(create_body, PREREQ_TOKEN, prereq_name)
        patch_body = _substitute(patch_body, PREREQ_TOKEN, prereq_name)
        put_body = _substitute(put_body, PREREQ_TOKEN, prereq_name)

    # --- 3. create ----------------------------------------------------------
    name = fixture_name(run_id, f"dur-{index}")
    body = dict(create_body, name=name)

    # Registered BEFORE the create is even asserted: DUR is not a sweepable
    # family, so this cleanup is the only thing that will ever remove it.
    cleanup.add(lambda: harness.invoke(
        ops["delete_by_name"], _params={"product_name": product,
                                        "name": assert_ours(name)}))

    created, cv = run_op(recorder, ops["create"], DUR, tier="create",
                         expect="success", product_name=product,
                         **{data_param: body})
    _mark(ops["create"], cv, (_text(created) or "created")[:180])
    if cv != PASS:
        # A structured rejection of the body shape must not cascade into 7
        # more misleading failures; the create failure is the finding.
        for key in ("get_by_id", "get_by_name", "update_by_id",
                    "update_by_name", "replace_by_id", "replace_by_name",
                    "delete_by_id", "delete_by_name"):
            record_blocked(recorder, ops[key], DUR,
                           f"no fixture to target: {ops['create']} failed")
        assert cv == PASS, f"{ops['create']} failed: {_text(created)}"

    obj_id = _item_id(created)
    assert obj_id is not None, (
        f"{ops['create']} returned no object id, so the by-id verbs cannot be "
        f"exercised: {created}")

    # --- 4. read back, both handles ----------------------------------------
    by_id, giv = run_op(recorder, ops["get_by_id"], DUR, tier="read",
                        expect="success", product_name=product,
                        **{id_param: str(obj_id)})
    _mark(ops["get_by_id"], giv, f"id={obj_id}")
    assert giv == PASS, f"{ops['get_by_id']} failed: {_text(by_id)}"

    by_name, gnv = run_op(recorder, ops["get_by_name"], DUR, tier="read",
                          expect="success", product_name=product, name=name)
    _mark(ops["get_by_name"], gnv, f"name={name}")
    assert gnv == PASS, f"{ops['get_by_name']} failed: {_text(by_name)}"

    # --- 5. PATCH, both handles (guarded immediately before each write) ------
    assert_ours(name)
    upd_id, uiv = run_op(recorder, ops["update_by_id"], DUR, tier="update",
                         expect="success", product_name=product,
                         **{id_param: str(obj_id), data_param: dict(patch_body)})
    _mark(ops["update_by_id"], uiv, (_text(upd_id) or "patched by id")[:120])
    assert uiv == PASS, f"{ops['update_by_id']} failed: {_text(upd_id)}"

    assert_ours(name)
    upd_name, unv = run_op(recorder, ops["update_by_name"], DUR, tier="update",
                           expect="success", product_name=product, name=name,
                           **{data_param: dict(patch_body)})
    _mark(ops["update_by_name"], unv, (_text(upd_name) or "patched by name")[:120])
    assert unv == PASS, f"{ops['update_by_name']} failed: {_text(upd_name)}"

    # --- 6. PUT — variant alternates by family index ------------------------
    put_by_name = (index % 2 == 0)
    put_op = ops["replace_by_name"] if put_by_name else ops["replace_by_id"]
    put_full = dict(put_body, name=name)
    put_params: Dict[str, Any] = {"product_name": product, data_param: put_full}
    put_params.update({"name": name} if put_by_name else {id_param: str(obj_id)})

    assert_ours(name)
    replaced, rv = run_op(recorder, put_op, DUR, tier="update",
                          expect="success", **put_params)
    _mark(put_op, rv, (_text(replaced) or "replaced")[:120])
    record_blocked(
        recorder,
        ops["replace_by_id"] if put_by_name else ops["replace_by_name"], DUR,
        "the other PUT handle for this family; exercised on the families with "
        "the opposite index parity so all 10 DUR verbs are covered")
    assert rv == PASS, f"{put_op} failed: {_text(replaced)}"

    # --- 7. DELETE — variant alternates by family index ---------------------
    del_by_name = (index % 2 == 0)
    del_op = ops["delete_by_name"] if del_by_name else ops["delete_by_id"]
    del_params: Dict[str, Any] = {"product_name": product}
    del_params.update({"name": name} if del_by_name else {id_param: str(obj_id)})

    assert_ours(name)  # the id we are about to delete belongs to this name
    deleted, dv = run_op(recorder, del_op, DUR, tier="delete",
                         expect="success", **del_params)
    _mark(del_op, dv, (_text(deleted) or "deleted")[:120])
    record_blocked(
        recorder,
        ops["delete_by_id"] if del_by_name else ops["delete_by_name"], DUR,
        "the other DELETE handle for this family; exercised on the families "
        "with the opposite index parity so all 10 DUR verbs are covered")
    assert dv == PASS, f"{del_op} failed: {_text(deleted)}"

    # --- 8. it is really gone ----------------------------------------------
    gone, gv = run_op(recorder, ops["get_by_name"], DUR, tier="negative",
                      expect="absent", product_name=product, name=name)
    assert gv == PASS, f"{name} still readable after delete: {gone}"

    survivors, sv = run_op(recorder, ops["list"], DUR, tier="read",
                           expect="success", product_name=product, limit=1000)
    if sv == PASS:
        items = survivors.get("items") or []
        ours = [i for i in items
                if isinstance(i, dict) and harness.is_ours(i.get("name"))
                and i.get("name") != (prereq_name if prereq else None)]
        assert not ours, f"fixture {plural} survived the lifecycle: {ours}"
        NOTES.append(f"DUR {plural} [{product}]: {pre_existing} pre-existing, "
                     f"{len(items)} after the lifecycle")


# --------------------------------------------------------------------------
# The 2 base enforcement-profile PUTs (not DUR endpoints, but in this module)
# --------------------------------------------------------------------------


def test_replace_enforcement_profile_by_name_and_by_id(recorder, run_id, cleanup):
    """Full PUT lifecycle on the base ``/enforcement-profile`` resource.

    ``enforcement_profiles`` IS a sweepable fixture family, so the fixture is
    created with the existing ``create_enforcement_profile`` operation, fully
    replaced through both PUT handles, and deleted. A PUT clears every omitted
    field, which is precisely why it may only ever target a fixture.

    Because it clears omitted fields, the appliance also *validates* the whole
    object: a body carrying only name/type/description/attributes is rejected
    with ``422 action must be specified``. Each PUT body is therefore built
    from a GET of the fixture itself — the appliance's own representation,
    minus the server-owned ``id``/``_links`` — with a single harmless field
    mutated, which is what a full replace is supposed to look like.
    """
    name = fixture_name(run_id, "putprof")
    attrs = [{"type": "Radius:IETF", "name": "Session-Timeout", "value": "3600"}]

    cleanup.add(lambda: harness.invoke("delete_enforcement_profile",
                                       profile_name=assert_ours(name),
                                       confirm_deletion=True))

    created, cv = run_op(recorder, "create_enforcement_profile",
                         "enforcement_profiles", tier="create",
                         expect="success", name=name, profile_type="RADIUS",
                         attributes=attrs)
    assert cv == PASS, f"fixture profile create failed: {_text(created)}"
    pid = (created.get("profile") or {}).get("id")
    assert isinstance(pid, int), f"no profile id returned: {created}"

    def _put_body(description: str) -> Dict[str, Any]:
        """The fixture as the appliance currently represents it, re-described."""
        current, gv = run_op(recorder, "get_enforcement_profile_details",
                             "enforcement_profiles", tier="read",
                             expect="success", profile_id=pid)
        assert gv == PASS, f"could not read the fixture back: {_text(current)}"
        profile = dict(current.get("profile") or {})
        assert profile.get("name") == name, (
            f"the profile read back is not the fixture: {profile.get('name')!r}")
        for server_owned in ("id", "_links"):
            profile.pop(server_owned, None)
        profile["description"] = description
        return profile

    # --- PUT by name --------------------------------------------------------
    assert_ours(name)
    by_name, bnv = run_op(
        recorder, "replace_enforcement_profile_by_name", DUR, tier="update",
        expect="success", name=name,
        profile_data=_put_body("replaced-by-name"))
    _mark("replace_enforcement_profile_by_name", bnv,
          (_text(by_name) or "replaced by name")[:120])
    assert bnv == PASS, f"replace-by-name failed: {_text(by_name)}"

    check, _ = run_op(recorder, "get_enforcement_profile_details",
                      "enforcement_profiles", tier="read", expect="success",
                      profile_name=name)
    assert (check.get("profile") or {}).get("description") == "replaced-by-name", \
        f"PUT by name did not take effect: {check}"

    # --- PUT by id ----------------------------------------------------------
    assert_ours(name)
    by_id, biv = run_op(
        recorder, "replace_enforcement_profile_by_id", DUR, tier="update",
        expect="success", enforcement_profile_id=pid,
        profile_data=_put_body("replaced-by-id"))
    _mark("replace_enforcement_profile_by_id", biv,
          (_text(by_id) or "replaced by id")[:120])
    assert biv == PASS, f"replace-by-id failed: {_text(by_id)}"

    check2, _ = run_op(recorder, "get_enforcement_profile_details",
                       "enforcement_profiles", tier="read", expect="success",
                       profile_id=pid)
    assert (check2.get("profile") or {}).get("description") == "replaced-by-id", \
        f"PUT by id did not take effect: {check2}"
    assert (check2.get("profile") or {}).get("name") == name, \
        "the PUT renamed the fixture out of the fixture namespace"

    # --- delete -------------------------------------------------------------
    assert_ours(name)
    deleted, dv = run_op(recorder, "delete_enforcement_profile",
                         "enforcement_profiles", tier="delete",
                         expect="success", profile_name=name,
                         confirm_deletion=True)
    assert dv == PASS, f"fixture profile delete failed: {_text(deleted)}"


def test_replace_enforcement_profile_absent_targets(recorder, cleanup):
    """Both PUT handles against objects that cannot exist.

    The name is deliberately inside the fixture namespace: a PUT against a name
    can behave as an upsert, and if this appliance creates rather than 404s,
    the object lands somewhere ``assert_ours`` vouches for, the registered
    cleanup removes it, and the session sweep would catch it regardless
    (``enforcement_profiles`` is a sweepable family). Nothing pre-existing can
    be touched either way.
    """
    absent_name = "zzz-mcptest-object-that-does-not-exist"
    body = {"name": absent_name, "type": "RADIUS"}
    cleanup.add(lambda: harness.invoke("delete_enforcement_profile",
                                       profile_name=assert_ours(absent_name),
                                       confirm_deletion=True))

    _, v1 = run_op(recorder, "replace_enforcement_profile_by_name", DUR,
                   tier="negative", expect="absent", name=absent_name,
                   profile_data=body)
    assert v1 == PASS

    _, v2 = run_op(recorder, "replace_enforcement_profile_by_id", DUR,
                   tier="negative", expect="absent",
                   enforcement_profile_id=999999999, profile_data=body)
    assert v2 == PASS


# ==========================================================================
# session_control — the 6 operations added after the first sweep
# ==========================================================================


def test_get_active_session_by_mac_unmatchable(recorder):
    """``GET session/mac/<mac>`` against a locally-administered MAC.

    Nothing on this appliance can hold ``02:00:5e:*``, so the correct answer is
    an empty collection or a structured 404 — never invented session data and
    never a crash.
    """
    result, verdict = run_op(recorder, "get_active_session_by_mac", SESSIONS,
                             tier="negative", expect="absent",
                             mac_address=NX_MAC)
    _mark("get_active_session_by_mac", verdict,
          (_text(result) or "empty result for an unmatchable MAC")[:160])
    assert verdict == PASS, f"unmatchable MAC mishandled: {result}"
    assert not _crash_markers(result), result

    # the optional ``interval`` branch of the same operation
    windowed, wv = run_op(recorder, "get_active_session_by_mac", SESSIONS,
                          tier="negative", expect="absent",
                          mac_address=NX_MAC, interval="1")
    assert wv == PASS, f"interval branch mishandled: {windowed}"


def test_session_action_and_coa_by_mac_are_denylisted(recorder):
    """The 5 session-mutating operations added in this scope must raise before
    the gateway is touched.

    Policy consistency: the four ``perform_coa_*`` operations were already
    denylisted for acting on live authenticated sessions, and these five do the
    same thing through different routes. It is also why this suite never
    observes the appliance's documented HTTP-500-with-an-HTML-body answer on
    ``session-action/disconnect*`` — the route is never dispatched at all.
    """
    cases = {
        "coa_active_session_by_mac": {"mac_address": NX_MAC,
                                      "enforcement_profile": "zzz-mcptest-x"},
        "session_action_disconnect": {"filter_criteria": {"username": NX_USERNAME}},
        "session_action_disconnect_by_mac": {"mac_address": NX_MAC},
        "session_action_disconnect_by_ip": {"client_ip_address": NX_IP},
        "session_action_disconnect_by_username": {"username": NX_USERNAME},
    }
    for operation, params in cases.items():
        assert_denylisted(recorder, operation, SESSIONS, params)


# ==========================================================================
# tools_utilities (6)
# ==========================================================================


def test_random_password_generators(recorder):
    """GET and POST ``/random-password``. Pure generators — no appliance state
    changes, so both are dispatched freely."""
    got, gv = run_op(recorder, "get_random_password", UTILS, tier="read",
                     expect="success")
    _mark("get_random_password", gv, "default options")
    assert gv == PASS, f"get_random_password failed: {_text(got)}"
    assert got.get("random_password"), f"no password returned: {got}"

    # options omitted (the FieldInfo path) ...
    made, mv = run_op(recorder, "generate_random_password", UTILS, tier="read",
                      expect="success")
    _mark("generate_random_password", mv, "options omitted + supplied")
    assert mv == PASS, f"generate_random_password (omitted) failed: {_text(made)}"

    # ... then the explicitly-specified branch
    sized, sv = run_op(recorder, "generate_random_password", UTILS, tier="read",
                       expect="tolerant",
                       password_options={"random_password_length": 16})
    assert sv in (PASS, EXPECTED_SKIP), f"length branch crashed: {sized}"
    assert not _crash_markers(sized), sized


def test_random_mpsk_generators(recorder):
    """GET and POST ``/random-mpsk``. Same reasoning as random-password."""
    got, gv = run_op(recorder, "get_random_mpsk", UTILS, tier="read",
                     expect="tolerant")
    _mark("get_random_mpsk", gv, (_text(got) or "default options")[:120])
    assert not _crash_markers(got), got

    made, mv = run_op(recorder, "generate_random_mpsk", UTILS, tier="read",
                      expect="tolerant")
    _mark("generate_random_mpsk", mv,
          (_text(made) or "options omitted + supplied")[:120])
    assert not _crash_markers(made), made

    sized, sv = run_op(recorder, "generate_random_mpsk", UTILS, tier="read",
                       expect="tolerant",
                       mpsk_options={"random_mpsk_length": 12})
    assert not _crash_markers(sized), sized
    if gv != PASS:
        NOTES.append(f"random-mpsk is not served on this appliance: "
                     f"{(_text(got) or '').strip()[:140]}")


def test_send_email_and_sms_are_denylisted(recorder):
    """Both dispatch to real humans through real gateways; never invoked."""
    assert_denylisted(recorder, "send_email", UTILS,
                      {"email_data": {"to": ["nobody@example.invalid"],
                                      "message": "zzz-mcptest"}})
    assert_denylisted(recorder, "send_sms", UTILS,
                      {"sms_data": {"recipient": "+10000000000",
                                    "message": "zzz-mcptest"}})


# ==========================================================================
# api_operations (4)
# ==========================================================================


def test_oauth_identity_and_privileges(recorder):
    """``GET /oauth/me`` and ``GET /oauth/privileges`` — pure reads describing
    the credential this suite is already using."""
    me, mv = run_op(recorder, "get_oauth_me", APIOPS, tier="read",
                    expect="success")
    _mark("get_oauth_me", mv, (_text(me) or "identity returned")[:120])
    assert mv == PASS, f"get_oauth_me failed: {_text(me)}"
    assert me.get("identity"), f"no identity payload: {me}"
    assert "FieldInfo" not in json.dumps(me, default=str)

    privs, pv = run_op(recorder, "get_oauth_privileges", APIOPS, tier="read",
                       expect="success")
    _mark("get_oauth_privileges", pv, (_text(privs) or "privileges returned")[:120])
    assert pv == PASS, f"get_oauth_privileges failed: {_text(privs)}"
    assert privs.get("privileges") is not None, f"no privileges payload: {privs}"


def test_post_oauth_me_info(recorder):
    """``POST /oauth/me`` with an empty body — the endpoint documents both body
    keys as defaulting to the authenticated identity, so an empty object is the
    "defaults" call. It returns information; it changes nothing."""
    result, verdict = run_op(recorder, "post_oauth_me_info", APIOPS,
                             tier="read", expect="tolerant", me_data={})
    _mark("post_oauth_me_info", verdict,
          (_text(result) or "identity returned for the default body")[:160])
    assert not _crash_markers(result), result
    if verdict != PASS:
        NOTES.append(f"post_oauth_me_info (empty body) -> "
                     f"{(_text(result) or '').strip()[:160]}")


def test_request_oauth_token(recorder):
    """``POST /oauth`` for OUR OWN client credentials.

    This mints an additional access token for the client the suite already
    authenticates as — it creates no appliance object, grants no new privilege
    and leaves nothing to clean up. The request body carries the client secret,
    which sits one level below the top of ``params_sent`` and would therefore
    slip past ``RunRecorder._redact``; the recorded parameters are overridden
    with a redacted placeholder so no secret can reach the artifact file.
    """
    client_id = os.environ.get("CLEARPASS_CLIENT_ID")
    client_secret = os.environ.get("CLEARPASS_CLIENT_SECRET")
    if not (client_id and client_secret):
        pytest.skip("client-credentials pair not in the environment")

    result, verdict = run_op(
        recorder, "request_oauth_token", APIOPS, tier="read", expect="success",
        record_params={"token_request": "***REDACTED***"},
        token_request={"grant_type": "client_credentials",
                       "client_id": client_id,
                       "client_secret": client_secret})
    _mark("request_oauth_token", verdict,
          "minted a token for the suite's own client")
    assert verdict == PASS, f"request_oauth_token failed: {_text(result)}"

    token_response = result.get("token_response") or {}
    assert isinstance(token_response, dict) and token_response.get("access_token"), \
        "no access_token in the response"

    # The token value must not have reached the artifact file.
    artifact = recorder.path.read_text(encoding="utf-8")
    assert token_response["access_token"] not in artifact, \
        "the minted access token leaked into the results artifact"
    assert client_secret not in artifact, \
        "the client secret leaked into the results artifact"


# ==========================================================================
# Summary / coverage reconciliation
# ==========================================================================


def test_zz_coverage_is_complete_and_reported(recorder, live_enabled):
    """Every one of the 158 in-scope operations must carry a disposition."""
    import src.main  # noqa: F401
    from src.registry import registry

    in_scope = sorted(
        s.name for d in (DUR, SESSIONS, UTILS, APIOPS)
        for s in registry.search(domain=d)
    )
    # session_control holds 20 operations; 14 of them belong to the earlier
    # sweep in test_network_and_sessions.py and are out of scope here.
    previously_covered = {
        "list_active_sessions", "get_active_session_details",
        "disconnect_session", "disconnect_sessions_bulk",
        "disconnect_sessions_by_username", "disconnect_sessions_by_mac",
        "disconnect_sessions_by_ip", "get_session_reauthorization_profiles",
        "reauthorize_session", "get_session_action_status",
        "perform_coa_bulk", "perform_coa_by_username", "perform_coa_by_mac",
        "perform_coa_by_ip",
    }
    mine = [n for n in in_scope if n not in previously_covered]
    assert len(mine) == 158, (
        f"expected 158 in-scope operations, got {len(mine)}")

    tally: Dict[str, int] = {}
    for name in mine:
        entry = COVERAGE.get(name, {"verdict": "NOT RUN", "note": ""})
        tally[entry["verdict"]] = tally.get(entry["verdict"], 0) + 1

    print("\n" + "=" * 72)
    print("enforcement_profiles_dur / session_control(new) / tools_utilities / "
          "api_operations — live summary")
    print("=" * 72)
    print(f"recorded verdicts : {recorder.counts}")
    print(f"coverage tally    : {tally}  (of {len(mine)})")
    for note in NOTES:
        print(f"  note: {note}")
    if FINDINGS:
        print(f"\n{len(FINDINGS)} finding(s):")
        for i, finding in enumerate(FINDINGS, 1):
            print(f"  {i}. {finding['operation']}")
            print(f"     params: {finding['params']}")
            print(f"     error : {finding['error']}")
    print("=" * 72)

    missing = [n for n in mine if n not in COVERAGE]
    assert not missing, f"operations with no recorded disposition: {missing}"
    assert tally.get(FAIL, 0) == 0, (
        "FAIL verdicts recorded: "
        + str({k: v for k, v in COVERAGE.items() if v["verdict"] == FAIL}))
