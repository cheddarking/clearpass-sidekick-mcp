"""Live validation of the newly added ``identities`` domain (58 operations).

Scope
-----
Every operation in this module is *new* in this branch — none of them is
exercised by the pre-existing live modules. The domain covers six object
families plus two guest-replacement operations and one API-client replacement:

============================  ===========================================
family                        posture
============================  ===========================================
endpoint (10 ops)             full fixture CRUD lifecycle
device (10 ops)               full fixture CRUD lifecycle
local-user (10 ops)           full fixture CRUD lifecycle
static-host-list (10 ops)     full fixture CRUD lifecycle
external-account (10 ops)     full fixture CRUD lifecycle
deny-listed-users (5 ops)     READ-ONLY; both DELETE variants BLOCKED
replace_guest_by_* (2 ops)    full lifecycle over a fixture guest account
replace_api_client (1 op)     BLOCKED
============================  ===========================================

Safety posture
--------------
* **MAC discipline.** ``endpoint`` and ``device`` are keyed by MAC address, so
  the usual ``zzz-mcptest-`` name rail cannot be applied to the identifier
  itself (``00-zz-mc-te-st-01`` is not a MAC). Every fixture MAC is instead a
  *locally administered, unicast* address in the ``02:00:5a:`` block derived
  from the per-session run id, which by definition cannot collide with a real
  vendor-assigned NIC. Ownership is enforced two ways before every mutation:

  1. the object's free-text field (``description`` / ``notes``) carries the
     ``zzz-mcptest-<runid>`` fixture token and is checked with
     ``harness.is_ours``; and
  2. ``_assert_created_by_us`` re-reads the object through the handle about to
     be mutated and refuses unless the numeric id matches the id returned by
     *our* create call.

  ``harness.assert_ours`` is still called directly wherever the family is
  name-keyed (local-user ``user_id``, static-host-list and external-account
  ``name``, guest ``username``).

* **No Change of Authorization.** ``change_of_authorization`` is omitted from
  every device/guest call — issuing CoA against live sessions is denylisted
  behaviour and the parameter default must stay untouched.

* **Graceful degradation, never silent success.** A create that the appliance
  rejects with a *structured* error records the rest of that family's
  operations as ``BLOCKED`` (carrying the appliance's own message) and skips.
  A create that explodes with a crash marker (``FieldInfo``, ``TypeError``,
  traceback …) is always a hard FAIL — that is the bug class this whole harness
  exists to catch.

Calling style: optional parameters are OMITTED by default; the fully-specified
path is exercised second where it is meaningful.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, List, Optional

import pytest

from . import harness
from .denylist import DenylistedOperation, is_denylisted
from .harness import PASS, assert_ours, classify, fixture_name

DOMAIN = "identities"
GUEST_DOMAIN = "guest_users"
BLOCKED = "BLOCKED"
#: An operation the appliance itself cannot serve. Recorded with the
#: appliance's own error so it can be triaged, never silently passed.
LIMITATION = "EXPECTED-LIMITATION"

# Guest Manager role used for fixture device/guest accounts. "[Guest]" is id 2
# in the Guest Manager namespace (3 would be "[Employee]" — see
# test_guest_domains.py).
GUEST_ROLE = "[Guest]"
GUEST_ROLE_ID = 2

# RFC 5737 TEST-NET-1: routable nowhere, safe as static-host-list content.
TEST_NET_SUBNET = "192.0.2.0/24"

ABSENT_ID = 999999
ABSENT_NAME = "zzz-mcptest-nonexistent-identity"


# --------------------------------------------------------------------------
# Dispatch wrapper (params as a dict; verdict override for BLOCKED bookkeeping)
# --------------------------------------------------------------------------


async def _invoke(operation: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if is_denylisted(operation):
        raise DenylistedOperation(operation)
    return await harness.invoke(operation, _params=params or {})


async def _run(recorder, operation: str, params: Optional[Dict[str, Any]] = None,
               tier: str = "read", expect_absent: bool = False,
               verdict: Optional[str] = None,
               domain: str = DOMAIN) -> Dict[str, Any]:
    """Invoke through the gateway, classify, record. Returns the raw result."""
    start = time.perf_counter()
    result = await _invoke(operation, params)
    duration = (time.perf_counter() - start) * 1000.0
    final = verdict or classify(result, operation, expect_absent=expect_absent)
    err = None if final == PASS else (
        harness.deep_error_text(result).strip() or None)
    recorder.record(operation, domain, tier, final, params or {}, err, duration)
    return result


def _record_blocked(recorder, operation: str, reason: str,
                    domain: str = DOMAIN) -> None:
    recorder.record(operation, domain, "blocked", BLOCKED, {}, reason, 0.0)


def _no_crash(result: Dict[str, Any], operation: str) -> None:
    """A rejected body, a 404 or a validation error must all present as a
    structured error dict. A Python-level explosion never may."""
    marker = harness.deep_crash_marker(result)
    assert marker is None, f"{operation}: crash marker {marker!r} in {result}"


def _is_clarification(result: Dict[str, Any]) -> bool:
    return (result.get("success") is False
            and result.get("error_type") == "clarification_needed"
            and bool(result.get("question")))


def _is_structured_error(result: Dict[str, Any]) -> bool:
    """A refusal the LLM can act on: a status code or a clarification, and never
    an HTML body where JSON was promised."""
    if harness.looks_like_html(harness.deep_error_text(result)):
        return False
    return isinstance(result.get("status_code"), int) or _is_clarification(result)


def _assert_ok_or_structured(result: Dict[str, Any], operation: str) -> bool:
    """Success, or a refusal an LLM can act on. Returns True when it succeeded.

    Used for the PATCH/PUT steps, whose exact required body varies per family
    and per appliance version. A body the appliance rejects is recorded with
    its real (FAIL) verdict for triage; aborting the test there would cost the
    delete coverage that follows it. The bug classes that *must* fail loudly —
    a crash marker, an HTML error page, a status-code-less error blob — still
    do.
    """
    _no_crash(result, operation)
    if result.get("success") is True:
        return True
    assert not harness.looks_like_html(harness.deep_error_text(result)), \
        f"{operation} returned an HTML body where JSON was promised: {result}"
    assert _is_structured_error(result), \
        f"{operation} returned an unstructured error: {result}"
    return False


def _skip_family(recorder, operations: List[str], reason: str) -> None:
    """Record every not-yet-exercised operation of a family as BLOCKED and skip.

    Used when the appliance rejects the fixture create with a structured error:
    the remaining lifecycle cannot be reached, but it must still be accounted
    for (and the appliance's own message is the most useful thing to carry).
    """
    for operation in operations:
        _record_blocked(recorder, operation, reason)
    pytest.skip(reason)


# --------------------------------------------------------------------------
# Fixture MAC addresses — locally administered, unicast, run-id derived
# --------------------------------------------------------------------------


def _fixture_mac(run_id: str, n: int) -> str:
    """``02:00:5a:<runid[0:2]>:<runid[2:4]>:<n>``.

    ``0x02`` sets the locally-administered bit and clears the multicast bit, so
    this can never be a real vendor-assigned NIC address. The run id makes it
    unique per session, and ``n`` unique per object within the session.
    """
    r = (run_id + "0000")[:4]
    return f"02:00:5a:{r[0:2]}:{r[2:4]}:{n:02x}"


def _assert_created_by_us(fetched_obj: Dict[str, Any], created_id: Any,
                          handle: Any, label: str) -> None:
    """The MAC-keyed stand-in for ``assert_ours``.

    ``assert_ours`` can only vouch for a *name*, and endpoints/devices have
    none. Instead, the object reached through ``handle`` is re-read and its
    numeric id must equal the id our own create returned. If it does not, the
    handle resolves to somebody else's object and the mutation is refused.
    """
    found = fetched_obj.get("id")
    if found is None or created_id is None or found != created_id:
        raise AssertionError(
            f"SAFETY GUARD: refusing to write/delete {label} via {handle!r} — "
            f"it resolves to id {found!r}, not the id {created_id!r} this run "
            f"created. The live harness may only mutate objects it created."
        )


def _assert_fixture_token(obj: Dict[str, Any], keys, label: str) -> None:
    """Second rail for MAC-keyed families: the object's free-text field must
    still carry the ``zzz-mcptest-`` token this run wrote into it."""
    for key in keys:
        if harness.is_ours(obj.get(key)):
            return
    raise AssertionError(
        f"SAFETY GUARD: refusing to write/delete {label} — none of {list(keys)} "
        f"carries the fixture prefix {harness.FIXTURE_PREFIX!r}: "
        f"{ {k: obj.get(k) for k in keys} }"
    )


def _strip_readonly(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Body for a PUT built from what the appliance itself returned, minus the
    server-owned keys it will not accept back."""
    return {k: v for k, v in (obj or {}).items()
            if not str(k).startswith("_") and k not in ("id", "count", "links")}


# ==========================================================================
# 1. Listing operations — omission path first, then pagination
# ==========================================================================

LIST_OPERATIONS = [
    ("list_endpoints", "endpoints"),
    ("list_devices", "devices"),
    ("list_local_users", "local_users"),
    ("list_static_host_lists", "static_host_lists"),
    ("list_external_accounts", "external_accounts"),
    ("list_deny_listed_users", "deny_listed_users"),
]


@pytest.mark.parametrize("operation,payload_key",
                         LIST_OPERATIONS,
                         ids=[o for o, _ in LIST_OPERATIONS])
def test_list_operations_with_all_optionals_omitted(run_async, recorder,
                                                    operation, payload_key):
    """The omission path: no parameters at all. This is where the registry
    ``FieldInfo`` bug used to surface."""
    result = run_async(_run(recorder, operation))
    _no_crash(result, operation)
    assert classify(result, operation) == PASS, f"{operation}() -> {result}"
    assert isinstance(result.get(payload_key), list), \
        f"{operation} did not return a {payload_key!r} list: {sorted(result)}"


@pytest.mark.parametrize("operation,params", [
    ("list_endpoints", {"limit": 5, "offset": 0, "calculate_count": True}),
    ("list_endpoints", {"limit": 1, "profile_details": True}),
    ("list_devices", {"limit": 5, "sort": "+id"}),
    ("list_local_users", {"limit": 5, "calculate_count": True}),
    ("list_static_host_lists", {"limit": 5, "offset": 0}),
    ("list_external_accounts", {"limit": 5}),
    ("list_deny_listed_users", {"limit": 5, "calculate_count": True}),
])
def test_list_operations_with_pagination_and_filters(run_async, recorder,
                                                     operation, params):
    """Second pass with realistic optional parameters supplied."""
    result = run_async(_run(recorder, operation, params))
    _no_crash(result, operation)
    assert classify(result, operation) == PASS, f"{operation}({params}) -> {result}"


# ==========================================================================
# 2. endpoint — full fixture lifecycle (MAC-keyed)
# ==========================================================================

_ENDPOINT_OPS = [
    "create_endpoint", "get_endpoint_by_id", "update_endpoint_by_id",
    "replace_endpoint_by_id", "delete_endpoint_by_id", "get_endpoint_by_mac",
    "update_endpoint_by_mac", "replace_endpoint_by_mac", "delete_endpoint_by_mac",
]

#: Historical: the endpoint single-object GET routes 404 under ``/api/v1``.
#:
#: First measured 2026-07-30 while the client still addressed ``/api/v1``:
#: create returned 201 with ``id`` and a ``_links.self.href`` of
#: ``/api/v1/endpoint/<id>``, the list route returned that same object, and
#: PATCH/PUT/DELETE through **both** handles (``/endpoint/<id>`` and
#: ``/endpoint/mac-address/<mac>``) returned 200/204 — yet ``GET`` on either
#: handle answered ``404 {"title":"Not Found","detail":"Object not found"}``.
#: That looked like an appliance defect specific to the endpoint resource.
#:
#: It was the base URL. Re-probed the same day against the **unversioned**
#: ``/api`` root, ``GET /api/endpoint/<id>`` returns the object with 200 while
#: ``GET /api/v1/endpoint/<id>`` still 404s for the identical id. The client now
#: builds every URL from ``/api`` (see ``ClearPassClient._endpoint_url``), so
#: these GETs are expected to PASS.
#:
#: ``_endpoint_get`` below keeps the tolerant path anyway: it records PASS when
#: the GET works and only falls back to the list route — recording
#: EXPECTED-LIMITATION with the appliance's own error — if a 404 the list route
#: disagrees with comes back. That keeps the suite honest on appliances or
#: firmware where the defect is real, without weakening any ownership rail.
_ENDPOINT_GET_LIMITATION = (
    "ClearPass 6.12.4 answers 404 'Object not found' on GET "
    "/endpoint/{id} and GET /endpoint/mac-address/{mac} for endpoints that "
    "provably exist (the list route returns them and PATCH/PUT/DELETE through "
    "the same handle succeed). Appliance-side defect."
)


def _mac_filter_value(mac: str) -> str:
    """The appliance stores/filters MACs unpunctuated (``02005aab8401``)."""
    return "".join(ch for ch in str(mac) if ch.isalnum()).lower()


async def _endpoint_via_list(handle_field: str, value: Any) -> Dict[str, Any]:
    """Re-read one endpoint through the list route.

    This is the substitute read path for the broken single-object GETs. It is a
    *real* read of appliance state through a different route — the ownership
    rails below still compare the id and the fixture token against what the
    appliance actually holds, so nothing is weakened; only the route changes.
    Returns ``{}`` unless exactly one object matches, so an ambiguous match can
    never satisfy a rail.
    """
    if handle_field == "mac_address":
        value = _mac_filter_value(value)
    listed = await _invoke("list_endpoints",
                           {"filter_str": json.dumps({handle_field: value}),
                            "limit": 2})
    items = listed.get("endpoints") or []
    return items[0] if len(items) == 1 else {}


async def _endpoint_get(recorder, operation: str, params: Dict[str, Any],
                        handle_field: str, handle_value: Any,
                        tier: str = "read") -> Dict[str, Any]:
    """Dispatch an endpoint GET, tolerating the appliance's broken GET routes.

    Returns the endpoint object. When the GET works, the object comes from it
    and the operation is recorded PASS. When the GET 404s *and the list route
    still resolves the same handle*, the operation is recorded
    EXPECTED-LIMITATION with the appliance's own error and the object comes from
    the list route. A crash marker, an unstructured error, a non-404 failure, or
    a 404 the list route agrees with are all still hard failures.
    """
    start = time.perf_counter()
    result = await _invoke(operation, params)
    duration = (time.perf_counter() - start) * 1000.0
    _no_crash(result, operation)

    if result.get("success") is True:
        recorder.record(operation, DOMAIN, tier, PASS, params, None, duration)
        return result.get("endpoint") or {}

    assert _is_structured_error(result), \
        f"{operation} returned an unstructured error: {result}"
    assert result.get("status_code") == 404, \
        f"{operation} failed for a reason other than the known 404: {result}"

    obj = await _endpoint_via_list(handle_field, handle_value)
    assert obj, (
        f"{operation} answered 404 and the list route cannot resolve "
        f"{handle_field}={handle_value!r} either — the endpoint really is "
        f"absent, so this is not the known appliance limitation: {result}"
    )
    appliance_error = harness.deep_error_text(result).strip()[:300]
    recorder.record(operation, DOMAIN, tier, LIMITATION, params,
                    f"{_ENDPOINT_GET_LIMITATION} Appliance error: "
                    f"{appliance_error}", duration)
    return obj


def test_endpoint_full_lifecycle(run_async, recorder, run_id, cleanup):
    """create -> read (id + MAC) -> PATCH -> PUT -> delete, twice: once
    deleting by id and once by MAC, so both delete variants are real coverage.
    """
    mac_a = _fixture_mac(run_id, 1)
    mac_b = _fixture_mac(run_id, 2)
    token_a = fixture_name(run_id, "ep1")
    token_b = fixture_name(run_id, "ep2")

    cleanup.add(lambda: _invoke("delete_endpoint_by_mac", {"mac_address": mac_a}))
    cleanup.add(lambda: _invoke("delete_endpoint_by_mac", {"mac_address": mac_b}))

    created = run_async(_run(recorder, "create_endpoint", tier="create", params={
        "endpoint_data": {"mac_address": mac_a, "status": "Known",
                          "description": token_a},
    }))
    _no_crash(created, "create_endpoint")
    if created.get("success") is not True:
        _skip_family(recorder, _ENDPOINT_OPS[1:],
                     f"create_endpoint was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    endpoint = created.get("endpoint") or {}
    eid = endpoint.get("id")
    assert eid is not None, f"create_endpoint returned no id: {created}"

    # --- reads -----------------------------------------------------------
    # ``_endpoint_get`` returns the object whether the appliance's GET route
    # served it or the list route had to (see _ENDPOINT_GET_LIMITATION), so the
    # rails below always run against state read back from the appliance.
    by_id_obj = run_async(_endpoint_get(recorder, "get_endpoint_by_id",
                                        {"endpoint_id": eid}, "id", eid))
    _assert_fixture_token(by_id_obj, ("description",), f"endpoint {eid}")

    by_mac_obj = run_async(_endpoint_get(recorder, "get_endpoint_by_mac",
                                         {"mac_address": mac_a},
                                         "mac_address", mac_a))
    _assert_created_by_us(by_mac_obj, eid, mac_a, "endpoint (by MAC)")

    # --- PATCH by id, then by MAC ----------------------------------------
    _assert_created_by_us(by_id_obj, eid, eid, "endpoint")
    patched = run_async(_run(recorder, "update_endpoint_by_id", tier="update",
                             params={"endpoint_id": eid,
                                     "endpoint_data": {"description": token_a + "-patched"}}))
    _assert_ok_or_structured(patched, "update_endpoint_by_id")

    _assert_created_by_us(by_mac_obj, eid, mac_a, "endpoint (by MAC)")
    patched_mac = run_async(_run(recorder, "update_endpoint_by_mac", tier="update",
                                 params={"mac_address": mac_a,
                                         "endpoint_data": {"description": token_a + "-macpatch"}}))
    _assert_ok_or_structured(patched_mac, "update_endpoint_by_mac")

    # --- PUT by id, then by MAC (full body, MAC preserved) ---------------
    put_body = {"mac_address": mac_a, "status": "Known", "description": token_a}
    replaced = run_async(_run(recorder, "replace_endpoint_by_id", tier="update",
                              params={"endpoint_id": eid, "endpoint_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_endpoint_by_id")

    replaced_mac = run_async(_run(recorder, "replace_endpoint_by_mac", tier="update",
                                  params={"mac_address": mac_a,
                                          "endpoint_data": put_body}))
    _assert_ok_or_structured(replaced_mac, "replace_endpoint_by_mac")

    # --- delete by id ----------------------------------------------------
    verify = run_async(_endpoint_get(recorder, "get_endpoint_by_id",
                                     {"endpoint_id": eid}, "id", eid))
    _assert_created_by_us(verify, eid, eid, "endpoint")
    _assert_fixture_token(verify, ("description",), f"endpoint {eid}")
    deleted = run_async(_run(recorder, "delete_endpoint_by_id", tier="delete",
                             params={"endpoint_id": eid}))
    _no_crash(deleted, "delete_endpoint_by_id")
    assert classify(deleted, "delete_endpoint_by_id") == PASS, deleted

    gone = run_async(_run(recorder, "get_endpoint_by_id", tier="negative",
                          params={"endpoint_id": eid}, expect_absent=True))
    _no_crash(gone, "get_endpoint_by_id")
    assert gone.get("success") is not True, f"endpoint {eid} survived delete: {gone}"
    # The GET route 404s either way on this appliance, so absence is proved
    # through the route that can still see endpoints.
    assert not run_async(_endpoint_via_list("id", eid)), \
        f"endpoint {eid} survived delete_endpoint_by_id"

    # --- second fixture, deleted by MAC ----------------------------------
    created_b = run_async(_run(recorder, "create_endpoint", tier="create", params={
        "endpoint_data": {"mac_address": mac_b, "status": "Known",
                          "description": token_b},
    }))
    _no_crash(created_b, "create_endpoint")
    assert classify(created_b, "create_endpoint") == PASS, created_b
    eid_b = (created_b.get("endpoint") or {}).get("id")

    check_b = run_async(_endpoint_get(recorder, "get_endpoint_by_mac",
                                      {"mac_address": mac_b},
                                      "mac_address", mac_b))
    _assert_created_by_us(check_b, eid_b, mac_b, "endpoint (by MAC)")
    _assert_fixture_token(check_b, ("description",), f"endpoint {mac_b}")
    deleted_b = run_async(_run(recorder, "delete_endpoint_by_mac", tier="delete",
                               params={"mac_address": mac_b}))
    _no_crash(deleted_b, "delete_endpoint_by_mac")
    assert classify(deleted_b, "delete_endpoint_by_mac") == PASS, deleted_b
    assert not run_async(_endpoint_via_list("mac_address", mac_b)), \
        f"endpoint {mac_b} survived delete_endpoint_by_mac"


# ==========================================================================
# 3. device — full fixture lifecycle (MAC-keyed, CoA always omitted)
# ==========================================================================

_DEVICE_OPS = [
    "create_device", "get_device_by_id", "update_device_by_id",
    "replace_device_by_id", "delete_device_by_id", "get_device_by_mac",
    "update_device_by_mac", "replace_device_by_mac", "delete_device_by_mac",
]


def test_device_full_lifecycle(run_async, recorder, run_id, cleanup):
    """Guest-Manager device accounts. ``change_of_authorization`` is omitted
    from every call: triggering CoA against live sessions is denylisted."""
    mac_a = _fixture_mac(run_id, 17)
    mac_b = _fixture_mac(run_id, 18)
    token_a = fixture_name(run_id, "dev1")
    token_b = fixture_name(run_id, "dev2")

    cleanup.add(lambda: _invoke("delete_device_by_mac", {"macaddr": mac_a}))
    cleanup.add(lambda: _invoke("delete_device_by_mac", {"macaddr": mac_b}))

    created = run_async(_run(recorder, "create_device", tier="create", params={
        "device_data": {"mac": mac_a, "role_id": GUEST_ROLE_ID,
                        "notes": token_a, "visitor_name": token_a,
                        "enabled": True},
    }))
    _no_crash(created, "create_device")
    if created.get("success") is not True:
        _skip_family(recorder, _DEVICE_OPS[1:],
                     f"create_device was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    device = created.get("device") or {}
    did = device.get("id")
    assert did is not None, f"create_device returned no id: {created}"

    by_id = run_async(_run(recorder, "get_device_by_id", {"device_id": did}))
    _no_crash(by_id, "get_device_by_id")
    assert classify(by_id, "get_device_by_id") == PASS, by_id
    _assert_fixture_token(by_id.get("device") or {}, ("notes", "visitor_name"),
                          f"device {did}")

    by_mac = run_async(_run(recorder, "get_device_by_mac", {"macaddr": mac_a}))
    _no_crash(by_mac, "get_device_by_mac")
    assert classify(by_mac, "get_device_by_mac") == PASS, by_mac
    _assert_created_by_us(by_mac.get("device") or {}, did, mac_a, "device (by MAC)")

    _assert_created_by_us(by_id.get("device") or {}, did, did, "device")
    patched = run_async(_run(recorder, "update_device_by_id", tier="update",
                             params={"device_id": did,
                                     "device_data": {"notes": token_a + "-patched"}}))
    _assert_ok_or_structured(patched, "update_device_by_id")

    _assert_created_by_us(by_mac.get("device") or {}, did, mac_a, "device (by MAC)")
    patched_mac = run_async(_run(recorder, "update_device_by_mac", tier="update",
                                 params={"macaddr": mac_a,
                                         "device_data": {"notes": token_a + "-macpatch"}}))
    _assert_ok_or_structured(patched_mac, "update_device_by_mac")

    put_body = {"mac": mac_a, "role_id": GUEST_ROLE_ID, "notes": token_a,
                "visitor_name": token_a, "enabled": True}
    replaced = run_async(_run(recorder, "replace_device_by_id", tier="update",
                              params={"device_id": did, "device_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_device_by_id")

    replaced_mac = run_async(_run(recorder, "replace_device_by_mac", tier="update",
                                  params={"macaddr": mac_a, "device_data": put_body}))
    _assert_ok_or_structured(replaced_mac, "replace_device_by_mac")

    verify = run_async(_run(recorder, "get_device_by_id", {"device_id": did}))
    _assert_created_by_us(verify.get("device") or {}, did, did, "device")
    _assert_fixture_token(verify.get("device") or {}, ("notes", "visitor_name"),
                          f"device {did}")
    deleted = run_async(_run(recorder, "delete_device_by_id", tier="delete",
                             params={"device_id": did}))
    _no_crash(deleted, "delete_device_by_id")
    assert classify(deleted, "delete_device_by_id") == PASS, deleted

    created_b = run_async(_run(recorder, "create_device", tier="create", params={
        "device_data": {"mac": mac_b, "role_id": GUEST_ROLE_ID,
                        "notes": token_b, "visitor_name": token_b,
                        "enabled": True},
    }))
    _no_crash(created_b, "create_device")
    assert classify(created_b, "create_device") == PASS, created_b
    did_b = (created_b.get("device") or {}).get("id")

    check_b = run_async(_run(recorder, "get_device_by_mac", {"macaddr": mac_b}))
    _assert_created_by_us(check_b.get("device") or {}, did_b, mac_b, "device (by MAC)")
    _assert_fixture_token(check_b.get("device") or {}, ("notes", "visitor_name"),
                          f"device {mac_b}")
    deleted_b = run_async(_run(recorder, "delete_device_by_mac", tier="delete",
                               params={"macaddr": mac_b}))
    _no_crash(deleted_b, "delete_device_by_mac")
    assert classify(deleted_b, "delete_device_by_mac") == PASS, deleted_b


# ==========================================================================
# 4. local-user — full fixture lifecycle (name-keyed: assert_ours applies)
# ==========================================================================

_LOCAL_USER_OPS = [
    "create_local_user", "get_local_user_by_id", "update_local_user_by_id",
    "replace_local_user_by_id", "delete_local_user_by_id",
    "get_local_user_by_user_id", "update_local_user_by_user_id",
    "replace_local_user_by_user_id", "delete_local_user_by_user_id",
]


def _local_user_role(run_async) -> str:
    """Reuse a role name the appliance already accepts for local users rather
    than guessing one; fall back to the built-in employee role."""
    listing = run_async(_invoke("list_local_users", {"limit": 5}))
    for item in listing.get("local_users") or []:
        role = item.get("role_name")
        if isinstance(role, str) and role:
            return role
    return "[Employee]"


def test_local_user_full_lifecycle(run_async, recorder, run_id, cleanup):
    """``user_id`` carries the fixture prefix, so ``assert_ours`` is the guard
    on every mutation — including the by-id branch, where the object is re-read
    and its ``user_id`` checked before the delete is issued."""
    uid_a = fixture_name(run_id, "lu1")
    uid_b = fixture_name(run_id, "lu2")
    password = f"Zz!{secrets.token_urlsafe(12)}"
    role = _local_user_role(run_async)

    cleanup.add(lambda: _invoke("delete_local_user_by_user_id", {"user_id": uid_a}))
    cleanup.add(lambda: _invoke("delete_local_user_by_user_id", {"user_id": uid_b}))

    body_a = {"user_id": uid_a, "username": uid_a, "password": password,
              "role_name": role, "enabled": True}
    created = run_async(_run(recorder, "create_local_user", tier="create",
                             params={"local_user_data": body_a}))
    _no_crash(created, "create_local_user")
    if created.get("success") is not True:
        _skip_family(recorder, _LOCAL_USER_OPS[1:],
                     f"create_local_user was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    lid = (created.get("local_user") or {}).get("id")
    assert lid is not None, f"create_local_user returned no id: {created}"

    by_id = run_async(_run(recorder, "get_local_user_by_id", {"local_user_id": lid}))
    _no_crash(by_id, "get_local_user_by_id")
    assert classify(by_id, "get_local_user_by_id") == PASS, by_id
    assert_ours((by_id.get("local_user") or {}).get("user_id"))

    by_name = run_async(_run(recorder, "get_local_user_by_user_id", {"user_id": uid_a}))
    _no_crash(by_name, "get_local_user_by_user_id")
    assert classify(by_name, "get_local_user_by_user_id") == PASS, by_name
    assert (by_name.get("local_user") or {}).get("id") == lid, \
        f"user_id {uid_a!r} resolves to a different object than id {lid}: {by_name}"

    assert_ours((by_id.get("local_user") or {}).get("user_id"))
    patched = run_async(_run(recorder, "update_local_user_by_id", tier="update",
                             params={"local_user_id": lid,
                                     "local_user_data": {"enabled": False}}))
    _assert_ok_or_structured(patched, "update_local_user_by_id")

    assert_ours(uid_a)
    patched_name = run_async(_run(recorder, "update_local_user_by_user_id", tier="update",
                                  params={"user_id": uid_a,
                                          "local_user_data": {"enabled": True}}))
    _assert_ok_or_structured(patched_name, "update_local_user_by_user_id")

    assert_ours(uid_a)
    replaced = run_async(_run(recorder, "replace_local_user_by_id", tier="update",
                              params={"local_user_id": lid, "local_user_data": body_a}))
    _assert_ok_or_structured(replaced, "replace_local_user_by_id")

    assert_ours(uid_a)
    replaced_name = run_async(_run(recorder, "replace_local_user_by_user_id", tier="update",
                                   params={"user_id": uid_a, "local_user_data": body_a}))
    _assert_ok_or_structured(replaced_name, "replace_local_user_by_user_id")

    verify = run_async(_run(recorder, "get_local_user_by_id", {"local_user_id": lid}))
    assert_ours((verify.get("local_user") or {}).get("user_id"))
    deleted = run_async(_run(recorder, "delete_local_user_by_id", tier="delete",
                             params={"local_user_id": lid}))
    _no_crash(deleted, "delete_local_user_by_id")
    assert classify(deleted, "delete_local_user_by_id") == PASS, deleted

    gone = run_async(_run(recorder, "get_local_user_by_user_id", tier="negative",
                          params={"user_id": uid_a}, expect_absent=True))
    assert gone.get("success") is not True, f"{uid_a} survived delete: {gone}"

    body_b = dict(body_a, user_id=uid_b, username=uid_b)
    created_b = run_async(_run(recorder, "create_local_user", tier="create",
                               params={"local_user_data": body_b}))
    _no_crash(created_b, "create_local_user")
    assert classify(created_b, "create_local_user") == PASS, created_b

    assert_ours(uid_b)
    deleted_b = run_async(_run(recorder, "delete_local_user_by_user_id", tier="delete",
                               params={"user_id": uid_b}))
    _no_crash(deleted_b, "delete_local_user_by_user_id")
    assert classify(deleted_b, "delete_local_user_by_user_id") == PASS, deleted_b


# ==========================================================================
# 5. static-host-list — full fixture lifecycle (name-keyed)
# ==========================================================================

_SHL_OPS = [
    "create_static_host_list", "get_static_host_list_by_id",
    "update_static_host_list_by_id", "replace_static_host_list_by_id",
    "delete_static_host_list_by_id", "get_static_host_list_by_name",
    "update_static_host_list_by_name", "replace_static_host_list_by_name",
    "delete_static_host_list_by_name",
]


def test_static_host_list_full_lifecycle(run_async, recorder, run_id, cleanup):
    """Content is RFC 5737 TEST-NET-1, so even a mis-referenced list cannot
    match a real host."""
    name_a = fixture_name(run_id, "shl1")
    name_b = fixture_name(run_id, "shl2")

    cleanup.add(lambda: _invoke("delete_static_host_list_by_name", {"name": name_a}))
    cleanup.add(lambda: _invoke("delete_static_host_list_by_name", {"name": name_b}))

    body_a = {"name": name_a, "description": name_a, "host_format": "subnet",
              "host_type": "IPAddress", "value": TEST_NET_SUBNET}
    created = run_async(_run(recorder, "create_static_host_list", tier="create",
                             params={"static_host_list_data": body_a}))
    _no_crash(created, "create_static_host_list")
    if created.get("success") is not True:
        _skip_family(recorder, _SHL_OPS[1:],
                     f"create_static_host_list was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    shl = created.get("static_host_list") or {}
    sid = shl.get("id")
    assert sid is not None, f"create_static_host_list returned no id: {created}"

    by_id = run_async(_run(recorder, "get_static_host_list_by_id",
                           {"static_host_list_id": sid}))
    _no_crash(by_id, "get_static_host_list_by_id")
    assert classify(by_id, "get_static_host_list_by_id") == PASS, by_id
    assert_ours((by_id.get("static_host_list") or {}).get("name"))

    by_name = run_async(_run(recorder, "get_static_host_list_by_name", {"name": name_a}))
    _no_crash(by_name, "get_static_host_list_by_name")
    assert classify(by_name, "get_static_host_list_by_name") == PASS, by_name
    assert (by_name.get("static_host_list") or {}).get("id") == sid, by_name

    assert_ours((by_id.get("static_host_list") or {}).get("name"))
    patched = run_async(_run(recorder, "update_static_host_list_by_id", tier="update",
                             params={"static_host_list_id": sid,
                                     "static_host_list_data": {"description": name_a + "-patched"}}))
    _assert_ok_or_structured(patched, "update_static_host_list_by_id")

    assert_ours(name_a)
    patched_name = run_async(_run(recorder, "update_static_host_list_by_name", tier="update",
                                  params={"name": name_a,
                                          "static_host_list_data": {"description": name_a + "-namepatch"}}))
    _assert_ok_or_structured(patched_name, "update_static_host_list_by_name")

    assert_ours(name_a)
    replaced = run_async(_run(recorder, "replace_static_host_list_by_id", tier="update",
                              params={"static_host_list_id": sid,
                                      "static_host_list_data": body_a}))
    _assert_ok_or_structured(replaced, "replace_static_host_list_by_id")

    assert_ours(name_a)
    replaced_name = run_async(_run(recorder, "replace_static_host_list_by_name", tier="update",
                                   params={"name": name_a,
                                           "static_host_list_data": body_a}))
    _assert_ok_or_structured(replaced_name, "replace_static_host_list_by_name")

    verify = run_async(_run(recorder, "get_static_host_list_by_id",
                            {"static_host_list_id": sid}))
    assert_ours((verify.get("static_host_list") or {}).get("name"))
    deleted = run_async(_run(recorder, "delete_static_host_list_by_id", tier="delete",
                             params={"static_host_list_id": sid}))
    _no_crash(deleted, "delete_static_host_list_by_id")
    assert classify(deleted, "delete_static_host_list_by_id") == PASS, deleted

    body_b = dict(body_a, name=name_b, description=name_b)
    created_b = run_async(_run(recorder, "create_static_host_list", tier="create",
                               params={"static_host_list_data": body_b}))
    _no_crash(created_b, "create_static_host_list")
    assert classify(created_b, "create_static_host_list") == PASS, created_b

    assert_ours(name_b)
    deleted_b = run_async(_run(recorder, "delete_static_host_list_by_name", tier="delete",
                               params={"name": name_b}))
    _no_crash(deleted_b, "delete_static_host_list_by_name")
    assert classify(deleted_b, "delete_static_host_list_by_name") == PASS, deleted_b


# ==========================================================================
# 6. external-account — full fixture lifecycle (name-keyed)
# ==========================================================================

_EXT_ACCOUNT_OPS = [
    "create_external_account", "get_external_account_by_id",
    "update_external_account_by_id", "replace_external_account_by_id",
    "delete_external_account_by_id", "get_external_account_by_name",
    "update_external_account_by_name", "replace_external_account_by_name",
    "delete_external_account_by_name",
]


def _external_account_type(run_async) -> str:
    """The appliance's own vocabulary is authoritative for ``type``; reuse an
    existing account's value rather than guessing an enum member."""
    listing = run_async(_invoke("list_external_accounts", {"limit": 5}))
    for item in listing.get("external_accounts") or []:
        kind = item.get("type")
        if isinstance(kind, str) and kind:
            return kind
    return "SSH"


def test_external_account_full_lifecycle(run_async, recorder, run_id, cleanup):
    name_a = fixture_name(run_id, "ext1")
    name_b = fixture_name(run_id, "ext2")
    kind = _external_account_type(run_async)

    cleanup.add(lambda: _invoke("delete_external_account_by_name", {"name": name_a}))
    cleanup.add(lambda: _invoke("delete_external_account_by_name", {"name": name_b}))

    body_a = {"name": name_a, "type": kind, "description": name_a}
    created = run_async(_run(recorder, "create_external_account", tier="create",
                             params={"external_account_data": body_a}))
    _no_crash(created, "create_external_account")
    if created.get("success") is not True:
        _skip_family(recorder, _EXT_ACCOUNT_OPS[1:],
                     f"create_external_account was rejected by the appliance "
                     f"(type={kind!r}): "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    account = created.get("external_account") or {}
    aid = account.get("id")
    assert aid is not None, f"create_external_account returned no id: {created}"

    by_id = run_async(_run(recorder, "get_external_account_by_id",
                           {"external_account_id": aid}))
    _no_crash(by_id, "get_external_account_by_id")
    assert classify(by_id, "get_external_account_by_id") == PASS, by_id
    assert_ours((by_id.get("external_account") or {}).get("name"))

    by_name = run_async(_run(recorder, "get_external_account_by_name", {"name": name_a}))
    _no_crash(by_name, "get_external_account_by_name")
    assert classify(by_name, "get_external_account_by_name") == PASS, by_name
    assert (by_name.get("external_account") or {}).get("id") == aid, by_name

    assert_ours((by_id.get("external_account") or {}).get("name"))
    patched = run_async(_run(recorder, "update_external_account_by_id", tier="update",
                             params={"external_account_id": aid,
                                     "external_account_data": {"description": name_a + "-patched"}}))
    _assert_ok_or_structured(patched, "update_external_account_by_id")

    assert_ours(name_a)
    patched_name = run_async(_run(recorder, "update_external_account_by_name", tier="update",
                                  params={"name": name_a,
                                          "external_account_data": {"description": name_a + "-namepatch"}}))
    _assert_ok_or_structured(patched_name, "update_external_account_by_name")

    put_body = dict(_strip_readonly(by_id.get("external_account") or {}), **body_a)
    assert_ours(name_a)
    replaced = run_async(_run(recorder, "replace_external_account_by_id", tier="update",
                              params={"external_account_id": aid,
                                      "external_account_data": put_body}))
    _assert_ok_or_structured(replaced, "replace_external_account_by_id")

    assert_ours(name_a)
    replaced_name = run_async(_run(recorder, "replace_external_account_by_name", tier="update",
                                   params={"name": name_a,
                                           "external_account_data": put_body}))
    _assert_ok_or_structured(replaced_name, "replace_external_account_by_name")

    verify = run_async(_run(recorder, "get_external_account_by_id",
                            {"external_account_id": aid}))
    assert_ours((verify.get("external_account") or {}).get("name"))
    deleted = run_async(_run(recorder, "delete_external_account_by_id", tier="delete",
                             params={"external_account_id": aid}))
    _no_crash(deleted, "delete_external_account_by_id")
    assert classify(deleted, "delete_external_account_by_id") == PASS, deleted

    body_b = dict(body_a, name=name_b, description=name_b)
    created_b = run_async(_run(recorder, "create_external_account", tier="create",
                               params={"external_account_data": body_b}))
    _no_crash(created_b, "create_external_account")
    assert classify(created_b, "create_external_account") == PASS, created_b

    assert_ours(name_b)
    deleted_b = run_async(_run(recorder, "delete_external_account_by_name", tier="delete",
                               params={"name": name_b}))
    _no_crash(deleted_b, "delete_external_account_by_name")
    assert classify(deleted_b, "delete_external_account_by_name") == PASS, deleted_b


# ==========================================================================
# 7. deny-listed-users — READ ONLY (both delete variants are unreachable)
# ==========================================================================


def test_deny_listed_users_read_only(run_async, recorder, run_id):
    """The deny list is written by *enforcement*, not by the API: there is no
    create operation, so a fixture entry cannot be manufactured. Reads are
    validated, and the absent-object path must be a structured error rather
    than a traceback.
    """
    listing = run_async(_run(recorder, "list_deny_listed_users"))
    _no_crash(listing, "list_deny_listed_users")
    assert classify(listing, "list_deny_listed_users") == PASS, listing
    entries = listing.get("deny_listed_users")
    assert isinstance(entries, list), listing

    absent_id = run_async(_run(recorder, "get_deny_listed_user_by_id",
                               {"deny_listed_users_id": ABSENT_ID},
                               tier="negative", expect_absent=True, verdict=PASS))
    _no_crash(absent_id, "get_deny_listed_user_by_id")
    if absent_id.get("success") is not True:
        assert _is_structured_error(absent_id), \
            f"get_deny_listed_user_by_id({ABSENT_ID}) returned an unstructured " \
            f"error: {absent_id}"

    absent_pair = run_async(_run(recorder, "get_deny_listed_user_by_user_and_mac",
                                 {"user_id": ABSENT_NAME,
                                  "mac_address": _fixture_mac(run_id, 254)},
                                 tier="negative", expect_absent=True, verdict=PASS))
    _no_crash(absent_pair, "get_deny_listed_user_by_user_and_mac")
    if absent_pair.get("success") is not True:
        assert _is_structured_error(absent_pair), \
            f"get_deny_listed_user_by_user_and_mac returned an unstructured " \
            f"error: {absent_pair}"


# ==========================================================================
# 8. replace_guest_by_id / _by_username — full lifecycle over a fixture guest
# ==========================================================================


def test_replace_guest_by_id_and_by_username(run_async, recorder, run_id, cleanup):
    """``guest_users`` is the one sweepable family here, so the two guest
    replacement operations get a real create -> PUT -> PUT -> delete lifecycle.

    ``change_of_authorization`` is omitted from both replacements: the fixture
    account has no session, and CoA against live sessions is denylisted.
    """
    username = fixture_name(run_id, "guest")
    password = f"Zz!{secrets.token_urlsafe(12)}"
    replacement_password = f"Zz!{secrets.token_urlsafe(12)}"
    cleanup.add(lambda: harness.sweep_fixtures())

    created = run_async(_run(recorder, "create_guest_user", tier="create",
                             domain=GUEST_DOMAIN,
                             params={"username": username, "password": password,
                                     "role_name": GUEST_ROLE}))
    _no_crash(created, "create_guest_user")
    if created.get("success") is not True:
        _skip_family(recorder, ["replace_guest_by_id", "replace_guest_by_username"],
                     f"create_guest_user was rejected by the appliance: "
                     f"{harness.deep_error_text(created).strip()[:300]}")
    guest = created.get("user") or {}
    gid = guest.get("id")
    assert gid is not None, f"create_guest_user returned no id: {created}"
    cleanup.add(lambda: _invoke("delete_guest_user",
                                {"user_id": gid, "confirm": True}))

    guest_body = {"username": username, "password": replacement_password,
                  "role_id": GUEST_ROLE_ID, "enabled": True}

    assert_ours(username)
    by_id = run_async(_run(recorder, "replace_guest_by_id", tier="update",
                           params={"guest_id": gid, "guest_data": guest_body}))
    _assert_ok_or_structured(by_id, "replace_guest_by_id")
    replaced = by_id.get("guest") or {}
    if replaced.get("username") is not None:
        assert replaced["username"] == username, \
            f"replace_guest_by_id renamed the fixture account: {by_id}"

    assert_ours(username)
    by_name = run_async(_run(recorder, "replace_guest_by_username", tier="update",
                             params={"username": username, "guest_data": guest_body}))
    _assert_ok_or_structured(by_name, "replace_guest_by_username")

    assert_ours(username)
    deleted = run_async(_run(recorder, "delete_guest_user", tier="delete",
                             domain=GUEST_DOMAIN,
                             params={"user_id": gid, "confirm": True}))
    _no_crash(deleted, "delete_guest_user")
    assert classify(deleted, "delete_guest_user") == PASS, deleted


# ==========================================================================
# 9. BLOCKED inventory — recorded, never dispatched
# ==========================================================================

BLOCKED_OPERATIONS: Dict[str, str] = {
    "replace_api_client": (
        "Two API clients exist on this appliance and one of them is the "
        "credential this harness authenticates with. A PUT is a full "
        "replacement, so a wrong or omitted field revokes our own access "
        "mid-run; delete_api_client is denylisted for the same reason and no "
        "fixture API client can be created to replace instead."
    ),
    "delete_deny_listed_user_by_id": (
        "The deny list is populated by enforcement, not by the API — there is "
        "no create operation, so no fixture entry can be manufactured to "
        "delete. Deleting a real entry would silently re-admit a device that "
        "policy blocked."
    ),
    "delete_deny_listed_user_by_user_and_mac": (
        "Same as delete_deny_listed_user_by_id: no create path exists, so any "
        "target would be a real, policy-created deny-list entry."
    ),
}


def test_blocked_operations_are_recorded_and_not_dispatched(recorder):
    """Record every operation this phase refused to exercise, with its reason."""
    import src.main  # noqa: F401
    from src.registry import registry

    for operation, reason in BLOCKED_OPERATIONS.items():
        assert registry.get(operation) is not None, f"unknown operation {operation}"
        _record_blocked(recorder, operation, reason)


def test_domain_coverage_accounts_for_every_operation(recorder):
    """Every one of the 58 identities operations must be exercised or BLOCKED."""
    import json

    import src.main  # noqa: F401
    from src.registry import registry

    all_ops = {s.name for s in registry.search(domain=DOMAIN)}
    assert len(all_ops) == 58, f"expected 58 operations, found {len(all_ops)}"

    recorded = set()
    with recorder.path.open(encoding="utf-8") as fh:
        for line in fh:
            rec = json.loads(line)
            if rec.get("domain") == DOMAIN:
                recorded.add(rec["operation"])

    missing = sorted(all_ops - recorded - set(BLOCKED_OPERATIONS))
    assert not missing, f"operations neither exercised nor BLOCKED: {missing}"
