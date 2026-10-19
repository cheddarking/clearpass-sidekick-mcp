"""Live validation — ``certificates`` (9), ``enforcement_profiles`` (8), ``api_clients`` (5).

22 operations in total, exercised against a real ClearPass 6.12.4 appliance.

Calling style
-------------
Optional parameters are OMITTED by default — that is the path where the
``FieldInfo`` leak lived (272 of 287 operations affected). Where an optional
parameter is meaningful, a second call supplies it explicitly so both branches
are covered.

The headline regression this file pins is ``list_certificate_trust_list`` with
*every* optional parameter omitted: that call previously did
``json.loads(FieldInfo)`` and raised ``TypeError``.

Safety
------
* ``enforcement_profiles`` is the only safe fixture family in scope. Full
  create -> read -> update -> delete lifecycles run there, always under
  ``zzz-mcptest-*`` names, and every update/delete is guarded by
  ``assert_ours`` immediately before dispatch. The appliance's 84 pre-existing
  enforcement profiles are never a write target.
* ``certificates`` is READ ONLY. ``create_certificate_signing_request`` and
  ``import_certificate_to_trust_list`` would put real objects on the appliance
  with no safe delete path, so both are recorded ``BLOCKED`` and never
  dispatched.
* ``api_clients`` is READ ONLY. Exactly 2 API clients exist and one of them is
  the credential this suite authenticates with; ``delete_api_client`` is
  denylisted, so an API client created here could never be cleaned up.
  create/update/delete are all recorded ``BLOCKED``; the denylist is asserted
  to fire for delete.
"""

from __future__ import annotations

import json
import time
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

BLOCKED = "BLOCKED"

# An id that cannot exist on this appliance; used for every absent-object path.
ABSENT_ID = 999999999
ABSENT_NAME = "zzz-mcptest-object-that-does-not-exist"

# ClearPass rejects a bare "RADIUS" attribute type; enforcement-profile
# attribute types are namespaced ("Radius:IETF", "Radius:Aruba", "cpass:HTTP",
# ...). This is the value that actually works on 6.12.4 and is the crux of the
# create_profile_from_template bug below.
VALID_ATTR = [{"type": "Radius:IETF", "name": "Session-Timeout", "value": "3600"}]

TEMPLATES = ["corporate_employee", "guest_internet", "contractor_limited",
             "iot_device", "executive_access"]

# Free-text observations surfaced in the final summary.
NOTES: List[str] = []

# Product bugs confirmed live in this scope and since FIXED. Kept empty so the
# xfail escape hatch below stays wired but grants nothing: every assertion in
# this file is now a hard assertion.
#
# Fixed in this scope (each was previously an entry here):
#   * create_profile_from_template  — the 5 templates declared their default
#     attributes with type="RADIUS"; ClearPass 6.12.4 requires a namespaced
#     type. All 5 now use "Radius:IETF" (every attribute they carry is a
#     standard RFC RADIUS attribute) and all 5 create successfully.
#   * validate_profile_configuration — the tool read result["valid"]/["issues"]
#     while the client method returns is_valid/errors/warnings/conflicts/
#     dependencies, so every input validated clean. The real keys are wired
#     through now.
#   * list_api_clients(filter_enabled=...) — sent an RSQL filter
#     ("enabled eq true"); 6.12.4 requires a JSON object, now json.dumps(
#     {"enabled": true}).
KNOWN_BUGS: Dict[str, str] = {}


# --------------------------------------------------------------------------
# Dispatch + verdict helper
# --------------------------------------------------------------------------

_ERROR_KEYS = ("error", "message", "detail", "details", "error_details",
               "warning", "safety_warning", "question")


def _text(result: Dict[str, Any]) -> str:
    return " ".join(str(result.get(k, "")) for k in _ERROR_KEYS)


def _crash_markers(text: str) -> List[str]:
    return [m for m in harness._CRASH_MARKERS if m in text]


_ABSENT_PAT = ("404", "not found", "does not exist", "no such", "not exist",
               "unknown template", "could not be found", "is invalid")


def _html_body(text: str) -> bool:
    """True when an error body looks like a rendered HTML page rather than a
    structured API error.

    A sibling agent found an HTTP 500 whose body was an Apache HTML "Error 404"
    page being classified PASS because the substring "Not Found" appeared
    inside the markup. Any HTML body in this scope is reported as a finding.
    """
    low = text.lower()
    return any(m in low for m in ("<html", "<!doctype html", "<body", "<h1>",
                                 "apache", "<title>"))


# The conftest event loop is session-scoped and reached through run_async; a
# module-level shim keeps the call sites readable.
_RUN_ASYNC = None


async def _dispatch(operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch through the gateway.

    ``harness.invoke(name, _ctx=None, **params)`` takes the operation name as
    its first positional parameter, so an operation that itself has a
    parameter literally called ``name`` -- ``create_enforcement_profile`` is
    one -- cannot be dispatched through it (``TypeError: invoke() got multiple
    values for argument 'name'``). Those calls go straight to
    ``invoke_operation`` with the params as a dict; everything else uses
    ``harness.invoke`` so the standard path stays under test. Both routes hit
    the same gateway entry point and both honour the denylist.
    """
    if "name" not in params:
        return await harness.invoke(operation, **params)

    if is_denylisted(operation):
        raise DenylistedOperation(operation)
    import src.main  # noqa: F401  (side effect: registers all 757 operations)
    from src.tools.gateway import invoke_operation

    result = await invoke_operation(harness.StubContext(), operation, params or None)
    if not isinstance(result, dict):
        return {"success": False,
                "error": f"non-dict result: {type(result).__name__}",
                "message": "Operation returned a non-dict payload"}
    return result


def harness_invoke_sync(operation: str, params: Dict[str, Any]) -> Dict[str, Any]:
    assert _RUN_ASYNC is not None, "loop shim not installed"
    return _RUN_ASYNC(_dispatch(operation, params))


def run_op(
    recorder,
    operation: str,
    domain: str,
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
      ``rejected`` — the appliance legitimately rejects the request; any
                     structured, crash-free failure is correct.
    """
    start = time.perf_counter()
    result = harness_invoke_sync(operation, params)
    duration = (time.perf_counter() - start) * 1000.0

    text = _text(result)
    crashes = _crash_markers(text)
    reason = expected_skip_reason(operation)
    success = result.get("success") is True

    if _html_body(text):
        NOTES.append(
            f"{operation}: error body is an HTML page, not a structured API "
            f"error -- harness.classify substring matching would mis-read it"
        )
        verdict = FAIL
    elif crashes:
        verdict = FAIL
    elif expect == "success":
        verdict = PASS if success else (EXPECTED_SKIP if reason else FAIL)
    elif expect == "absent":
        low = text.lower()
        if success:
            # Reporting plain success for an object that does not exist means
            # the operation invented data.
            verdict = FAIL
        elif any(p in low for p in _ABSENT_PAT):
            verdict = PASS
        else:
            verdict = EXPECTED_SKIP if reason else FAIL
    elif expect == "refusal":
        low = text.lower()
        verdict = PASS if (not success and
                           all(s.lower() in low for s in substrings)) else FAIL
    elif expect == "rejected":
        # The request is genuinely invalid; a structured, crash-free failure is
        # the correct outcome. Plain success would mean the guard is missing.
        verdict = FAIL if success else PASS
    else:  # pragma: no cover
        raise ValueError(expect)

    err = None if verdict == PASS else (text.strip() or None)
    recorder.record(operation, domain, tier, verdict, params, err, duration)
    return result, verdict


def check(verdict: str, bug_key: str, message: str) -> None:
    """Assert PASS, or xfail with the confirmed root cause for a known bug."""
    if verdict != PASS and bug_key in KNOWN_BUGS:
        pytest.xfail(f"KNOWN BUG [{bug_key}] {KNOWN_BUGS[bug_key]} :: {message}")
    assert verdict == PASS, message


def record_blocked(recorder, operation: str, domain: str, reason: str) -> None:
    recorder.record(operation, domain, "blocked", BLOCKED, {}, reason, 0.0)


@pytest.fixture(autouse=True, scope="module")
def _install_loop(request):
    global _RUN_ASYNC
    if not request.config.getoption("--live"):
        yield
        return
    _RUN_ASYNC = request.getfixturevalue("run_async")
    yield
    _RUN_ASYNC = None


# --------------------------------------------------------------------------
# Session catalogue — read the appliance once
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def catalogue(recorder, live_enabled) -> Dict[str, Any]:
    """Real ids/names harvested once, so detail calls target genuine objects."""
    cat: Dict[str, Any] = {}

    trust, _ = run_op(recorder, "list_certificate_trust_list", "certificates")
    entries = trust.get("trust_list_entries") or []
    cat["trust_ids"] = [e["id"] for e in entries if isinstance(e, dict) and "id" in e]

    servers, _ = run_op(recorder, "list_server_certificates", "certificates")
    certs = servers.get("server_certificates") or []
    cat["service_ids"] = [c["service_id"] for c in certs
                          if isinstance(c, dict) and "service_id" in c]

    profiles, _ = run_op(recorder, "list_enforcement_profiles", "enforcement_profiles")
    plist = profiles.get("profiles") or []
    cat["profile_total"] = profiles.get("total_count")
    cat["profile_names"] = [p["name"] for p in plist if isinstance(p, dict)]

    clients, _ = run_op(recorder, "list_api_clients", "api_clients")
    cat["clients"] = clients.get("clients") or []

    # The server UUID the `server_uuid` + `service_name` branch of
    # get_server_certificate_details needs. `list_cluster_servers` is the
    # operation that exists specifically to close the server-UUID catalogue gap.
    servers, _ = run_op(recorder, "list_cluster_servers", "local_server_config")
    uuid = None
    for item in (servers.get("cluster_servers") or []):
        if isinstance(item, dict):
            uuid = item.get("server_uuid") or item.get("uuid")
            if uuid:
                break
    cat["server_uuid"] = uuid
    return cat


# ==========================================================================
# certificates (9 operations) — READ ONLY
# ==========================================================================


def test_list_certificate_trust_list_all_optionals_omitted(recorder, catalogue):
    """THE regression pin: filter_str/sort/offset/limit/calculate_count all omitted.

    This exact call previously reached ``json.loads(FieldInfo)`` and raised
    ``TypeError``. It must now return real trust-list entries.
    """
    result, verdict = run_op(recorder, "list_certificate_trust_list", "certificates")

    assert verdict == PASS, f"trust list failed: {_text(result)}"
    assert result.get("success") is True
    entries = result.get("trust_list_entries")
    assert isinstance(entries, list) and entries, \
        "expected real trust-list entries, got nothing"
    # Real entries, not a fabricated envelope.
    first = entries[0]
    assert isinstance(first, dict) and "id" in first and "cert_file" in first, \
        f"trust-list entry does not look like a certificate: {first!r}"
    assert result.get("returned_count") == len(entries)
    # No FieldInfo leak anywhere in the payload.
    blob = json.dumps(result, default=str)
    assert "FieldInfo" not in blob and "annotation=" not in blob, \
        "FieldInfo leaked into the trust-list payload"


def test_list_certificate_trust_list_with_optionals(recorder, catalogue):
    """The explicitly-specified branch of the same operation."""
    if not catalogue["trust_ids"]:
        pytest.skip("no trust-list entries on this appliance")
    target = catalogue["trust_ids"][0]
    result, verdict = run_op(
        recorder, "list_certificate_trust_list", "certificates",
        filter_str=json.dumps({"id": target}), sort="+id", offset=0, limit=5,
        calculate_count=True)
    assert verdict == PASS, f"filtered trust list failed: {_text(result)}"
    entries = result.get("trust_list_entries") or []
    assert len(entries) == 1 and entries[0]["id"] == target


def test_get_certificate_trust_list_details(recorder, catalogue):
    if not catalogue["trust_ids"]:
        pytest.skip("no trust-list entries on this appliance")
    target = catalogue["trust_ids"][0]

    result, verdict = run_op(recorder, "get_certificate_trust_list_details",
                             "certificates", cert_trust_list_details_id=target)
    assert verdict == PASS, f"detail lookup failed: {_text(result)}"
    detail = result.get("trust_list_detail") or {}
    assert detail.get("id") == target
    assert detail.get("subject_DN"), "no subject DN on the trust-list detail"

    # absent id -> structured 404, not a crash and not invented data
    absent, av = run_op(recorder, "get_certificate_trust_list_details",
                        "certificates", tier="negative", expect="absent",
                        cert_trust_list_details_id=ABSENT_ID)
    assert av == PASS, f"absent trust-list id mishandled: {_text(absent)}"
    assert absent.get("status_code") == 404

    # non-numeric id -> structured 422 from the appliance, still no crash
    bad, bv = run_op(recorder, "get_certificate_trust_list_details",
                     "certificates", tier="negative", expect="absent",
                     cert_trust_list_details_id="notanint")
    assert bv == PASS, f"non-numeric trust-list id mishandled: {_text(bad)}"


def test_list_client_certificates(recorder, catalogue):
    """All optionals omitted. This appliance holds 0 client certificates — an
    empty list with success=True is the correct answer, not a failure."""
    result, verdict = run_op(recorder, "list_client_certificates", "certificates")
    assert verdict == PASS, f"client cert list failed: {_text(result)}"
    assert isinstance(result.get("client_certificates"), list)
    assert result.get("returned_count") == len(result["client_certificates"])
    NOTES.append(f"list_client_certificates: {result['returned_count']} client "
                 f"certificates on this appliance")

    # explicit-optionals branch
    _, fv = run_op(recorder, "list_client_certificates", "certificates",
                   filter_str=json.dumps({"id": 1}), sort="+id", offset=0,
                   limit=5, calculate_count=True)
    assert fv == PASS


def test_get_client_certificate_by_id(recorder, catalogue):
    """No client certificates exist, so only the absent path is reachable —
    it must be a structured 404, never a crash or invented payload."""
    result, verdict = run_op(recorder, "get_client_certificate_by_id",
                             "certificates", tier="negative", expect="absent",
                             client_cert_id=ABSENT_ID)
    assert verdict == PASS, f"absent client cert mishandled: {_text(result)}"
    assert result.get("status_code") == 404
    assert result.get("success") is False


def test_list_server_certificates(recorder, catalogue):
    """Takes no parameters at all."""
    result, verdict = run_op(recorder, "list_server_certificates", "certificates")
    assert verdict == PASS, f"server cert list failed: {_text(result)}"
    certs = result.get("server_certificates") or []
    assert certs, "expected real server certificates"
    assert all("service_id" in c and "subject" in c for c in certs)
    assert result.get("count") == len(certs)


def test_get_server_certificate_details(recorder, catalogue):
    if not catalogue["service_ids"]:
        pytest.skip("no server certificates on this appliance")
    target = catalogue["service_ids"][0]

    result, verdict = run_op(recorder, "get_server_certificate_details",
                             "certificates", service_id=target)
    assert verdict == PASS, f"server cert detail failed: {_text(result)}"
    detail = result.get("server_certificate_detail") or {}
    assert detail.get("service_id") == target
    assert detail.get("cert_file", "").startswith("-----BEGIN CERTIFICATE-----")

    # every optional omitted -> the operation cannot identify a target and
    # must ask, not guess
    empty, ev = run_op(recorder, "get_server_certificate_details", "certificates",
                       tier="negative", expect="refusal",
                       substrings=("insufficient parameters",))
    assert ev == PASS, f"no-identifier path mishandled: {_text(empty)}"
    assert empty.get("error_type") == "clarification_needed"

    # The uuid + service_name branch, positive path.
    #
    # This branch used to dispatch `GET server-cert-name/{uuid}/{name}`, a path
    # ClearPass does not serve: it answered 404 unconditionally, so the branch
    # could never succeed and this test only ever exercised its failure. It now
    # dispatches `GET server-cert/name/{uuid}/{name}` (the same route the
    # sibling get_server_certificate_by_name operation uses), so the positive
    # path is finally assertable.
    #
    # Note the service name must be one the endpoint documents — RADIUS,
    # HTTPS(ECC), HTTPS(RSA), RadSec or Database. Anything else (the old probe
    # used "RadiusServer") is rejected 422 with an "Allowed service names" list
    # before any lookup happens.
    uuid = catalogue["server_uuid"]
    assert uuid, "no cluster server UUID could be discovered"

    named, nv = run_op(recorder, "get_server_certificate_details", "certificates",
                       server_uuid=uuid, service_name="RADIUS")
    assert nv == PASS, f"uuid/service_name branch failed: {_text(named)}"
    named_detail = named.get("server_certificate_detail") or {}
    assert named_detail.get("service_name") == "RADIUS", named_detail
    assert named_detail.get("cert_file", "").startswith("-----BEGIN CERTIFICATE-----")

    # A UUID that cannot exist -> a structured, crash-free rejection. This
    # endpoint answers an unknown UUID with `422 "Validation error. Server not
    # found."` rather than a 404, so only structure is asserted, not the
    # appliance's choice of status code.
    alt, altv = run_op(recorder, "get_server_certificate_details", "certificates",
                       tier="negative", expect="rejected",
                       server_uuid="zzz-mcptest-bogus-uuid",
                       service_name="RADIUS")
    assert altv == PASS, f"uuid/service_name branch mishandled: {_text(alt)}"
    assert alt.get("success") is not True, alt


def test_list_service_certificates(recorder, catalogue):
    result, verdict = run_op(recorder, "list_service_certificates", "certificates")
    assert verdict == PASS, f"service cert list failed: {_text(result)}"
    assert isinstance(result.get("service_certificates"), list)

    _, fv = run_op(recorder, "list_service_certificates", "certificates",
                   sort="+id", offset=0, limit=5, calculate_count=True)
    assert fv == PASS


def test_certificates_write_operations_blocked(recorder):
    """``certificates`` is not a safe fixture family: 51 certificates exist and
    neither of these two operations has a safe undo path in the registry."""
    record_blocked(
        recorder, "create_certificate_signing_request", "certificates",
        "Generates a real CSR + private key on the appliance; no delete "
        "operation exists in the registry to clean it up.")
    record_blocked(
        recorder, "import_certificate_to_trust_list", "certificates",
        "Imports a real certificate into the trust list used by live EAP/HTTPS "
        "services; no delete operation exists in the registry to remove it.")
    assert True


# ==========================================================================
# enforcement_profiles (8 operations) — SAFE FIXTURE FAMILY, full lifecycle
# ==========================================================================


def test_list_enforcement_profiles(recorder, catalogue):
    """All optionals omitted, then each optional supplied."""
    result, verdict = run_op(recorder, "list_enforcement_profiles",
                             "enforcement_profiles")
    assert verdict == PASS, f"profile list failed: {_text(result)}"
    profiles = result.get("profiles") or []
    assert profiles, "expected real enforcement profiles"
    assert result.get("total_count") == 84, (
        f"expected the 84 documented pre-existing profiles, saw "
        f"{result.get('total_count')}")

    paged, pv = run_op(recorder, "list_enforcement_profiles",
                       "enforcement_profiles", limit=5, offset=0,
                       calculate_count=True)
    assert pv == PASS
    assert len(paged.get("profiles") or []) == 5

    named, nv = run_op(recorder, "list_enforcement_profiles",
                       "enforcement_profiles", name_contains="TACACS")
    assert nv == PASS
    assert all("TACACS" in p["name"] for p in (named.get("profiles") or []))

    typed, tv = run_op(recorder, "list_enforcement_profiles",
                       "enforcement_profiles", filter_type="RADIUS",
                       filter_action="Accept")
    assert tv == PASS, f"typed filter failed: {_text(typed)}"


def test_list_profile_templates(recorder, catalogue):
    result, verdict = run_op(recorder, "list_profile_templates",
                             "enforcement_profiles")
    assert verdict == PASS, f"template list failed: {_text(result)}"
    names = [t["name"] for t in (result.get("templates") or [])]
    assert sorted(names) == sorted(TEMPLATES), f"unexpected templates: {names}"


def test_enforcement_profile_lifecycle_by_name(recorder, run_id, catalogue, cleanup):
    """create -> get -> update -> delete, all addressed BY NAME."""
    name = fixture_name(run_id, "lc-name")
    cleanup.add(lambda: harness.invoke("delete_enforcement_profile",
                                       profile_name=assert_ours(name),
                                       confirm_deletion=True))

    created, cv = run_op(recorder, "create_enforcement_profile",
                         "enforcement_profiles", tier="create",
                         name=name, profile_type="RADIUS", attributes=VALID_ATTR)
    assert cv == PASS, f"profile create failed: {_text(created)}"
    profile = created.get("profile") or {}
    pid = profile.get("id")
    assert isinstance(pid, int) and profile.get("name") == name

    got, gv = run_op(recorder, "get_enforcement_profile_details",
                     "enforcement_profiles", profile_name=name)
    assert gv == PASS, f"get-by-name failed: {_text(got)}"
    assert (got.get("profile") or {}).get("id") == pid

    assert_ours(name)
    upd, uv = run_op(recorder, "update_enforcement_profile",
                     "enforcement_profiles", tier="update",
                     profile_name=name, description="updated-by-name")
    assert uv == PASS, f"update-by-name failed: {_text(upd)}"
    assert (upd.get("profile") or {}).get("description") == "updated-by-name"

    assert_ours(name)
    dele, dv = run_op(recorder, "delete_enforcement_profile",
                      "enforcement_profiles", tier="delete",
                      profile_name=name, confirm_deletion=True)
    assert dv == PASS, f"delete-by-name failed: {_text(dele)}"
    assert (dele.get("deleted_profile") or {}).get("id") == pid

    gone, gonev = run_op(recorder, "get_enforcement_profile_details",
                         "enforcement_profiles", tier="negative",
                         expect="absent", profile_name=name)
    assert gonev == PASS, f"deleted profile still readable: {_text(gone)}"


def test_enforcement_profile_lifecycle_by_id(recorder, run_id, catalogue, cleanup):
    """The same lifecycle addressed BY NUMERIC ID.

    This is the branch that ``delete_guest_user`` and ``get_network_device``
    get wrong (id-only, no name lookup); enforcement_profiles is checked both
    ways so the matrix is complete.
    """
    name = fixture_name(run_id, "lc-id")
    cleanup.add(lambda: harness.invoke("delete_enforcement_profile",
                                       profile_name=assert_ours(name),
                                       confirm_deletion=True))

    created, cv = run_op(recorder, "create_enforcement_profile",
                         "enforcement_profiles", tier="create",
                         name=name, profile_type="RADIUS",
                         description="created-for-id-branch",
                         action="Accept", attributes=VALID_ATTR)
    assert cv == PASS, f"profile create failed: {_text(created)}"
    pid = (created.get("profile") or {}).get("id")
    assert isinstance(pid, int)

    got, gv = run_op(recorder, "get_enforcement_profile_details",
                     "enforcement_profiles", profile_id=pid)
    assert gv == PASS, f"get-by-id failed: {_text(got)}"
    assert (got.get("profile") or {}).get("name") == name

    assert_ours(name)  # the id we are about to write to belongs to this name
    upd, uv = run_op(recorder, "update_enforcement_profile",
                     "enforcement_profiles", tier="update",
                     profile_id=pid, description="updated-by-id")
    assert uv == PASS, f"update-by-id failed: {_text(upd)}"
    assert (upd.get("profile") or {}).get("description") == "updated-by-id"

    assert_ours(name)
    dele, dv = run_op(recorder, "delete_enforcement_profile",
                      "enforcement_profiles", tier="delete",
                      profile_id=pid, confirm_deletion=True)
    assert dv == PASS, f"delete-by-id failed: {_text(dele)}"


def test_enforcement_profile_identifier_and_guard_paths(recorder, run_id, cleanup):
    """No-identifier refusals, absent-object 404s, and the delete confirmation
    guard — none of which may crash or touch a real profile."""
    # get with neither identifier
    _, v = run_op(recorder, "get_enforcement_profile_details",
                  "enforcement_profiles", tier="negative", expect="refusal",
                  substrings=("provide either profile_id or profile_name",))
    assert v == PASS

    # update with neither identifier
    _, v = run_op(recorder, "update_enforcement_profile", "enforcement_profiles",
                  tier="negative", expect="refusal",
                  substrings=("provide either profile_id or profile_name",),
                  description="no-identifier")
    assert v == PASS

    # absent id / absent name on every verb
    for op, params in (
        ("get_enforcement_profile_details", {"profile_id": ABSENT_ID}),
        ("get_enforcement_profile_details", {"profile_name": ABSENT_NAME}),
        ("update_enforcement_profile", {"profile_id": ABSENT_ID,
                                        "description": "x"}),
        ("update_enforcement_profile", {"profile_name": ABSENT_NAME,
                                        "description": "x"}),
        ("delete_enforcement_profile", {"profile_id": ABSENT_ID,
                                        "confirm_deletion": True}),
        ("delete_enforcement_profile", {"profile_name": ABSENT_NAME,
                                        "confirm_deletion": True}),
    ):
        res, verdict = run_op(recorder, op, "enforcement_profiles",
                              tier="negative", expect="absent", **params)
        assert verdict == PASS, f"{op}{params} mishandled: {_text(res)}"

    # the confirmation guard must refuse before anything is deleted
    name = fixture_name(run_id, "guard")
    cleanup.add(lambda: harness.invoke("delete_enforcement_profile",
                                       profile_name=assert_ours(name),
                                       confirm_deletion=True))
    created, cv = run_op(recorder, "create_enforcement_profile",
                         "enforcement_profiles", tier="create",
                         name=name, profile_type="RADIUS", attributes=VALID_ATTR)
    assert cv == PASS, f"guard fixture create failed: {_text(created)}"

    assert_ours(name)
    _, gv = run_op(recorder, "delete_enforcement_profile", "enforcement_profiles",
                   tier="negative", expect="refusal",
                   substrings=("confirm_deletion",), profile_name=name)
    assert gv == PASS, "unconfirmed delete was not refused"

    still, sv = run_op(recorder, "get_enforcement_profile_details",
                       "enforcement_profiles", profile_name=name)
    assert sv == PASS, "refused delete removed the profile anyway"

    assert_ours(name)
    _, dv = run_op(recorder, "delete_enforcement_profile", "enforcement_profiles",
                   tier="delete", profile_name=name, confirm_deletion=True)
    assert dv == PASS


def test_create_enforcement_profile_without_attributes(recorder, run_id):
    """A create carrying no enforcement parameters is refused LOCALLY.

    The appliance would answer 422 "Invalid value specified for attribute ->
    type", which names the wrong field. The tool now pre-checks that at least
    one enforcement parameter was supplied and returns an actionable message
    without dispatching the request.
    """
    name = fixture_name(run_id, "noattrs")
    result, verdict = run_op(recorder, "create_enforcement_profile",
                             "enforcement_profiles", tier="negative",
                             expect="rejected",
                             name=name, profile_type="RADIUS")
    assert verdict == PASS, f"attribute-less create mishandled: {_text(result)}"
    assert result.get("success") is False
    assert not _crash_markers(_text(result)), \
        f"attribute-less create crashed: {_text(result)}"

    # Refused before the API call: no appliance status code, and the message
    # names the field the caller actually has to supply.
    assert result.get("status_code") is None, \
        f"expected a local refusal, but the appliance answered: {result!r}"
    assert result.get("error_type") == "validation_error"
    text = _text(result).lower()
    assert "enforcement parameter" in text
    assert "attributes" in text and "radius:ietf" in text, \
        f"pre-check message is not actionable: {_text(result)}"

    # …and nothing was created.
    gone, gv = run_op(recorder, "get_enforcement_profile_details",
                      "enforcement_profiles", tier="negative", expect="absent",
                      profile_name=name)
    assert gv == PASS, f"refused create left a profile behind: {_text(gone)}"


def test_create_profile_from_template_all_templates(recorder, run_id, cleanup):
    """Template-based creation — the headline feature — for all 5 templates.

    Every template must create a real profile on the appliance, and every
    attribute it lands must carry a namespaced type (``Radius:IETF`` for these
    five, whose attributes are all standard RFC RADIUS attributes). A bare
    ``"RADIUS"`` is what ClearPass 6.12.4 rejects with 422.
    """
    failures: List[str] = []
    for template in TEMPLATES:
        name = fixture_name(run_id, f"tpl-{template}")
        cleanup.add(lambda n=name: harness.invoke(
            "delete_enforcement_profile", profile_name=assert_ours(n),
            confirm_deletion=True))
        result, verdict = run_op(recorder, "create_profile_from_template",
                                 "enforcement_profiles", tier="create",
                                 template_name=template, profile_name=name)
        if verdict != PASS:
            failures.append(f"{template}: {_text(result)[:160]}")
            continue

        profile = result.get("profile") or {}
        if not isinstance(profile.get("id"), int) or profile.get("name") != name:
            failures.append(f"{template}: created profile does not look real: "
                            f"{profile!r}")
            continue

        attrs = profile.get("attributes") or []
        if not attrs:
            failures.append(f"{template}: profile landed with no attributes")
            continue
        bare = [a for a in attrs if a.get("type") == "RADIUS"]
        if bare:
            failures.append(f"{template}: un-namespaced attribute type(s): {bare}")
            continue
        unnamespaced = [a for a in attrs if ":" not in str(a.get("type", ""))]
        if unnamespaced:
            failures.append(f"{template}: attribute type is not namespaced: "
                            f"{unnamespaced}")
            continue

        # the profile is genuinely readable back off the appliance
        got, gv = run_op(recorder, "get_enforcement_profile_details",
                         "enforcement_profiles", profile_name=name)
        if gv != PASS or (got.get("profile") or {}).get("id") != profile["id"]:
            failures.append(f"{template}: created profile not readable back")
            continue

        assert_ours(name)
        _, dv = run_op(recorder, "delete_enforcement_profile",
                       "enforcement_profiles", tier="delete",
                       profile_name=name, confirm_deletion=True)
        if dv != PASS:
            failures.append(f"{template}: fixture cleanup failed")

    # an unknown template must be refused locally, before any API call
    unknown, uv = run_op(recorder, "create_profile_from_template",
                         "enforcement_profiles", tier="negative",
                         expect="refusal", substrings=("unknown template",),
                         template_name="zzz_no_such_template",
                         profile_name=fixture_name(run_id, "tpl-bad"))
    assert uv == PASS, f"unknown template mishandled: {_text(unknown)}"

    assert not failures, f"{len(failures)}/5 templates failed: {failures}"


def test_validate_profile_configuration(recorder):
    """The validator must actually reject an invalid configuration.

    The tool reads the client method's real ValidationResult keys
    (is_valid / errors / warnings / conflicts / dependencies) — reading the
    non-existent "valid"/"issues" made every input, including ``{}``, validate
    clean.
    """
    good, gv = run_op(recorder, "validate_profile_configuration",
                      "enforcement_profiles",
                      profile_data={"name": "zzz-mcptest-shape",
                                    "type": "RADIUS",
                                    "attributes": VALID_ATTR})
    assert gv == PASS, f"validating a good profile failed: {_text(good)}"
    assert good.get("validation_passed") is True
    assert good.get("issues") == []

    # An empty profile has neither the required name nor the required type;
    # the client-side validator records both as errors.
    empty, _ = run_op(recorder, "validate_profile_configuration",
                      "enforcement_profiles", tier="negative", profile_data={})
    assert empty.get("validation_passed") is False, \
        f"empty profile validated clean: {json.dumps(empty, default=str)[:300]}"
    issues = empty.get("issues") or []
    assert len(issues) == 2, f"expected both required-field errors, got {issues}"
    blob = " ".join(issues).lower()
    assert "name is required" in blob and "type is required" in blob, issues
    assert empty.get("errors") == issues, \
        "the 'errors' key from ValidationResult was dropped"

    # warnings and dependencies must survive too — both were discarded before.
    rich, rv = run_op(recorder, "validate_profile_configuration",
                      "enforcement_profiles",
                      profile_data={
                          "name": "zzz-mcptest-warn",
                          "type": "RADIUS",
                          "device_group_list": ["zzz-mcptest-group"],
                          "attributes": [
                              {"type": "Radius:IETF", "name": "Session-Timeout",
                               "value": "999999"},
                              {"type": "Radius:IETF", "name": "Session-Timeout",
                               "value": "3600"},
                          ]})
    assert rv == PASS, f"validating a warn-worthy profile failed: {_text(rich)}"
    warnings = rich.get("warnings") or []
    assert any("24 hours" in w for w in warnings), \
        f"the session-timeout warning was dropped: {warnings}"
    assert any("Duplicate attribute names" in w for w in warnings), \
        f"the duplicate-attribute warning was dropped: {warnings}"
    dependencies = rich.get("dependencies") or []
    assert any("zzz-mcptest-group" in d for d in dependencies), \
        f"the dependency list was dropped: {dependencies}"


# ==========================================================================
# api_clients (5 operations) — READ ONLY
# ==========================================================================


def test_list_api_clients(recorder, catalogue):
    """All optionals omitted, then the ``filter_enabled`` branch.

    ``filter_enabled`` used to build an RSQL filter ("enabled eq true") that
    6.12.4's api-client endpoint rejects; it now sends a JSON object.
    """
    result, verdict = run_op(recorder, "list_api_clients", "api_clients")
    assert verdict == PASS, f"api client list failed: {_text(result)}"
    clients = result.get("clients") or []
    assert len(clients) == 2, f"expected exactly 2 API clients, saw {len(clients)}"
    assert any(c.get("client_id") == "mcp-api-client" for c in clients)

    _, lv = run_op(recorder, "list_api_clients", "api_clients", limit=10)
    assert lv == PASS

    enabled, fv = run_op(recorder, "list_api_clients", "api_clients",
                         filter_enabled=True)
    assert fv == PASS, f"filter_enabled=True branch failed: {_text(enabled)}"
    returned = enabled.get("clients") or []
    assert all(c.get("enabled") is True for c in returned), \
        f"filter_enabled=True returned a disabled client: {returned}"
    assert any(c.get("client_id") == "mcp-api-client" for c in returned), \
        "the authenticating client is enabled but was filtered out"

    disabled, dv = run_op(recorder, "list_api_clients", "api_clients",
                          filter_enabled=False)
    assert dv == PASS, f"filter_enabled=False branch failed: {_text(disabled)}"
    assert all(c.get("enabled") is False for c in (disabled.get("clients") or [])), \
        f"filter_enabled=False returned an enabled client: {disabled.get('clients')}"
    assert len(returned) + len(disabled.get("clients") or []) == len(clients), \
        "the two filter branches do not partition the client list"


def test_get_api_client(recorder, catalogue):
    """Read the authenticating client and verify the historical field-mapping
    and time-unit fixes still hold (description -> client_description,
    DAYS -> days)."""
    result, verdict = run_op(recorder, "get_api_client", "api_clients",
                             client_id="mcp-api-client")
    assert verdict == PASS, f"get_api_client failed: {_text(result)}"
    client = result.get("client") or {}
    assert client.get("client_id") == "mcp-api-client"

    # description -> client_description mapping survived
    assert client.get("client_description"), \
        "client_description is empty — the description field mapping regressed"
    assert "description" not in client or client.get("client_description"), \
        "raw 'description' key resurfaced alongside client_description"

    # DAYS -> days time-unit casing survived
    for key in ("access_token_lifetime_units", "refresh_token_lifetime_units"):
        unit = client.get(key)
        assert unit and unit == unit.lower(), \
            f"{key}={unit!r} is not lower-case — the time-unit fix regressed"
        assert unit in ("days", "hours", "minutes", "seconds"), \
            f"unexpected time unit {unit!r} for {key}"
    NOTES.append(
        f"get_api_client: client_description="
        f"{client.get('client_description')!r}, access lifetime="
        f"{client.get('access_token_lifetime')} "
        f"{client.get('access_token_lifetime_units')}")

    absent, av = run_op(recorder, "get_api_client", "api_clients",
                        tier="negative", expect="absent",
                        client_id="zzz-mcptest-no-such-client")
    assert av == PASS, f"absent api client mishandled: {_text(absent)}"
    assert absent.get("status_code") == 404


def test_api_client_write_operations_blocked(recorder, denylist):
    """create/update/delete are all off-limits on this appliance.

    Only 2 API clients exist and one of them is the credential this whole
    sweep authenticates with. ``delete_api_client`` is denylisted, so an API
    client created here could never be cleaned up — which makes create and
    update unsafe by extension.
    """
    record_blocked(
        recorder, "create_api_client", "api_clients",
        "delete_api_client is denylisted, so a created client could never be "
        "removed; it would be permanent inventory drift.")
    record_blocked(
        recorder, "update_api_client", "api_clients",
        "The only two clients are pre-existing, one of them the credential "
        "this run authenticates with; there is no fixture client to update.")
    record_blocked(
        recorder, "delete_api_client", "api_clients", DENYLIST["delete_api_client"])

    assert is_denylisted("delete_api_client")
    with pytest.raises(DenylistedOperation):
        harness_invoke_sync("delete_api_client",
                            {"client_id": "mcp-api-client", "confirm": True})


# ==========================================================================
# Summary
# ==========================================================================


def test_zz_summary(recorder, catalogue):
    """Print the tally and confirm the 84 pre-existing profiles survived."""
    survivors, verdict = run_op(recorder, "list_enforcement_profiles",
                                "enforcement_profiles", limit=1000)
    assert verdict == PASS
    profiles = survivors.get("profiles") or []
    foreign = [p["name"] for p in profiles if not harness.is_ours(p.get("name"))]

    print("\n" + "=" * 72)
    print("certificates / enforcement_profiles / api_clients — live summary")
    print("=" * 72)
    print(f"recorded verdicts: {recorder.counts}")
    print(f"pre-existing enforcement profiles surviving: {len(foreign)} "
          f"(expected 84)")
    print(f"fixture profiles still present: "
          f"{[p['name'] for p in profiles if harness.is_ours(p.get('name'))]}")
    for note in NOTES:
        print(f"  note: {note}")
    print("known bugs confirmed live:")
    for key, why in KNOWN_BUGS.items():
        print(f"  - {key}: {why}")
    print("=" * 72)

    assert len(foreign) == 84, (
        f"expected the 84 pre-existing enforcement profiles to survive, "
        f"found {len(foreign)}")
