"""Live validation of the ``local_server_config`` (15) and ``audit_logs`` (12)
domains — 27 operations.

Scope note: the full-SDK-coverage expansion grew ``audit_logs`` to 25
operations (``local_server_config`` is unchanged). This module still owns
exactly the original 27; the 13 additions are covered by
``test_certs_ca_audit_live.py`` and are listed in ``EXPANSION_OPERATIONS``
beside the coverage guard at the bottom of this file.

**Nothing here creates, updates or deletes anything on the appliance.** Neither
domain is a safe fixture family (only guest users, enforcement profiles and
roles can be created and swept), so every operation is either

* validated read-only,
* validated only up to its *local* refusal guard (confirmation / clarification),
  which returns before any client call is made, or
* recorded as BLOCKED and never dispatched.

``local_server_config`` is additionally the appliance's own access-control, AD
integration and cluster configuration — a wrong write here locks the harness
(and the operator) out of the box. ``leave_ad_domain`` and
``delete_server_access_control_by_resource`` are on the hard denylist; the
remaining writes are blocked here by policy.

Calling style: optional parameters are OMITTED by default (that is the path the
``FieldInfo`` bug lived on). ``audit_logs`` is rich in filter/pagination/
time-window parameters, so ``list_system_events`` is additionally exercised with
realistic filters, paging and a deliberately invalid filter.

Catalogue gap discovered while writing this module — now CLOSED
---------------------------------------------------------------
``local_server_config`` exposes ``get_cluster_server_by_uuid`` /
``update_cluster_server_by_uuid`` / ``get_server_access_control_settings`` /
``list_ad_domains`` — all of which need a *server UUID* — but the registry had
no operation that lists cluster servers, even though the client mixin already
implemented ``ClearPassClient.get_cluster_servers()`` (``GET cluster/server``).
An MCP consumer therefore had no in-catalogue way to obtain the UUID these four
operations require.

``list_cluster_servers`` now exposes it (registry 286 -> 287, see
``tests/test_tool_count.py``). The fixture below goes through the registry
operation, which doubles as the proof that the gap is closed.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, FAIL, PASS, classify

LOCAL = "local_server_config"
AUDIT = "audit_logs"

BLOCKED = "BLOCKED"


# --------------------------------------------------------------------------
# Operations deliberately never dispatched, with the reason
# --------------------------------------------------------------------------

BLOCKED_OPERATIONS: Dict[str, str] = {
    # --- local_server_config -------------------------------------------
    "update_server_access_control_by_resource": (
        "Rewrites the appliance's own application access-control rules "
        "(ClearPass API / Policy Manager / CLI network restrictions). A wrong "
        "value locks the harness and the operator out of the box, and there is "
        "no fixture family to scope it to."
    ),
    "delete_server_access_control_by_resource": (
        "DENYLISTED: " + DENYLIST["delete_server_access_control_by_resource"]
    ),
    "join_ad_domain": (
        "Joins the appliance to an Active Directory domain — an appliance-wide "
        "authentication change requiring real domain-admin credentials, and "
        "only reversible via the denylisted leave_ad_domain."
    ),
    "leave_ad_domain": ("DENYLISTED: " + DENYLIST["leave_ad_domain"]),
    "configure_ad_password_servers": (
        "PATCHes AD password-server configuration. The appliance is not joined "
        "to a domain (list_ad_domains returns an empty set), so there is no "
        "pre-existing config to read back and restore."
    ),
    "update_cluster_server_by_uuid": (
        "PATCHes cluster topology for the publisher itself (management IP, "
        "insight/profiler roles, replication). Destabilises the appliance and "
        "cannot be scoped to a fixture."
    ),
    # --- audit_logs -----------------------------------------------------
    "create_system_event": (
        "Appends a permanent row to the System Events log. The catalogue has "
        "no delete-system-event operation, so the write could never be cleaned "
        "up and would show as unattributable drift."
    ),
    "create_insight_alert": (
        "Creates an Insight alert configuration. Insight is not a sweepable "
        "fixture family — nothing would clean it up."
    ),
    "create_insight_report": (
        "Creates an Insight report configuration, including a delivery "
        "schedule that can email real recipients. Not a sweepable family."
    ),
    "update_insight_alert": (
        "Mutates a pre-existing Insight alert configuration. No fixture of our "
        "own exists to target, and the harness must never mutate a "
        "pre-existing object."
    ),
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _is_clarification(result: Dict[str, Any]) -> bool:
    return (isinstance(result, dict)
            and result.get("error_type") == "clarification_needed"
            and result.get("success") is False)


def _looks_like_html(result: Dict[str, Any]) -> bool:
    """True when an error body is HTML rather than the API's JSON problem doc.

    ``harness.classify`` matches on substrings such as 'Not Found', which an
    Apache error page also contains — so an HTML body must never be allowed to
    reach a PASS verdict. Nothing in these two domains produced one, and this
    assertion is here so a future regression is caught.
    """
    text = " ".join(str(result.get(k, "")) for k in
                    ("error", "message", "detail", "details", "raw_response"))
    lowered = text.lower()
    return "<html" in lowered or "<!doctype html" in lowered or "<address>" in lowered


def _assert_structured(result: Dict[str, Any], operation: str) -> None:
    assert not _looks_like_html(result), (
        f"{operation} returned a non-JSON/HTML error body; classification "
        f"cannot be trusted: {str(result)[:400]}"
    )


# --------------------------------------------------------------------------
# Session fixture: a real server UUID (see module docstring — catalogue gap)
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def server_uuid(run_async, live_enabled) -> str:
    """A real server UUID, obtained through the ``list_cluster_servers``
    *operation* (not a reach-through to the client mixin) — the catalogue gap
    described in the module docstring is closed, so this is now a supported
    consumer path."""
    result = run_async(harness.invoke("list_cluster_servers"))
    assert result.get("success") is True, result
    for item in result.get("cluster_servers") or []:
        uuid = item.get("server_uuid") or item.get("uuid")
        if uuid:
            return uuid
    raise AssertionError(f"no cluster server UUID could be discovered: {result}")


# ==========================================================================
# 1. local_server_config — identifier-free reads (all params required-free)
# ==========================================================================


@pytest.mark.parametrize("operation, payload_key", [
    ("get_cppm_version", "version_info"),
    ("get_server_version", "version_info"),
    ("get_server_fips_status", "fips_status"),
])
def test_local_zero_argument_reads(run_async, recorder, operation, payload_key):
    """No-parameter reads must succeed and carry a populated payload."""
    result = run_async(recorder.run(operation, domain=LOCAL, tier="read"))
    _assert_structured(result, operation)
    assert classify(result, operation) == PASS, f"{operation} -> {result}"
    assert isinstance(result.get(payload_key), dict) and result[payload_key], \
        f"{operation} returned an empty {payload_key}: {result}"


# ==========================================================================
# 2. local_server_config — UUID-scoped reads against the real publisher
# ==========================================================================


def test_get_cluster_server_by_uuid(run_async, recorder, server_uuid):
    result = run_async(recorder.run("get_cluster_server_by_uuid", domain=LOCAL,
                                    tier="read", uuid=server_uuid))
    _assert_structured(result, "get_cluster_server_by_uuid")
    assert classify(result, "get_cluster_server_by_uuid") == PASS, result
    details = result.get("server_details") or {}
    assert details.get("server_uuid") == server_uuid, result
    assert details.get("name"), result


def test_get_server_access_control_settings(run_async, recorder, server_uuid):
    result = run_async(recorder.run("get_server_access_control_settings",
                                    domain=LOCAL, tier="read",
                                    server_uuid=server_uuid))
    _assert_structured(result, "get_server_access_control_settings")
    assert classify(result, "get_server_access_control_settings") == PASS, result
    controls = result.get("access_controls") or {}
    # Applications are keyed by resource name; on an unrestricted appliance each
    # value is an empty dict (no network restriction configured).
    assert "ClearPass API" in controls, result


def test_list_ad_domains(run_async, recorder, server_uuid):
    """The appliance is not joined to any AD domain.

    FIXED: the operation's response shaping used to be wrong for exactly this
    case. ``GET ad-domain/<uuid>`` returns ``{"items": []}``; the operation only
    unwrapped ``_embedded.items``, so the raw envelope was wrapped in a list and
    reported as ``count: 1`` — one 'AD domain' that was actually the empty
    envelope. A bare ``{"items": [...]}`` envelope is now unwrapped too, so an
    unjoined appliance reports zero domains.
    """
    result = run_async(recorder.run("list_ad_domains", domain=LOCAL,
                                    tier="read", server_uuid=server_uuid))
    _assert_structured(result, "list_ad_domains")
    assert classify(result, "list_ad_domains") == PASS, result
    assert result.get("ad_domains") == [], \
        f"appliance is joined to no AD domain; expected an empty list: {result}"
    assert result.get("count") == 0, result


# ==========================================================================
# 3. local_server_config — structured not-found paths
# ==========================================================================


def test_access_control_by_resource_is_structured_404(run_async, recorder,
                                                      server_uuid):
    """No per-resource access control is configured, so every resource name —
    including one listed by get_server_access_control_settings — 404s. The
    requirement under test is that the 404 arrives as a structured API error,
    not as a crash or an HTML body.
    """
    for resource in ("ClearPass API", "zzz-mcptest-no-such-resource"):
        result = run_async(recorder.run(
            "get_server_access_control_by_resource", domain=LOCAL,
            tier="negative", expect_absent=True,
            server_uuid=server_uuid, resource_name=resource))
        _assert_structured(result, "get_server_access_control_by_resource")
        assert classify(result, "get_server_access_control_by_resource",
                        expect_absent=True) == PASS, result
        assert result.get("status_code") == 404, result
        assert result.get("error_type") == "api_error", result


def test_get_ad_domain_details_absent_domain(run_async, recorder, server_uuid):
    result = run_async(recorder.run("get_ad_domain_details", domain=LOCAL,
                                    tier="negative", expect_absent=True,
                                    server_uuid=server_uuid,
                                    netbios_name="ZZZMCPTEST"))
    _assert_structured(result, "get_ad_domain_details")
    assert classify(result, "get_ad_domain_details", expect_absent=True) == PASS, result
    assert result.get("status_code") == 404, result


def test_cluster_server_bogus_uuid_is_structured(run_async, recorder):
    result = run_async(recorder.run(
        "get_cluster_server_by_uuid", domain=LOCAL, tier="negative",
        expect_absent=True,
        uuid="00000000-0000-0000-0000-000000000000"))
    _assert_structured(result, "get_cluster_server_by_uuid")
    assert result.get("success") is False, result
    assert result.get("error_type") == "api_error", result


# ==========================================================================
# 4. audit_logs — system events, omitted-first then filtered
# ==========================================================================


def test_list_system_events_all_optional_omitted(run_async, recorder):
    """Every optional parameter omitted — the FieldInfo path.

    ``limit`` carries ``Field(default=25)``; if the omission path regressed the
    appliance would receive a ``FieldInfo`` repr as a query parameter and 422.
    """
    result = run_async(recorder.run("list_system_events", domain=AUDIT,
                                    tier="read"))
    _assert_structured(result, "list_system_events")
    assert classify(result, "list_system_events") == PASS, result
    assert result.get("returned_count") == 25, \
        f"omitted limit did not default to 25: {result.get('returned_count')}"
    assert result.get("total_count") is None, \
        "total_count must stay None when calculate_count is omitted"
    assert isinstance(result.get("system_events"), list) and result["system_events"]


@pytest.mark.parametrize("label, params", [
    ("filter_level", {"filter_str": '{"level": "ERROR"}', "limit": 5}),
    ("filter_category", {"filter_str": '{"category": "Import"}', "limit": 5}),
    ("paging", {"offset": 5, "limit": 2, "calculate_count": True}),
    ("count_only", {"limit": 1, "calculate_count": True}),
    ("large_limit", {"limit": 1000, "calculate_count": True}),
])
def test_list_system_events_with_filters(run_async, recorder, label, params):
    """Realistic filter / pagination combinations — the parameters most likely
    to have been broken by the FieldInfo defect."""
    result = run_async(recorder.run("list_system_events", domain=AUDIT,
                                    tier="read", **params))
    _assert_structured(result, "list_system_events")
    assert classify(result, "list_system_events") == PASS, f"{label} -> {result}"
    events = result.get("system_events")
    assert isinstance(events, list), result
    assert len(events) <= params["limit"], result
    if params.get("calculate_count"):
        assert isinstance(result.get("total_count"), int), result
    if label == "filter_level":
        assert all(e.get("level") == "ERROR" for e in events), result
    if label == "filter_category":
        assert all(e.get("category") == "Import" for e in events), result


@pytest.mark.parametrize("label, params, expect_field, expect_fragment", [
    ("bad_limit", {"limit": 0}, "limit", "Cannot be less than 1"),
    ("bad_filter_field", {"filter_str": '{"zzznosuchfield": "x"}', "limit": 2},
     "filter", "Invalid filter expression"),
    # The appliance rejects sorting on system events entirely; the operation's
    # own docstring warns about it. Asserted so the warning stays truthful.
    ("unsupported_sort", {"sort": "-timestamp", "limit": 2},
     "sort", "Cannot sort by field"),
])
def test_list_system_events_invalid_parameters(run_async, recorder, label,
                                               params, expect_field,
                                               expect_fragment):
    """Invalid parameter values must surface as a structured 422, never a crash.

    The appliance says exactly which parameter it rejected and why::

        422 {"detail": "Parameter validation failed",
             "validation_errors": {"limit": "Cannot be less than 1"}, ...}

    That body used to reach the caller only by accident -- ``_make_request``
    lost ``response_data`` and the raw JSON text got appended to the error
    message -- so this test used to substring-match the message blob. The body
    is passed through as data now (``response_data``), so the assertion is
    field-scoped: the named parameter must be the one the appliance faults.

    Recorded explicitly as PASS: a rejected bad value *is* the correct outcome
    here, and ``classify`` has no way to know that (it would score the
    ``success: False`` as a FAIL and pollute triage).
    """
    result = run_async(harness.invoke("list_system_events", **params))
    _assert_structured(result, "list_system_events")
    assert result.get("success") is False, f"{label} -> {result}"
    assert result.get("status_code") == 422, result
    assert result.get("error_type") == "api_error", result
    assert "Parameter validation failed" in str(result.get("error", "")), result

    body = result.get("response_data")
    assert isinstance(body, dict), f"structured error body was dropped: {result}"
    validation_errors = body.get("validation_errors")
    assert isinstance(validation_errors, dict), result
    assert expect_field in validation_errors, result
    assert expect_fragment in str(validation_errors[expect_field]), result
    recorder.record("list_system_events", AUDIT, "negative", PASS, params,
                    f"expected structured 422 for {label}: {expect_fragment}")


def test_list_system_events_accepts_the_alias_name(run_async, recorder):
    """``filter_str`` is declared with ``alias="filter"``.

    The gateway used to whitelist by *parameter* name only, so a caller
    following the documented alias was rejected with "Unknown parameter". The
    gateway now honours the alias (fixed in the gateway work-stream, not here),
    so both spellings must reach the appliance and agree.
    """
    via_alias = run_async(harness.invoke("list_system_events",
                                         filter='{"level": "ERROR"}', limit=5))
    _assert_structured(via_alias, "list_system_events")
    assert via_alias.get("success") is True, via_alias

    via_name = run_async(harness.invoke("list_system_events",
                                        filter_str='{"level": "ERROR"}', limit=5))
    assert via_name.get("success") is True, via_name
    assert via_alias.get("returned_count") == via_name.get("returned_count"), \
        f"alias and parameter name disagree: {via_alias} vs {via_name}"

    recorder.record("list_system_events", AUDIT, "negative", PASS,
                    {"filter": "<alias>"},
                    "alias 'filter' now accepted by the gateway; agrees with filter_str")


# ==========================================================================
# 5. audit_logs — admin login audit
# ==========================================================================


def test_get_admin_login_audit(run_async, recorder):
    result = run_async(recorder.run("get_admin_login_audit", domain=AUDIT,
                                    tier="read", username="apiadmin"))
    _assert_structured(result, "get_admin_login_audit")
    assert classify(result, "get_admin_login_audit") == PASS, result
    entries = result.get("login_audit_entries")
    assert isinstance(entries, list) and entries, result
    assert entries[0].get("username") == "apiadmin", result


def test_get_admin_login_audit_unknown_user_is_not_an_error(run_async, recorder):
    """Recorded behaviour, not an assertion of correctness.

    ``GET login-audit/<name>`` returns 200 with a synthesised record for a
    username that does not exist, so the operation reports
    ``success: True, count: 1``. There is no way for a caller to distinguish a
    real admin from a typo. Reported as an API-fidelity finding; the operation
    itself does not crash, so the verdict is PASS.
    """
    result = run_async(recorder.run("get_admin_login_audit", domain=AUDIT,
                                    tier="negative",
                                    username="zzz-mcptest-no-such-admin"))
    _assert_structured(result, "get_admin_login_audit")
    assert classify(result, "get_admin_login_audit") == PASS, result
    assert result.get("count") == 1, result


# ==========================================================================
# 6. audit_logs — Insight (licence-dependent, EXPECTED_SKIP)
# ==========================================================================


@pytest.mark.parametrize("operation, params, collection_key", [
    ("list_insight_alerts", {}, "insight_alerts"),                # all omitted
    ("list_insight_alerts", {"offset": 0, "limit": 5, "calculate_count": True},
     "insight_alerts"),
    ("list_insight_reports", {}, "insight_reports"),              # all omitted
    ("list_insight_reports", {"offset": 0, "limit": 5, "calculate_count": True},
     "insight_reports"),
])
def test_insight_collections_are_served(run_async, recorder, operation, params,
                                        collection_key):
    """FIXED: the two Insight collection reads now reach the appliance.

    These used to be pinned as known skips asserting ``status_code == 404``.
    That 404 was the ``/api/v1`` mount, not a missing licence: measured by
    direct curl on 2026-07-30, ``GET /api/v1/alert`` and ``GET /api/v1/report``
    answer ``404 Object not found`` while ``GET /api/alert`` and
    ``GET /api/report`` return proper collections (this appliance holds 1 alert
    and 0 reports). The client now builds every URL from the unversioned
    ``/api`` root — see ``ClearPassClient._endpoint_url``.

    Pinned as real reads so a regression back to the versioned mount fails here
    instead of being excused by the known-limitation allowlist.
    """
    result = run_async(recorder.run(operation, domain=AUDIT, tier="read", **params))
    _assert_structured(result, operation)
    assert classify(result, operation) == PASS, f"{operation}({params}) -> {result}"
    assert result.get("success") is True, result
    assert isinstance(result.get(collection_key), list), result
    if params.get("calculate_count"):
        assert isinstance(result.get("total_count"), int), result


@pytest.mark.parametrize("operation, params", [
    ("get_insight_alert_details", {"alert_id": 999999}),
    ("get_insight_alert_details", {"alert_name": "zzz-mcptest-no-such-alert"}),
    ("get_insight_report_details", {"report_id": 999999}),
])
def test_insight_detail_reads_are_known_skips(run_async, recorder, operation, params):
    """The per-object Insight reads still answer 404 for an absent object.

    Unlike the collections above these are dispatched against ids/names that do
    not exist, so a 404 is the only possible answer on any appliance and there is
    nothing here to distinguish "absent object" from "absent licence". Asserted
    as a *known* skip carrying its reason, and required to present as a
    structured error — a crash marker would still be a FAIL.
    """
    result = run_async(recorder.run(operation, domain=AUDIT, tier="read", **params))
    _assert_structured(result, operation)
    verdict = classify(result, operation)
    assert verdict == EXPECTED_SKIP, f"{operation}({params}) -> {result}"
    assert harness.expected_skip_reason(operation), operation
    assert result.get("status_code") == 404, result


def test_run_insight_report_body_is_no_longer_malformed(run_async, recorder):
    """FIXED: ``run_insight_report`` used never to reach the appliance's own
    handler at all.

    ``ClearPassClient.run_insight_report_by_id`` issued ``POST report/<id>/run``
    with ``data=None`` while the httpx client sets a global
    ``Content-Type: application/json`` header, so the appliance saw a JSON
    content type with an empty body and answered
    ``400 JSON decoding error: Syntax error, malformed JSON`` — before the report
    id was even resolved. The client now sends ``data={}``.

    Live proof of the fix: the same call now gets past body parsing and the
    appliance answers ``500`` for the non-existent report id 999999 (previously
    ``400 malformed JSON``). ``report/<id>/run`` therefore *does* exist on
    6.12.4 — the blanket "Insight unavailable" story is not the whole truth,
    even though this appliance's ``report`` collection itself 404s.

    NOTE (reported, not fixed — outside this work-stream): that 500 carries an
    HTML body, so ``_assert_structured`` is deliberately not applied here.
    """
    result = run_async(harness.invoke("run_insight_report", report_id=999999))
    error = str(result.get("error", ""))
    assert "malformed JSON" not in error, \
        f"empty-body POST regression -- data= is None again: {result}"
    assert result.get("status_code") != 400, result
    assert result.get("status_code") == 500, \
        f"appliance response for report/999999/run changed: {result}"
    recorder.record("run_insight_report", AUDIT, "negative", EXPECTED_SKIP,
                    {"report_id": 999999},
                    "empty-body POST fixed (data={}); appliance now answers 500 "
                    "for a non-existent report id instead of 400 malformed JSON")


def test_insight_alert_details_requires_an_identifier(run_async, recorder):
    """Both optional identifiers omitted -> structured clarification, no
    dispatch. Also the id-or-name check: unlike ``delete_guest_user`` /
    ``get_network_device``, this operation genuinely has both branches
    (``get_insight_alert_by_id`` and ``get_insight_alert_by_name``), so the
    documented name path is really implemented.
    """
    result = run_async(harness.invoke("get_insight_alert_details"))
    assert _is_clarification(result), result
    assert "alert_id" in str(result) and "alert_name" in str(result), result
    recorder.record("get_insight_alert_details", AUDIT, "negative", PASS,
                    {}, "identifier-less call returns structured clarification")


# ==========================================================================
# 7. audit_logs — deletion confirmation guard (local refusal, nothing dispatched)
# ==========================================================================


def test_delete_insight_alert_requires_confirmation(run_async, recorder):
    """``confirm`` omitted must refuse *before* any client call.

    The target id is deliberately non-existent: if the guard ever regressed
    (e.g. an omitted ``confirm`` arriving as a truthy ``FieldInfo``) the call
    would hit the appliance against an id that matches nothing.
    """
    result = run_async(harness.invoke("delete_insight_alert", alert_id=999999))
    assert _is_clarification(result), \
        f"delete_insight_alert did not refuse without confirm=True: {result}"
    assert "confirm" in str(result).lower(), result
    recorder.record("delete_insight_alert", AUDIT, "negative", PASS,
                    {"alert_id": 999999},
                    "confirmation guard refused locally; delete never dispatched")


# ==========================================================================
# 8. Denylist enforcement
# ==========================================================================


@pytest.mark.parametrize("operation", [
    "leave_ad_domain",
    "delete_server_access_control_by_resource",
])
def test_denylisted_operations_are_never_dispatched(run_async, recorder, operation):
    assert is_denylisted(operation), operation
    with pytest.raises(DenylistedOperation):
        run_async(harness.invoke(operation, server_uuid="x",
                                 netbios_name="x", resource_name="x"))
    recorder.record(operation, LOCAL, "denylist", BLOCKED, {},
                    BLOCKED_OPERATIONS[operation])


# ==========================================================================
# 9. BLOCKED inventory — every operation deliberately left unproven
# ==========================================================================


@pytest.mark.parametrize("operation", sorted(
    op for op in BLOCKED_OPERATIONS if not is_denylisted(op)))
def test_blocked_operations_are_recorded(recorder, operation):
    """No dispatch. Records why the operation is unproven so Phase 5 can see
    exactly what live coverage does not cover.

    The two denylisted entries are recorded by the denylist test above, so they
    are excluded here to keep one record per operation."""
    domain = LOCAL if operation in {
        "update_server_access_control_by_resource",
        "delete_server_access_control_by_resource",
        "join_ad_domain", "leave_ad_domain",
        "configure_ad_password_servers", "update_cluster_server_by_uuid",
    } else AUDIT
    reason = BLOCKED_OPERATIONS[operation]
    assert reason
    recorder.record(operation, domain, "blocked", BLOCKED, {}, reason)


# ==========================================================================
# 10. Scope coverage guard
# ==========================================================================


# Operations added to ``audit_logs`` by the full-SDK-coverage expansion
# (12 -> 25). They are owned by ``test_certs_ca_audit_live.py``;
# ``local_server_config`` did not change (15). This module keeps its original
# 27-operation scope and excludes them.
EXPANSION_OPERATIONS: List[str] = [
    "delete_insight_report_by_name",
    "disable_insight_alert_by_name",
    "disable_insight_report_by_name",
    "enable_insight_alert_by_name",
    "enable_insight_report_by_name",
    "get_insight_endpoint_by_ip",
    "get_insight_endpoint_by_mac",
    "get_insight_endpoints_by_ip_range",
    "get_insight_endpoints_by_time_range",
    "mute_insight_alert_by_name",
    "replace_insight_report_by_name",
    "unmute_insight_alert_by_name",
    "update_insight_report_by_name",
]


def test_every_operation_in_scope_is_accounted_for(live_enabled):
    """All 27 operations in this module's scope are either exercised above or
    listed in BLOCKED_OPERATIONS.

    26 -> 27: ``list_cluster_servers`` was added to close the server-UUID
    catalogue gap described in the module docstring.

    The two domains now hold 40 operations (15 + 25); the 13 in
    ``EXPANSION_OPERATIONS`` belong to ``test_certs_ca_audit_live.py``.
    Anything else appearing in either domain falls into this module's scope and
    must be accounted for here."""
    import src.main  # noqa: F401
    from src.registry import registry

    unknown = [n for n in EXPANSION_OPERATIONS if registry.get(n) is None]
    assert not unknown, f"unknown operations: {unknown}"

    exercised = {
        # local_server_config
        "list_cluster_servers",
        "get_cppm_version", "get_server_version", "get_server_fips_status",
        "get_cluster_server_by_uuid", "get_server_access_control_settings",
        "list_ad_domains", "get_server_access_control_by_resource",
        "get_ad_domain_details",
        # audit_logs
        "list_system_events", "get_admin_login_audit", "list_insight_alerts",
        "list_insight_reports", "get_insight_alert_details",
        "get_insight_report_details", "run_insight_report",
        "delete_insight_alert",
    }
    in_scope = ({s.name for s in registry.search(domain=LOCAL)} |
                {s.name for s in registry.search(domain=AUDIT)}) \
        - set(EXPANSION_OPERATIONS)
    assert len(in_scope) == 27, sorted(in_scope)
    unaccounted = in_scope - exercised - set(BLOCKED_OPERATIONS)
    assert not unaccounted, f"operations with no live disposition: {sorted(unaccounted)}"
