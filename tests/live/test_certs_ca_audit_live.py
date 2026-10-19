"""Live validation — ``certificates`` (the 20 operations added after the first
sweep), ``certificate_authority`` (19) and ``audit_logs`` (the 13 added after
the first sweep).

52 new operations, plus one re-covered, exercised against a real ClearPass
6.12.4 appliance.
``import_certificate_to_trust_list`` is the re-covered one: the first sweep
recorded it ``BLOCKED`` because "no delete operation exists in the registry to
remove it" — ``delete_certificate_trust_list`` (``DELETE /cert-trust-list/{id}``)
now exists, so the trust list has become a real fixture family and that
justification no longer holds.

Scope rules baked into this module
----------------------------------
**certificates** — reads across all five certificate collections (revocation
lists, trust list details, trust list by id, service certificates, server
certificate by name) plus ONE fixture lifecycle:

    import a throwaway CA -> find it in the list -> PATCH enabled on/off
                          -> DELETE -> prove it is gone

The imported certificate is a self-signed CA generated once for this suite and
embedded below as a literal PEM. Its private key was destroyed at generation
time and never existed in this repository, so the certificate cannot sign
anything; its subject carries ``zzz-mcptest`` so a human reading the appliance's
trust list can see instantly what it is and where it came from. It is imported
with ``cert_usage=['Others']`` and ``enabled=False``, which is the most inert
combination the endpoint accepts — while it exists it is trusted for nothing.
``Others`` is the appliance's own vocabulary: 6.12.4 answers ``422 Invalid
Certificate usage "OTHER_TLS" specified`` for the constant-style value, and
every entry already in this publisher's trust list is tagged with names from
``AD/LDAP Servers``, ``Aruba Services``, ``Endpoint Context Servers``, ``SAML``,
``SMTP`` and ``Others``.

The trust list IS one of the nine families the inventory guard snapshots, so a
survivor would fail the session. The delete is registered on the ``cleanup``
fixture the instant the import returns, and the test proves the entry is gone
before it finishes.

Everything that writes appliance *service* state is recorded ``BLOCKED`` and
never dispatched: ``create_self_signed_certificate``, ``create_service_certificate``,
``replace_server_certificate_by_name``, ``update_server_certificate``,
``enable_server_certificate``, ``disable_server_certificate``. So are the two
certificate-upload creates (``create_client_certificate``,
``create_service_certificate``) — both take only a ``certificate_url`` or a
``pkcs12_file_url``, i.e. they instruct the appliance to fetch from a URL it can
reach. There is no inline-PEM form, so no fixture can be created from this
harness at all; they are EXPECTED-LIMITATION as much as BLOCKED.

The three deletes with no fixture of their own (``delete_client_certificate``,
``delete_service_certificate``, ``delete_certificate_revocation_list``) are
dispatched against an id far outside anything this appliance holds. Nothing can
match, so nothing can be destroyed, and the code path is still proven.

**certificate_authority (19)** — Onboard is a separately licensed feature and is
expected to be absent here, so the reads are asserted only to answer with a
structured error or an empty collection. The three mutating certificate
operations (``onboard_sign_certificate_request``, ``onboard_revoke_certificate``,
``onboard_reject_certificate_request``) are on the hard denylist added for this
scope: each acts irreversibly on a certificate or request belonging to a real
enrolling device, and the Onboard CA has no fixture namespace. Device and user
writes are ``BLOCKED`` for the same reason — there is no enrollment path from
this harness that would produce a device or user we own.

**audit_logs (13)** — the four Insight endpoint lookups run against RFC 5737
TEST-NET-1 addresses and a locally-administered MAC; Insight is licence-
dependent and already on ``harness.KNOWN_LIMITATIONS``, so a structured 404 is
an EXPECTED-LIMITATION, not a failure. The alert/report by-name operations get
no fixture: the first sweep recorded ``create_insight_alert`` and
``create_insight_report`` as BLOCKED (not a sweepable family, and the report
create carries a delivery schedule that can email real recipients), and that
still holds. They are instead dispatched against **fixture-namespaced names
that do not exist**, guarded by ``assert_ours``, so a state toggle, a PATCH or a
DELETE can only ever address an object inside our own namespace — and there is
no such object. ``replace_insight_report_by_name`` is the one exception: a PUT
against a name can behave as an upsert, and an accidentally created report
carries a mail schedule, so it stays BLOCKED.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation, is_denylisted
from .harness import EXPECTED_SKIP, FAIL, PASS, assert_ours

BLOCKED = "BLOCKED"

CERTS = "certificates"
CA = "certificate_authority"
AUDIT = "audit_logs"

# An id far outside anything this appliance holds; used for every absent path.
ABSENT_ID = 999999999
# Inside the fixture namespace on purpose: ``assert_ours`` vouches for it, so
# any write that reached the appliance could only ever address our own
# namespace — and nothing in it exists.
ABSENT_FIXTURE_NAME = "zzz-mcptest-object-that-does-not-exist"

# RFC 5737 TEST-NET-1 / locally-administered MAC — nothing can match either.
NX_IP = "192.0.2.1"
NX_MAC = "02:00:5e:10:00:00"
NX_IP_RANGE = "192.0.2.0-24"

# --------------------------------------------------------------------------
# The throwaway trust-list fixture certificate
# --------------------------------------------------------------------------
#
# Generated once, offline, purely for this suite:
#
#   openssl req -x509 -newkey rsa:2048 -nodes -days 7300 \
#     -subj "/C=GB/O=zzz-mcptest/OU=clearpass-sidekick-live-suite/\
# CN=zzz-mcptest-live-suite-ca" \
#     -addext "basicConstraints=critical,CA:TRUE" \
#     -addext "keyUsage=critical,keyCertSign,cRLSign"
#
# The private key was written to a temporary directory and destroyed in the
# same shell; it has never existed in this repository and nothing can be signed
# with this CA. Embedding the PEM as a literal is deliberate — the test must not
# shell out to openssl, and a certificate generated at run time would produce a
# different object on every run, which is exactly what the inventory guard is
# built to notice.
FIXTURE_CA_SUBJECT_CN = "zzz-mcptest-live-suite-ca"
FIXTURE_CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIUVt17CMhATCpiE4TecR+3vkD0epgwDQYJKoZIhvcNAQEL
BQAwbzELMAkGA1UEBhMCR0IxFDASBgNVBAoMC3p6ei1tY3B0ZXN0MSYwJAYDVQQL
DB1jbGVhcnBhc3Mtc2lkZWtpY2stbGl2ZS1zdWl0ZTEiMCAGA1UEAwwZenp6LW1j
cHRlc3QtbGl2ZS1zdWl0ZS1jYTAeFw0yNjA3MzAxMzU5NTBaFw00NjA3MjUxMzU5
NTBaMG8xCzAJBgNVBAYTAkdCMRQwEgYDVQQKDAt6enotbWNwdGVzdDEmMCQGA1UE
CwwdY2xlYXJwYXNzLXNpZGVraWNrLWxpdmUtc3VpdGUxIjAgBgNVBAMMGXp6ei1t
Y3B0ZXN0LWxpdmUtc3VpdGUtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDf+D+7dqbmf8nb0KKS8TIGRJAIGrjlw/bXZZDWkc0gXdNc4V7SF/Mmnjp/
lFMXqJzzIa+/MnoW67YyGR+xn4A0dxY9Og5cfA7+kqClShbv79DV1NmD0fZUUy+o
BaDwyzCaS92zvTUG8MBv1+xPNIP3R8J+uq6GLJxTn+64S0+vyhqh0nIPPsBn7hYK
VK9PpYRZOaKucMctEmXoQe0sYcjaB76tcQuSne6bOJHyLycOhuZQOq2su6/AoA8x
QsrMsnI5K/6BCfVK8JFAcvqCh35P5+ZkSVHpDF44O9QrT9F2rEFq5HSJqi9igLol
OaFzjpQ0O/tQagYkO1XFk0m3zJmnAgMBAAGjYzBhMB0GA1UdDgQWBBQneX9H97CW
DZO6k7G1UxDXuDagcDAfBgNVHSMEGDAWgBQneX9H97CWDZO6k7G1UxDXuDagcDAP
BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOC
AQEAja8vtCLc859s/W0TIerH3sW2adxiacqGQb8yTwXiaBTQPLCMR57iAxLeJ0aU
lu99YtXoJY2yJRm2mr30htUPwriFrTjBsEepHmlq1NIddF5Jaj9jm1yssacouBtG
Xo5+LF1mlVY/eYqts7EZF1+xyGRSvx2IRsrFBqfrw2yDp8Td50K+C9qtt2Z5H9Cd
COaj6yp72Nl9ya5pNz2XUbJHlpfj3QkrxRszYzzvEbauzNt8Saio3N41PPig3oGb
2hrxwFLoHi461VHClhID4YLxrDKOr9nr38dWrqAcLb+Vk1cue/NmhniA4fCXZjvV
GFwyHNwEl304llU9PZivpVPkOg==
-----END CERTIFICATE-----
"""

# operation -> {"verdict": ..., "note": ...}; asserted complete by the summary.
COVERAGE: Dict[str, Dict[str, str]] = {}
NOTES: List[str] = []
FINDINGS: List[Dict[str, Any]] = []


def _mark(operation: str, verdict: str, note: str = "") -> None:
    COVERAGE[operation] = {"verdict": verdict, "note": note[:180]}


# --------------------------------------------------------------------------
# Dispatch + verdict helper
# --------------------------------------------------------------------------

_ERROR_KEYS = ("error", "message", "detail", "details", "error_details",
               "warning", "safety_warning", "question")

_ABSENT_PAT = ("404", "not found", "does not exist", "no such", "not exist",
               "could not be found", "invalid id")

_ENVELOPE_KEYS = ("success", "message", "count", "total_count",
                  "returned_count", "pagination_info", "error", "status_code",
                  "mac_address", "ip", "ip_range", "from_time", "to_time")


def _text(result: Dict[str, Any]) -> str:
    return " ".join(str(result.get(k, "")) for k in _ERROR_KEYS)


def _crash_markers(result: Any) -> List[str]:
    marker = harness.deep_crash_marker(result)
    return [marker] if marker else []


def _html_body(result: Dict[str, Any]) -> bool:
    return harness.looks_like_html(harness.deep_error_text(result) or _text(result))


def _payload_items(result: Dict[str, Any]) -> List[Any]:
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
            return list(value)
    return []


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
    **params: Any,
) -> Tuple[Dict[str, Any], str]:
    """Invoke through the gateway, classify, record. Returns (result, verdict).

    ``expect``:
      ``success``  — should work against real data.
      ``absent``   — a structured "not found" (or an empty collection) for a
                     deliberately absent object.
      ``refusal``  — a structured guard refusal; ``substrings`` must appear.
      ``rejected`` — the appliance legitimately rejects it; any structured,
                     crash-free failure is correct.
      ``tolerant`` — success is ideal, but a structured, crash-free failure is
                     an acceptable environment answer (EXPECTED_SKIP).
    """
    start = time.perf_counter()
    result = _sync(harness.invoke(operation, _params=params))
    duration = (time.perf_counter() - start) * 1000.0

    text = _text(result)
    crashes = _crash_markers(result)
    success = result.get("success") is True

    if _html_body(result):
        NOTES.append(f"{operation}: error body is an HTML page, not a "
                     f"structured API error")
        verdict = FAIL
    elif crashes:
        verdict = FAIL
    elif expect == "success":
        verdict = PASS if success else FAIL
    elif expect == "absent":
        low = (harness.deep_error_text(result) or text).lower()
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
    recorder.record(operation, domain, tier, verdict, params, err, duration)
    if verdict == FAIL:
        FINDINGS.append({"operation": operation, "params": params,
                         "error": (err or "")[:400]})
    return result, verdict


def record_blocked(recorder, operation: str, domain: str, reason: str) -> None:
    recorder.record(operation, domain, "blocked", BLOCKED, {}, reason, 0.0)
    _mark(operation, BLOCKED, reason)


def record_limitation(recorder, operation: str, domain: str, reason: str) -> None:
    recorder.record(operation, domain, "read", EXPECTED_SKIP, {},
                    f"EXPECTED-LIMITATION: {reason}", 0.0)
    _mark(operation, EXPECTED_SKIP, f"EXPECTED-LIMITATION: {reason}")


def assert_denylisted(recorder, operation: str, domain: str,
                      params: Dict[str, Any]) -> None:
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


# --------------------------------------------------------------------------
# Session catalogue — read the appliance once
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def catalogue(recorder, live_enabled) -> Dict[str, Any]:
    """Real ids harvested once so detail calls target genuine objects."""
    cat: Dict[str, Any] = {}

    crls, _ = run_op(recorder, "list_certificate_revocation_lists", CERTS,
                     expect="tolerant")
    cat["crl_ids"] = [e.get("id") for e in _payload_items(crls)
                      if isinstance(e, dict) and e.get("id") is not None]

    trust, _ = run_op(recorder, "list_certificate_trust_list", CERTS,
                      expect="tolerant", limit=1000)
    cat["trust_ids"] = [e.get("id") for e in (trust.get("trust_list_entries") or [])
                        if isinstance(e, dict) and e.get("id") is not None]

    svc, _ = run_op(recorder, "list_service_certificates", CERTS,
                    expect="tolerant")
    cat["service_cert_ids"] = [e.get("id") for e in _payload_items(svc)
                               if isinstance(e, dict) and e.get("id") is not None]

    servers, _ = run_op(recorder, "list_cluster_servers", "local_server_config",
                        expect="tolerant")
    uuid = None
    for item in (servers.get("cluster_servers") or []):
        if isinstance(item, dict):
            uuid = item.get("server_uuid") or item.get("uuid")
            if uuid:
                break
    cat["server_uuid"] = uuid
    return cat


# ==========================================================================
# certificates — revocation lists (reads; writes blocked)
# ==========================================================================


def test_certificate_revocation_list_reads(recorder, catalogue):
    """``GET /revocation-list`` with every optional omitted, then supplied."""
    result, verdict = run_op(recorder, "list_certificate_revocation_lists",
                             CERTS, expect="success")
    _mark("list_certificate_revocation_lists", verdict,
          f"{len(_payload_items(result))} CRL(s) configured")
    assert verdict == PASS, f"CRL list failed: {_text(result)}"
    assert "FieldInfo" not in json.dumps(result, default=str), \
        "FieldInfo leaked into the CRL list payload"

    _, fv = run_op(recorder, "list_certificate_revocation_lists", CERTS,
                   expect="success", sort="+id", offset=0, limit=5,
                   calculate_count=True)
    assert fv == PASS, "the explicitly-specified CRL list branch failed"

    if catalogue["crl_ids"]:
        target = catalogue["crl_ids"][0]
        got, gv = run_op(recorder, "get_certificate_revocation_list_by_id",
                         CERTS, expect="success", revocation_list_id=target)
        _mark("get_certificate_revocation_list_by_id", gv, f"id={target}")
        assert gv == PASS, f"CRL detail failed: {_text(got)}"
    else:
        NOTES.append("no CRLs configured on this appliance; "
                     "get_certificate_revocation_list_by_id only has an "
                     "absent path to exercise")

    absent, av = run_op(recorder, "get_certificate_revocation_list_by_id",
                        CERTS, tier="negative", expect="absent",
                        revocation_list_id=ABSENT_ID)
    if "get_certificate_revocation_list_by_id" not in COVERAGE:
        _mark("get_certificate_revocation_list_by_id", av, "absent path only")
    assert av == PASS, f"absent CRL id mishandled: {absent}"


def test_certificate_revocation_list_writes(recorder):
    """Create/update are blocked; delete is proven against an impossible id.

    A CRL entry is a URL the appliance polls on a schedule. Creating one makes
    the appliance fetch an external URL on a timer and the object carries no
    name that ``assert_ours`` could vouch for, so neither create nor update is
    dispatched. The delete *is* dispatched, against an id no appliance in this
    lab holds — nothing can match, so nothing can be destroyed.
    """
    record_blocked(
        recorder, "create_certificate_revocation_list", CERTS,
        "Adds a CRL the appliance polls on a timer; the object carries no name "
        "the fixture guard can vouch for, so it could not be safely swept.")
    record_blocked(
        recorder, "update_certificate_revocation_list", CERTS,
        "Would have to target a pre-existing CRL — the harness never mutates "
        "an object it did not create.")

    result, verdict = run_op(recorder, "delete_certificate_revocation_list",
                             CERTS, tier="negative", expect="absent",
                             revocation_list_id=ABSENT_ID)
    _mark("delete_certificate_revocation_list", verdict,
          "dispatched against an impossible id; nothing can match")
    assert verdict == PASS, f"absent CRL delete mishandled: {result}"


# ==========================================================================
# certificates — trust list reads + the fixture lifecycle
# ==========================================================================


def test_certificate_trust_list_details_and_by_id(recorder, catalogue):
    """``GET /cert-trust-list-details`` and ``GET /cert-trust-list/{id}``."""
    details, dv = run_op(recorder, "list_certificate_trust_list_details", CERTS,
                         expect="success")
    _mark("list_certificate_trust_list_details", dv,
          f"{len(_payload_items(details))} detail record(s)")
    assert dv == PASS, f"trust-list details failed: {_text(details)}"
    assert "FieldInfo" not in json.dumps(details, default=str)

    _, fv = run_op(recorder, "list_certificate_trust_list_details", CERTS,
                   expect="success", sort="+id", offset=0, limit=5,
                   calculate_count=True)
    assert fv == PASS, "the explicitly-specified details branch failed"

    assert catalogue["trust_ids"], \
        "no trust-list entries on this appliance — the by-id read has no target"
    target = catalogue["trust_ids"][0]
    got, gv = run_op(recorder, "get_certificate_trust_list_by_id", CERTS,
                     expect="success", cert_trust_list_id=target)
    _mark("get_certificate_trust_list_by_id", gv, f"id={target}")
    assert gv == PASS, f"trust-list by-id failed: {_text(got)}"

    absent, av = run_op(recorder, "get_certificate_trust_list_by_id", CERTS,
                        tier="negative", expect="absent",
                        cert_trust_list_id=ABSENT_ID)
    assert av == PASS, f"absent trust-list id mishandled: {absent}"


def _der_body(pem: Any) -> str:
    """The base64 body of a PEM blob, free of armour and whitespace.

    Two representations of the same certificate differ only in line wrapping
    and trailing newlines, so comparing the stripped body is an exact identity
    test on the certificate itself.
    """
    if not isinstance(pem, str):
        return ""
    return "".join(pem.replace("-----BEGIN CERTIFICATE-----", "")
                      .replace("-----END CERTIFICATE-----", "").split())


FIXTURE_CA_DER = _der_body(FIXTURE_CA_PEM)


def _find_fixture_trust_entry(recorder) -> Optional[Dict[str, Any]]:
    """Locate our throwaway CA in the trust list by its certificate body.

    A trust-list entry carries only ``id``, ``cert_file``, ``cert_usage`` and
    ``enabled`` — 6.12.4 returns no parsed subject/issuer fields, so the
    fixture's ``zzz-mcptest`` CN exists only *inside* the DER and can never be
    matched as a substring of the JSON. The certificate body itself is the
    handle, and it is a stronger one: it identifies this exact certificate
    rather than anything that merely mentions the name.
    """
    listed, _ = run_op(recorder, "list_certificate_trust_list", CERTS,
                       expect="tolerant", limit=1000)
    for entry in (listed.get("trust_list_entries") or []):
        if not isinstance(entry, dict):
            continue
        if _der_body(entry.get("cert_file")) == FIXTURE_CA_DER:
            return entry
    return None


def test_certificate_trust_list_fixture_lifecycle(recorder, cleanup, catalogue):
    """import -> locate -> PATCH disable/enable -> DELETE -> prove it is gone.

    This is the lifecycle the first sweep could not run: without
    ``delete_certificate_trust_list`` an imported certificate was permanent.

    The certificate is inert while it exists — imported with
    ``enabled=False`` and ``cert_usage=['Others']``, and its private key was
    destroyed at generation time, so it can never validate a peer or sign
    anything. The delete is registered on ``cleanup`` before anything is
    asserted, because the trust list is one of the nine families the inventory
    guard snapshots and a survivor would fail the whole session.
    """
    before = len(catalogue["trust_ids"])

    holder: Dict[str, Any] = {}

    def _cleanup_entry():
        entry_id = holder.get("id")
        if entry_id is None:
            entry = _find_fixture_trust_entry(recorder)
            entry_id = entry.get("id") if entry else None
        if entry_id is None:
            return harness.invoke("list_certificate_trust_list", limit=1)
        return harness.invoke("delete_certificate_trust_list",
                              cert_trust_list_id=entry_id)

    cleanup.add(_cleanup_entry)

    imported, iv = run_op(recorder, "import_certificate_to_trust_list", CERTS,
                          tier="create", expect="success",
                          cert_file_content=FIXTURE_CA_PEM,
                          cert_usage=["Others"], enabled=False)
    _mark("import_certificate_to_trust_list", iv,
          "throwaway zzz-mcptest CA, Others, disabled")
    assert iv == PASS, f"trust-list import failed: {_text(imported)}"

    entry = _find_fixture_trust_entry(recorder)
    assert entry is not None, (
        f"the imported {FIXTURE_CA_SUBJECT_CN} certificate is not in the trust "
        f"list: {imported}")
    entry_id = entry.get("id")
    assert entry_id is not None, f"imported trust-list entry has no id: {entry}"
    holder["id"] = entry_id

    # The entry that is about to be PATCHed and DELETEd was matched on the
    # fixture certificate's own body, so it cannot be anything but ours. The CN
    # inside that certificate is namespaced too, which is what makes the entry
    # legible to a human reading the appliance's trust list.
    assert _der_body(entry.get("cert_file")) == FIXTURE_CA_DER, \
        "the located trust-list entry is not the fixture certificate"
    assert FIXTURE_CA_SUBJECT_CN.startswith(harness.FIXTURE_PREFIX), \
        "the fixture certificate's CN is outside the fixture namespace"

    # --- PATCH: enable, then disable again ---------------------------------
    enabled, ev = run_op(recorder, "update_certificate_trust_list", CERTS,
                         tier="update", expect="success",
                         cert_trust_list_id=entry_id,
                         trust_list_data={"enabled": True})
    _mark("update_certificate_trust_list", ev, "PATCH enabled True then False")
    assert ev == PASS, f"trust-list PATCH (enable) failed: {_text(enabled)}"

    disabled, dv2 = run_op(recorder, "update_certificate_trust_list", CERTS,
                           tier="update", expect="success",
                           cert_trust_list_id=entry_id,
                           trust_list_data={"enabled": False})
    assert dv2 == PASS, f"trust-list PATCH (disable) failed: {_text(disabled)}"

    # --- DELETE -------------------------------------------------------------
    deleted, delv = run_op(recorder, "delete_certificate_trust_list", CERTS,
                           tier="delete", expect="success",
                           cert_trust_list_id=entry_id)
    _mark("delete_certificate_trust_list", delv, f"removed id {entry_id}")
    assert delv == PASS, f"trust-list delete failed: {_text(deleted)}"
    holder.pop("id", None)

    # --- prove it is really gone -------------------------------------------
    assert _find_fixture_trust_entry(recorder) is None, \
        f"{FIXTURE_CA_SUBJECT_CN} survived the delete — the inventory guard " \
        f"will fail this session"

    survivors, sv = run_op(recorder, "list_certificate_trust_list", CERTS,
                           expect="success", limit=1000)
    assert sv == PASS
    after = len(survivors.get("trust_list_entries") or [])
    assert after == before, (
        f"trust list went from {before} to {after} entries — the fixture "
        f"lifecycle did not balance")
    NOTES.append(f"trust-list fixture lifecycle balanced at {before} entries")


# ==========================================================================
# certificates — client / service / server certificates
# ==========================================================================


def test_client_certificate_writes(recorder):
    """create is impossible from this harness; delete is proven safely.

    ``POST /client-cert`` accepts only ``certificate_url`` or
    ``pkcs12_file_url`` — the appliance fetches the material itself. There is
    no inline-PEM form, so the embedded fixture certificate cannot be used and
    no client-certificate fixture can exist. That is an environment limitation
    of the endpoint, not a harness choice.
    """
    record_limitation(
        recorder, "create_client_certificate", CERTS,
        "POST /client-cert takes only certificate_url / pkcs12_file_url; there "
        "is no inline-PEM form, so no fixture client certificate can be "
        "created from this harness")

    result, verdict = run_op(recorder, "delete_client_certificate", CERTS,
                             tier="negative", expect="absent",
                             client_cert_id=ABSENT_ID)
    _mark("delete_client_certificate", verdict,
          "dispatched against an impossible id; nothing can match")
    assert verdict == PASS, f"absent client-cert delete mishandled: {result}"


def test_service_certificate_reads_and_writes(recorder, catalogue):
    """``GET /service-cert/{id}`` plus the blocked/probed write paths."""
    if catalogue["service_cert_ids"]:
        target = catalogue["service_cert_ids"][0]
        got, gv = run_op(recorder, "get_service_certificate_by_id", CERTS,
                         expect="success", service_cert_id=target)
        _mark("get_service_certificate_by_id", gv, f"id={target}")
        assert gv == PASS, f"service-cert detail failed: {_text(got)}"
    else:
        NOTES.append("no service certificates on this appliance; "
                     "get_service_certificate_by_id has only an absent path")

    absent, av = run_op(recorder, "get_service_certificate_by_id", CERTS,
                        tier="negative", expect="absent",
                        service_cert_id=ABSENT_ID)
    if "get_service_certificate_by_id" not in COVERAGE:
        _mark("get_service_certificate_by_id", av, "absent path only")
    assert av == PASS, f"absent service-cert id mishandled: {absent}"

    record_blocked(
        recorder, "create_service_certificate", CERTS,
        "POST /service-cert takes only certificate_url / pkcs12_file_url and "
        "binds the result to a live appliance service; no inline-PEM form "
        "exists and the result would be appliance service state.")

    gone, dv = run_op(recorder, "delete_service_certificate", CERTS,
                      tier="negative", expect="absent",
                      service_cert_id=ABSENT_ID)
    _mark("delete_service_certificate", dv,
          "dispatched against an impossible id; nothing can match")
    assert dv == PASS, f"absent service-cert delete mishandled: {gone}"


def test_get_server_certificate_by_name(recorder, catalogue):
    """``GET /server-cert/name/{server_uuid}/{service_name}``.

    The UUID comes from ``list_cluster_servers`` — the operation that exists
    specifically to close the server-UUID catalogue gap — and the service names
    are the four the endpoint documents. Whichever the appliance serves is
    recorded; a lab publisher always has at least RADIUS, and the RADIUS answer
    is asserted to be a real payload, not merely a non-crash.

    The negative probe only requires a *structured, crash-free* rejection. This
    endpoint answers a syntactically invalid UUID with ``422`` and an empty
    detail rather than a 404: the UUID never reaches an object lookup, so there
    is nothing for the appliance to call "not found". A 422 here is a graceful
    answer, and demanding 404-shaped wording would be asserting the appliance's
    phrasing rather than the operation's behaviour.
    """
    uuid = catalogue["server_uuid"]
    assert uuid, "no cluster server UUID could be discovered"

    served: List[str] = []
    last: Dict[str, Any] = {}
    radius: Dict[str, Any] = {}
    for service_name in ("RADIUS", "HTTPS(RSA)", "HTTPS(ECC)", "RadSec"):
        result, verdict = run_op(recorder, "get_server_certificate_by_name",
                                 CERTS, expect="tolerant", server_uuid=uuid,
                                 service_name=service_name)
        assert not _crash_markers(result), \
            f"get_server_certificate_by_name({service_name}) crashed: {result}"
        last = result
        if service_name == "RADIUS":
            radius = result
        if result.get("success") is True:
            served.append(service_name)

    _mark("get_server_certificate_by_name", PASS if served else EXPECTED_SKIP,
          f"served for {served or 'no service name on this appliance'}")
    NOTES.append(f"get_server_certificate_by_name served for: "
                 f"{served or 'none'}")
    assert served, (
        f"no service name answered on this publisher; last response: {last}")

    # the positive path proper: the publisher's own RADIUS certificate
    assert "RADIUS" in served, (
        f"the cluster publisher served no RADIUS certificate: {radius}")
    payload = {k: v for k, v in radius.items()
               if k not in ("success", "message", "server_uuid", "service_name")}
    assert payload, f"RADIUS answered 200 with no certificate payload: {radius}"
    assert "FieldInfo" not in json.dumps(radius, default=str)

    # a UUID that cannot exist -> structured error, never invented data
    bogus, bv = run_op(recorder, "get_server_certificate_by_name", CERTS,
                       tier="negative", expect="rejected",
                       server_uuid="zzz-mcptest-bogus-uuid",
                       service_name=served[0])
    assert bv == PASS, f"bogus server uuid mishandled: {bogus}"
    assert not _crash_markers(bogus), bogus


def test_server_certificate_writes_are_blocked(recorder):
    """Every server-certificate write changes live appliance service state.

    A server certificate is what the appliance presents for RADIUS/EAP and for
    its own HTTPS listener — the listener this suite is talking to. Replacing,
    patching, enabling or disabling one can terminate the management session
    mid-run and cannot be scoped to a fixture, because the harness can never
    own a server certificate.
    """
    for operation, reason in (
        ("replace_server_certificate_by_name",
         "PUT /server-cert/name/{uuid}/{service} swaps the certificate a live "
         "service presents; on HTTPS(RSA) that is the listener this run is "
         "authenticated against."),
        ("update_server_certificate",
         "PATCH /server-cert/{service_id} rewrites the certificate bound to a "
         "live service; there is no fixture server certificate to target."),
        ("enable_server_certificate",
         "Changes which certificate a live HTTPS listener presents."),
        ("disable_server_certificate",
         "Disabling the HTTPS server certificate can drop the management "
         "listener this run depends on."),
        ("create_self_signed_certificate",
         "POST /self-signed-cert mints and binds a certificate to a real "
         "appliance service (RADIUS / HTTPS / RadSec); the registry has no "
         "operation that would unbind it."),
    ):
        record_blocked(recorder, operation, CERTS, reason)
    assert True


# ==========================================================================
# certificate_authority (19) — Onboard
# ==========================================================================


@pytest.mark.parametrize("operation", [
    "onboard_list_certificates",
    "onboard_list_devices",
    "onboard_list_users",
])
def test_onboard_collection_reads(recorder, operation):
    """Onboard is separately licensed and expected to be absent here.

    Both calling styles are exercised: every optional omitted (the ``FieldInfo``
    path) and every optional supplied. An empty collection and a structured 404
    are both correct; a Python-level explosion never is.
    """
    result, verdict = run_op(recorder, operation, CA, expect="tolerant")
    assert not _crash_markers(result), f"{operation} crashed: {result}"
    assert not _html_body(result), \
        f"{operation} returned an HTML error body: {result}"

    _, fv = run_op(recorder, operation, CA, expect="tolerant",
                   sort="+id", offset=0, limit=5, calculate_count=True)

    note = (_text(result) or f"{len(_payload_items(result))} item(s)").strip()
    if verdict == PASS:
        _mark(operation, PASS, note[:160])
    else:
        _mark(operation, EXPECTED_SKIP,
              f"EXPECTED-LIMITATION: Onboard is unlicensed/absent here — "
              f"{note[:120]}")
        NOTES.append(f"{operation}: {note[:140]}")


@pytest.mark.parametrize("operation, params", [
    ("onboard_get_certificate_by_id", {"certificate_id": ABSENT_ID}),
    ("onboard_get_certificate_chain", {"cert_id": ABSENT_ID}),
    ("onboard_get_device_by_id", {"device_id": ABSENT_ID}),
    ("onboard_get_user_by_id", {"user_id": ABSENT_ID}),
])
def test_onboard_detail_reads_absent(recorder, operation, params):
    """No enrollment exists here, so only the absent path is reachable.

    It must be a structured 404 (or an empty answer) — never a crash and never
    invented data.
    """
    result, verdict = run_op(recorder, operation, CA, tier="negative",
                             expect="absent", **params)
    assert not _crash_markers(result), f"{operation} crashed: {result}"
    _mark(operation, verdict,
          (_text(result) or "structured absent answer").strip()[:160])
    assert verdict == PASS, f"{operation} mishandled an absent id: {result}"


def test_onboard_certificate_mutations_are_denylisted(recorder):
    """sign / revoke / reject act irreversibly on real enrolling devices.

    The Onboard CA has no fixture namespace: every certificate and every
    pending request in it belongs to a real device that enrolled through the
    portal. Signing mints a trusted credential that cannot be un-issued;
    revoking cuts a real device off the network; rejecting destroys a pending
    request that must then be re-enrolled by hand.
    """
    cases = {
        "onboard_sign_certificate_request": {"cert_id": ABSENT_ID,
                                             "sign_data": {}},
        "onboard_revoke_certificate": {"cert_id": ABSENT_ID,
                                       "revoke_data": {}},
        "onboard_reject_certificate_request": {"cert_id": ABSENT_ID,
                                               "reject_data": {}},
    }
    for operation, params in cases.items():
        assert_denylisted(recorder, operation, CA, params)


def test_onboard_write_operations_are_blocked(recorder):
    """Nine Onboard writes with no safe fixture path."""
    for operation, reason in (
        ("onboard_create_certificate",
         "Mints a certificate from the appliance CA; the registry has no way "
         "to attribute it to this harness and the Onboard store is not a "
         "sweepable fixture family."),
        ("onboard_import_certificate",
         "Imports certificate material into the Onboard CA store; it would "
         "become permanent, unattributable inventory."),
        ("onboard_import_certificate_request",
         "Creates a pending certificate request in the Onboard CA queue that "
         "an operator would then have to triage by hand."),
        ("onboard_delete_certificate",
         "Every certificate in the store belongs to a real enrolled device; "
         "there is no fixture certificate to delete."),
        ("onboard_export_certificate",
         "POST /certificate/{id}/export emits certificate — and, depending on "
         "the export format, private-key — material for a real enrolled "
         "device; key material must never be pulled onto a test runner."),
        ("onboard_update_device",
         "Every Onboard device is a real enrolled device; no enrollment path "
         "exists from this harness that would produce one we own."),
        ("onboard_delete_device",
         "Deleting an Onboard device revokes its certificate and can "
         "disconnect its active sessions; it is always someone's real device."),
        ("onboard_update_user",
         "Onboard users are real directory-backed users; there is no fixture "
         "user to mutate."),
        ("onboard_delete_user",
         "Deleting an Onboard user removes every device and certificate "
         "enrolled under it."),
    ):
        record_blocked(recorder, operation, CA, reason)
    assert True


# ==========================================================================
# audit_logs — Insight endpoint lookups (4)
# ==========================================================================


@pytest.mark.parametrize("operation, params, what", [
    ("get_insight_endpoint_by_ip", {"ip": NX_IP},
     "RFC 5737 TEST-NET-1 address"),
    ("get_insight_endpoint_by_mac", {"mac": NX_MAC},
     "locally-administered MAC"),
    ("get_insight_endpoints_by_ip_range", {"ip_range": NX_IP_RANGE},
     "TEST-NET-1 /24 in the SDK's start-prefix form"),
])
def test_insight_endpoint_lookups(recorder, operation, params, what):
    """Insight is licence-dependent and already on the known-limitation
    allowlist, so a structured 404 here is an EXPECTED-LIMITATION.

    The targets cannot match anything even if Insight *is* licensed, so a
    success carrying an empty collection is equally correct. Only a crash or an
    HTML error body is a failure.
    """
    result, verdict = run_op(recorder, operation, AUDIT, tier="read",
                             expect="tolerant", **params)
    assert not _crash_markers(result), f"{operation} crashed: {result}"
    assert not _html_body(result), \
        f"{operation} returned an HTML error body: {result}"

    if verdict == PASS:
        assert not _payload_items(result), (
            f"{operation} invented endpoint data for a {what}: {result}")
        _mark(operation, PASS, f"empty result for a {what}")
    else:
        _mark(operation, EXPECTED_SKIP,
              f"EXPECTED-LIMITATION: Insight unavailable — "
              f"{(_text(result) or '').strip()[:120]}")
        assert harness.expected_skip_reason(operation), (
            f"{operation} is not covered by harness.KNOWN_LIMITATIONS but "
            f"failed: {result}")


def test_insight_endpoints_by_time_range(recorder):
    """The last hour, as two UNIX timestamps (the form the operation documents)."""
    now = int(time.time())
    result, verdict = run_op(recorder, "get_insight_endpoints_by_time_range",
                             AUDIT, tier="read", expect="tolerant",
                             from_time=str(now - 3600), to_time=str(now))
    assert not _crash_markers(result), result
    assert not _html_body(result), result

    if verdict == PASS:
        _mark("get_insight_endpoints_by_time_range", PASS,
              f"{len(_payload_items(result))} endpoint(s) in the last hour")
    else:
        _mark("get_insight_endpoints_by_time_range", EXPECTED_SKIP,
              f"EXPECTED-LIMITATION: Insight unavailable — "
              f"{(_text(result) or '').strip()[:120]}")
        assert harness.expected_skip_reason("get_insight_endpoints_by_time_range")


# ==========================================================================
# audit_logs — alert / report by-name operations (9)
# ==========================================================================


@pytest.mark.parametrize("operation", [
    "enable_insight_alert_by_name",
    "disable_insight_alert_by_name",
    "mute_insight_alert_by_name",
    "unmute_insight_alert_by_name",
])
def test_insight_alert_state_toggles_by_name(recorder, operation):
    """State toggles against a fixture-namespaced alert that does not exist.

    These operations can only change the state of an object that already
    exists — they never create one. The name is inside the fixture namespace
    and ``assert_ours`` is called immediately before dispatch, so even a
    regression that made one of them an upsert could only ever land inside our
    own namespace.

    There is no fixture alert to target because ``create_insight_alert`` stays
    BLOCKED (Insight is not a sweepable family), so the absent path is the only
    reachable one.
    """
    assert_ours(ABSENT_FIXTURE_NAME)
    result, verdict = run_op(recorder, operation, AUDIT, tier="negative",
                             expect="absent", alert_name=ABSENT_FIXTURE_NAME)
    assert not _crash_markers(result), f"{operation} crashed: {result}"
    _mark(operation, verdict,
          (_text(result) or "structured absent answer").strip()[:160])
    assert verdict == PASS, f"{operation} mishandled an absent alert: {result}"


@pytest.mark.parametrize("operation, extra", [
    ("enable_insight_report_by_name", {}),
    ("disable_insight_report_by_name", {}),
    ("update_insight_report_by_name",
     {"report_data": {"name": ABSENT_FIXTURE_NAME, "category": "Endpoint",
                      "subcategory": "Summary"}}),
])
def test_insight_report_by_name_operations(recorder, operation, extra):
    """The same reasoning as the alert toggles, plus the PATCH.

    A PATCH never creates, so it is safe against a fixture-namespaced absent
    name and it proves a code path that would otherwise carry no live evidence
    at all.
    """
    assert_ours(ABSENT_FIXTURE_NAME)
    result, verdict = run_op(recorder, operation, AUDIT, tier="negative",
                             expect="absent",
                             report_name=ABSENT_FIXTURE_NAME, **extra)
    assert not _crash_markers(result), f"{operation} crashed: {result}"
    _mark(operation, verdict,
          (_text(result) or "structured absent answer").strip()[:160])
    assert verdict == PASS, f"{operation} mishandled an absent report: {result}"


def test_delete_insight_report_by_name_guard_and_absent_path(recorder):
    """Both branches of the confirmation-gated delete.

    ``confirm`` omitted must refuse **locally**, before anything is dispatched —
    the target name is fixture-namespaced and non-existent precisely so that a
    regressed guard (an omitted ``confirm`` arriving as a truthy ``FieldInfo``,
    say) could still not destroy anything. Then the confirmed call, which finds
    nothing to delete.
    """
    assert_ours(ABSENT_FIXTURE_NAME)
    refused, rv = run_op(recorder, "delete_insight_report_by_name", AUDIT,
                         tier="negative", expect="refusal",
                         substrings=("confirm",),
                         report_name=ABSENT_FIXTURE_NAME)
    assert rv == PASS, \
        f"delete_insight_report_by_name did not refuse without confirm: {refused}"
    assert refused.get("error_type") == "clarification_needed", refused

    assert_ours(ABSENT_FIXTURE_NAME)
    result, verdict = run_op(recorder, "delete_insight_report_by_name", AUDIT,
                             tier="negative", expect="absent",
                             report_name=ABSENT_FIXTURE_NAME, confirm=True)
    assert not _crash_markers(result), result
    _mark("delete_insight_report_by_name", verdict,
          "confirmation guard + absent-name delete")
    assert verdict == PASS, \
        f"delete_insight_report_by_name mishandled an absent report: {result}"


def test_replace_insight_report_by_name_is_blocked(recorder):
    """The one by-name operation that is not dispatched.

    ``PUT /report/{name}`` can behave as an upsert, and an Insight report
    carries a delivery schedule that can email real recipients — the same
    reason the first sweep blocked ``create_insight_report``. Insight is also
    not a sweepable family, so an accidentally created report would be
    permanent, unattributable inventory.
    """
    record_blocked(
        recorder, "replace_insight_report_by_name", AUDIT,
        "PUT /report/{name} can upsert, and an Insight report carries a "
        "delivery schedule that can email real recipients; Insight is not a "
        "sweepable fixture family, so the object could never be removed.")
    assert True


# ==========================================================================
# Summary / coverage reconciliation
# ==========================================================================


# Operations in these three domains that the FIRST sweep already covered
# (tests/live/test_certs_profiles_api.py and
# tests/live/test_local_config_and_audit.py). They are out of scope here.
PREVIOUSLY_COVERED = {
    # certificates
    "list_certificate_trust_list", "get_certificate_trust_list_details",
    "list_client_certificates", "get_client_certificate_by_id",
    "list_server_certificates", "get_server_certificate_details",
    "list_service_certificates", "create_certificate_signing_request",
    # audit_logs
    "list_system_events", "create_system_event", "get_admin_login_audit",
    "list_insight_alerts", "list_insight_reports", "get_insight_alert_details",
    "get_insight_report_details", "run_insight_report", "delete_insight_alert",
    "create_insight_alert", "create_insight_report", "update_insight_alert",
}


def test_zz_coverage_is_complete_and_reported(recorder, live_enabled):
    """Every one of the 53 in-scope operations must carry a disposition.

    52 of them are new since the first sweep (20 certificates, 19
    certificate_authority, 13 audit_logs). The 53rd is
    ``import_certificate_to_trust_list``, deliberately re-covered here: the
    first sweep recorded it BLOCKED for want of a delete operation, and
    ``delete_certificate_trust_list`` now supplies one.
    """
    import src.main  # noqa: F401
    from src.registry import registry

    in_scope = sorted(
        s.name for d in (CERTS, CA, AUDIT) for s in registry.search(domain=d)
    )
    mine = [n for n in in_scope if n not in PREVIOUSLY_COVERED]
    assert len(mine) == 53, f"expected 53 in-scope operations, got {len(mine)}"

    tally: Dict[str, int] = {}
    print("\n" + "=" * 72)
    print("certificates(new) / certificate_authority / audit_logs(new) — "
          "live summary")
    print("=" * 72)
    for name in mine:
        entry = COVERAGE.get(name, {"verdict": "NOT RUN", "note": ""})
        tally[entry["verdict"]] = tally.get(entry["verdict"], 0) + 1
        print(f"   {entry['verdict']:14s} {name:44s} {entry['note'][:80]}")
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
