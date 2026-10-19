"""Shared scaffolding for the two ``endpoint_visibility`` live modules.

Not a test module (the leading underscore keeps it out of collection). It holds
the dispatch/verdict helper, the extra safety guards this domain needs, and the
fixture sweepers, so ``test_endpoint_visibility_live.py`` and
``test_endpoint_visibility_onguard_live.py`` share one implementation instead of
two drifting copies.

Why this domain needs guards beyond ``assert_ours``
---------------------------------------------------
``harness.assert_ours`` can only vouch for an object whose identity is a NAME
carrying the ``zzz-mcptest-`` prefix. Three families in this domain are not
name-keyed:

* ``windows-hotfix`` is keyed by ``kbid`` + ``operating_system``. The fixtures
  use KBIDs of the form ``KB0000001`` — six leading zeros, a shape Microsoft has
  never issued — AND carry the fixture prefix in the free ``title`` field.
  ``assert_hotfix_is_ours`` reads the record back and refuses unless *both* hold.
* ``profiler-subnet-mapping`` is keyed by ``scan_type`` + ``network``, and
  ``config/network-scan`` by numeric id only. Every network these tests write is
  inside RFC 5737 documentation space (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24), which can never be a real network, and
  ``assert_doc_network`` refuses anything else.
* ``device-profiler/device-fingerprint`` is keyed by MAC. The fixtures use
  locally-administered MACs (``02:00:5e:…``) derived from the run id, so the
  endpoint exists only because this run posted it; ``assert_local_mac`` refuses
  any globally-administered address.

Every id-keyed delete additionally goes through ``assert_created_id``: the id
must be one this run's create returned, never an id harvested from a list.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import harness
from .harness import (  # noqa: F401  (re-exported for the test modules)
    EXPECTED_SKIP,
    FAIL,
    FIXTURE_PREFIX,
    PASS,
    assert_ours,
    expected_skip_reason,
    fixture_name,
    is_ours,
)

__all__ = [
    "ABSENT_ID",
    "BLOCKED",
    "DOC_NETWORKS",
    "DOMAIN",
    "EXPECTED_SKIP",
    "FAIL",
    "FIXTURE_PREFIX",
    "LIMITATION",
    "NOTES",
    "PASS",
    "assert_created_id",
    "assert_doc_network",
    "assert_fixture_kbid",
    "assert_local_mac",
    "assert_ours",
    "expected_skip_reason",
    "fixture_name",
    "id_of",
    "is_ours",
    "is_structured_envelope",
    "items_of",
    "local_mac",
    "no_crash",
    "note",
    "obj_of",
    "record_blocked",
    "record_limitation",
    "run_op",
    "surviving_fixtures",
    "sweep_named_family",
]

DOMAIN = "endpoint_visibility"

# Verdicts beyond the three harness ones.
BLOCKED = "BLOCKED"
#: The appliance refused a legitimate fixture write (unknown enum value, missing
#: prerequisite, unserved route). Recorded with the appliance's own error so
#: Phase 5 can triage it; never silently swallowed.
LIMITATION = "EXPECTED-LIMITATION"

#: An id that cannot exist on this appliance.
ABSENT_ID = 999999999

#: RFC 5737 documentation address space. Never routable, never a real network.
DOC_NETWORKS: Tuple[str, ...] = (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
    # Single documentation addresses used where a "/" in the value would be
    # eaten by the URL path (see the by-network tests).
    "192.0.2.51", "192.0.2.52", "198.51.100.51", "198.51.100.52",
)

#: KBIDs with six leading zeros — a shape Microsoft has never issued.
FIXTURE_KBIDS: Tuple[str, ...] = tuple(f"KB{n:07d}" for n in range(1, 10))

#: Locally-administered OUI used for every MAC this domain writes.
LOCAL_MAC_OUI = "02:00:5e"

#: Notes surfaced by each module's ``test_summary``.
NOTES: List[str] = []


def note(message: str) -> None:
    if message not in NOTES:
        NOTES.append(message)


# --------------------------------------------------------------------------
# Extra safety guards
# --------------------------------------------------------------------------


def assert_doc_network(value: Any) -> str:
    """Refuse to write any network outside RFC 5737 documentation space."""
    if not isinstance(value, str) or value not in DOC_NETWORKS:
        raise AssertionError(
            f"SAFETY GUARD: refusing to write/delete network {value!r} — the "
            f"live harness may only touch RFC 5737 documentation networks "
            f"{DOC_NETWORKS}."
        )
    return value


def assert_fixture_kbid(value: Any) -> str:
    """Refuse to write any KBID outside the fixture set."""
    if not isinstance(value, str) or value not in FIXTURE_KBIDS:
        raise AssertionError(
            f"SAFETY GUARD: refusing to write/delete Windows hotfix {value!r} — "
            f"the live harness may only touch its own fake KBIDs "
            f"{FIXTURE_KBIDS}."
        )
    return value


def local_mac(run_id: str, n: int = 0) -> str:
    """A locally-administered MAC unique to this run: ``02:00:5e:rr:rr:nn``."""
    rid = (run_id + "00000000")[:4]
    return f"{LOCAL_MAC_OUI}:{rid[0:2]}:{rid[2:4]}:{n:02x}"


def assert_local_mac(value: Any) -> str:
    """Refuse to write/delete anything but a locally-administered fixture MAC."""
    if not isinstance(value, str) or not value.lower().startswith(LOCAL_MAC_OUI):
        raise AssertionError(
            f"SAFETY GUARD: refusing to write/delete endpoint MAC {value!r} — "
            f"the live harness may only touch locally-administered "
            f"{LOCAL_MAC_OUI}:* addresses it posted itself."
        )
    return value


def assert_created_id(ident: Any, created: Sequence[Any]) -> Any:
    """Refuse to delete/update an id this run did not create."""
    if ident is None or ident not in created:
        raise AssertionError(
            f"SAFETY GUARD: refusing to write/delete id {ident!r} — it is not "
            f"one of the ids this run created ({list(created)!r}). Ids harvested "
            f"from a list operation belong to the appliance, not to us."
        )
    return ident


# --------------------------------------------------------------------------
# Payload helpers
# --------------------------------------------------------------------------


def items_of(result: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    """The list of objects a list-operation returned under ``key``."""
    if not isinstance(result, dict):
        return []
    for container in (result, result.get("data") or {}):
        if isinstance(container, dict) and isinstance(container.get(key), list):
            return [i for i in container[key] if isinstance(i, dict)]
    return []


def obj_of(result: Dict[str, Any], key: str) -> Dict[str, Any]:
    """The single object a get/create returned under ``key``."""
    if not isinstance(result, dict):
        return {}
    value = result.get(key)
    return value if isinstance(value, dict) else {}


def id_of(obj: Dict[str, Any]) -> Optional[int]:
    ident = obj.get("id") if isinstance(obj, dict) else None
    if isinstance(ident, bool):
        return None
    if isinstance(ident, int):
        return ident
    if isinstance(ident, str) and ident.isdigit():
        return int(ident)
    return None


# --------------------------------------------------------------------------
# Dispatch + verdict
# --------------------------------------------------------------------------

_ERROR_KEYS = ("error", "message", "detail", "details", "suggestion",
               "error_type", "warning")

_ABSENT_PAT = ("404", "not found", "does not exist", "no such", "not exist",
               "could not be found", "no matching", "does not support")


def _text(result: Dict[str, Any]) -> str:
    return " ".join(str(result.get(k, "")) for k in _ERROR_KEYS)


def _deep(result: Any) -> str:
    return json.dumps(result, default=str)


def _crash_markers(text: str) -> List[str]:
    return [m for m in harness._CRASH_MARKERS if m in text]


def is_structured_envelope(result: Any) -> bool:
    """True when the MCP wrapped a failure in its own structured error envelope.

    This is the property that actually matters when the appliance answers
    something graceless: the operation must come back as a dict carrying the
    MCP's ``success: False`` + an error string + a machine-readable
    ``error_type``, rather than a bare string, a raw payload, or a traceback
    that escaped the wrapper. Crash markers are checked separately and always
    win, so this can never launder a real explosion into a pass.
    """
    if not isinstance(result, dict) or result.get("success") is not False:
        return False
    if not str(result.get("error") or "").strip():
        return False
    return bool(str(result.get("error_type") or "").strip())


def run_op(
    run_async,
    recorder,
    operation: str,
    tier: str = "read",
    expect: str = "success",
    substrings: Sequence[str] = (),
    **params: Any,
) -> Tuple[Dict[str, Any], str]:
    """Dispatch through ``harness.invoke`` (i.e. the gateway), classify, record.

    ``harness.invoke``'s first parameter is positional-only and the operation's
    own parameters go through ``_params``, so the ten operations in this domain
    that take a parameter literally called ``name`` dispatch unmodified.

    ``expect``:
      ``success``   the operation should work against real data;
      ``absent``    a structured not-found for a deliberately absent object;
      ``refusal``   a structured local guard refusal — ``substrings`` must appear;
      ``graceful``  any structured outcome is acceptable, a crash is not (used
                    where the appliance's behaviour genuinely cannot be
                    predicted, e.g. messaging a MAC no agent has ever reported);
      ``lenient``   a fixture write the appliance may legitimately refuse
                    (unknown enum value, missing prerequisite): success is PASS,
                    a structured refusal is recorded ``EXPECTED-LIMITATION``
                    carrying the appliance's own error, a crash is FAIL;
      ``absent_or_error``
                    like ``absent``, but the appliance is also allowed to answer
                    a nonexistent id with a structured non-404 error instead of a
                    not-found (see below);
      ``unserved``  the route may not be served at all on this appliance: an
                    appliance-origin error page is recorded
                    ``EXPECTED-LIMITATION``, but the MCP must still have wrapped
                    it in its own structured envelope.
    """
    start = time.perf_counter()
    result = run_async(harness.invoke(operation, _params=dict(params)))
    duration = (time.perf_counter() - start) * 1000.0

    text = _text(result)
    deep = _deep(result)
    success = result.get("success") is True
    reason = expected_skip_reason(operation)
    crashes = _crash_markers(text) or _crash_markers(deep)
    # An HTML body where structured JSON was expected is never a not-found: on
    # 6.12.4 some unserved routes answer HTTP 500 carrying an HPE
    # "Error 404 (Not Found)" page, and the bare 404 regex would read that as a
    # legitimate absence. Same rule as harness.classify.
    html_body = harness.looks_like_html(harness.deep_error_text(result) or text)

    if crashes:
        verdict = FAIL
    elif expect == "success":
        verdict = PASS if success else (EXPECTED_SKIP if reason else FAIL)
    elif expect == "absent":
        if html_body:
            verdict = FAIL
        elif any(p in deep.lower() for p in _ABSENT_PAT):
            verdict = PASS
        elif success:
            verdict = FAIL          # invented data for an object that cannot exist
        else:
            verdict = EXPECTED_SKIP if reason else FAIL
    elif expect == "absent_or_error":
        # Some 6.12.4 routes do not resolve a nonexistent id to a 404 at all:
        # ``agentless-onguard/subnet-mapping/<absent id>`` answers HTTP 500 with
        # the structured JSON body ["Error in processing request. Please
        # retry..."]. That is the appliance being graceless, not the MCP being
        # broken. The three things that still must hold are unchanged: no crash
        # marker (checked above), no HTML body masquerading as a not-found, and
        # above all never ``success`` — inventing data for an id that cannot
        # exist stays a FAIL.
        if html_body:
            verdict = FAIL
        elif any(p in deep.lower() for p in _ABSENT_PAT):
            verdict = PASS
        elif success:
            verdict = FAIL          # invented data for an object that cannot exist
        elif is_structured_envelope(result):
            verdict = PASS
        else:
            verdict = EXPECTED_SKIP if reason else FAIL
    elif expect == "unserved":
        # The endpoint may simply not be served on this appliance (e.g. an
        # OnGuard agent route on a lab box that has never had an agent). The
        # appliance answers HTTP 500 carrying an HPE HTML error page, which
        # ``graceful`` rightly refuses to read as a clean answer. What is being
        # asserted here is narrower and is about the MCP, not the appliance: the
        # HTML must have been wrapped in the MCP's own structured envelope
        # rather than surfacing raw. A crash marker still FAILs above.
        if success:
            verdict = PASS
        elif is_structured_envelope(result):
            verdict = LIMITATION
        else:
            verdict = FAIL
    elif expect == "refusal":
        low = text.lower()
        verdict = PASS if (not success and not html_body
                           and any(s.lower() in low for s in substrings)) else FAIL
    elif expect == "graceful":
        verdict = FAIL if html_body else (PASS if (success or text.strip()) else FAIL)
    elif expect == "lenient":
        verdict = PASS if success else LIMITATION
    else:  # pragma: no cover
        raise ValueError(f"unknown expect={expect!r}")

    err = None if verdict == PASS else (
        (harness.deep_error_text(result) or text).strip() or None)
    if err and expect == "unserved":
        # An unserved route answers with a whole HTML page; the MCP's own error
        # line is the informative part, the markup is noise in the artifact.
        err = str(result.get("error") or err)[:300]
    recorder.record(operation, DOMAIN, tier, verdict, params, err, duration)
    if verdict == LIMITATION:
        note(f"{operation}: "
             + ("route not served on this appliance" if expect == "unserved"
                else "appliance refused a fixture write")
             + f" -> {err}")
    return result, verdict


def record_blocked(recorder, operation: str, reason: str) -> None:
    """Record an operation that was deliberately never dispatched."""
    recorder.record(operation, DOMAIN, "blocked", BLOCKED, {}, reason, 0.0)
    note(f"{operation}: BLOCKED — {reason}")


def record_limitation(recorder, operation: str, reason: str,
                      params: Optional[Dict[str, Any]] = None) -> None:
    recorder.record(operation, DOMAIN, "limitation", LIMITATION, params or {},
                    reason, 0.0)
    note(f"{operation}: EXPECTED-LIMITATION — {reason}")


def no_crash(result: Dict[str, Any], operation: str) -> None:
    markers = _crash_markers(_deep(result))
    assert not markers, f"{operation}: crash marker(s) {markers} in {result}"


# --------------------------------------------------------------------------
# Fixture sweepers
# --------------------------------------------------------------------------


def sweep_named_family(
    run_async,
    list_op: str,
    items_key: str,
    name_key: str,
    delete_op: str,
    delete_param: str,
    list_params: Optional[Dict[str, Any]] = None,
    extra_delete_params: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Delete every surviving ``zzz-mcptest-*`` object in a name-keyed family.

    Only objects whose name passes ``assert_ours`` are touched; everything else
    is left strictly alone. Returns one record per deletion attempt.
    """
    swept: List[Dict[str, Any]] = []
    try:
        listing = run_async(harness.invoke(list_op, _params=dict(list_params or {})))
    except Exception as exc:  # a raise here is itself a finding, but never fatal
        return [{"family": list_op, "error": f"{type(exc).__name__}: {exc}"}]
    if not isinstance(listing, dict) or listing.get("success") is not True:
        return swept
    for item in items_of(listing, items_key):
        name = item.get(name_key)
        if not is_ours(name):
            continue
        assert_ours(name)  # guard immediately before the delete
        params = {delete_param: name}
        params.update(extra_delete_params or {})
        try:
            deleted = run_async(harness.invoke(delete_op, _params=params))
            ok = bool(isinstance(deleted, dict) and deleted.get("success"))
        except Exception as exc:
            deleted, ok = {"error": f"{type(exc).__name__}: {exc}"}, False
        swept.append({"family": list_op, "name": name, "deleted": ok,
                      "detail": harness.deep_error_text(deleted)[:200] or None})
    return swept


def surviving_fixtures(run_async, list_op: str, items_key: str, name_key: str,
                       list_params: Optional[Dict[str, Any]] = None) -> List[Any]:
    """Names in a family that still carry the fixture prefix."""
    listing = run_async(harness.invoke(list_op, _params=dict(list_params or {})))
    if not isinstance(listing, dict) or listing.get("success") is not True:
        return []
    return [i.get(name_key) for i in items_of(listing, items_key)
            if is_ours(i.get(name_key))]
