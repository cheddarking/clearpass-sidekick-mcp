"""Live-validation harness primitives for the ClearPass Sidekick MCP server.

Everything here is import-safe offline: importing this module makes no network
call and reads no credential file. Credentials are expected to already be in
``os.environ`` (the operator sources the .env before invoking pytest); this
module never reads, prints, or logs a credential value or the appliance
address.

Design rules enforced here
--------------------------
1. All dispatch goes through ``src.tools.gateway.invoke_operation`` so the
   progressive-disclosure path (name resolution, parameter whitelisting,
   Context injection, error wrapping) is validated alongside the operations.
2. Optional parameters are OMITTED by default. A recently fixed bug in
   ``src/registry.py`` caused omitted ``Field()``-defaulted parameters to reach
   operation bodies as raw ``FieldInfo`` objects (272 of 287 operations
   affected). The omission path is where real bugs live, so it is the default
   calling style.
3. Writes/deletes may only ever target names carrying the fixture prefix.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .denylist import DenylistedOperation, is_denylisted

__all__ = [
    "FIXTURE_PREFIX",
    "ARTIFACT_DIR",
    "StubContext",
    "RunRecorder",
    "assert_ours",
    "classify",
    "deep_crash_marker",
    "deep_error_text",
    "looks_like_html",
    "timed_invoke",
    "expected_skip_reason",
    "fixture_name",
    "invoke",
    "is_ours",
    "new_run_id",
    "snapshot_inventory",
    "diff_inventory",
    "sweep_fixtures",
    "INVENTORY_FAMILIES",
    "PASS",
    "FAIL",
    "EXPECTED_SKIP",
]

# --------------------------------------------------------------------------
# Naming / fixture namespace
# --------------------------------------------------------------------------

FIXTURE_PREFIX = "zzz-mcptest-"

ARTIFACT_DIR = Path(__file__).parent / "_artifacts"

PASS = "PASS"
FAIL = "FAIL"
EXPECTED_SKIP = "EXPECTED_SKIP"


def new_run_id() -> str:
    """Per-session random token used to namespace everything this run creates."""
    return secrets.token_hex(4)


def fixture_name(run_id: str, n: Any = 1, suffix: str = "") -> str:
    """Build a fixture object name: ``zzz-mcptest-<runid>-<n>``.

    ``suffix`` is appended (dash-joined) for families that need a
    distinguishable second name, e.g. ``fixture_name(rid, 1, "updated")``.
    """
    name = f"{FIXTURE_PREFIX}{run_id}-{n}"
    if suffix:
        name = f"{name}-{suffix}"
    return name


def is_ours(name: Any) -> bool:
    return isinstance(name, str) and name.startswith(FIXTURE_PREFIX)


def assert_ours(name: Any) -> str:
    """Guard called immediately before every delete/update.

    This is the load-bearing safety rail: it is the difference between a safe
    sweep and wrecking the appliance. Raises unless ``name`` carries the
    fixture prefix.
    """
    if not is_ours(name):
        raise AssertionError(
            f"SAFETY GUARD: refusing to write/delete {name!r} — it does not "
            f"carry the fixture prefix {FIXTURE_PREFIX!r}. The live harness "
            f"may only mutate objects it created."
        )
    return name


# --------------------------------------------------------------------------
# Minimal MCP Context stub
# --------------------------------------------------------------------------


class StubContext:
    """Minimal stand-in for ``fastmcp.Context``.

    Operations in ``src/tools`` only ever await ``ctx.info`` (250 call sites)
    and ``ctx.error`` (1 call site); ``debug``/``warning`` are provided for
    forward-compatibility. Messages are buffered, never printed, so no
    credential or hostname that an operation might echo can leak to stdout or
    to an artifact file.
    """

    def __init__(self) -> None:
        self.messages: List[Tuple[str, str]] = []

    async def info(self, message: str = "", *args: Any, **kwargs: Any) -> None:
        self.messages.append(("info", str(message)))

    async def error(self, message: str = "", *args: Any, **kwargs: Any) -> None:
        self.messages.append(("error", str(message)))

    async def debug(self, message: str = "", *args: Any, **kwargs: Any) -> None:
        self.messages.append(("debug", str(message)))

    async def warning(self, message: str = "", *args: Any, **kwargs: Any) -> None:
        self.messages.append(("warning", str(message)))

    # Some FastMCP versions expose report_progress / log on Context.
    async def report_progress(self, *args: Any, **kwargs: Any) -> None:
        return None

    async def log(self, message: str = "", *args: Any, **kwargs: Any) -> None:
        self.messages.append(("log", str(message)))


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


async def invoke(
    operation: str,
    /,
    _ctx: Optional[StubContext] = None,
    _params: Optional[Dict[str, Any]] = None,
    **params: Any,
) -> Dict[str, Any]:
    """Dispatch ``operation`` through the gateway with ``params``.

    Optional parameters you do not pass are simply omitted — that is the point.
    Raises :class:`DenylistedOperation` before any network activity if the
    operation is on the hard denylist.

    ``invoke_operation`` never raises; it returns a dict, and on failure
    ``{"success": False, "error": ..., "message": ...}``.

    Operation parameters called ``name``
    ------------------------------------
    The first parameter is **positional-only**, so operations that themselves
    take a parameter literally called ``name`` dispatch normally::

        await invoke("get_role_details", name="[Guest]")
        await invoke("create_enforcement_profile", name=fixture, ...)

    For the remaining reserved words (``_ctx``, ``_params``) — and for any
    future collision — pass the operation's parameters as an explicit dict::

        await invoke("some_operation", _params={"_ctx": 1, "name": "x"})

    ``_params`` is merged with (and overridden by) any keyword parameters, so
    both calling styles can be mixed.
    """
    if is_denylisted(operation):
        raise DenylistedOperation(operation)

    call_params: Dict[str, Any] = dict(_params or {})
    call_params.update(params)

    # Imported lazily so this module stays import-safe with no credentials set.
    import src.main  # noqa: F401  (side effect: registers all 757 operations)
    from src.tools.gateway import invoke_operation

    ctx = _ctx or StubContext()
    result = await invoke_operation(ctx, operation, call_params or None)
    if not isinstance(result, dict):
        return {"success": False, "error": f"non-dict result: {type(result).__name__}",
                "message": "Operation returned a non-dict payload", "raw": result}
    return result


async def timed_invoke(
    operation: str,
    /,
    _params: Optional[Dict[str, Any]] = None,
    **params: Any,
) -> Tuple[Dict[str, Any], float]:
    """``invoke`` plus wall-clock duration in milliseconds."""
    start = time.perf_counter()
    result = await invoke(operation, _params=_params, **params)
    return result, (time.perf_counter() - start) * 1000.0


# --------------------------------------------------------------------------
# Result classification
# --------------------------------------------------------------------------

# Known environment limitations of ClearPass 6.12.4 (documented in
# docs/live_testing_plan_phase1.md). These are NOT product bugs, but each must
# be asserted as a *known* skip carrying its reason so that a genuine
# regression elsewhere still fails.
KNOWN_LIMITATIONS: List[Tuple[re.Pattern, str]] = [
    # 2026-07-31: the blanket password-policy allowlist entry was removed.
    # /admin-user/password-policy and /local-user/password-policy both answer
    # 200 on this 6.12.4 appliance — the 404s that motivated the entry came
    # from the legacy hyphen-path operations
    # (get|update_admin_password_policy, get|update_local_user_password_policy),
    # which have now been deleted from the registry. The surviving operations
    # (get|update|replace_admin_user_password_policy and the
    # ..._local_user_password_policy_settings trio) must pass for real.
    (re.compile(r"proxy_target"),
     "Proxy Target endpoints have no pyclearpass implementation"),
    (re.compile(r"insight"),
     "Insight endpoints are licence-dependent and unavailable on this appliance"),
    (re.compile(r"^configure_device_(snmp|radsec|cli)_settings$"),
     "Requires a live managed device; the appliance returns 422/400 without one"),
    # 2026-07-31: removed. docs/live_testing_plan_phase1.md:2340 recorded a 404
    # for `application-license-summary`, but that is simply the wrong path —
    # `/application-license/summary` answers 200 on this appliance. The
    # wrongly-pathed `get_application_license_summary` has been deleted from
    # the registry; `get_application_license_summary_detail` targets the real
    # resource and must pass for real.
    # docs/live_testing_plan_phase1.md:1792 — the appliance answers
    # "This operation requires a development license".
    (re.compile(r"^delete_radius_dictionary$"),
     "Deleting a RADIUS dictionary requires a development license on this appliance"),
]

# Substrings that always mean FAIL regardless of anything else: they indicate a
# crash surfacing through invoke_operation's generic catch rather than a
# structured domain-level error.
_CRASH_MARKERS = (
    "FieldInfo",
    "Traceback (most recent call last)",
    "TypeError:",
    "AttributeError:",
    "NameError:",
    "KeyError:",
    "UnboundLocalError",
    "object is not subscriptable",
    "object has no attribute",
    "takes no arguments",
    "missing required argument",
    "unexpected keyword argument",
    "positional argument",
    "annotation=",  # pydantic FieldInfo repr leak
)


def expected_skip_reason(operation: str) -> Optional[str]:
    """Return the known-limitation reason for ``operation``, if any."""
    for pattern, reason in KNOWN_LIMITATIONS:
        if pattern.search(operation):
            return reason
    return None


def _error_text(result: Dict[str, Any]) -> str:
    return " ".join(
        str(result.get(k, "")) for k in ("error", "message", "detail", "details")
    )


# Keys whose *string* values carry an error body, at any nesting depth. Used for
# the HTML-body and not-found checks, which must not look at ordinary payload
# content (a weblogin page or print template legitimately contains markup).
_ERROR_KEYS = {
    "error", "errors", "message", "messages", "detail", "details", "reason",
    "body", "response", "response_text", "response_body", "raw", "exception",
    "traceback", "status_message", "error_message", "error_description",
}

# Markers of an HTML body where a structured (JSON) error was expected. An
# Apache "Error 404" page returned with an HTTP 500 must never be read as a
# legitimate not-found.
_HTML_MARKERS = ("<html", "<!doctype html", "<body", "<h1>", "<title>", "apache")


def _collect_error_strings(obj: Any, key: Optional[str] = None,
                           out: Optional[List[str]] = None) -> List[str]:
    """Recursively collect every string that sits under an error-ish key."""
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            _collect_error_strings(v, str(k).lower(), out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _collect_error_strings(v, key, out)
    elif isinstance(obj, str):
        if key in _ERROR_KEYS:
            out.append(obj)
    return out


def deep_error_text(result: Any) -> str:
    """All error-ish strings anywhere in the payload, joined.

    ``_error_text`` only reads the four top-level keys, which is why an
    exception string buried in ``data.error`` used to be invisible.
    """
    return " ".join(_collect_error_strings(result))


def _serialise(result: Any) -> str:
    try:
        return json.dumps(result, default=str)
    except Exception:
        return str(result)


def deep_crash_marker(result: Any) -> Optional[str]:
    """Return the first crash marker found ANYWHERE in the payload, else None.

    The shallow check missed operations that return ``success: True`` with a
    Python exception string buried in a nested field — e.g.
    ``test_proxy_target_connectivity`` returning ``data.error =
    "'ClearPassClient' object has no attribute 'get_proxy_target'"``.
    """
    blob = _serialise(result)
    for marker in _CRASH_MARKERS:
        if marker in blob:
            return marker
    return None


def looks_like_html(text: str) -> bool:
    """True when ``text`` is an HTML document rather than a structured error."""
    low = (text or "").lower()
    return any(marker in low for marker in _HTML_MARKERS)


def classify(
    result: Dict[str, Any],
    operation: str = "",
    expect_absent: bool = False,
) -> str:
    """Sort one outcome into PASS / EXPECTED_SKIP / FAIL.

    PASS           — ``success: True``, or a structured domain-level failure
                     that is legitimately correct (e.g. a 404 during a negative
                     test where ``expect_absent=True``).
    EXPECTED_SKIP  — matches the known-limitation allowlist.
    FAIL           — anything else, especially a traceback, a FieldInfo leak, a
                     TypeError, or an unhandled exception string surfacing
                     through invoke_operation's generic catch.
    """
    if not isinstance(result, dict):
        return FAIL

    text = _error_text(result)
    deep_text = deep_error_text(result)

    # A crash marker is always a FAIL, even if the op is on the allowlist:
    # a known environment limitation must present as a structured error, not
    # as a Python-level explosion. The scan is over the WHOLE serialised
    # payload, so a crash string buried in a nested field (under a
    # ``success: True`` envelope) is still caught.
    if deep_crash_marker(result) is not None:
        return FAIL

    if result.get("success") is True:
        return PASS

    # An HTML error body where structured JSON was expected is a FAIL, never a
    # not-found: an HTTP 500 carrying an Apache "Error 404" page used to be
    # read as a legitimate absence because "not found" appeared in the markup.
    if looks_like_html(deep_text or text):
        return FAIL

    if expect_absent and re.search(r"\b404\b|not found|does not exist",
                                   deep_text or text, re.I):
        return PASS

    reason = expected_skip_reason(operation)
    if reason:
        return EXPECTED_SKIP

    return FAIL


# --------------------------------------------------------------------------
# Machine-readable results (JSON lines)
# --------------------------------------------------------------------------

_SECRET_KEYS = {"password", "client_secret", "secret", "api_token", "token",
                "access_token", "passphrase", "private_key"}


def _redact(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        k: ("***REDACTED***" if k.lower() in _SECRET_KEYS else v)
        for k, v in (params or {}).items()
    }


@dataclass
class RunRecorder:
    """Appends one JSON-lines record per operation to results-<runid>.jsonl."""

    run_id: str
    artifact_dir: Path = field(default_factory=lambda: ARTIFACT_DIR)
    counts: Dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.artifact_dir / f"results-{self.run_id}.jsonl"

    def record(
        self,
        operation: str,
        domain: str,
        tier: str,
        verdict: str,
        params_sent: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> Dict[str, Any]:
        rec = {
            "operation": operation,
            "domain": domain,
            "tier": tier,
            "verdict": verdict,
            "params_sent": _redact(params_sent or {}),
            "error": error,
            "duration_ms": round(duration_ms, 2) if duration_ms is not None else None,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        self.counts[verdict] = self.counts.get(verdict, 0) + 1
        return rec

    async def run(
        self,
        operation: str,
        /,
        domain: str = "",
        tier: str = "read",
        expect_absent: bool = False,
        _params: Optional[Dict[str, Any]] = None,
        **params: Any,
    ) -> Dict[str, Any]:
        """Invoke, classify, and record in one step. Returns the raw result.

        ``operation`` is positional-only, so an operation parameter called
        ``name`` passes straight through::

            await recorder.run("get_role_details", tier="read", name="[Guest]")

        The recorder's own keywords (``domain``, ``tier``, ``expect_absent``,
        ``_params``) still shadow operation parameters of the same name; pass
        those through the ``_params`` dict instead::

            await recorder.run("create_guest_domain", tier="write",
                               _params={"domain": "example.com"})
        """
        start = time.perf_counter()
        params = {**(_params or {}), **params}
        try:
            result = await invoke(operation, _params=params)
        except DenylistedOperation:
            raise
        except Exception as exc:  # a raise here is itself a finding
            duration = (time.perf_counter() - start) * 1000.0
            self.record(operation, domain, tier, FAIL, params,
                        f"{type(exc).__name__}: {exc}", duration)
            raise
        duration = (time.perf_counter() - start) * 1000.0
        verdict = classify(result, operation, expect_absent=expect_absent)
        err = None
        if verdict != PASS:
            err = (deep_error_text(result) or _error_text(result)).strip() or None
        self.record(operation, domain or _domain_of(operation), tier, verdict,
                    params, err, duration)
        return result


def _domain_of(operation: str) -> str:
    try:
        import src.main  # noqa: F401
        from src.registry import registry

        spec = registry.get(operation)
        return spec.domain if spec else ""
    except Exception:
        return ""


# --------------------------------------------------------------------------
# Inventory snapshot / diff / sweep
# --------------------------------------------------------------------------

# family -> (list operation, extra params needed to get a full listing)
# `endpoints` has no list operation in the current registry; it is recorded as
# unavailable rather than silently skipped.
INVENTORY_FAMILIES: Dict[str, Optional[Tuple[str, Dict[str, Any]]]] = {
    "network_devices": ("list_network_devices", {"limit": 1000}),
    "guest_users": ("list_guest_users", {"limit": 1000}),
    "admin_users": ("list_admin_users", {"limit": 1000}),
    "roles": ("list_roles", {"limit": 1000}),
    "enforcement_profiles": ("list_enforcement_profiles", {"limit": 1000}),
    "api_clients": ("list_api_clients", {}),
    # `list_endpoints` arrived with the full-SDK-coverage expansion (identities
    # domain). Wiring it in here would change what the live sweep snapshots, so
    # the family stays out of the guard until that is decided deliberately.
    "endpoints": None,
    "device_groups": ("list_network_device_groups", {"limit": 1000}),
    "certificates": ("list_certificate_trust_list", {"limit": 1000}),
}

_NAME_KEYS = ("name", "username", "client_id", "subject", "cn", "id")
_ID_KEYS = ("id", "client_id", "cert_id", "user_id")


def _extract_items(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull the list of objects out of a list-operation result.

    List operations return under different keys (``devices``, ``users``,
    ``roles``, ``clients``, ``device_groups``, ``data``/``_embedded`` ...), so
    fall back to scanning for the first list-of-dicts.
    """
    if not isinstance(result, dict):
        return []
    embedded = result.get("data", {})
    if isinstance(embedded, dict):
        items = embedded.get("_embedded", {}).get("items")
        if isinstance(items, list):
            return [i for i in items if isinstance(i, dict)]
    items = result.get("_embedded", {})
    if isinstance(items, dict) and isinstance(items.get("items"), list):
        return [i for i in items["items"] if isinstance(i, dict)]
    for key, value in result.items():
        if key in ("success", "message", "error"):
            continue
        if isinstance(value, list) and all(isinstance(i, dict) for i in value) and value:
            return value
    return []


def _identify(item: Dict[str, Any]) -> Dict[str, Any]:
    ident: Dict[str, Any] = {}
    for k in _ID_KEYS:
        if k in item:
            ident["id"] = item[k]
            break
    for k in _NAME_KEYS:
        if item.get(k) is not None:
            ident["name"] = item[k]
            break
    return ident or {"id": None, "name": None}


async def snapshot_inventory(recorder: Optional[RunRecorder] = None) -> Dict[str, Any]:
    """Capture id+name of every object in each family."""
    snap: Dict[str, Any] = {}
    for family, spec in INVENTORY_FAMILIES.items():
        if spec is None:
            snap[family] = {"available": False,
                            "note": "no list operation registered for this family",
                            "items": []}
            continue
        op, params = spec
        try:
            result = await invoke(op, **params)
        except Exception as exc:
            snap[family] = {"available": False,
                            "note": f"{type(exc).__name__}: {exc}", "items": []}
            continue
        if not result.get("success"):
            snap[family] = {"available": False,
                            "note": _error_text(result).strip()[:300], "items": []}
            continue
        items = [_identify(i) for i in _extract_items(result)]
        snap[family] = {"available": True, "items": items}
    return snap


def _key(entry: Dict[str, Any]) -> str:
    return f"{entry.get('id')}|{entry.get('name')}"


def diff_inventory(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """Diff two snapshots. Returns per-family added/removed plus a foreign-drift
    list containing only changes NOT carrying the fixture prefix."""
    diff: Dict[str, Any] = {"families": {}, "foreign_drift": []}
    for family in INVENTORY_FAMILIES:
        b = before.get(family, {})
        a = after.get(family, {})
        if not (b.get("available") and a.get("available")):
            diff["families"][family] = {"skipped": True,
                                        "reason": a.get("note") or b.get("note")}
            continue
        bkeys = {_key(i): i for i in b.get("items", [])}
        akeys = {_key(i): i for i in a.get("items", [])}
        added = [akeys[k] for k in akeys.keys() - bkeys.keys()]
        removed = [bkeys[k] for k in bkeys.keys() - akeys.keys()]
        diff["families"][family] = {"added": added, "removed": removed}
        for entry in added:
            if not is_ours(entry.get("name")):
                diff["foreign_drift"].append({"family": family, "change": "added",
                                              "object": entry})
        for entry in removed:
            if not is_ours(entry.get("name")):
                diff["foreign_drift"].append({"family": family, "change": "removed",
                                              "object": entry})
    diff["clean"] = not diff["foreign_drift"]
    return diff


# family -> (list op, list params, delete op, target parameter, "name"|"id",
#            extra delete params)
#
# The safety guard can only vouch for a NAME, so `assert_ours(name)` is always
# called on the listed record's name immediately before the delete, whichever
# handle the API actually accepts. Guest deletion must go by numeric id --
# `DELETE guest/<username>` returns 422 "Invalid ID" on 6.12.4 even though the
# operation's docstring advertises username support (see README / report).
_SWEEPABLE: Dict[str, Tuple[str, Dict[str, Any], str, str, str, Dict[str, Any]]] = {
    "guest_users": ("list_guest_users", {"limit": 1000}, "delete_guest_user",
                    "user_id", "id", {"confirm": True}),
    "enforcement_profiles": ("list_enforcement_profiles", {"limit": 1000},
                             "delete_enforcement_profile", "profile_name",
                             "name", {"confirm_deletion": True}),
    "roles": ("list_roles", {"limit": 1000}, "delete_role", "role_name",
              "name", {"confirm": True}),
    # network devices / device groups / api clients / admin users are
    # intentionally absent: their delete operations are denylisted.
}


async def sweep_fixtures() -> List[Dict[str, Any]]:
    """List every sweepable family and delete surviving zzz-mcptest-* objects."""
    swept: List[Dict[str, Any]] = []
    for family, (list_op, list_params, del_op, target_param, by, extra) in _SWEEPABLE.items():
        if is_denylisted(del_op):
            continue
        try:
            result = await invoke(list_op, **list_params)
        except Exception as exc:
            swept.append({"family": family, "error": f"list failed: {exc}"})
            continue
        if not result.get("success"):
            continue
        for item in _extract_items(result):
            ident = _identify(item)
            name = ident.get("name")
            if not is_ours(name):
                continue
            try:
                assert_ours(name)  # guard immediately before delete
                handle = ident.get("id") if by == "id" else name
                if handle is None:
                    handle = name
                params = {target_param: handle}
                params.update(extra)
                del_result = await invoke(del_op, **params)
                swept.append({"family": family, "name": name,
                              "id": ident.get("id"),
                              "deleted": bool(del_result.get("success")),
                              "detail": _error_text(del_result).strip()[:200] or None})
            except Exception as exc:
                swept.append({"family": family, "name": name,
                              "deleted": False, "detail": f"{type(exc).__name__}: {exc}"})
    return swept


def env_ready() -> Tuple[bool, str]:
    """True when live credentials are present in the environment.

    Only checks for presence — never reads, echoes, or logs a value.
    """
    required = ("CLEARPASS_SERVER", "CLEARPASS_CLIENT_ID", "CLEARPASS_CLIENT_SECRET")
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        return False, (
            "Live credentials are not in the environment (missing: "
            + ", ".join(missing)
            + "). Source the operator .env before running with --live."
        )
    if ".invalid" in os.environ.get("CLEARPASS_SERVER", ""):
        return False, ("CLEARPASS_SERVER points at the offline test placeholder; "
                       "source the operator .env before running with --live.")
    return True, ""
