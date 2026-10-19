# Live-validation harness (`tests/live/`)

Opt-in test suite that exercises the ClearPass Sidekick MCP server against a **real**
ClearPass 6.12.4 appliance. Everything here is skipped at collection time unless `--live`
is passed, so the offline suite stays hermetic and fast: `pytest tests/` reports
**222 passed, 730 skipped** — the 730 skips are exactly this directory.

The registry now holds **757 operations** (full `pyclearpass-1.0.8` coverage). The
original sweep covered 287; the **475-op expansion** is covered by the nine modules added
below, each of which owns exactly the operations its docstring names. Where an existing
module's domain grew, that module keeps its original scope and excludes the additions via
an `EXPANSION_OPERATIONS` list next to its coverage guard — so both the old and the new
module still fail loudly if an operation appears that nobody covers.

```
tests/live/
  conftest.py                          --live flag, session scaffolding, inventory guard, cleanup fixture
  harness.py                           dispatch, safety rails, classification, snapshot/diff/sweep, recorder
  denylist.py                          hard denylist (32 entries) + one-line reason per entry
  test_smoke.py                        6-test proof that the harness itself works

  # original sweep (287 operations)
  test_network_and_sessions.py         network devices (16), device groups, sessions/CoA (14)
  test_guest_domains.py                guest users, guest actions, guest configuration
  test_certs_profiles_api.py           certificates (9), enforcement profiles, api clients
  test_policy_elements_a.py            policy elements (roles, mappings, services, auth)
  test_policy_elements_b.py            policy elements (posture, dictionaries, device config)
  test_global_server_config.py         admin users, privileges, licences, attributes, SNMP, backup (58)
  test_local_config_and_audit.py       cluster, AD, access control, version, audit logs (27)

  # full-SDK-coverage expansion (475 operations)
  test_identities_live.py              identities (58) — endpoints, local users, static host lists, guest/API-client replacements
  test_global_config_expansion_live.py the 28 operations added to global_server_config (by-name writes, password policies, portal, db-sync)
  test_network_devices_expansion_live.py the 5 operations added to network_devices (by-name get/update/replace/delete, replace-by-id)
  test_endpoint_visibility_live.py     endpoint_visibility part 1 of 2 (38 of 94) — fingerprints, Windows hotfixes, OnGuard custom scripts, device profiler
  test_endpoint_visibility_onguard_live.py endpoint_visibility part 2 of 2 (56 of 94) — agentless OnGuard settings/subnet mappings, network scans, profiler subnet mappings
  _endpoint_visibility_common.py       shared scaffolding for the two endpoint_visibility modules (not collected — leading underscore)
  test_integrations_live.py            integrations (80) — context servers, extensions, Onboard, messaging setups
  test_dur_and_misc_live.py            enforcement_profiles_dur (142) + the 6 new session_control ops + tools_utilities (6) + api_operations (4) = 158
  test_certs_ca_audit_live.py          the 20 new certificates ops + certificate_authority (19) + the 13 new audit_logs ops (53 with one re-covered)

  _artifacts/                          results-<runid>.jsonl + inventory-<runid>.json   (gitignored)
```

## Running

```bash
# Offline (default) — no network, no credentials, must report 222 passed, 730 skipped
.venv-refactor/bin/python -m pytest tests/ -q

# Offline suite only (no live collection at all) — must report 222 passed
.venv-refactor/bin/python -m pytest tests/ --ignore=tests/live -q

# Live — source the operator .env first so credentials arrive via os.environ
set -a; . /home/elvis/Projects/clearpass-sidekick-claude-code/.env; set +a
.venv-refactor/bin/python -m pytest tests/live --live -q -s
```

Without `--live`, `pytest_collection_modifyitems` marks every item under this directory
skipped, so no network call, credential read, or `src` import happens.

`-s` is recommended: the run id, sweep report and inventory-diff verdict are printed to
stdout. Credentials and the appliance address are never printed, logged, or written to an
artifact — `harness.env_ready()` only checks for the *presence* of `CLEARPASS_SERVER`,
`CLEARPASS_CLIENT_ID` and `CLEARPASS_CLIENT_SECRET`, and refuses to run if
`CLEARPASS_SERVER` still points at the offline `.invalid` placeholder.

## Safety rails

| Rail | Where | What it does |
|---|---|---|
| Fixture namespace | `harness.fixture_name(run_id, n, suffix="")` | every created object is `zzz-mcptest-<runid>-<n>` (`FIXTURE_PREFIX` = `zzz-mcptest-`); `<runid>` is a fresh 8-hex-char token per session |
| Write guard | `harness.assert_ours(name)` | raises unless the name carries `zzz-mcptest-`; call it *immediately* before every update/delete |
| Hard denylist | `denylist.DENYLIST` (32 entries) | `harness.invoke()` raises `DenylistedOperation` before the gateway is touched |
| Inventory guard | session-autouse `inventory_guard` | before/after snapshot of every family; **fails the run** on any change outside the prefix |
| Per-test cleanup | `cleanup` fixture | registered coroutine factories run in a `finally`, even on failure |
| Session sweep | `harness.sweep_fixtures()` | lists each sweepable family and deletes surviving `zzz-mcptest-*` objects; reports what it removed |

The 32 denylist entries (18 from the original sweep, 14 added with the expansion) cover:

| Group | Entries | Examples |
|---|---:|---|
| Credential / access self-destruction | 2 | `delete_api_client`, `delete_admin_user` |
| Production infrastructure | 5 | `delete_network_device`, `bulk_update_network_devices`, `delete_network_device_group`, `leave_ad_domain`, `delete_server_access_control_by_resource` |
| Licensing | 3 | `activate_application_license_online` / `_offline`, `delete_application_license` |
| Server / cluster configuration | 3 | `delete_file_backup_server`, `delete_server_policy_manager_zone`, `sync_cluster_database` |
| CoA / disconnect against live sessions | 9 | 4 × `perform_coa_*`, `coa_active_session_by_mac`, 4 × `session_action_disconnect*` |
| Onboard certificate authority | 3 | `onboard_sign_certificate_request`, `onboard_revoke_certificate`, `onboard_reject_certificate_request` |
| Extension lifecycle | 3 | `install_extension_instance`, `reinstall_extension_instance`, `upgrade_extension_instance` |
| Outbound messaging to real humans | 4 | `send_guest_receipt_sms` / `_email`, `send_sms`, `send_email` |

`test_smoke.py::test_denylist_names_all_exist_in_registry` pins every key to a real
registry operation, so a rename cannot silently empty the denylist.

The session-level `harness.sweep_fixtures()` covers 3 families — guest users, enforcement
profiles, roles — the only ones in `harness._SWEEPABLE` whose delete operation is not
denylisted. The expansion modules create fixtures in families the session sweep does not
know about (fingerprints, Windows hotfixes, OnGuard scripts, subnet mappings, static host
lists, local users, context servers, DUR profiles, trust-list certificates…), so each one
ships its own teardown: the per-test `cleanup` fixture plus module-scoped sweepers
(`_endpoint_visibility_common.py` for both endpoint_visibility modules,
`test_integrations_live.py` for its own families). **Never create a fixture in a family
with no teardown path** — nothing will clean it up and the inventory guard will fail the
run. Guest deletion goes
by numeric id, not username: `DELETE guest/<username>` returns 422 "Invalid ID" on 6.12.4
even though the operation's docstring advertises username support.

## Dispatch

All live calls go through `src.tools.gateway.invoke_operation`, never by importing an
operation function directly. That means every call also validates the
progressive-disclosure path: name resolution, parameter whitelisting, `Context` injection
and error wrapping. The registry holds **757 operations**.

```python
result = await harness.invoke("list_network_devices")            # raw
result = await recorder.run("list_network_devices", tier="read") # raw + recorded
```

### Operations whose own parameter is called `name`

The operation name is a **positional-only** parameter of both `harness.invoke()` and
`RunRecorder.run()`, so an operation parameter called `name` passes straight through —
no local shim needed. 172 of the 757 registry operations take a parameter literally called
`name` (including `create_role`, `create_enforcement_profile`, every `get_*_details` name
branch and the whole `*_by_name` family the expansion added); all of them used to be
undispatchable from the harness.

```python
await harness.invoke("get_role_details", name="[Guest]")
await recorder.run("get_role_details", tier="read", name="[Guest]")
```

The only remaining reserved words are the harness's own keywords: `_ctx` / `_params` on
`invoke`, and `domain` / `tier` / `expect_absent` / `_params` on `run`. Pass colliding
operation parameters through the `_params` dict, which is merged with (and overridden by)
the keyword parameters:

```python
await harness.invoke("create_guest_domain", _params={"domain": "example.com"})
await recorder.run("create_guest_domain", tier="write",
                   _params={"domain": "example.com"})
```

**Omit optional parameters by default.** A fixed bug in `src/registry.py` made omitted
`Field()`-defaulted parameters arrive in operation bodies as raw `FieldInfo` objects,
affecting **272 of the 287 operations** that existed when it was found (that many carried
at least one `Field()`-defaulted parameter). The exposure only grew with the expansion:
**733 of today's 757 operations** have at least one `Field()`-defaulted parameter. The
omission path is where the bugs are; the
fully-specified path is the easy case. Call operations with required parameters only
unless the test is specifically about an optional one.

## Verdicts

`harness.classify(result, operation, expect_absent=False)` returns:

- **PASS** — `success: True`, or a structured domain-level failure that is legitimately
  correct (e.g. a 404 for a genuinely absent object when `expect_absent=True`).
- **EXPECTED_SKIP** — matches the known-limitation allowlist below.
- **FAIL** — anything else, and *always* for a crash marker (`FieldInfo`, `Traceback`,
  `TypeError:`, `AttributeError:`, `missing required argument`, …) even on an
  allowlisted operation: a known environment limit must present as a structured error,
  never as a Python-level explosion.

Two things the classifier deliberately refuses to be lenient about:

- **Crash markers are searched over the whole serialised payload**
  (`harness.deep_crash_marker`, 14 markers in `_CRASH_MARKERS`), not just the four
  top-level `error`/`message`/`detail`/`details` keys. An operation returning
  `success: True` with `data.error = "'ClearPassClient' object has no attribute
  'get_proxy_target'"` is a FAIL, not a PASS.
- **An HTML error body is never a not-found** (`harness.looks_like_html`). A body
  containing any of the 6 `_HTML_MARKERS` — `<html`, `<!doctype html`, `<body`, `<h1>`,
  `<title>`, `apache` — scores FAIL even under `expect_absent=True`. Under the old
  `/api/v1` base URL, ClearPass 6.12.4 answered `POST session-action/disconnect*` with an
  HTTP **500** carrying an HPE "Error 404 (Not Found)" HTML page; the bare `not found`
  regex used to read that as a legitimate absence and score `disconnect_sessions_bulk` /
  `_by_username` / `_by_mac` / `_by_ip` as PASS. Scoring an HTML body as FAIL is what
  surfaced that, and it was the right call — the 500 turned out to be the `/api/v1` mount,
  not a missing route. The client now addresses the unversioned `/api` root, where the
  same routes answer structured JSON (see `ClearPassClient._endpoint_url`). The HTML rule
  stays: an HTML error body is never evidence of a legitimate absence.

The HTML and not-found checks only look at strings sitting under one of the 17 error-ish
keys in `_ERROR_KEYS` (`error`, `message`, `detail`, `body`, `response`, `raw`,
`traceback`, …), so a weblogin page or print template that legitimately *contains* markup
in its payload is not misread as an error body.

`harness.deep_error_text(result)` returns every error-ish string at any nesting depth and
is what the recorder writes into the `error` field of a non-PASS record.

### Known-limitation allowlist

4 entries in `harness.KNOWN_LIMITATIONS`. Environment limits of ClearPass 6.12.4 (per
`docs/live_testing_plan_phase1.md`), not product bugs — but each is asserted as a *known*
skip with its reason so a genuine regression still fails:

| Match | Reason |
|---|---|
| `*proxy_target*` | Missing `pyclearpass` implementation |
| `*insight*` | Licence-dependent |
| `configure_device_{snmp,radsec,cli}_settings` | Require a live managed device (422/400) |
| `delete_radius_dictionary` | Requires a development license on this appliance (`docs/live_testing_plan_phase1.md:1792`) |

> **Two rows were removed on 2026-07-31.** A blanket `*_password_policy*` entry
> and `get_application_license_summary[_detail]` used to sit in this table.
> Both were wrong. curl against the lab appliance showed that
> `/admin-user/password-policy`, `/local-user/password-policy` and
> `/application-license/summary` all answer **200** on 6.12.4 — the 404s
> recorded in `docs/live_testing_plan_phase1.md:2340` came from the hyphenated
> paths `/admin-user-password-policy`, `/local-user-password-policy` and
> `/application-license-summary`, which no ClearPass version serves. The five
> operations built on those paths have been deleted from the registry, and the
> operations against the real paths must now genuinely pass. Treat those
> sections of `live_testing_plan_phase1.md` as superseded.

Deliberately **not** allowlisted, though documented: `update_tacacs_service_dictionary`
(TACACS+ dictionaries are read-only, 405) — the product already converts that into a
structured, explanatory success/error, so an allowlist entry would only mask a
regression.

## Artifacts

### `results-<runid>.jsonl`

One JSON object per line, one line per operation invoked. **Schema is stable** — Phase 4
writes it, Phase 5 triages from it. 7 fields, always all present:

| Field | Type | Notes |
|---|---|---|
| `operation` | string | registry operation name |
| `domain` | string | registry domain, resolved automatically when omitted |
| `tier` | string | caller-supplied bucket: `read` / `create` / `update` / `delete` / `negative` / `denylist` |
| `verdict` | string | `PASS` \| `EXPECTED_SKIP` \| `FAIL` |
| `params_sent` | object | exactly what was passed; secret-looking keys replaced with `***REDACTED***` |
| `error` | string \| null | joined deep error text from the result; `null` on PASS |
| `duration_ms` | number \| null | wall-clock, 2dp |

### `inventory-<runid>.json`

`{run_id, before, after, swept, diff}`. `diff.families[<family>]` holds `added`/`removed`
lists of `{id, name}`; `diff.foreign_drift` holds only the changes **not** carrying the
fixture prefix; `diff.clean` is `true` when `foreign_drift` is empty. A non-clean diff
fails the session.

9 families are snapshotted: network devices, guest users, admin users, roles, enforcement
profiles, api clients, endpoints, device groups, certificates. 8 of them resolve to a list
operation; `endpoints` is still recorded as `available: false`. `list_endpoints` *does*
now exist (the expansion added it under the `identities` domain), but wiring it into the
guard changes what the live sweep snapshots and diffs, so that stays a deliberate,
separate decision — see the comment on `harness.INVENTORY_FAMILIES["endpoints"]`.
