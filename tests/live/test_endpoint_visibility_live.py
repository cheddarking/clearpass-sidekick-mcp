"""Live validation — ``endpoint_visibility`` domain, part 1 of 2 (38 of 94 ops).

Scope of this module
--------------------
* ``fingerprint`` — the profiler fingerprint dictionary (10 ops)
* ``windows-hotfix`` — the hotfix database posture policies check against (10)
* ``onguard-custom-script`` — OnGuard custom health-collection scripts (10)
* ``device-profiler/device-fingerprint`` — posting profiling attributes (3)
* ``onguard-activity`` — OnGuard endpoint activity and agent messaging (5)

The remaining 56 operations (agentless OnGuard settings and subnet mappings,
``config/network-scan``, profiler subnet mappings, OnGuard Policy Manager zones,
and the two OnGuard global-state settings singletons) live in
``test_endpoint_visibility_onguard_live.py``.

Calling style
-------------
Everything dispatches through ``harness.invoke`` (i.e. through
``src.tools.gateway.invoke_operation``), so the progressive-disclosure path —
name resolution, alias handling, required-parameter validation, ``Context``
injection, error wrapping — is validated alongside each operation. Optional
parameters are OMITTED by default; that is the path the ``FieldInfo`` leak lived
on. A second pass supplies them where they are meaningful.

Fixture identity in families that are not name-keyed
----------------------------------------------------
``harness.assert_ours`` can only vouch for a NAME carrying ``zzz-mcptest-``.
Two families here are keyed on something else, so each gets an explicit rail
(all defined in ``_endpoint_visibility_common``):

* **Windows hotfixes are keyed by ``kbid`` + ``operating_system``**, and the
  schema has no name field — but it does have a free-text ``title``. The
  fixtures therefore carry the prefix in ``title`` *and* use fake KBIDs of the
  form ``KB0000001`` (six leading zeros — a shape Microsoft has never issued, so
  it cannot collide with a real hotfix). Before any hotfix update or delete,
  ``_assert_hotfix_is_ours`` reads the record back and refuses unless the KBID
  is one of ours **and** the stored title carries the fixture prefix. A hotfix
  is never deleted on the strength of its KBID alone.
* **Endpoints posted through ``device-profiler/device-fingerprint`` are keyed by
  MAC.** The fixtures use locally-administered addresses (``02:00:5e:<runid>:nn``)
  derived from the run id, so the endpoint exists only because this run created
  it; ``assert_local_mac`` refuses anything globally administered.

Every id-keyed write additionally passes ``assert_created_id``: the id must be
one this run's own create returned, never an id harvested from a list.

Safety of the messaging operations
----------------------------------
``send_onguard_activity_message`` / ``_notification`` can broadcast to every live
OnGuard agent on the appliance. This module **never** sets ``is_broadcast`` true
and never sends an empty/wildcard ``host_mac_list``: both calls target exactly
one locally-administered MAC that no real agent can have. A guard asserts that
invariant on the payload before dispatch.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

import pytest

from . import harness
from ._endpoint_visibility_common import (
    ABSENT_ID,
    FAIL,
    LIMITATION,
    NOTES,
    PASS,
    assert_created_id,
    assert_fixture_kbid,
    assert_local_mac,
    assert_ours,
    fixture_name,
    id_of,
    is_structured_envelope,
    items_of,
    local_mac,
    no_crash,
    note,
    obj_of,
    record_blocked,
    record_limitation,
    run_op,
    surviving_fixtures,
    sweep_named_family,
)

# Legitimate ClearPass taxonomy values. The fixture identity is carried by the
# NAME, so category/family may be real values without any risk of touching a
# real object.
FP_CATEGORY = "Computer"
FP_FAMILY = "Windows"

# Fake KBIDs — six leading zeros, never issued by Microsoft.
KBID_NAME_PATH = "KB0000001"
KBID_ID_PATH = "KB0000002"
KBID_ABSENT = "KB0000009"
HOTFIX_OS = "Windows 10"

# device-profiler/device-fingerprint ingestion is asynchronous: the POST returns
# "Successfully posted device fingerprint to profiler" before the record is
# readable. Measured live on 6.12.4 the record usually lands within ~2s, but the
# pipeline is not prompt and has been seen to take longer, so the budget is
# generous. Bounded retry — never an unbounded wait; the first probe is
# immediate, so the worst-case sleep is (ATTEMPTS - 1) * INTERVAL.
DFP_INGEST_ATTEMPTS = 6
DFP_INGEST_INTERVAL_S = 2.0
DFP_INGEST_BUDGET_S = (DFP_INGEST_ATTEMPTS - 1) * DFP_INGEST_INTERVAL_S


# ==========================================================================
# 1. fingerprint — 10 operations, full fixture CRUD on both handles
# ==========================================================================


def test_list_fingerprints_optionals_omitted(run_async, recorder):
    """No parameters at all — the omission path.

    ``limit`` carries ``Field(25)``, so this also proves the default survives
    dispatch rather than arriving as a raw ``FieldInfo``.
    """
    result, verdict = run_op(run_async, recorder, "list_fingerprints", tier="read")
    no_crash(result, "list_fingerprints")
    assert verdict == PASS, f"list_fingerprints (no params) -> {result}"
    assert "fingerprints" in result, f"unexpected payload shape: {sorted(result)}"


def test_list_fingerprints_with_optionals(run_async, recorder):
    """Second pass with every optional supplied, including the ``filter`` alias
    on ``filter_str``."""
    result, verdict = run_op(
        run_async, recorder, "list_fingerprints", tier="read",
        filter_str='{"category": "Computer"}', sort="+id", offset=0, limit=5,
        calculate_count=True,
    )
    no_crash(result, "list_fingerprints")
    assert verdict == PASS, f"list_fingerprints (optionals supplied) -> {result}"


def _delete_fingerprint_by_name(name: str):
    """Cleanup factory — guarded, idempotent, never raises into teardown."""
    assert_ours(name)
    return harness.invoke(
        "delete_fingerprint_by_name",
        _params={"category": FP_CATEGORY, "family": FP_FAMILY, "name": name},
    )


def test_fingerprint_lifecycle_by_name(run_async, recorder, run_id, cleanup):
    """create -> get -> update(rename) -> replace(rename back) -> delete, all on
    the name handle, entirely inside the fixture namespace."""
    name = fixture_name(run_id, "fp1")
    renamed = fixture_name(run_id, "fp1", "updated")
    cleanup.add(lambda: _delete_fingerprint_by_name(name))
    cleanup.add(lambda: _delete_fingerprint_by_name(renamed))

    created, verdict = run_op(
        run_async, recorder, "create_fingerprint", tier="create", expect="lenient",
        fingerprint_data={"category": FP_CATEGORY, "family": FP_FAMILY,
                          "name": name},
    )
    no_crash(created, "create_fingerprint")
    if verdict != PASS:
        pytest.skip(f"create_fingerprint refused by the appliance: {created}")

    got, verdict = run_op(run_async, recorder, "get_fingerprint_by_name",
                          tier="read", category=FP_CATEGORY, family=FP_FAMILY,
                          name=name)
    assert verdict == PASS, f"get_fingerprint_by_name({name!r}) -> {got}"
    assert obj_of(got, "fingerprint").get("name") == name, got

    assert_ours(name)
    updated, verdict = run_op(
        run_async, recorder, "update_fingerprint_by_name", tier="update",
        category=FP_CATEGORY, family=FP_FAMILY, name=name,
        fingerprint_data={"name": renamed},
    )
    assert verdict == PASS, f"update_fingerprint_by_name({name!r}) -> {updated}"

    after_rename, verdict = run_op(
        run_async, recorder, "get_fingerprint_by_name", tier="read",
        category=FP_CATEGORY, family=FP_FAMILY, name=renamed)
    assert verdict == PASS, \
        f"PATCH claimed success but {renamed!r} is not readable -> {after_rename}"

    assert_ours(renamed)
    replaced, verdict = run_op(
        run_async, recorder, "replace_fingerprint_by_name", tier="update",
        category=FP_CATEGORY, family=FP_FAMILY, name=renamed,
        fingerprint_data={"category": FP_CATEGORY, "family": FP_FAMILY,
                          "name": name},
    )
    assert verdict == PASS, f"replace_fingerprint_by_name({renamed!r}) -> {replaced}"

    assert_ours(name)
    deleted, verdict = run_op(
        run_async, recorder, "delete_fingerprint_by_name", tier="delete",
        category=FP_CATEGORY, family=FP_FAMILY, name=name)
    assert verdict == PASS, f"delete_fingerprint_by_name({name!r}) -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_fingerprint_by_name", tier="negative",
        expect="absent", category=FP_CATEGORY, family=FP_FAMILY, name=name)
    assert verdict == PASS, f"deleted fingerprint still readable: {gone}"


def test_fingerprint_lifecycle_by_id(run_async, recorder, run_id, cleanup):
    """The numeric-id handle: create -> get -> update -> replace -> delete.

    The id is taken from our own create (falling back to a read-back of our own
    fixture name), never from the family listing, and ``assert_created_id``
    refuses anything else immediately before each write.
    """
    name = fixture_name(run_id, "fp2")
    renamed = fixture_name(run_id, "fp2", "updated")
    cleanup.add(lambda: _delete_fingerprint_by_name(name))
    cleanup.add(lambda: _delete_fingerprint_by_name(renamed))

    created, verdict = run_op(
        run_async, recorder, "create_fingerprint", tier="create", expect="lenient",
        fingerprint_data={"category": FP_CATEGORY, "family": FP_FAMILY,
                          "name": name},
    )
    no_crash(created, "create_fingerprint")
    if verdict != PASS:
        pytest.skip(f"create_fingerprint refused by the appliance: {created}")

    fid = id_of(obj_of(created, "fingerprint"))
    if fid is None:
        # The POST body did not echo an id; read our own fixture back for it.
        readback, _ = run_op(run_async, recorder, "get_fingerprint_by_name",
                             tier="read", category=FP_CATEGORY,
                             family=FP_FAMILY, name=name)
        fid = id_of(obj_of(readback, "fingerprint"))
    if fid is None:
        record_blocked(recorder, "delete_fingerprint_by_id",
                       "neither create_fingerprint nor get_fingerprint_by_name "
                       "returned a numeric id for our own fixture, so no id can "
                       "be proven to be ours")
        pytest.skip("no id available for the fingerprint we created")

    created_ids = [fid]

    got, verdict = run_op(run_async, recorder, "get_fingerprint_by_id",
                          tier="read", fingerprint_id=fid)
    assert verdict == PASS, f"get_fingerprint_by_id({fid}) -> {got}"
    assert_ours(obj_of(got, "fingerprint").get("name"))

    assert_created_id(fid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "update_fingerprint_by_id", tier="update",
        fingerprint_id=fid, fingerprint_data={"name": renamed})
    assert verdict == PASS, f"update_fingerprint_by_id({fid}) -> {updated}"

    assert_created_id(fid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "replace_fingerprint_by_id", tier="update",
        fingerprint_id=fid,
        fingerprint_data={"category": FP_CATEGORY, "family": FP_FAMILY,
                          "name": name})
    assert verdict == PASS, f"replace_fingerprint_by_id({fid}) -> {replaced}"

    assert_created_id(fid, created_ids)
    assert_ours(obj_of(got, "fingerprint").get("name"))
    deleted, verdict = run_op(run_async, recorder, "delete_fingerprint_by_id",
                              tier="delete", fingerprint_id=fid)
    assert verdict == PASS, f"delete_fingerprint_by_id({fid}) -> {deleted}"

    gone, verdict = run_op(run_async, recorder, "get_fingerprint_by_id",
                           tier="negative", expect="absent", fingerprint_id=fid)
    assert verdict == PASS, f"deleted fingerprint still readable by id: {gone}"


FINGERPRINT_NAME_OPS: List[Tuple[str, Dict[str, Any]]] = [
    ("get_fingerprint_by_name", {}),
    ("delete_fingerprint_by_name", {}),
    ("update_fingerprint_by_name",
     {"fingerprint_data": {"name": "@absent"}}),
    ("replace_fingerprint_by_name",
     {"fingerprint_data": {"category": FP_CATEGORY, "family": FP_FAMILY,
                           "name": "@absent"}}),
]


@pytest.mark.parametrize("operation,extra", FINGERPRINT_NAME_OPS,
                         ids=[o[0] for o in FINGERPRINT_NAME_OPS])
def test_fingerprint_by_name_absent(run_async, recorder, run_id, operation, extra):
    """Every by-name operation against a fixture name that cannot exist.

    Guarantees the operation is dispatched even when the appliance refuses the
    fixture create, and proves the by-name route is implemented rather than
    answering with a type error or a "must supply id" message.
    """
    name = assert_ours(fixture_name(run_id, "fp", "absent"))
    params = {k: ({**v, "name": name} if k.endswith("_data") else v)
              for k, v in extra.items()}
    result, verdict = run_op(
        run_async, recorder, operation, tier="negative", expect="absent",
        category=FP_CATEGORY, family=FP_FAMILY, name=name, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(absent {name!r}) -> {result}"


FINGERPRINT_ID_OPS: List[Tuple[str, Dict[str, Any]]] = [
    ("get_fingerprint_by_id", {}),
    ("delete_fingerprint_by_id", {}),
    ("update_fingerprint_by_id", {"fingerprint_data": {"name": "@absent"}}),
    ("replace_fingerprint_by_id",
     {"fingerprint_data": {"category": FP_CATEGORY, "family": FP_FAMILY,
                           "name": "@absent"}}),
]


@pytest.mark.parametrize("operation,extra", FINGERPRINT_ID_OPS,
                         ids=[o[0] for o in FINGERPRINT_ID_OPS])
def test_fingerprint_by_id_absent(run_async, recorder, run_id, operation, extra):
    name = assert_ours(fixture_name(run_id, "fp", "absent"))
    params = {k: ({**v, "name": name} if k.endswith("_data") else v)
              for k, v in extra.items()}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", fingerprint_id=ABSENT_ID, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(fingerprint_id={ABSENT_ID}) -> {result}"


def test_create_fingerprint_missing_body_is_rejected(run_async, recorder):
    """Required parameter omitted — the gateway must refuse before dispatch."""
    result, verdict = run_op(
        run_async, recorder, "create_fingerprint", tier="negative",
        expect="refusal",
        substrings=("missing required parameter", "fingerprint_data"))
    no_crash(result, "create_fingerprint")
    assert verdict == PASS, f"create_fingerprint() -> {result}"


# ==========================================================================
# 2. windows-hotfix — 10 operations
# ==========================================================================


def _delete_hotfix_by_kbid(kbid: str):
    assert_fixture_kbid(kbid)
    return harness.invoke("delete_windows_hotfix_by_kbid",
                          _params={"kbid": kbid,
                                   "operating_system": HOTFIX_OS})


def _assert_hotfix_is_ours(run_async, recorder, kbid: str) -> Dict[str, Any]:
    """Read the hotfix back and refuse unless BOTH rails hold.

    The KBID must be one of the fixture set, and the stored ``title`` must carry
    the fixture prefix. A hotfix is never written or deleted on the strength of
    its KBID alone.
    """
    assert_fixture_kbid(kbid)
    result, verdict = run_op(run_async, recorder, "get_windows_hotfix_by_kbid",
                             tier="read", kbid=kbid, operating_system=HOTFIX_OS)
    assert verdict == PASS, f"get_windows_hotfix_by_kbid({kbid}) -> {result}"
    record = obj_of(result, "windows_hotfix")
    assert_ours(record.get("title"))
    return record


def test_list_windows_hotfixes_optionals_omitted(run_async, recorder):
    result, verdict = run_op(run_async, recorder, "list_windows_hotfixes",
                             tier="read")
    no_crash(result, "list_windows_hotfixes")
    assert verdict == PASS, f"list_windows_hotfixes (no params) -> {result}"
    assert "windows_hotfixes" in result, f"unexpected shape: {sorted(result)}"


def test_list_windows_hotfixes_with_optionals(run_async, recorder):
    result, verdict = run_op(
        run_async, recorder, "list_windows_hotfixes", tier="read",
        filter_str='{"operating_system": "Windows 10"}', sort="-id", offset=0,
        limit=5, calculate_count=True)
    no_crash(result, "list_windows_hotfixes")
    assert verdict == PASS, f"list_windows_hotfixes (optionals) -> {result}"


def test_windows_hotfix_lifecycle_by_kbid(run_async, recorder, run_id, cleanup):
    """create -> get -> update -> replace -> delete on the kbid handle.

    The fixture is identified by a fake KBID (``KB0000001``) plus a
    fixture-prefixed ``title``; both are verified before every write.
    """
    title = fixture_name(run_id, "hf1")
    cleanup.add(lambda: _delete_hotfix_by_kbid(KBID_NAME_PATH))

    created, verdict = run_op(
        run_async, recorder, "create_windows_hotfix", tier="create",
        expect="lenient",
        hotfix_data={"kbid": KBID_NAME_PATH, "operating_system": HOTFIX_OS,
                     "title": title, "severity_rating": "Critical"},
    )
    no_crash(created, "create_windows_hotfix")
    if verdict != PASS:
        pytest.skip(f"create_windows_hotfix refused by the appliance: {created}")

    record = _assert_hotfix_is_ours(run_async, recorder, KBID_NAME_PATH)
    assert record.get("kbid") == KBID_NAME_PATH, record

    updated, verdict = run_op(
        run_async, recorder, "update_windows_hotfix_by_kbid", tier="update",
        kbid=KBID_NAME_PATH, operating_system=HOTFIX_OS,
        hotfix_data={"description": f"{title} patched"})
    assert verdict == PASS, f"update_windows_hotfix_by_kbid -> {updated}"

    _assert_hotfix_is_ours(run_async, recorder, KBID_NAME_PATH)
    replaced, verdict = run_op(
        run_async, recorder, "replace_windows_hotfix_by_kbid", tier="update",
        kbid=KBID_NAME_PATH, operating_system=HOTFIX_OS,
        hotfix_data={"kbid": KBID_NAME_PATH, "operating_system": HOTFIX_OS,
                     "title": title, "severity_rating": "Important"})
    assert verdict == PASS, f"replace_windows_hotfix_by_kbid -> {replaced}"

    _assert_hotfix_is_ours(run_async, recorder, KBID_NAME_PATH)
    deleted, verdict = run_op(
        run_async, recorder, "delete_windows_hotfix_by_kbid", tier="delete",
        kbid=KBID_NAME_PATH, operating_system=HOTFIX_OS)
    assert verdict == PASS, f"delete_windows_hotfix_by_kbid -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_windows_hotfix_by_kbid", tier="negative",
        expect="absent", kbid=KBID_NAME_PATH, operating_system=HOTFIX_OS)
    assert verdict == PASS, f"deleted hotfix still readable: {gone}"


def test_windows_hotfix_lifecycle_by_id(run_async, recorder, run_id, cleanup):
    """The numeric-id handle for the hotfix family."""
    title = fixture_name(run_id, "hf2")
    cleanup.add(lambda: _delete_hotfix_by_kbid(KBID_ID_PATH))

    created, verdict = run_op(
        run_async, recorder, "create_windows_hotfix", tier="create",
        expect="lenient",
        hotfix_data={"kbid": KBID_ID_PATH, "operating_system": HOTFIX_OS,
                     "title": title, "severity_rating": "Critical"},
    )
    no_crash(created, "create_windows_hotfix")
    if verdict != PASS:
        pytest.skip(f"create_windows_hotfix refused by the appliance: {created}")

    record = _assert_hotfix_is_ours(run_async, recorder, KBID_ID_PATH)
    hid = id_of(obj_of(created, "windows_hotfix")) or id_of(record)
    if hid is None:
        record_blocked(recorder, "delete_windows_hotfix_by_id",
                       "the appliance returned no numeric id for our own hotfix "
                       "fixture, so no id can be proven to be ours")
        pytest.skip("no id available for the hotfix we created")
    created_ids = [hid]

    got, verdict = run_op(run_async, recorder, "get_windows_hotfix_by_id",
                          tier="read", windows_hotfix_id=hid)
    assert verdict == PASS, f"get_windows_hotfix_by_id({hid}) -> {got}"
    assert_ours(obj_of(got, "windows_hotfix").get("title"))

    assert_created_id(hid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "update_windows_hotfix_by_id", tier="update",
        windows_hotfix_id=hid, hotfix_data={"description": f"{title} patched"})
    assert verdict == PASS, f"update_windows_hotfix_by_id({hid}) -> {updated}"

    assert_created_id(hid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "replace_windows_hotfix_by_id", tier="update",
        windows_hotfix_id=hid,
        hotfix_data={"kbid": KBID_ID_PATH, "operating_system": HOTFIX_OS,
                     "title": title, "severity_rating": "Important"})
    assert verdict == PASS, f"replace_windows_hotfix_by_id({hid}) -> {replaced}"

    _assert_hotfix_is_ours(run_async, recorder, KBID_ID_PATH)
    assert_created_id(hid, created_ids)
    deleted, verdict = run_op(run_async, recorder, "delete_windows_hotfix_by_id",
                              tier="delete", windows_hotfix_id=hid)
    assert verdict == PASS, f"delete_windows_hotfix_by_id({hid}) -> {deleted}"

    gone, verdict = run_op(run_async, recorder, "get_windows_hotfix_by_id",
                           tier="negative", expect="absent",
                           windows_hotfix_id=hid)
    assert verdict == PASS, f"deleted hotfix still readable by id: {gone}"


HOTFIX_KBID_OPS: List[Tuple[str, Dict[str, Any]]] = [
    ("get_windows_hotfix_by_kbid", {}),
    ("delete_windows_hotfix_by_kbid", {}),
    ("update_windows_hotfix_by_kbid",
     {"hotfix_data": {"severity_rating": "Low"}}),
    ("replace_windows_hotfix_by_kbid",
     {"hotfix_data": {"kbid": KBID_ABSENT, "operating_system": HOTFIX_OS,
                      "severity_rating": "Low"}}),
]


@pytest.mark.parametrize("operation,extra", HOTFIX_KBID_OPS,
                         ids=[o[0] for o in HOTFIX_KBID_OPS])
def test_windows_hotfix_by_kbid_absent(run_async, recorder, run_id, operation,
                                       extra):
    """Every by-kbid operation against a fixture KBID that cannot exist."""
    kbid = assert_fixture_kbid(KBID_ABSENT)
    params = dict(extra)
    if "hotfix_data" in params:
        params["hotfix_data"] = {**params["hotfix_data"],
                                 "title": fixture_name(run_id, "hf", "absent")}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", kbid=kbid,
                             operating_system=HOTFIX_OS, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(kbid={kbid}) -> {result}"


HOTFIX_ID_OPS: List[Tuple[str, Dict[str, Any]]] = [
    ("get_windows_hotfix_by_id", {}),
    ("delete_windows_hotfix_by_id", {}),
    ("update_windows_hotfix_by_id", {"hotfix_data": {"severity_rating": "Low"}}),
    ("replace_windows_hotfix_by_id",
     {"hotfix_data": {"kbid": KBID_ABSENT, "operating_system": HOTFIX_OS,
                      "severity_rating": "Low"}}),
]


@pytest.mark.parametrize("operation,extra", HOTFIX_ID_OPS,
                         ids=[o[0] for o in HOTFIX_ID_OPS])
def test_windows_hotfix_by_id_absent(run_async, recorder, run_id, operation,
                                     extra):
    params = dict(extra)
    if "hotfix_data" in params:
        params["hotfix_data"] = {**params["hotfix_data"],
                                 "title": fixture_name(run_id, "hf", "absent")}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", windows_hotfix_id=ABSENT_ID,
                             **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(windows_hotfix_id={ABSENT_ID}) -> {result}"


def test_create_windows_hotfix_missing_body_is_rejected(run_async, recorder):
    result, verdict = run_op(
        run_async, recorder, "create_windows_hotfix", tier="negative",
        expect="refusal",
        substrings=("missing required parameter", "hotfix_data"))
    no_crash(result, "create_windows_hotfix")
    assert verdict == PASS, f"create_windows_hotfix() -> {result}"


# ==========================================================================
# 3. onguard-custom-script — 10 operations
# ==========================================================================

SCRIPT_ATTRIBUTES = {
    "Path": "C:\\zzz-mcptest",
    "Command": "zzz-mcptest-noop.bat",
    "ExecutionLevel": "User",
    "WaitTime": 10,
}


def _script_body(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "description": "zzz-mcptest live-harness fixture",
        "os_type": "Windows",
        "script_type": "Health Collection",
        "attributes": dict(SCRIPT_ATTRIBUTES),
    }


def _delete_script_by_name(name: str):
    assert_ours(name)
    return harness.invoke("delete_onguard_custom_script_by_name",
                          _params={"name": name})


def test_list_onguard_custom_scripts_optionals_omitted(run_async, recorder):
    result, verdict = run_op(run_async, recorder, "list_onguard_custom_scripts",
                             tier="read")
    no_crash(result, "list_onguard_custom_scripts")
    assert verdict == PASS, f"list_onguard_custom_scripts (no params) -> {result}"
    assert "custom_scripts" in result, f"unexpected shape: {sorted(result)}"


def test_list_onguard_custom_scripts_with_optionals(run_async, recorder):
    result, verdict = run_op(
        run_async, recorder, "list_onguard_custom_scripts", tier="read",
        filter_str='{"os_type": "Windows"}', sort="+name", offset=0, limit=5,
        calculate_count=True)
    no_crash(result, "list_onguard_custom_scripts")
    assert verdict == PASS, f"list_onguard_custom_scripts (optionals) -> {result}"


def test_onguard_custom_script_lifecycle_by_name(run_async, recorder, run_id,
                                                 cleanup):
    """create -> get -> update -> replace -> delete on the name handle."""
    name = fixture_name(run_id, "cs1")
    cleanup.add(lambda: _delete_script_by_name(name))

    created, verdict = run_op(
        run_async, recorder, "create_onguard_custom_script", tier="create",
        expect="lenient", script_data=_script_body(name))
    no_crash(created, "create_onguard_custom_script")
    if verdict != PASS:
        pytest.skip(f"create_onguard_custom_script refused: {created}")

    got, verdict = run_op(run_async, recorder,
                          "get_onguard_custom_script_by_name", tier="read",
                          name=name)
    assert verdict == PASS, f"get_onguard_custom_script_by_name({name!r}) -> {got}"
    assert obj_of(got, "custom_script").get("name") == name, got

    assert_ours(name)
    updated, verdict = run_op(
        run_async, recorder, "update_onguard_custom_script_by_name",
        tier="update", name=name,
        script_data={"description": "zzz-mcptest live-harness fixture (patched)"})
    assert verdict == PASS, f"update_onguard_custom_script_by_name -> {updated}"

    assert_ours(name)
    replaced, verdict = run_op(
        run_async, recorder, "replace_onguard_custom_script_by_name",
        tier="update", name=name, script_data=_script_body(name))
    assert verdict == PASS, f"replace_onguard_custom_script_by_name -> {replaced}"

    assert_ours(name)
    deleted, verdict = run_op(
        run_async, recorder, "delete_onguard_custom_script_by_name",
        tier="delete", name=name)
    assert verdict == PASS, f"delete_onguard_custom_script_by_name -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_onguard_custom_script_by_name",
        tier="negative", expect="absent", name=name)
    assert verdict == PASS, f"deleted custom script still readable: {gone}"


def test_onguard_custom_script_lifecycle_by_id(run_async, recorder, run_id,
                                               cleanup):
    """The numeric-id handle for the OnGuard custom-script family."""
    name = fixture_name(run_id, "cs2")
    cleanup.add(lambda: _delete_script_by_name(name))

    created, verdict = run_op(
        run_async, recorder, "create_onguard_custom_script", tier="create",
        expect="lenient", script_data=_script_body(name))
    no_crash(created, "create_onguard_custom_script")
    if verdict != PASS:
        pytest.skip(f"create_onguard_custom_script refused: {created}")

    sid = id_of(obj_of(created, "custom_script"))
    if sid is None:
        readback, _ = run_op(run_async, recorder,
                             "get_onguard_custom_script_by_name", tier="read",
                             name=name)
        sid = id_of(obj_of(readback, "custom_script"))
    if sid is None:
        record_blocked(recorder, "delete_onguard_custom_script_by_id",
                       "the appliance returned no numeric id for our own custom "
                       "script fixture, so no id can be proven to be ours")
        pytest.skip("no id available for the custom script we created")
    created_ids = [sid]

    got, verdict = run_op(run_async, recorder, "get_onguard_custom_script_by_id",
                          tier="read", onguard_custom_script_id=sid)
    assert verdict == PASS, f"get_onguard_custom_script_by_id({sid}) -> {got}"
    assert_ours(obj_of(got, "custom_script").get("name"))

    assert_created_id(sid, created_ids)
    updated, verdict = run_op(
        run_async, recorder, "update_onguard_custom_script_by_id", tier="update",
        onguard_custom_script_id=sid,
        script_data={"description": "zzz-mcptest live-harness fixture (patched)"})
    assert verdict == PASS, f"update_onguard_custom_script_by_id -> {updated}"

    assert_created_id(sid, created_ids)
    replaced, verdict = run_op(
        run_async, recorder, "replace_onguard_custom_script_by_id",
        tier="update", onguard_custom_script_id=sid, script_data=_script_body(name))
    assert verdict == PASS, f"replace_onguard_custom_script_by_id -> {replaced}"

    assert_created_id(sid, created_ids)
    assert_ours(obj_of(got, "custom_script").get("name"))
    deleted, verdict = run_op(
        run_async, recorder, "delete_onguard_custom_script_by_id", tier="delete",
        onguard_custom_script_id=sid)
    assert verdict == PASS, f"delete_onguard_custom_script_by_id -> {deleted}"

    gone, verdict = run_op(
        run_async, recorder, "get_onguard_custom_script_by_id", tier="negative",
        expect="absent", onguard_custom_script_id=sid)
    assert verdict == PASS, f"deleted custom script still readable by id: {gone}"


SCRIPT_NAME_OPS: List[Tuple[str, Dict[str, Any]]] = [
    ("get_onguard_custom_script_by_name", {}),
    ("delete_onguard_custom_script_by_name", {}),
    ("update_onguard_custom_script_by_name",
     {"script_data": {"description": "zzz-mcptest absent probe"}}),
    ("replace_onguard_custom_script_by_name", {"script_data": "@body"}),
]


@pytest.mark.parametrize("operation,extra", SCRIPT_NAME_OPS,
                         ids=[o[0] for o in SCRIPT_NAME_OPS])
def test_onguard_custom_script_by_name_absent(run_async, recorder, run_id,
                                              operation, extra):
    name = assert_ours(fixture_name(run_id, "cs", "absent"))
    params = {k: (_script_body(name) if v == "@body" else v)
              for k, v in extra.items()}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", name=name, **params)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}(absent {name!r}) -> {result}"


SCRIPT_ID_OPS: List[Tuple[str, Dict[str, Any]]] = [
    ("get_onguard_custom_script_by_id", {}),
    ("delete_onguard_custom_script_by_id", {}),
    ("update_onguard_custom_script_by_id",
     {"script_data": {"description": "zzz-mcptest absent probe"}}),
    ("replace_onguard_custom_script_by_id", {"script_data": "@body"}),
]


@pytest.mark.parametrize("operation,extra", SCRIPT_ID_OPS,
                         ids=[o[0] for o in SCRIPT_ID_OPS])
def test_onguard_custom_script_by_id_absent(run_async, recorder, run_id,
                                            operation, extra):
    name = assert_ours(fixture_name(run_id, "cs", "absent"))
    params = {k: (_script_body(name) if v == "@body" else v)
              for k, v in extra.items()}
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", onguard_custom_script_id=ABSENT_ID,
                             **params)
    no_crash(result, operation)
    assert verdict == PASS, \
        f"{operation}(onguard_custom_script_id={ABSENT_ID}) -> {result}"


def test_create_onguard_custom_script_missing_body_is_rejected(run_async,
                                                               recorder):
    result, verdict = run_op(
        run_async, recorder, "create_onguard_custom_script", tier="negative",
        expect="refusal",
        substrings=("missing required parameter", "script_data"))
    no_crash(result, "create_onguard_custom_script")
    assert verdict == PASS, f"create_onguard_custom_script() -> {result}"


# ==========================================================================
# 4. device-profiler/device-fingerprint — 3 operations
# ==========================================================================


def _delete_device_fingerprint(mac: str):
    assert_local_mac(mac)
    return harness.invoke("delete_device_fingerprint", _params={"mac_or_ip": mac})


def _await_fingerprint(run_async, mac: str, present: bool) -> bool:
    """Poll ``device-profiler/device-fingerprint/<mac>`` until it matches.

    Both directions of this resource are eventually consistent (see
    ``test_device_fingerprint_lifecycle``), so the same bounded poll serves the
    read-after-write and the read-after-delete. The probes are deliberately
    UNRECORDED — the artifact should carry one verdict per operation, not one
    per retry — and a crash in any probe still fails the test immediately.

    Returns True if the desired state was observed within the budget.
    """
    assert_local_mac(mac)
    for attempt in range(DFP_INGEST_ATTEMPTS):
        if attempt:
            time.sleep(DFP_INGEST_INTERVAL_S)
        probe = run_async(harness.invoke("get_device_fingerprint",
                                         _params={"mac_or_ip": mac}))
        no_crash(probe, "get_device_fingerprint")
        if (probe.get("success") is True) == present:
            return True
    return False


def test_device_fingerprint_lifecycle(run_async, recorder, run_id, cleanup):
    """POST -> GET -> DELETE a profiling record for a MAC that exists only
    because this run posted it.

    ``02:00:5e:*`` is locally administered, so the address cannot belong to any
    real NIC; the endpoint the POST creates is therefore ours by construction and
    ``assert_local_mac`` refuses any other MAC before the delete.
    """
    mac = local_mac(run_id, 1)
    assert_local_mac(mac)
    cleanup.add(lambda: _delete_device_fingerprint(mac))

    created, verdict = run_op(
        run_async, recorder, "create_device_fingerprint", tier="create",
        expect="lenient",
        fingerprint_data={"mac": mac, "ip": "192.0.2.51",
                          "hostname": fixture_name(run_id, "dfp1"),
                          "device": {"category": FP_CATEGORY,
                                     "family": FP_FAMILY,
                                     "name": fixture_name(run_id, "dfp1")}},
    )
    no_crash(created, "create_device_fingerprint")
    if verdict != PASS:
        record_limitation(recorder, "get_device_fingerprint",
                          "the POST that would have created our own endpoint was "
                          "refused, so there is no fixture MAC to read back")
        pytest.skip(f"create_device_fingerprint refused: {created}")

    # ``device-profiler/device-fingerprint`` is EVENTUALLY CONSISTENT IN BOTH
    # DIRECTIONS on 6.12.4, which is what makes this lifecycle unlike every other
    # one in these two modules:
    #
    #   * the POST answers "Successfully posted device fingerprint to profiler"
    #     as soon as the record is queued, so a GET fired in the same breath 404s;
    #   * the DELETE likewise reports success while the record is still readable
    #     — observed live, a GET immediately after a successful DELETE returned
    #     the full record with success: true.
    #
    # Neither is an MCP fault and neither may be asserted away, so each edge is
    # awaited on the same short bounded poll before the state is asserted.
    if not _await_fingerprint(run_async, mac, present=True):
        record_limitation(
            recorder, "get_device_fingerprint",
            f"the profiler did not surface our own POSTed endpoint within "
            f"{DFP_INGEST_BUDGET_S:.0f}s; device-profiler/device-fingerprint "
            f"ingestion is asynchronous on 6.12.4, so the resource can be "
            f"write-only from this API's point of view",
            {"mac_or_ip": mac})
        record_limitation(
            recorder, "delete_device_fingerprint",
            "the endpoint our POST created never became readable, so there was "
            "nothing for the DELETE to remove (async profiler ingestion)",
            {"mac_or_ip": mac})
        pytest.skip(f"device fingerprint for {mac} not ingested within "
                    f"{DFP_INGEST_BUDGET_S:.0f}s")

    got, verdict = run_op(run_async, recorder, "get_device_fingerprint",
                          tier="read", mac_or_ip=mac)
    assert verdict == PASS, f"get_device_fingerprint({mac}) -> {got}"
    assert obj_of(got, "device_fingerprint").get("hostname") == \
        fixture_name(run_id, "dfp1"), \
        f"read back an endpoint that is not the one we posted: {got}"

    assert_local_mac(mac)
    deleted, verdict = run_op(run_async, recorder, "delete_device_fingerprint",
                              tier="delete", mac_or_ip=mac)
    assert verdict == PASS, f"delete_device_fingerprint({mac}) -> {deleted}"

    # Removal propagates on the same asynchronous pipeline as ingestion.
    if not _await_fingerprint(run_async, mac, present=False):
        record_limitation(
            recorder, "get_device_fingerprint",
            f"the endpoint was still readable {DFP_INGEST_BUDGET_S:.0f}s after a "
            f"DELETE the appliance reported successful; removal propagates "
            f"asynchronously on 6.12.4, so read-after-delete is not immediately "
            f"consistent",
            {"mac_or_ip": mac})
        return

    gone, verdict = run_op(run_async, recorder, "get_device_fingerprint",
                           tier="negative", expect="absent", mac_or_ip=mac)
    assert verdict == PASS, f"deleted device fingerprint still readable: {gone}"


@pytest.mark.parametrize("operation",
                         ["get_device_fingerprint", "delete_device_fingerprint"])
def test_device_fingerprint_absent_mac(run_async, recorder, run_id, operation):
    """A locally-administered MAC nothing has ever posted."""
    mac = assert_local_mac(local_mac(run_id, 0x7f))
    result, verdict = run_op(run_async, recorder, operation, tier="negative",
                             expect="absent", mac_or_ip=mac)
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}({mac}) -> {result}"


# ==========================================================================
# 5. onguard-activity — 5 operations (4 reads + 2 guarded writes)
# ==========================================================================


def _assert_targeted_not_broadcast(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Refuse to dispatch anything that could reach a real OnGuard agent.

    ``is_broadcast: true`` (or an empty ``host_mac_list``) would fan the message
    out to every live agent on the appliance. Both are refused here, before
    dispatch, and every MAC in the list must be a locally-administered fixture
    address.
    """
    if payload.get("is_broadcast") is not False:
        raise AssertionError(
            "SAFETY GUARD: refusing to send an OnGuard agent message with "
            f"is_broadcast={payload.get('is_broadcast')!r}; the live harness may "
            "only send targeted messages to its own fake MACs."
        )
    macs = payload.get("host_mac_list")
    if not isinstance(macs, list) or not macs:
        raise AssertionError(
            "SAFETY GUARD: refusing to send an OnGuard agent message with an "
            f"empty/wildcard host_mac_list ({macs!r}) — that is a broadcast in "
            "everything but name."
        )
    for mac in macs:
        assert_local_mac(mac)
    return payload


def test_list_onguard_activity_optionals_omitted(run_async, recorder):
    result, verdict = run_op(run_async, recorder, "list_onguard_activity",
                             tier="read")
    no_crash(result, "list_onguard_activity")
    assert verdict == PASS, f"list_onguard_activity (no params) -> {result}"
    assert "onguard_activity" in result, f"unexpected shape: {sorted(result)}"


def test_list_onguard_activity_with_optionals(run_async, recorder):
    result, verdict = run_op(
        run_async, recorder, "list_onguard_activity", tier="read",
        sort="-id", offset=0, limit=5, calculate_count=True)
    no_crash(result, "list_onguard_activity")
    assert verdict == PASS, f"list_onguard_activity (optionals) -> {result}"


def test_get_onguard_activity_by_id(run_async, recorder):
    """Read one listed activity record by id — or, when the appliance has no
    OnGuard agents at all, prove the absent path answers cleanly."""
    listing, verdict = run_op(run_async, recorder, "list_onguard_activity",
                              tier="read", limit=5)
    assert verdict == PASS, f"list_onguard_activity -> {listing}"
    records = items_of(listing, "onguard_activity")
    ident = next((id_of(r) for r in records if id_of(r) is not None), None)
    if ident is None:
        note("get_onguard_activity_by_id: no OnGuard activity records exist on "
             "this appliance; validated on the absent-id path only")
        result, verdict = run_op(run_async, recorder,
                                 "get_onguard_activity_by_id", tier="negative",
                                 expect="absent", onguard_activity_id=ABSENT_ID)
        no_crash(result, "get_onguard_activity_by_id")
        assert verdict == PASS, \
            f"get_onguard_activity_by_id({ABSENT_ID}) -> {result}"
        return
    result, verdict = run_op(run_async, recorder, "get_onguard_activity_by_id",
                             tier="read", onguard_activity_id=ident)
    no_crash(result, "get_onguard_activity_by_id")
    assert verdict == PASS, f"get_onguard_activity_by_id({ident}) -> {result}"


def test_get_onguard_activity_by_host_mac_absent(run_async, recorder, run_id):
    """A locally-administered MAC no OnGuard agent can ever have reported.

    Read-only, so this is safe regardless of what the appliance knows about.
    """
    mac = assert_local_mac(local_mac(run_id, 2))
    result, verdict = run_op(run_async, recorder,
                             "get_onguard_activity_by_host_mac", tier="negative",
                             expect="absent", host_mac=mac)
    no_crash(result, "get_onguard_activity_by_host_mac")
    assert verdict == PASS, \
        f"get_onguard_activity_by_host_mac({mac}) -> {result}"


def _assert_send_answered_structurally(result: Dict[str, Any],
                                       operation: str) -> None:
    """The MCP contract for the two agent-messaging writes.

    Both routes ARE served on this appliance — at the unversioned ``/api`` root,
    which is the only root the client uses now. The earlier note here (HTTP 500
    carrying an HPE "Error 404 (Not Found)" HTML page) was an ``/api/v1`` mount
    artefact; see ``ClearPassClient._endpoint_url``.

    Re-probed by direct curl on 2026-07-30 with this exact payload shape:
    ``POST /api/onguard-activity/message`` answers a structured **422**
    ``"MAC Address not found"`` for a locally-administered MAC no agent can
    have, and ``POST /api/onguard-activity/notification`` answers **422**
    ``"Invalid action specified"``. Those are real appliance answers about a
    real environment limitation (this lab has never had an OnGuard agent), so
    the operations are still recorded as EXPECTED-LIMITATION rather than PASS —
    ``expect="unserved"`` simply records whichever of the two the appliance
    gives.

    What is still asserted unconditionally is the part this project owns: the
    MCP must have caught that response and returned its own structured envelope
    — ``success: False`` plus an error string, an ``error_type`` and the status
    code — instead of letting a traceback or the raw markup escape.
    """
    no_crash(result, operation)
    if result.get("success") is True:
        return
    assert is_structured_envelope(result), (
        f"{operation} did not answer with a structured MCP error envelope; the "
        f"appliance response leaked through raw -> {result}")
    assert result.get("status_code"), \
        f"{operation} error envelope carries no status_code -> {result}"


def test_send_onguard_activity_message_targeted_only(run_async, recorder, run_id):
    """Targeted (never broadcast) message to a MAC no agent can have.

    ``is_broadcast`` is pinned false and the guard refuses to dispatch
    otherwise. See ``_assert_send_answered_structurally`` for why the appliance's
    own answer is an EXPECTED-LIMITATION here while the MCP's error shape is not.
    """
    mac = local_mac(run_id, 3)
    payload = _assert_targeted_not_broadcast({
        "host_mac_list": [mac],
        "message": "zzz-mcptest live-harness probe (no agent should exist)",
        "is_broadcast": False,
    })
    result, verdict = run_op(run_async, recorder, "send_onguard_activity_message",
                             tier="negative", expect="unserved",
                             message_data=payload)
    _assert_send_answered_structurally(result, "send_onguard_activity_message")
    assert verdict in (PASS, LIMITATION), \
        f"send_onguard_activity_message must answer cleanly -> {result}"


def test_send_onguard_activity_notification_targeted_only(run_async, recorder,
                                                          run_id):
    """Same rails as the message probe, plus ``action``/``endpoint_status``."""
    mac = local_mac(run_id, 4)
    payload = _assert_targeted_not_broadcast({
        "host_mac_list": [mac],
        "message": "zzz-mcptest live-harness probe (no agent should exist)",
        "is_broadcast": False,
        "action": "Notify",
        "endpoint_status": "Unknown",
    })
    result, verdict = run_op(run_async, recorder,
                             "send_onguard_activity_notification",
                             tier="negative", expect="unserved",
                             message_data=payload)
    _assert_send_answered_structurally(result,
                                       "send_onguard_activity_notification")
    assert verdict in (PASS, LIMITATION), \
        f"send_onguard_activity_notification must answer cleanly -> {result}"


@pytest.mark.parametrize("operation", ["send_onguard_activity_message",
                                       "send_onguard_activity_notification"])
def test_onguard_activity_send_missing_body_is_rejected(run_async, recorder,
                                                        operation):
    """Required body omitted — refused by the gateway before any dispatch, so no
    accidental broadcast can be constructed from a default."""
    result, verdict = run_op(
        run_async, recorder, operation, tier="negative", expect="refusal",
        substrings=("missing required parameter", "message_data"))
    no_crash(result, operation)
    assert verdict == PASS, f"{operation}() -> {result}"


# ==========================================================================
# 6. End-of-module fixture sweep + drift check
# ==========================================================================


def test_fixture_sweep_part1(run_async, recorder, run_id):
    """Delete any surviving fixture object in this module's name-keyed families
    and assert nothing carrying the prefix is left behind.

    ``harness.sweep_fixtures`` only knows about guest users, enforcement profiles
    and roles, and the session inventory guard does not snapshot any
    endpoint-visibility family — so this module cleans up after itself.
    """
    swept: List[Dict[str, Any]] = []
    swept += sweep_named_family(
        run_async, "list_onguard_custom_scripts", "custom_scripts", "name",
        "delete_onguard_custom_script_by_name", "name",
        list_params={"limit": 1000})

    # Fingerprints are keyed by category/family/name, so they need the triple.
    listing = run_async(harness.invoke("list_fingerprints",
                                       _params={"limit": 1000}))
    for item in items_of(listing, "fingerprints"):
        name = item.get("name")
        if not isinstance(name, str) or not name.startswith("zzz-mcptest-"):
            continue
        assert_ours(name)
        removed = run_async(harness.invoke(
            "delete_fingerprint_by_name",
            _params={"category": item.get("category") or FP_CATEGORY,
                     "family": item.get("family") or FP_FAMILY, "name": name}))
        swept.append({"family": "fingerprint", "name": name,
                      "deleted": bool(removed.get("success"))})

    # Windows hotfixes: both rails must hold before anything is removed.
    hotfixes = run_async(harness.invoke("list_windows_hotfixes",
                                        _params={"limit": 1000}))
    for item in items_of(hotfixes, "windows_hotfixes"):
        kbid, title = item.get("kbid"), item.get("title")
        if not (isinstance(title, str) and title.startswith("zzz-mcptest-")):
            continue
        assert_ours(title)
        assert_fixture_kbid(kbid)
        removed = run_async(harness.invoke(
            "delete_windows_hotfix_by_kbid",
            _params={"kbid": kbid,
                     "operating_system": item.get("operating_system") or HOTFIX_OS}))
        swept.append({"family": "windows-hotfix", "kbid": kbid, "title": title,
                      "deleted": bool(removed.get("success"))})

    print(f"\n[endpoint_visibility-1] sweep removed {len(swept)} object(s)")
    for entry in swept:
        print(f"   - {entry}")

    leftovers = {
        "onguard_custom_scripts": surviving_fixtures(
            run_async, "list_onguard_custom_scripts", "custom_scripts", "name",
            {"limit": 1000}),
        "fingerprints": surviving_fixtures(
            run_async, "list_fingerprints", "fingerprints", "name",
            {"limit": 1000}),
        "windows_hotfixes": surviving_fixtures(
            run_async, "list_windows_hotfixes", "windows_hotfixes", "title",
            {"limit": 1000}),
    }
    remaining = {k: v for k, v in leftovers.items() if v}
    assert not remaining, f"fixture objects survived the sweep: {remaining}"


def test_summary(recorder):
    """Scope tally; declared last so it runs last within the module."""
    print(f"\n[endpoint_visibility-1] verdict counts: {recorder.counts}")
    for entry in NOTES:
        print(f"[endpoint_visibility-1] note: {entry}")
