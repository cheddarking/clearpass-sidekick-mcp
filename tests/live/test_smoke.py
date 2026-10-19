"""Smoke test proving the live harness works. Deliberately tiny.

Four things only:
  1. one read operation with every optional parameter omitted,
  2. one full create -> read -> update -> delete lifecycle on a fixture object,
  3. one denylist assertion (a denylisted op raises instead of dispatching),
  4. one negative test (unknown operation returns a structured error).

The broad per-domain sweep is NOT here; Phase 4 agents add that.
"""

from __future__ import annotations

import secrets

import pytest

from . import harness
from .denylist import DENYLIST, DenylistedOperation
from .harness import PASS, assert_ours, classify, fixture_name

# Guest role present on this appliance. The create_guest_user default is
# "Guest", which does not exist on ClearPass 6.12.4 here (the built-in role is
# "[Guest]"). Environment fact, not a product bug.
GUEST_ROLE = "[Guest]"


# --------------------------------------------------------------------------
# 1. Read with all optional parameters omitted
# --------------------------------------------------------------------------


def test_read_with_all_optionals_omitted(run_async, recorder):
    """list_network_devices called with NO parameters at all.

    This is the omission path that the src/registry.py FieldInfo bug lived on,
    so it is the most valuable single assertion in the harness.
    """
    result = run_async(
        recorder.run("list_network_devices", tier="read")
    )
    verdict = classify(result, "list_network_devices")
    assert verdict == PASS, f"list_network_devices (no params) -> {result}"
    assert "devices" in result, f"unexpected payload shape: {sorted(result)}"
    assert "FieldInfo" not in str(result), "FieldInfo leaked into the response"


# --------------------------------------------------------------------------
# 2. Full lifecycle on a fixture object (guest user — safest family)
# --------------------------------------------------------------------------


def test_guest_user_lifecycle(run_async, recorder, run_id, cleanup):
    """create -> read -> update -> delete, all inside the fixture namespace.

    Optional parameters are omitted on every call except the ones under test.
    """
    name = fixture_name(run_id, 1)
    password = f"Zz!{secrets.token_urlsafe(12)}"

    # The generic sweep is the backstop; this registers an explicit per-test
    # cleanup as well so nothing survives even a mid-test explosion.
    cleanup.add(lambda: harness.sweep_fixtures())

    # --- create -----------------------------------------------------------
    # role_name is passed because this appliance's guest role is "[Guest]",
    # not the operation default "Guest" (environment fact, not a bug).
    # Everything else optional is omitted.
    created = run_async(recorder.run(
        "create_guest_user", tier="create",
        username=name, password=password, role_name=GUEST_ROLE,
    ))
    assert classify(created, "create_guest_user") == PASS, \
        f"create_guest_user -> {created}"

    user = created.get("user") or {}
    uid = user.get("id")
    assert uid is not None, f"create_guest_user returned no id: {created}"

    # --- read back --------------------------------------------------------
    fetched = run_async(recorder.run(
        "get_guest_user", tier="read", user_id=uid
    ))
    assert classify(fetched, "get_guest_user") == PASS, \
        f"get_guest_user -> {fetched}"
    # Re-verify the id really belongs to our fixture before any write.
    assert fetched["user"]["username"] == name, \
        f"id {uid} does not belong to {name}: {fetched}"

    # --- update (guard immediately before the write) ----------------------
    assert_ours(fetched["user"]["username"])
    updated = run_async(recorder.run(
        "update_guest_user", tier="update", user_id=uid, enabled=False
    ))
    assert classify(updated, "update_guest_user") == PASS, \
        f"update_guest_user -> {updated}"

    # --- delete (guard immediately before the delete) ---------------------
    assert_ours(name)
    deleted = run_async(recorder.run(
        "delete_guest_user", tier="delete", user_id=uid, confirm=True
    ))
    assert classify(deleted, "delete_guest_user") == PASS, \
        f"delete_guest_user -> {deleted}"

    # --- confirm it is really gone (negative read) ------------------------
    gone = run_async(recorder.run(
        "get_guest_user", tier="read", expect_absent=True, user_id=uid
    ))
    assert gone.get("success") is not True, \
        f"guest user {name} still present after delete: {gone}"
    assert classify(gone, "get_guest_user", expect_absent=True) == PASS, \
        f"absent-object read should be a structured 404, got {gone}"


def test_safety_guard_rejects_foreign_names():
    """assert_ours is the difference between a safe sweep and a wrecked box."""
    assert assert_ours(fixture_name("deadbeef", 1))
    for foreign in ("Guest", "corp-switch-01", "", None, "mcptest-1"):
        with pytest.raises(AssertionError):
            assert_ours(foreign)


# --------------------------------------------------------------------------
# 3. Denylist
# --------------------------------------------------------------------------


def test_denylisted_operation_is_not_dispatched(run_async, recorder):
    """delete_api_client must raise before anything reaches the appliance."""
    with pytest.raises(DenylistedOperation) as excinfo:
        run_async(harness.invoke("delete_api_client"))
    assert "delete_api_client" in str(excinfo.value)
    assert DENYLIST["delete_api_client"] in str(excinfo.value)
    recorder.record("delete_api_client", "api_clients", "denylist",
                    harness.EXPECTED_SKIP, {},
                    f"DENYLISTED: {DENYLIST['delete_api_client']}", 0.0)


def test_denylist_names_all_exist_in_registry():
    """A typo in the denylist would silently disarm a rail."""
    import src.main  # noqa: F401
    from src.registry import registry

    missing = [n for n in DENYLIST if registry.get(n) is None]
    assert not missing, f"denylist references unknown operations: {missing}"


# --------------------------------------------------------------------------
# 4. Negative: unknown operation name
# --------------------------------------------------------------------------


def test_unknown_operation_returns_structured_error(run_async, recorder):
    result = run_async(recorder.run(
        "no_such_operation_zzz", domain="n/a", tier="negative"
    ))
    assert result.get("success") is False
    assert "Unknown operation" in str(result.get("error"))
    assert "Traceback" not in str(result)
    assert classify(result, "no_such_operation_zzz") == harness.FAIL, \
        "an unknown op is correctly a FAIL verdict for the sweep"
