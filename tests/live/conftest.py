"""Opt-in live-validation harness wiring.

Without ``--live`` every test under ``tests/live/`` is skipped at collection
time and no network call, credential read, or ``src`` import happens. The
offline suite is unaffected.

Run offline (default):   pytest tests/
Run live:                set -a; . /path/to/.env; set +a; pytest tests/live --live
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from . import harness
from .denylist import DENYLIST
from .harness import ARTIFACT_DIR, RunRecorder, env_ready, new_run_id


# --------------------------------------------------------------------------
# CLI flag
# --------------------------------------------------------------------------


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Run the live-validation suite against the real ClearPass appliance. "
             "Requires credentials in the environment (source the operator .env).",
    )


def pytest_collection_modifyitems(config: pytest.Config, items) -> None:
    """Skip everything in tests/live/ unless --live was passed."""
    if config.getoption("--live"):
        return
    here = Path(__file__).parent.resolve()
    skip = pytest.mark.skip(reason="live appliance test; pass --live to enable")
    for item in items:
        try:
            in_live = Path(str(item.fspath)).resolve().is_relative_to(here)
        except (AttributeError, ValueError):
            in_live = str(here) in str(item.fspath)
        if in_live:
            item.add_marker(skip)


# --------------------------------------------------------------------------
# Neutralise the offline autouse fixture from tests/conftest.py
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def offline_clearpass_env():
    """Override the parent conftest's autouse dummy-credential fixture.

    ``tests/conftest.py`` monkeypatches CLEARPASS_* to placeholder values for
    the hermetic offline suite. Live tests must keep the operator's real
    environment, so this override does nothing but reset the client singleton
    between tests.
    """
    yield


# --------------------------------------------------------------------------
# Session scaffolding
# --------------------------------------------------------------------------


@pytest.fixture(scope="session")
def live_enabled(request: pytest.FixtureRequest) -> bool:
    if not request.config.getoption("--live"):
        pytest.skip("live appliance test; pass --live to enable")
    ok, why = env_ready()
    if not ok:
        pytest.fail(f"--live was requested but the environment is not ready: {why}")
    return True


@pytest.fixture(scope="session")
def run_id(live_enabled: bool) -> str:
    rid = new_run_id()
    print(f"\n[live-harness] run id: {rid}  (fixture prefix "
          f"{harness.FIXTURE_PREFIX}{rid}-*)")
    return rid


@pytest.fixture(scope="session")
def live_loop(live_enabled: bool):
    """One event loop for the whole session so the ClearPass client singleton
    (and its auth token) is reused rather than re-authenticated per test."""
    loop = asyncio.new_event_loop()
    try:
        yield loop
    finally:
        loop.close()


@pytest.fixture(scope="session")
def run_async(live_loop):
    """Run a coroutine on the session event loop."""
    def _run(coro):
        return live_loop.run_until_complete(coro)
    return _run


@pytest.fixture(scope="session")
def recorder(run_id: str) -> RunRecorder:
    rec = RunRecorder(run_id)
    print(f"[live-harness] results -> {rec.path}")
    return rec


@pytest.fixture(scope="session")
def denylist() -> Dict[str, str]:
    return DENYLIST


@pytest.fixture(scope="session", autouse=True)
def inventory_guard(request: pytest.FixtureRequest):
    """Snapshot the appliance before and after the session, diff, and fail the
    run if anything outside our fixture prefix was added or removed.

    Also runs the session-end fixture sweep before the 'after' snapshot so that
    surviving fixtures do not show up as drift.
    """
    if not request.config.getoption("--live"):
        yield
        return

    run_async = request.getfixturevalue("run_async")
    rid = request.getfixturevalue("run_id")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = ARTIFACT_DIR / f"inventory-{rid}.json"

    before = run_async(harness.snapshot_inventory())
    print(f"[live-harness] inventory before: "
          f"{ {k: len(v.get('items', [])) for k, v in before.items()} }")

    payload: Dict[str, Any] = {"run_id": rid, "before": before}
    try:
        yield
    finally:
        swept = run_async(harness.sweep_fixtures())
        if swept:
            print(f"[live-harness] session sweep removed {len(swept)} fixture "
                  f"object(s):")
            for entry in swept:
                print(f"   - {entry}")
        else:
            print("[live-harness] session sweep: nothing left to remove")

        after = run_async(harness.snapshot_inventory())
        diff = harness.diff_inventory(before, after)
        payload.update({"after": after, "swept": swept, "diff": diff})
        artifact.write_text(json.dumps(payload, indent=2, default=str),
                            encoding="utf-8")
        print(f"[live-harness] inventory artifact -> {artifact}")
        print(f"[live-harness] inventory diff clean: {diff['clean']}")

        if not diff["clean"]:
            pytest.fail(
                "LIVE INVENTORY DRIFT: objects outside the fixture prefix were "
                "added or removed during this run:\n"
                + json.dumps(diff["foreign_drift"], indent=2, default=str)
                + f"\nFull detail: {artifact}",
                pytrace=False,
            )


@pytest.fixture
def cleanup(run_async):
    """Per-test cleanup registry.

    Usage::

        cleanup.add(lambda: harness.invoke("delete_guest_user",
                                           user_id=name, confirm=True))

    Every registered coroutine factory runs in a ``finally`` at test teardown,
    even if the test body raised.
    """
    class _Cleanup:
        def __init__(self) -> None:
            self._actions = []

        def add(self, factory) -> None:
            self._actions.append(factory)

        def _drain(self) -> None:
            while self._actions:
                factory = self._actions.pop()
                try:
                    run_async(factory())
                except Exception as exc:  # never mask the real test failure
                    print(f"[live-harness] cleanup action failed: "
                          f"{type(exc).__name__}: {exc}")

    c = _Cleanup()
    try:
        yield c
    finally:
        c._drain()
