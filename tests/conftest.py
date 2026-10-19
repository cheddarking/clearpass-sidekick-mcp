import sys
import os

import pytest

# Add the repository root to the Python path so that `src` is importable as a
# package (the source modules use relative imports like `from ..registry import
# operation`, which requires `src` to be a package, not the sys.path root).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture(autouse=True)
def offline_clearpass_env(monkeypatch):
    """
    Provide dummy ClearPass credentials for offline unit tests.

    These tests never make real network calls (the HTTP layer is mocked), but
    client construction validates/uses the server URL. Supplying a dummy
    https:// endpoint keeps the suite hermetic and independent of whatever the
    developer happens to have in their real environment.
    """
    monkeypatch.setenv("CLEARPASS_SERVER", "https://clearpass.test.invalid:443/api")
    monkeypatch.setenv("CLEARPASS_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("CLEARPASS_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv("CLEARPASS_VERIFY_SSL", "false")
    monkeypatch.delenv("CLEARPASS_API_TOKEN", raising=False)

    # Reset the process-wide ClearPass client singleton so a client built (or
    # mocked) by one test can never leak into the next.
    import src.app_config
    src.app_config._clearpass_client = None
    try:
        yield
    finally:
        src.app_config._clearpass_client = None
