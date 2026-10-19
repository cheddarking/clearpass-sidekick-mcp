"""Verify progressive-disclosure end state: all domain operations live in the
registry, and only a small number of tools are registered directly on the MCP
server in default mode.

Count reconciliation:
- Pre-expansion baseline: 287 registry operations. That number came from the
  progressive-disclosure migration -- 286 tools migrated out of the 12
  migratable domain modules, + 1 when ``list_cluster_servers`` was added to the
  ``local_server_config`` domain on 2026-07-20 to close a catalogue gap (four
  operations in that domain require a ``server_uuid``/``uuid``, but no registry
  operation listed cluster servers).
- 2026-07-30 full-SDK-coverage expansion: +475 operations, bringing the registry
  to 762. This closed the gap to **pyclearpass 1.0.8 parity** -- every endpoint
  the reference SDK covers is now reachable through the gateway. The expansion
  both grew existing domains (e.g. ``certificates``, ``global_server_config``,
  ``audit_logs``, ``network_devices``, ``session_control``) and added seven new
  domain modules: ``identities``, ``endpoint_visibility``, ``integrations``,
  ``certificate_authority``, ``tools_utilities``, ``api_operations`` and
  ``enforcement_profiles_dur``, each backed by a matching mixin composed into
  ``ClearPassClient``.
- ``server_utility.py`` keeps its ``@mcp.tool()`` registrations by design (it is
  NOT migrated), so it stays a set of direct tools and is NOT in the registry.
- 2026-07-31 dead-endpoint removal: -5 operations from ``global_server_config``
  (86 -> 81). ``get_admin_password_policy``, ``update_admin_password_policy``,
  ``get_local_user_password_policy``, ``update_local_user_password_policy`` and
  ``get_application_license_summary`` targeted the hyphenated resource paths
  ``/admin-user-password-policy``, ``/local-user-password-policy`` and
  ``/application-license-summary``, all of which return HTTP 404 on ClearPass
  6.12.4 -- they could never succeed. The real resources
  (``/admin-user/password-policy``, ``/local-user/password-policy``,
  ``/application-license/summary``) already have working operations:
  ``get|update|replace_admin_user_password_policy``,
  ``get|update|replace_local_user_password_policy_settings`` and
  ``get_application_license_summary_detail``. pyclearpass parity is unaffected:
  the reference SDK's endpoints all remain reachable; only the duplicate,
  wrongly-pathed names are gone.
- Therefore the registry holds exactly 757 operations. The direct-tool surface is
  unchanged: the gateway contributes 3 direct meta-tools and
  ``server_utility`` 4, for 7 direct tools in default mode.
"""

import asyncio

# Number of domain operations in the registry.
# 287 pre-expansion + 475 added by the 2026-07-30 full-SDK-coverage expansion
# (pyclearpass 1.0.8 parity) == 762, - 5 dead hyphen-path operations removed on
# 2026-07-31 == 757. Any change to this number must be deliberate -- see the
# module docstring.
EXPECTED_OPERATIONS = 757

# Direct MCP tools in default (non-legacy) mode: 3 gateway meta-tools + 4
# server_utility tools == 7 (<= 10).
MAX_DIRECT_TOOLS = 10


def _get_tool_names(mcp):
    """Enumerate directly-registered tool names (FastMCP 2.5.1: async get_tools())."""
    return set(asyncio.run(mcp.get_tools()))


def test_all_domain_operations_registered_and_tool_count_small():
    from src import main  # noqa: F401  (imports all tool modules, registers ops)
    from src.registry import registry
    from src.app_config import mcp

    assert len(registry.all()) == EXPECTED_OPERATIONS, (
        f"Expected {EXPECTED_OPERATIONS} registered operations, "
        f"got {len(registry.all())}"
    )

    names = _get_tool_names(mcp)
    assert {"list_operations", "describe_operations", "invoke_operation"} <= names, (
        f"Gateway meta-tools missing from direct registration: {sorted(names)}"
    )
    assert len(names) <= MAX_DIRECT_TOOLS, (
        f"Expected <={MAX_DIRECT_TOOLS} direct tools, got {len(names)}: {sorted(names)}"
    )
