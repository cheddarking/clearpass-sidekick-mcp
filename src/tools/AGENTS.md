# src/tools/

## Purpose

ClearPass operation definitions — 761 operations across 20 modules, exposed through **progressive disclosure** rather than 761 direct MCP tools.

- 757 domain operations are registered in the in-process operation registry (`src/registry.py`) via `@operation(domain="...")`. They are NOT direct MCP tools.
- `gateway.py` registers the 3 direct meta-tools that expose the whole catalogue: `list_operations`, `describe_operations`, `invoke_operation`.
- `server_utility.py` keeps its 4 direct `@mcp.tool()` registrations (not migrated, not in the registry).
- Default mode therefore boots with **7 direct tools** (3 gateway + 4 utility). Legacy mode (`CLEARPASS_MCP_LEGACY_TOOLS=true`) additionally registers all 757 domain operations as direct tools (764 total).

Operations are thin wrappers: validate inputs, call a `ClearPassClient` mixin method, return structured output.

## Ownership

One module per ClearPass API domain, mirroring `client_methods/`. Two exceptions: `gateway.py` owns the progressive-disclosure meta-tools, and `server_utility.py` owns cross-cutting health/utility tools with no corresponding mixin.

## Local Contracts

| File | Operations | Registration | Domain |
|---|---|---|---|
| `gateway.py` | 3 | direct `@mcp.tool()` | Catalogue discovery, description, invocation |
| `server_utility.py` | 4 | direct `@mcp.tool()` | Connection testing, credentials, health monitoring |
| `api_clients.py` | 5 | registry | API client CRUD |
| `network_devices.py` | 16 | registry | Network device management |
| `guest_users.py` | 5 | registry | Guest user provisioning |
| `guest_actions.py` | 5 | registry | Credential delivery, sponsor workflows |
| `guest_configuration.py` | 28 | registry | Portal customization, templates |
| `certificates.py` | 9 | registry | Certificate lifecycle |
| `audit_logs.py` | 12 | registry | System events, login audits |
| `session_control.py` | 14 | registry | Active sessions, CoA |
| `policy_elements.py` | 112 | registry | Policy engine (largest module) |
| `enforcement_profiles.py` | 8 | registry | Enforcement profiles |
| `global_server_config.py` | 58 | registry | Global server configuration |
| `local_server_config.py` | 15 | registry | Local server configuration |
| `__init__.py` | — | — | Package init |

- Every module must be imported in `src/main.py` to trigger registration
- New domain operations are added by decorating an async function with `@operation(domain="...")` — no `src/main.py` change is needed beyond the module already being imported
- Operations must not contain HTTP logic; delegate to `client_methods/` mixins
- Operations must use models from `src/models/` for input validation where schemas exist

## Work Guidance

- Operation docstrings become the description the LLM sees via `list_operations` / `describe_operations`; keep them accurate and concise
- Return dicts or Pydantic models, not raw `httpx` response objects
- Errors must be surfaced as structured error dicts, not raised exceptions, so the LLM can report them
- Any change to the operation count must be deliberate and mirrored in `tests/test_tool_count.py`, `CLAUDE.md`, `AGENTS.md`, and `README.md`

## Verification

```bash
python -m pytest tests/
python -m pytest tests/test_tool_count.py   # pins 757 registry operations, <=10 direct tools
```
