# src/

## Purpose

Core Python library for ClearPass Sidekick MCP server. Contains the FastMCP server entry point, singleton API client configuration, credential management, audit logging, custom exceptions, utility helpers, and stdio-safe logging configuration.

## Ownership

All Python source under `src/` except subfolders delegated to child AGENTS.md files.

## Local Contracts

- **Entry point**: `main.py` — initializes stdio-safe stderr logging (`configure_mcp_logging()`), FastMCP server, and imports all tool modules; domain modules register their operations into the registry, `gateway.py`/`server_utility.py` register direct `@mcp.tool()` tools
- **Logging configuration**: `logging_config.py` — stdio-safe stderr logging (`configure_mcp_logging()`) and `builtins.print` monkey-patching (`stdio_safe_print`) ensuring `sys.stdout` is reserved exclusively for MCP JSON-RPC message framing
- **Operation registry**: `registry.py` — owns the `@operation(...)` decorator, the catalogue the gateway meta-tools read, and `register_legacy_tools(mcp)` for `CLEARPASS_MCP_LEGACY_TOOLS=true`
- **Global config**: `app_config.py` — owns the `mcp` singleton instance and `get_clearpass_client()` factory; no other file creates these
- **API client**: `clearpass_client.py` — composes all mixins from `client_methods/`; OAuth2 token refresh lives here (lines 99–130)
- **Credentials**: `credentials.py` — loads from environment variables only (`CLEARPASS_SERVER` plus either `CLEARPASS_CLIENT_ID`/`CLEARPASS_CLIENT_SECRET` or `CLEARPASS_API_TOKEN`); no credentials file, no constructor arguments; sanitizes secrets before logging
- **Audit logger**: `audit_logger.py` — every API operation must be logged with metadata, execution time, and error state
- **Exceptions**: `exceptions.py` — all custom exception types; do not raise generic exceptions from library code
- **Utils**: `utils.py` — shared helpers and 3-part error formatting helpers (`format_api_error`, `format_validation_error`, `format_unexpected_error`, `format_error`) returning standardized error schemas (`success: False`, `error`, `error_type`, `message`, `suggestion`, `status_code`, `response_data`) with actionable recovery guidance for LLMs

## Work Guidance

- Use relative imports within the `src` package
- New API domains follow the pattern: add mixin to `client_methods/`, add `@operation(domain="...")` functions to `tools/`, import tool module in `main.py` (lines 43–56), add models to `models/` if needed
- Do not add OAuth2 logic, credential loading, or audit wiring outside their designated files
- Keep `app_config.py` as the single source of truth for the global `mcp` and client instances
- Ensure stdio transport safety: never write directly to `sys.stdout` or let third-party logs leak to stdout; all log output must be routed to `sys.stderr` via `logging_config.py`
- Format tool errors using the 3-part error formatters in `utils.py` to ensure structured error responses with actionable recovery guidance

## Verification

```bash
python -m pytest tests/
```

## Child DOX Index

- `client_methods/AGENTS.md` — Mixin classes implementing ClearPass REST API calls per domain
- `models/AGENTS.md` — Pydantic schemas for all API request/response entities
- `tools/AGENTS.md` — 761 ClearPass operations (757 registry operations + 4 direct `server_utility` tools) that wrap client method mixins, exposed via the 3 gateway meta-tools
