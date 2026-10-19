# CLAUDE.md

Public repository: https://github.com/cheddarking/clearpass-sidekick-mcp. MIT licensed. Keep local MCP client configs, credentials, generated indexes, and virtual environments untracked.

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ClearPass Sidekick** is a Model Context Protocol (MCP) server that bridges natural language AI assistants (like Claude) with **Aruba ClearPass Policy Manager**, enabling conversational control of enterprise network access control infrastructure.

### What It Does

Transforms complex network administration tasks into simple natural language commands:
- "Create a guest account for visitor01 valid for 24 hours"
- "Show me all network devices with Change of Authorization enabled"
- "Generate a certificate for switch-01"
- "Create a contractor role with VLAN 100 access"

### Progressive Disclosure (Gateway) Architecture

The server supports **761 ClearPass operations**, but does NOT register all 761 as
direct MCP tools — that would flood the LLM context window with 761 tool schemas.
Instead:

- **757 domain operations** are registered in an in-process **operation registry**
  (`src/registry.py`) via `@operation(domain="...")` decorators in each
  `src/tools/{domain}.py` module. They are NOT direct MCP tools.
- **3 gateway meta-tools** in `src/tools/gateway.py` expose the whole catalog:
  `list_operations` (discover), `describe_operations` (get parameter schemas),
  `invoke_operation` (execute by name).
- **4 `server_utility` tools** stay direct `@mcp.tool()` registrations (not migrated).
- **Default mode = 7 direct tools** (3 gateway + 4 utility).
- **Legacy mode** (`CLEARPASS_MCP_LEGACY_TOOLS=true`) calls
  `register_legacy_tools(mcp)` to additionally register all 757 domain operations
  as direct tools (764 total) and logs `Legacy mode: registered 757 direct tools`.

Adding a new operation: write the async function in the appropriate
`src/tools/{domain}.py` module and decorate it with `@operation(domain="...")` so
it lands in the registry and is reachable through the gateway (no `src/main.py`
change needed beyond the module already being imported).

### Three-Layer Architecture

```
┌─────────────────────────┐
│  User / LLM (Claude)    │  Natural language commands
└───────────┬─────────────┘
            │
            ↓ Structured tool calls (stdio/SSE)
┌─────────────────────────┐
│  MCP Client             │  Claude Desktop, etc.
│  (e.g., Claude Desktop) │
└───────────┬─────────────┘
            │
            ↓ Model Context Protocol
┌─────────────────────────┐
│  MCP Server             │  ← THIS PROJECT
│  (Python/FastMCP)       │  ClearPass Sidekick
└───────────┬─────────────┘
            │
            ↓ REST API calls (HTTPS)
┌─────────────────────────┐
│  Aruba ClearPass        │  Network Access Control
│  Policy Manager         │  Enterprise Infrastructure
└─────────────────────────┘
```

### Key Technologies

- **FastMCP**: Framework for building Model Context Protocol servers
- **httpx**: Async HTTP client for ClearPass API communication
- **Pydantic**: Data validation and type-safe models
- **OAuth2**: Secure client credentials authentication
- **pyclearpass**: Reference SDK for ClearPass API patterns

## Project Structure

```
clearpass-sidekick-claude-code/
├── src/                              # Source code
│   ├── main.py                       # MCP server entry point
│   ├── logging_config.py             # Stdio-safe stderr logging & print patching
│   ├── app_config.py                 # Global configuration & singleton instances
│   ├── clearpass_client.py           # Main API client (composes all mixins)
│   ├── credentials.py                # Secure credential management
│   ├── audit_logger.py               # Operation logging & audit trails
│   ├── exceptions.py                 # Custom exception types
│   ├── utils.py                      # Utility functions
│   │
│   ├── client_methods/               # API method implementations (mixins)
│   │   ├── api_clients.py            # API client CRUD operations
│   │   ├── network_devices.py        # Network device management
│   │   ├── guest_users.py            # Guest user provisioning
│   │   ├── guest_actions.py          # Guest credential delivery & sponsor workflows
│   │   ├── guest_configuration.py    # Portal customization & template management
│   │   ├── certificates.py           # Certificate operations
│   │   ├── audit_logs.py             # Audit log retrieval
│   │   ├── session_control.py        # Active session management
│   │   ├── policy_elements.py        # Policy engine (largest, 192 methods)
│   │   ├── enforcement_profiles.py   # Enforcement profile management
│   │   ├── global_server_config.py   # Global configuration
│   │   └── local_server_config.py    # Local server settings
│   │
│   ├── registry.py                   # Operation registry + @operation decorator + legacy mode
│   ├── tools/                        # 761 operations (757 registry ops + 4 direct tools)
│   │   ├── gateway.py                # 3 direct gateway meta-tools (list/describe/invoke)
│   │   ├── server_utility.py         # 4 direct @mcp.tool tools
│   │   ├── enforcement_profiles_dur.py  # 142 operations (largest module)
│   │   ├── policy_elements.py        # 112 operations
│   │   ├── endpoint_visibility.py    # 94 operations
│   │   ├── global_server_config.py   # 81 operations
│   │   ├── integrations.py           # 80 operations
│   │   ├── identities.py             # 58 operations
│   │   ├── certificates.py           # 29 operations
│   │   ├── guest_configuration.py    # 28 operations
│   │   ├── audit_logs.py             # 25 operations
│   │   ├── network_devices.py        # 21 operations
│   │   ├── session_control.py        # 20 operations
│   │   ├── certificate_authority.py  # 19 operations
│   │   ├── local_server_config.py    # 15 operations
│   │   ├── enforcement_profiles.py   # 8 operations
│   │   ├── tools_utilities.py        # 6 operations
│   │   ├── api_clients.py            # 5 operations
│   │   ├── guest_users.py            # 5 operations
│   │   ├── guest_actions.py          # 5 operations
│   │   └── api_operations.py         # 4 operations
│   │
│   └── models/                       # Pydantic data models
│       ├── api_client.py             # API client schemas
│       ├── network_device.py         # Network device schemas
│       ├── guest_user.py             # Guest user schemas
│       ├── certificates.py           # Certificate schemas
│       ├── audit.py                  # Audit log schemas
│       ├── policy_elements.py        # Policy element schemas
│       ├── enforcement_profiles.py   # Profile schemas
│       ├── global_server_config.py   # Global config schemas
│       └── local_server_config.py    # Local config schemas
│
├── docs/                             # Documentation
│   ├── live_testing_plan_phase1.md   # Phase 1 testing procedures
│   └── live_testing_plan_phase2.md   # Phase 2 testing procedures
│
├── tests/                            # Test files
│   ├── conftest.py                   # Pytest configuration
│   └── test_*.py                     # Test modules
│
├── Dockerfile                        # Docker containerization
├── requirements.txt                  # Python dependencies
├── CLAUDE.md                         # This file - development guidance
└── README.md                         # User-facing documentation
```

### Code Flow

1. **Entry Point** (`src/main.py`): Initializes stdio-safe stderr logging (`configure_mcp_logging()`), FastMCP server, and imports all tool modules
2. **Configuration** (`src/app_config.py`): Sets up global `mcp` instance and `get_clearpass_client()` singleton
3. **Operation Registration**: Importing domain tool modules registers their operations in the registry (`src/registry.py`) via `@operation(...)`; `gateway.py` and `server_utility.py` register their direct `@mcp.tool()` tools with the global `mcp` instance
4. **API Methods**: Each mixin in `src/client_methods/` provides specialized methods
5. **MCP Tools**: Each tool in `src/tools/` wraps mixin methods for MCP protocol
6. **Models**: Pydantic schemas validate all API inputs/outputs

## Development Commands

### Running the MCP Server
```bash
python src/main.py
```

### Running Tests
```bash
python -m pytest tests/
```

### Code Quality
```bash
# Format code
black src/

# Lint code
flake8 src/

# Type checking
mypy src/
```

### Dependencies
```bash
# Install dependencies
pip install -r requirements.txt

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
.venv\Scripts\activate     # On Windows
```

## Architecture Overview

### Core Components

**FastMCP Server**: Built using FastMCP framework for Model Context Protocol communication
- Entry point: `src/main.py`
- Configuration: `src/app_config.py` (singleton pattern with global MCP instance)
- 761 ClearPass operations across 20 specialized modules, exposed via progressive disclosure (7 direct tools in default mode; see "Progressive Disclosure (Gateway) Architecture" above)

**ClearPass Client**: Modular API client using mixin pattern
- Main client: `src/clearpass_client.py`
- Mixins: `src/client_methods/` (API method implementations)
- Models: `src/models/` (Pydantic data models)
- Tools: `src/tools/` (MCP tool definitions)

**Authentication**: OAuth2 client credentials flow with fallback to API tokens
- Credentials management: `src/credentials.py`
- Environment variables only — `CredentialsManager()` takes no arguments and reads `CLEARPASS_SERVER` plus either `CLEARPASS_CLIENT_ID` + `CLEARPASS_CLIENT_SECRET` (OAuth2 client credentials) or `CLEARPASS_API_TOKEN` (fallback), with optional `CLEARPASS_VERIFY_SSL`. There is no credentials file; file-based loading was removed during the refactor
- Automatic token refresh and error handling

### Modular Design Pattern

The codebase uses a sophisticated mixin pattern to organize ClearPass API functionality:

```
ClearPassClient (src/clearpass_client.py)
├── ApiClientMethodsMixin (src/client_methods/api_clients.py)
├── NetworkDeviceMethodsMixin (src/client_methods/network_devices.py)
├── GuestUserMethodsMixin (src/client_methods/guest_users.py)
├── GuestActionMethodsMixin (src/client_methods/guest_actions.py)
├── GuestConfigurationMethodsMixin (src/client_methods/guest_configuration.py)
├── CertificateMethodsMixin (src/client_methods/certificates.py)
├── AuditLogsMethodsMixin (src/client_methods/audit_logs.py)
├── LocalServerConfigMethodsMixin (src/client_methods/local_server_config.py)
├── GlobalServerConfigMethodsMixin (src/client_methods/global_server_config.py)
├── SessionControlMethodsMixin (src/client_methods/session_control.py)
├── PolicyElementsMethodsMixin (src/client_methods/policy_elements.py)
└── EnforcementProfileMethodsMixin (src/client_methods/enforcement_profiles.py)
```

Each mixin provides specialized API methods that are exposed as MCP tools in corresponding `src/tools/` modules.

### Operation Organization

**20 Specialized Modules** (761 total = 757 registry operations + 4 direct `server_utility` tools):

Nineteen domain modules register their functions in the operation registry with
`@operation(domain="...")` (from `src/registry.py`) — they are NOT direct MCP
tools and are reached through the 3 gateway meta-tools in `src/tools/gateway.py`.
Only `server_utility.py` (4 tools) and `gateway.py` (3 meta-tools) use direct
`@mcp.tool()` registration.

#### Core Management (84 operations)
- **api_clients.py** (5 operations): API client CRUD operations, OAuth client management
- **network_devices.py** (21 operations): Network device management, NAD configuration with RADIUS/TACACS+ support, by-name variants
- **guest_users.py** (5 operations): Guest user provisioning, temporary access with sponsor workflows
- **guest_actions.py** (5 operations): Digital passes, receipt generation, SMS/email delivery, sponsor workflows
- **guest_configuration.py** (28 operations): Pass/print templates, web login pages, authentication & manager settings
- **certificates.py** (29 operations): Complete certificate lifecycle - CSR generation, trust lists (incl. delete), revocation lists, client/service/server certificates, self-signed certs
- **audit_logs.py** (25 operations): System events, login audits, insight alerts & reports (by-id and by-name, enable/disable/mute), insight endpoint lookups (ip/mac/range), API operation tracking
- **server_utility.py** (4 direct tools): Connection testing, configuration validation, health monitoring — keeps `@mcp.tool()`, not in the registry

#### Advanced Server Configuration (73 operations)
- **global_server_config.py** (81 operations): Admin users, privileges, licenses, attributes, data filters, operator profiles, SNMP, messaging, backup servers, policy manager zones — with by-name/by-user-id variants, password policies, portal, db-sync
- **local_server_config.py** (15 operations): Access control, Active Directory integration, cluster management (including `list_cluster_servers`, which yields the `server_uuid` the other cluster operations require), version info

#### Session & Network Control (14 operations)
- **session_control.py** (20 operations): Active session monitoring, disconnect operations (composed + native session-action routes), reauthorization, Change of Authorization (CoA), active-session by MAC

#### Policy Engine Components (120 operations) - Largest Implementation
- **policy_elements.py** (112 operations):
  - Core Components: Roles, role mappings, enforcement policies, configuration services
  - Authentication: Methods (EAP, certificates), sources (AD/LDAP integration)
  - Network Infrastructure: Device groups, enhanced device configuration (SNMP, RadSec, CLI)
  - Advanced Policies: Posture policies, RADIUS dynamic authorization templates
  - Dictionaries: Application and RADIUS custom attribute definitions
  - Specialized: Proxy targets (RADIUS proxy), TACACS+ service dictionaries
- **enforcement_profiles.py** (8 operations): Basic profile management with template-based creation for common networking scenarios (corporate, guest, contractor, IoT, executive)

#### Full-SDK-Coverage Expansion (2026-07-30, 475 operations — pyclearpass 1.0.8 parity)
- **identities.py** (58 operations): Endpoints (by id + MAC), devices, local users, static host lists, external accounts, deny-listed users, guest/api-client replace
- **endpoint_visibility.py** (94 operations): OnGuard (settings, global settings, activity, custom scripts, policy-manager zones), agentless OnGuard (settings, subnet mappings), device profiler & fingerprints, network scans, profiler subnet mappings, Windows hotfixes
- **integrations.py** (80 operations): Endpoint context servers (+ trigger-poll), context server actions, event sources, extensions (store, instances, lifecycle), ingress event dictionaries, syslog targets & export filters, Device Insight
- **enforcement_profiles_dur.py** (142 operations): The complete Downloadable User Role sub-API — 14 resource families (ACLs, classes, policies, QoS/policer/VoIP profiles, NAT pools, net destinations/services, time ranges, captive portal) x id/name/enable-disable variants, plus base-profile PUT replace
- **certificate_authority.py** (19 operations): Onboard CA — certificate list/get/chain, issue/sign/revoke/reject, import/export, onboard devices and users
- **tools_utilities.py** (6 operations): Random password/MPSK generators, email/SMS send
- **api_operations.py** (4 operations): OAuth introspection (me, privileges) and token endpoint parity

> Counts verified against source: an AST count of `@operation` decorators under `src/tools/` → 757 registry operations; `grep -c "@mcp.tool" src/tools/server_utility.py` → 4 direct tools (761 total). Booting the server confirms 7 direct tools in default mode and 764 in legacy mode. `tests/test_tool_count.py` pins these numbers.

### Key Patterns

**Singleton Pattern**: Global ClearPass client instance managed through `get_clearpass_client()` in `app_config.py`

**Stdio-Safe Stderr Logging & Print Redirection**: In accordance with the MCP stdio transport specification, `sys.stdout` is strictly reserved for JSON-RPC message framing. `src/logging_config.py` configures the root logger, `logging.basicConfig()`, and third-party loggers (`httpx`, `urllib3`, `asyncio`, `fastmcp`, `mcp`, `uvicorn`) to output exclusively to `sys.stderr` via `_StderrProxy`. Additionally, `builtins.print` is monkey-patched (`stdio_safe_print`) to safely intercept unredirected or `sys.stdout`-bound calls and reroute them to `sys.stderr`.

**Helpful Error Schemas & Recovery**: Tool errors return a standardized 3-part schema (`success: False`, `error`, `error_type`, `message`, `suggestion`, `status_code`, `response_data`). Helper formatters in `src/utils.py` (`format_api_error`, `format_validation_error`, `format_unexpected_error`, `format_error`) provide actionable recovery guidance for LLMs.

**Comprehensive Audit Logging**: All API operations are logged with metadata, execution times, and error handling via `src/audit_logger.py`

**Error Handling**: Custom exceptions in `src/exceptions.py` and comprehensive error recovery mechanisms

**Credential Security**: Automatic sanitization of sensitive data in logs and audit trails

## Configuration

### Environment Variables
```bash
# OAuth2 Client Credentials
CLEARPASS_SERVER=https://your-clearpass-server.com:443/api
CLEARPASS_CLIENT_ID=your-oauth-client-id
CLEARPASS_CLIENT_SECRET=your-oauth-client-secret
CLEARPASS_VERIFY_SSL=true

# OR API Token Authentication
CLEARPASS_SERVER=https://your-clearpass-server.com:443/api
CLEARPASS_API_TOKEN=your-pre-generated-api-token
CLEARPASS_VERIFY_SSL=true
```

## Important Development Notes

### Module Imports
The project uses relative imports within the `src` package. Entry point `src/main.py` handles path setup for direct execution.

### Test Configuration
Tests use `tests/conftest.py` for path setup. Run tests from project root using `python -m pytest tests/`

### Tool Registration
Importing the domain tool modules in `src/main.py` registers their operations into the registry (`src/registry.py`, via `@operation(...)`), reachable through the 3 gateway meta-tools. Only `gateway.py` and `server_utility.py` register direct `@mcp.tool()` tools on the global `mcp` instance (7 direct tools in default mode). Legacy mode (`CLEARPASS_MCP_LEGACY_TOOLS=true`) additionally registers all 757 domain operations as direct tools (764 total).

### IDE Diagnostics
Always use IDE diagnostics to validate code after implementation

### Mixin Pattern Usage
When adding new API functionality:
1. Add methods to appropriate mixin in `src/client_methods/`
2. Create corresponding MCP tools in `src/tools/`
3. Import the tool module in `src/main.py`

### Error Handling Philosophy
- Comprehensive error logging with audit trails
- Graceful degradation for non-critical failures
- Sensitive data sanitization in all logs
- Failed operation recovery mechanisms

## Use Cases

### Network Administration Automation
- **Bulk Device Management**: "Add all switches from this CSV to ClearPass"
- **Policy Standardization**: "Create enforcement profiles for all branch offices using the corporate template"
- **Configuration Auditing**: "Compare network device configurations across all sites"

### Guest Access Management
- **Event Provisioning**: "Create 50 guest accounts for conference attendees, valid for 3 days"
- **Sponsor Workflows**: "Show me all pending guest access requests requiring approval"
- **Temporary Access**: "Extend guest user 'contractor-john' access by 1 week"

### Compliance & Security
- **Audit Trails**: "Show me all unauthorized access attempts in the last 7 days"
- **Certificate Lifecycle**: "List all certificates expiring in the next 30 days"
- **Policy Enforcement**: "Verify all corporate devices are using current security posture policies"

### Session Control & Monitoring
- **Active Session Management**: "Show all active VPN sessions for the finance department"
- **Change of Authorization**: "Force reauthorization for all users in the guest role"
- **Incident Response**: "Disconnect all sessions from user 'compromised-account'"

### Advanced Policy Configuration
- **Role-Based Access**: "Create a contractor role with limited network access to VLAN 100"
- **Authentication Services**: "Configure EAP-TLS authentication for wireless users with certificate validation"
- **Dynamic Authorization**: "Set up RADIUS dynamic authorization templates for posture-based access"

## Security Features

### Authentication & Authorization
- **OAuth2 Client Credentials Flow**: Industry-standard secure authentication
- **API Token Fallback**: Alternative authentication method for legacy systems
- **Automatic Token Refresh**: Transparent token lifecycle management

### Secure Communications
- **TLS 1.2+ Enforcement**: All API communications encrypted
- **Certificate Verification**: Configurable SSL/TLS certificate validation
- **HTTPS-Only**: No plaintext transmission of credentials or data

### Data Protection
- **Credential Sanitization**: Automatic removal of sensitive data from logs and audit trails
- **Secure Storage**: Environment variables only — the server never reads or writes a credentials file
- **No Credential Caching**: Credentials never stored in memory longer than necessary

### Audit & Compliance
- **Complete Audit Trail**: Every API operation logged with metadata and execution times
- **Operation Tracking**: Source attribution for all configuration changes
- **Error Logging**: Comprehensive error capture without exposing sensitive details

## Deployment Options

### Production: Docker (Recommended)

Easiest deployment method using pre-built Docker image:

**Claude Desktop Configuration (OAuth2):**
```json
{
  "mcpServers": {
    "clearpass-sidekick": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "CLEARPASS_SERVER=https://your-clearpass-server.com:443/api",
        "-e", "CLEARPASS_CLIENT_ID=your-oauth-client-id",
        "-e", "CLEARPASS_CLIENT_SECRET=your-oauth-client-secret",
        "-e", "CLEARPASS_VERIFY_SSL=true",
        "bicharri/clearpass-sidekick:latest"
      ]
    }
  }
}
```

**Claude Desktop Configuration (API Token):**
```json
{
  "mcpServers": {
    "clearpass-sidekick": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "CLEARPASS_SERVER=https://your-clearpass-server.com:443/api",
        "-e", "CLEARPASS_API_TOKEN=your-api-token",
        "-e", "CLEARPASS_VERIFY_SSL=true",
        "bicharri/clearpass-sidekick:latest"
      ]
    }
  }
}
```

Docker image automatically pulled on first use. Claude Desktop manages container lifecycle.

### Development: Local Python

For development or running from source:

1. Install dependencies: `pip install -r requirements.txt`
2. Configure MCP client:

```json
{
  "mcpServers": {
    "clearpass-sidekick": {
      "command": "python",
      "args": ["/absolute/path/to/clearpass-sidekick/src/main.py"],
      "env": {
        "CLEARPASS_SERVER": "https://your-clearpass-server.com:443/api",
        "CLEARPASS_CLIENT_ID": "your-oauth-client-id",
        "CLEARPASS_CLIENT_SECRET": "your-oauth-client-secret",
        "CLEARPASS_VERIFY_SSL": "true"
      }
    }
  }
}
```

### Manual Docker Run (Testing)

For standalone testing outside MCP client:

```bash
docker run --rm -i \
  -e CLEARPASS_SERVER="https://your-clearpass-server.com:443/api" \
  -e CLEARPASS_CLIENT_ID="your-oauth-client-id" \
  -e CLEARPASS_CLIENT_SECRET="your-oauth-client-secret" \
  bicharri/clearpass-sidekick:latest
```

## Quick Reference for Common Development Tasks

### Adding a New API Endpoint
1. **Add method** to appropriate mixin: `src/client_methods/{module}.py`
2. **Create MCP tool** wrapper: `src/tools/{module}.py`
3. **Import tool module** in: `src/main.py` (lines 43-56)
4. **Add data models** if needed: `src/models/{module}.py`
5. **Test** using live testing procedures

### Debugging Authentication Issues
- **Credentials loading**: `src/credentials.py`
- **OAuth2 flow**: `src/clearpass_client.py` (lines 103-155)
- **Client initialization**: `src/app_config.py` (lines 54-96)
- **Environment variables**: Check `CLEARPASS_SERVER`, `CLEARPASS_CLIENT_ID`, `CLEARPASS_CLIENT_SECRET`

### Understanding Tool Execution
1. **Tool called** via MCP protocol → `src/tools/{module}.py`
2. **Tool wrapper** calls mixin method → `src/client_methods/{module}.py`
3. **Mixin method** uses client → `src/clearpass_client.py`
4. **Client makes** HTTP request → ClearPass API
5. **Audit logger** records operation → `src/audit_logger.py`

### Finding Specific Functionality
- **API client management**: `src/client_methods/api_clients.py` + `src/tools/api_clients.py`
- **Network devices**: `src/client_methods/network_devices.py` + `src/tools/network_devices.py`
- **Guest users**: `src/client_methods/guest_users.py` + `src/tools/guest_users.py`
- **Guest actions**: `src/client_methods/guest_actions.py` + `src/tools/guest_actions.py`
- **Guest configuration**: `src/client_methods/guest_configuration.py` + `src/tools/guest_configuration.py`
- **Certificates**: `src/client_methods/certificates.py` + `src/tools/certificates.py`
- **Policy engine**: `src/client_methods/policy_elements.py` + `src/tools/policy_elements.py` (largest)
- **Sessions**: `src/client_methods/session_control.py` + `src/tools/session_control.py`
- **Server config**: `src/client_methods/{global,local}_server_config.py` + `src/tools/{global,local}_server_config.py`

### Key Files by Purpose
| Purpose | File Location |
|---------|---------------|
| MCP server entry point | `src/main.py` |
| Stdio-safe logging setup | `src/logging_config.py` |
| Global configuration | `src/app_config.py` |
| API client singleton | `src/app_config.py:54-96` |
| Main API client class | `src/clearpass_client.py` |
| Authentication logic | `src/clearpass_client.py:103-155` |
| Audit logging | `src/audit_logger.py` |
| Error handling & formatters | `src/exceptions.py` & `src/utils.py` |
| Credential management | `src/credentials.py` |

## Live Testing

The offline suite is hermetic and must stay that way — `python -m pytest tests/ --ignore=tests/live` reports **222 passed, 0 failed** with no network access and no credentials.

Everything that touches a real appliance lives in `tests/live/`, an **opt-in** harness gated behind a `--live` flag. `pytest_collection_modifyitems` in `tests/live/conftest.py` marks every item under that directory skipped unless `--live` is passed, so a normal run performs no network call, no credential read, and no `src` import from the live tests. Running it requires a reachable ClearPass appliance and credentials in the environment:

```bash
# Offline (default) — fast and hermetic
python -m pytest tests/ --ignore=tests/live

# Live — source the operator .env first so credentials arrive via os.environ
set -a; . .env; set +a
python -m pytest tests/live --live -q -s
```

### Safety Rails

- **Fixture namespace**: every object the harness creates is named `zzz-mcptest-<runid>-<n>`. `harness.assert_ours(name)` runs immediately before every update and delete and raises unless the name carries the `zzz-mcptest-` prefix, so writes and deletes can only ever target objects the harness itself created.
- **Hard denylist**: `tests/live/denylist.py` lists 32 operations that are never dispatched live — `harness.invoke()` raises `DenylistedOperation` before the gateway is touched. They cover credential and access self-destruction (deleting the sole API client would revoke our own access; deleting one of the two admin users risks administrative lockout), production infrastructure, licensing and cluster configuration, Change of Authorization against live sessions, and `send_guest_receipt_sms` / `send_guest_receipt_email`, which dispatch to real recipients.
- **Inventory guard**: a session-autouse fixture snapshots 9 object families before and after the run and diffs them. Any addition or removal **outside** the fixture prefix fails the run.
- **Cleanup**: a per-test `cleanup` fixture drains registered teardowns in a `finally` even when the test body raised, and a session-end `harness.sweep_fixtures()` deletes any surviving `zzz-mcptest-*` object before the "after" snapshot is taken.

### Dispatch

Live calls route through `src.tools.gateway.invoke_operation` rather than importing operation functions directly, so every call also validates the progressive-disclosure path — name resolution, parameter whitelisting, `Context` injection, error wrapping — at the same time as the operation itself.

The 2026-07-20 run exercised **284 of 291 operations**; the 2026-07-30 full-SDK-coverage run exercised **all 757 registry operations** (1,318 recorded verdicts, 711 tests passed, 0 failed) against the same lab appliance (ClearPass 6.12.4) with zero drift to pre-existing objects. `tests/live/README.md` carries the full contract: verdict classification, the known-limitation allowlist (environment limits of 6.12.4, cross-referenced to `docs/live_testing_plan_phase1.md` and `docs/live_testing_plan_phase2.md`), and the `results-<runid>.jsonl` / `inventory-<runid>.json` artifact schemas.

---

**Last Updated**: 2026-08-13
**Project**: ClearPass Sidekick MCP Server
**Purpose**: Enable natural language control of Aruba ClearPass Policy Manager through AI assistants
