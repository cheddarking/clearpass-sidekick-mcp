# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable docs must stay understandable from the nearest applicable AGENTS.md plus every parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path, read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide rules
7. If docs conflict, the closer doc controls local work details, but no child doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child index changes. Update child docs when parent changes alter local rules. Remove stale or contradictory text immediately. Small edits that do not change behavior or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences, durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX Index
- Each parent explains what its direct children cover and what stays owned by the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user instructions; if there are no specific standards or instructions yet, leave it empty
- Verification must reflect an existing check; if no verification framework exists yet, leave it empty and update it when one exists

Default section order:
- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## User Preferences

When the user requests a durable behavior change, record it here or in the relevant child AGENTS.md

## Project Summary

Public repository: https://github.com/cheddarking/clearpass-sidekick-mcp. MIT licensed. Local MCP client configs, credentials, generated indexes, and virtual environments must remain untracked.

ClearPass Sidekick — a Model Context Protocol (MCP) server for managing Aruba ClearPass Policy Manager via its REST API. Async Python (FastMCP + httpx) with OAuth2 authentication. 761 ClearPass operations across 19 domain modules plus `server_utility`, exposed by **progressive disclosure**: 757 operations live in the in-process registry and are reached through 3 gateway meta-tools, so default mode boots with only 7 direct MCP tools.

Everything below this Child DOX Index mirrors `CLAUDE.md` verbatim — it is the same project documentation served to non-Claude harnesses. Keep the two files in sync; edit `CLAUDE.md` first, then mirror.

## Child DOX Index

- `src/AGENTS.md` — Core library: MCP server entry, API client, credentials, audit logging, exceptions, utilities, and mixin-based client methods; owns client_methods/, models/, tools/
- `tests/AGENTS.md` — pytest test suite covering all tool modules, client integration, and credential/audit logic

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
