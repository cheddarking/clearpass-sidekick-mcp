# ClearPass Sidekick MCP Server

A Model Context Protocol (MCP) server that enables natural language automation of Aruba ClearPass configuration tasks through LLM clients like Claude.

## Overview

ClearPass Sidekick bridges the gap between natural language commands and ClearPass API operations, allowing network administrators to manage ClearPass configurations through conversational interfaces. The system leverages the Model Context Protocol to provide structured tool access to ClearPass APIs.

## Architecture

```
+---------------------+       Natural Language        +----------------------+
|  User / LLM Client  | <---------------------------->|      MCP Client      |
|  (e.g., Claude)     |   (structured tool call)      | (e.g., Claude Desktop)|
+---------------------+                               +----------+-----------+
                                                             |
                                                             | (via stdio or SSE)
                                                             v
                                                  +----------------------+
                                                  |      MCP Server      |
                                                  |  (Python/Typescript) |
                                                  +----------+-----------+
                                                             |
                                          ClearPass API Client Module
                                                             |
                                                             v
                                                  +----------------------+
                                                  |  Aruba ClearPass API |
                                                  |  (REST endpoints)    |
                                                  +----------------------+
```

## Progressive Disclosure Architecture

ClearPass Sidekick supports **761 distinct ClearPass operations** — full endpoint parity with Aruba's `pyclearpass` 1.0.8 SDK (801/801 endpoints), plus operations beyond it. Exposing all 761 as individual MCP tools means the LLM must load 761 full tool schemas into its context window on every request — tens of thousands of tokens of parameter definitions the model rarely needs all at once. That crowds out the user's actual task, slows responses, and degrades tool-selection accuracy.

To solve this, the server uses **progressive disclosure**: instead of 761 direct tools, default mode exposes just **7 direct tools** — 3 gateway meta-tools plus 4 `server_utility` tools. All 761 operations remain fully available; 757 are reached on demand through the gateway, and the 4 utility tools stay direct.

### The Three Gateway Meta-Tools

| Meta-tool | Purpose |
|-----------|---------|
| `list_operations` | List available operations (name, domain, one-line summary). Filter with `domain=...` or `search=...` to narrow the catalog. |
| `describe_operations` | Get full descriptions and parameter JSON schemas for named operations. Call before invoking. |
| `invoke_operation` | Execute an operation by `name` with a `params` object matching its schema. |

### Typical Flow

```text
1. list_operations(search="guest account")
     -> [{ name: "create_guest_user", domain: "guest_users", summary: "..." }, ...]

2. describe_operations(names=["create_guest_user"])
     -> full parameter schema for create_guest_user

3. invoke_operation(name="create_guest_user", params={ "username": "visitor01", ... })
     -> operation result
```

The model loads only the schemas it actually needs, keeping the context window lean while retaining the full operation catalog.

### Legacy Mode

To restore the pre-refactor behavior (every operation registered as its own direct `@mcp.tool()`), set the environment variable:

```bash
CLEARPASS_MCP_LEGACY_TOOLS=true
```

In legacy mode the server registers all 757 domain operations as direct tools **in addition** to the 7 default tools (764 total) and logs `Legacy mode: registered 757 direct tools` at startup. Leave this `false` (the default) unless a client cannot use the gateway pattern.

## Features

- **Natural Language Interface**: Issue commands in plain English to manage ClearPass configurations
- **Comprehensive API Coverage**: Support for API clients, devices, endpoints, guest management, guest portals, and certificates
- **OAuth2 Authentication**: Secure authentication using client credentials grant
- **Audit Logging**: Complete audit trail of all automated changes
- **Error Handling**: Detailed error messages and confirmation prompts for ambiguous operations

## Use Cases

### **Core Network Management**
- **API Client Management**: "Create an API client named 'automation-bot' with read-only privileges"
- **Network Device Operations**: "Show me all network devices with CoA enabled" or "Add a new Aruba switch with IP 192.168.1.100"
- **Guest User Management**: "Extend guest user 'visitor01' by 24 hours" or "Create a guest account for contractor access"

### **Guest Portal & Credential Delivery**
- **Digital Passes**: "Generate an Apple Wallet pass for guest user 'visitor01'" or "Create a Google Pay pass for conference attendees"
- **Receipt Generation**: "Generate a printable receipt for guest 'contractor-john'" or "Create HTML receipt for email delivery"
- **Credential Delivery**: "Send guest credentials via SMS" or "Email the WiFi password to the visitor"
- **Sponsor Workflows**: "Approve the pending guest access request" or "Reject unauthorized guest registration"
- **Portal Customization**: "List all web login pages" or "Create a new captive portal for the lobby"
- **Template Management**: "Update the guest receipt template" or "Create a new digital pass template with company branding"

### **Advanced Policy Management**
- **Enforcement Profiles**: "Create a corporate employee profile using the template" or "List all active enforcement policies"
- **Authentication Methods**: "Configure EAP-TLS authentication for wireless users"
- **Role Management**: "Create a contractor role with limited network access"
- **Configuration Services**: "Set up RADIUS authentication source for Active Directory"

### **Session Control & Monitoring**
- **Active Session Management**: "Show me all active user sessions" or "Disconnect sessions for user 'jdoe'"
- **Change of Authorization**: "Perform CoA to update user policies immediately"
- **Audit & Compliance**: "Show me login audit records for the past week"

### **Certificate & Security Operations** 
- **Certificate Lifecycle**: "Issue a certificate for device 'switch-01'" or "Generate CSR for new server"
- **Trust Management**: "Import certificate to trust list" or "Validate certificate configuration"

### **Server Configuration**
- **Global Settings**: "Configure SNMP trap receivers" or "Manage application licenses"
- **Local Configuration**: "Join server to Active Directory domain" or "Configure cluster parameters"
- **Administrative Tasks**: "Create admin user with operator privileges" or "Update password policies"

## Prerequisites

- Python 3.8 or higher
- Access to an Aruba ClearPass Policy Manager instance
- ClearPass API client credentials (OAuth2)
- LLM client supporting MCP (e.g., Claude Desktop)

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/cheddarking/clearpass-sidekick-mcp.git
   cd clearpass-sidekick-mcp
   ```

2. **Create and activate virtual environment**:
   ```bash
   python -m venv .venv
   
   # On Windows
   .venv\Scripts\activate
   
   # On macOS/Linux
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure ClearPass credentials**:

   Set the following environment variables:
   ```bash
   export CLEARPASS_SERVER=https://your-clearpass-server.com:443/api
   export CLEARPASS_CLIENT_ID=your-oauth-client-id
   export CLEARPASS_CLIENT_SECRET=your-oauth-client-secret
   export CLEARPASS_VERIFY_SSL=true
   ```
   
   Or use API token authentication:
   ```bash
   export CLEARPASS_SERVER=https://your-clearpass-server.com:443/api
   export CLEARPASS_API_TOKEN=your-pre-generated-api-token
   export CLEARPASS_VERIFY_SSL=true
   ```

## Configuration

ClearPass Sidekick uses environment variables for authentication. You can use either OAuth2 client credentials or API token authentication:

### **OAuth2 Client Credentials**
```bash
CLEARPASS_SERVER=https://your-clearpass-server.com:443/api
CLEARPASS_CLIENT_ID=your-oauth-client-id  
CLEARPASS_CLIENT_SECRET=your-oauth-client-secret
CLEARPASS_VERIFY_SSL=true  # Optional, defaults to true
```

### **API Token Authentication**
```bash
CLEARPASS_SERVER=https://your-clearpass-server.com:443/api
CLEARPASS_API_TOKEN=your-pre-generated-api-token
CLEARPASS_VERIFY_SSL=true  # Optional, defaults to true
```

## Usage

### **Docker Setup (Recommended)**

The easiest way to use ClearPass Sidekick is with the pre-built Docker image. Configure it directly in your MCP client settings - no need to run Docker commands separately.

#### **For Claude Desktop**

Add this to your Claude Desktop configuration file:

**Using OAuth2 Client Credentials:**
```json
{
  "mcpServers": {
    "clearpass-sidekick": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
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

**Using API Token:**
```json
{
  "mcpServers": {
    "clearpass-sidekick": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-e", "CLEARPASS_SERVER=https://your-clearpass-server.com:443/api",
        "-e", "CLEARPASS_API_TOKEN=your-api-token",
        "-e", "CLEARPASS_VERIFY_SSL=true",
        "bicharri/clearpass-sidekick:latest"
      ]
    }
  }
}
```

The Docker image will be automatically pulled if not present. Claude Desktop will start and manage the container lifecycle automatically.

### **Local Python Setup (Development)**

For development or if you prefer running from source:

1. Follow the [Installation](#installation) steps
2. Configure your MCP client:

```json
{
  "mcpServers": {
    "clearpass-sidekick": {
      "command": "python",
      "args": ["/path/to/your/project/src/main.py"],
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

### **Manual Docker Run (Optional)**

If you need to run the Docker container manually for testing:

```bash
docker run --rm -i \
  -e CLEARPASS_SERVER="https://your-clearpass-server.com:443/api" \
  -e CLEARPASS_CLIENT_ID="your-oauth-client-id" \
  -e CLEARPASS_CLIENT_SECRET="your-oauth-client-secret" \
  bicharri/clearpass-sidekick:latest
```




## Available Operations

The server provides **761 ClearPass operations** across 20 specialized domains. In default mode these are reached through the gateway meta-tools (see [Progressive Disclosure Architecture](#progressive-disclosure-architecture) above) rather than being registered as 761 individual tools. The domains and their operation groups:

### **Core ClearPass Management (84 operations)**
- **API Client Management** (5 operations): Complete CRUD operations for OAuth API clients
- **Network Device Management** (16 operations): NAD configuration with RADIUS/TACACS+ support
- **Guest User Management** (5 operations): Temporary access provisioning with sponsor workflows
- **Guest Actions** (5 operations): Digital pass generation, receipt printing, SMS/email credential delivery, sponsor approval workflows
- **Guest Configuration** (28 operations): Pass templates, print templates, web login pages, authentication settings, guest manager configuration
- **Certificate Operations** (9 operations): CSR generation, trust lists, client/server certificates, CA operations
- **Audit & Logging** (12 operations): System events, login audits, insight alerts, comprehensive API operation tracking
- **Server Utility** (4 direct tools): Connection testing, configuration validation, health monitoring (always registered as direct MCP tools)

### **Advanced Server Configuration (73 operations)**
- **Global Server Configuration** (58 operations): Admin users, privileges, licenses, attributes, data filters, operator profiles, SNMP, messaging, backup servers, policy manager zones
- **Local Server Configuration** (15 operations): Access control, Active Directory integration, cluster management (`list_cluster_servers` supplies the `server_uuid` the other cluster operations need), version info

### **Session & Network Control (14 operations)**
- **Session Control** (14 operations): Active session monitoring, disconnect operations, reauthorization, Change of Authorization (CoA)

### **Policy Engine Components (120 operations)**
- **Policy Elements** (112 operations): The largest implementation covering:
  - **Core Components**: Roles, role mappings, enforcement policies, configuration services
  - **Authentication**: Methods (EAP, certificates), sources (AD/LDAP integration)  
  - **Network Infrastructure**: Device groups, enhanced device configuration (SNMP, RadSec, CLI)
  - **Advanced Policies**: Posture policies, RADIUS dynamic authorization templates
  - **Dictionaries**: Application and RADIUS custom attribute definitions
  - **Specialized**: Proxy targets (RADIUS proxy), TACACS+ service dictionaries
- **Enforcement Profiles** (8 operations): Basic profile management with template-based creation for common networking scenarios

### **Enterprise Features**
- **Template-Driven Configuration**: Predefined templates for corporate, guest, contractor, IoT, and executive access
- **Bulk Operations**: Mass updates and configuration changes with safety confirmations
- **Advanced Search & Filtering**: Multi-criteria search across all components
- **Validation & Testing**: Configuration validation, connectivity testing, dependency checking
- **Statistics & Analytics**: Usage monitoring, performance metrics, compliance reporting

## Development

### Project Structure

```
clearpass-sidekick/
├── src/                    # Source code
│   ├── registry.py        # Operation registry (progressive disclosure)
│   ├── tools/             # 761 operations: 757 registry ops + 4 direct tools
│   │   ├── gateway.py            # 3 gateway meta-tools (list/describe/invoke)
│   │   ├── server_utility.py     # 4 direct @mcp.tool utilities
│   │   ├── guest_actions.py      # Guest credential delivery (5 operations)
│   │   ├── guest_configuration.py # Portal & template management (28 operations)
│   │   └── ...                   # Other domain modules (@operation registry)
│   ├── client_methods/    # API interaction mixins
│   ├── models/            # Pydantic data models
│   ├── clearpass_client.py # Main API client
│   ├── credentials.py     # Secure credential management
│   ├── app_config.py      # Application configuration
│   └── main.py           # MCP server entry point
├── docs/                  # Implementation plans and documentation
├── tests/                 # Test files
├── scripts/               # PRD and utility scripts
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

### Running Tests

The offline suite is hermetic — no network, no credentials — and reports **222 passed, 0 failed**:

```bash
python -m pytest tests/ --ignore=tests/live
```

### Live Validation

`tests/live/` holds an **opt-in** harness that exercises the server against a real ClearPass appliance. It is skipped at collection time unless `--live` is passed, so the normal suite stays offline and fast; running it requires a reachable appliance and credentials in the environment:

```bash
set -a; . .env; set +a
python -m pytest tests/live --live -q -s
```

It is safe to point at a lab appliance. Every object it creates is namespaced `zzz-mcptest-*`, and writes and deletes only ever target that prefix; an 18-operation denylist is never dispatched live (deleting the sole API client would revoke the harness's own access, deleting admin users risks lockout, and the guest SMS/email receipt operations send to real recipients); and a before/after inventory snapshot diff fails the run if anything outside the prefix changed. Calls route through `invoke_operation`, so a live run validates the progressive-disclosure dispatch path alongside the operations themselves.

The 2026-07-30 full-coverage run exercised **all 757 registry operations** (711 live tests passed, 0 failed) against a ClearPass 6.12.4 lab appliance with zero drift to pre-existing objects. See `tests/live/README.md` for the full contract.

### Code Style

This project follows PEP 8 style guidelines. Use the following tools for code quality:

```bash
# Format code
black src/

# Lint code
flake8 src/

# Type checking
mypy src/
```

## Security Considerations

- **OAuth2 Authentication**: All API calls use secure OAuth2 client credentials
- **HTTPS Transport**: All communications use TLS 1.2+
- **Credential Storage**: Store sensitive credentials in secure vaults
- **Audit Logging**: Complete audit trail of all operations
- **Input Validation**: Comprehensive validation of all user inputs

## API References

- **ClearPass Policy Manager REST API**: [Developer Documentation](https://developer.arubanetworks.com/aruba-cppm/docs/getting-started-with-the-clearpass-policy-manager-api)
- **PyClearPass SDK**: [GitHub Repository](https://github.com/aruba/pyclearpass)
- **Model Context Protocol**: [Official Documentation](https://modelcontextprotocol.io)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- Create an issue in this repository
- Check the [ClearPass API documentation](https://developer.arubanetworks.com/aruba-cppm/)
- Review the [MCP documentation](https://modelcontextprotocol.io)

## Acknowledgments

- Aruba Networks for the ClearPass API
- Anthropic for the Model Context Protocol
- The open-source community for various dependencies 