# ClearPass Sidekick MCP Server

A Model Context Protocol (MCP) server that enables natural language automation of Aruba ClearPass configuration tasks through LLM clients like Claude.

## Overview

ClearPass Sidekick bridges the gap between natural language commands and ClearPass API operations, allowing network administrators to manage ClearPass configurations through conversational interfaces. The system leverages the Model Context Protocol to provide structured tool access to ClearPass APIs.

This is a Dockerized version of the ClearPass Sidekick MCP Server. It allows you to run the server in a container and connect to it from an MCP client.

## Features

- **Natural Language Interface**: Issue commands in plain English to manage ClearPass configurations
- **Comprehensive API Coverage**: Support for API clients, devices, endpoints, guest management, and certificates
- **OAuth2 Authentication**: Secure authentication using client credentials grant
- **Audit Logging**: Complete audit trail of all automated changes
- **Error Handling**: Detailed error messages and confirmation prompts for ambiguous operations

## Usage

The server speaks MCP over **stdio** — it binds no port and exposes no HTTP listener. Run the container interactively so the MCP client can talk to it over stdin/stdout:

```bash
docker run --rm -i \
  -e CLEARPASS_SERVER="<your-clearpass-server>" \
  -e CLEARPASS_CLIENT_ID="<your-client-id>" \
  -e CLEARPASS_CLIENT_SECRET="<your-client-secret>" \
  -e CLEARPASS_VERIFY_SSL="true" \
  clearpass-sidekick
```

In practice the MCP client launches this command itself and manages the container lifecycle; there is no address to connect to.

## Example Use Cases

- **Core Network Management**: "Create an API client named 'automation-bot' with read-only privileges"
- **Network Device Operations**: "Show me all network devices with CoA enabled" or "Add a new Aruba switch with IP 192.168.1.100"
- **Guest User Management**: "Extend guest user 'visitor01' by 24 hours" or "Create a guest account for contractor access"
- **Advanced Policy Management**: "Create a corporate employee profile using the template" or "List all active enforcement policies"
- **Session Control & Monitoring**: "Show me all active user sessions" or "Disconnect sessions for user 'jdoe'"

## Available Tools

The MCP server provides **761 ClearPass operations** across 20 specialized modules, covering Core ClearPass Management, Advanced Server Configuration, Session & Network Control, and the Policy Engine.

These are exposed by **progressive disclosure** rather than as 761 individual tool schemas: 757 operations live in an in-process registry reached on demand through 3 gateway meta-tools (`list_operations`, `describe_operations`, `invoke_operation`), and 4 `server_utility` tools stay direct. A client therefore sees just **7 tools** by default. Setting `CLEARPASS_MCP_LEGACY_TOOLS=true` additionally registers all 757 domain operations as direct tools (764 total) for clients that cannot use the gateway pattern.

## Security Considerations

- **OAuth2 Authentication**: All API calls use secure OAuth2 client credentials
- **HTTPS Transport**: All communications use TLS 1.2+
- **Credential Storage**: Store sensitive credentials in secure vaults
- **Audit Logging**: Complete audit trail of all operations
- **Input Validation**: Comprehensive validation of all user inputs

## License

**MIT License**

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
