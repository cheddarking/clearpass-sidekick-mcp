#!/usr/bin/env python3

import os
import sys

# --- Start of new block ---
if __name__ == '__main__' and __package__ is None:
    # This script is being run directly, not as a module.
    # Adjust sys.path to include the project root, so 'src' can be found as a package,
    # and set __package__ so that relative imports (.app_config) work.
    script_path = os.path.abspath(__file__)
    src_directory = os.path.dirname(script_path)
    project_root_directory = os.path.dirname(src_directory)

    if project_root_directory not in sys.path:
        sys.path.insert(0, project_root_directory)
    
    # Set __package__ to the name of the package this module belongs to.
    # This allows relative imports to work correctly.
    __package__ = "src"
# --- End of new block ---

"""
ClearPass Sidekick MCP Server

A FastMCP server that provides natural language automation of Aruba ClearPass 
configuration tasks through LLM clients like Claude.
"""

import logging
from .logging_config import configure_mcp_logging

# Configure stdio-safe logging (directs all logging to stderr and patches print)
configure_mcp_logging()
logger = logging.getLogger(__name__)

# Import app configuration (this sets up mcp instance and other globals)
from .app_config import mcp

# Import all tool modules. Domain modules register their functions in the
# operation registry (progressive disclosure via the gateway meta-tools);
# server_utility keeps its direct @mcp.tool() registrations; gateway registers
# the list/describe/invoke meta-tools directly on the mcp instance.
from .tools import (
    api_clients,
    network_devices,
    guest_users,
    guest_actions,
    guest_configuration,
    certificates,
    audit_logs,
    server_utility,
    global_server_config,
    local_server_config,
    session_control,
    policy_elements,
    enforcement_profiles,
    identities,
    endpoint_visibility,
    integrations,
    certificate_authority,
    tools_utilities,
    api_operations,
    enforcement_profiles_dur,
    gateway,
)

# Optional legacy mode: register every registry operation as a direct MCP tool
# (pre-refactor behavior). Enabled via CLEARPASS_MCP_LEGACY_TOOLS=true.
from .registry import register_legacy_tools

if os.getenv("CLEARPASS_MCP_LEGACY_TOOLS", "").lower() == "true":
    _legacy_count = register_legacy_tools(mcp)
    logger.info(f"Legacy mode: registered {_legacy_count} direct tools")

# Import resources and prompts
from .app_config import CLEARPASS_CONFIG

@mcp.resource("clearpass://config")
async def get_clearpass_config() -> str:
    """Get current ClearPass configuration status."""
    config_info = f"""
ClearPass Configuration Status:
- Host: {'✓ Configured' if CLEARPASS_CONFIG['host'] else '✗ Not configured'}
- Credentials: {'✓ Configured' if CLEARPASS_CONFIG['client_id'] and CLEARPASS_CONFIG['client_secret'] else '✗ Not configured'}
- API Version: {CLEARPASS_CONFIG['api_version']}
- SSL Verification: {CLEARPASS_CONFIG['verify_ssl']}

Environment Variables Required:
- CLEARPASS_SERVER: ClearPass server hostname
- CLEARPASS_CLIENT_ID: OAuth2 client ID
- CLEARPASS_CLIENT_SECRET: OAuth2 client secret
- CLEARPASS_VERIFY_SSL: SSL verification (default: true)
"""
    return config_info

@mcp.prompt()
def clearpass_help() -> str:
    """Generate a help prompt for ClearPass operations."""
    return """
I can help you manage your Aruba ClearPass Policy Manager through natural language commands. Here are some examples:

**API Client Management:**
- "Create an API client named 'automation-bot' with read-write privileges"
- "List all enabled API clients"
- "Show me API clients with read-only access"
- "Get details for API client 'monitoring-service'"
- "Update API client 'automation-bot' to enable it"
- "Delete API client with ID 123 (requires confirmation)"

**Network Device Management:**
- "Add a new network device with IP 192.168.1.100 named 'new-switch'"
- "List all network devices that support Change of Authorization"
- "Show me all Aruba devices"

**Guest User Management:**
- "Create a guest user 'visitor01' with password 'temp123'"
- "Extend guest user 'visitor01' by 24 hours"
- "List all active guest users"

**Enforcement Profile Management:**
- "List all enforcement profiles"
- "Create a corporate employee profile using the template"
- "Show me available profile templates"
- "Get details for enforcement profile 'Guest-Internet-Access'"
- "Update the guest profile to reduce session timeout"
- "Create a custom contractor profile with VLAN assignment"

**Configuration & Testing:**
- "Test ClearPass connection"
- "Show current ClearPass configuration status"
- "Check if ClearPass connection is properly configured"

What would you like me to help you with?
"""

if __name__ == "__main__":
    # Run the FastMCP server
    logger.info("Starting ClearPass Sidekick MCP Server...")
    mcp.run()
