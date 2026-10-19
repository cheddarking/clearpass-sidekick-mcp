"""
MCP tools for ClearPass Sidekick MCP Server.
"""

# Import all tool modules to ensure they are registered with the mcp instance
from . import api_clients
from . import network_devices
from . import guest_users
from . import certificates
from . import audit_logs
from . import server_utility
from . import global_server_config
from . import local_server_config
from . import session_control
from . import policy_elements

__all__ = [
    "api_clients",
    "network_devices", 
    "guest_users",
    "certificates",
    "audit_logs",
    "server_utility",
    "global_server_config",
    "local_server_config", 
    "session_control",
    "policy_elements"
]