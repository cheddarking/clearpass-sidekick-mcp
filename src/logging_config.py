"""
Stdio-safe logging configuration for ClearPass Sidekick MCP Server.

According to the Model Context Protocol (MCP) specification for stdio transport,
stdout is strictly reserved for JSON-RPC message framing. All logging, diagnostic,
debug, and error outputs MUST be directed exclusively to stderr.
"""

import builtins
import logging
import sys
from typing import Optional


class _StderrProxy:
    """Proxy stream that dynamically evaluates sys.stderr on every write/flush."""
    def write(self, message):
        return sys.stderr.write(message)

    def flush(self):
        return sys.stderr.flush()

    @property
    def closed(self):
        return getattr(sys.stderr, 'closed', False)


def configure_mcp_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configure all application and library loggers to output exclusively to sys.stderr.

    This prevents logging statements from polluting sys.stdout and corrupting
    the JSON-RPC transport stream used by MCP.

    Args:
        level: Default logging level (default: logging.INFO)

    Returns:
        Root logger instance
    """
    # 1. Force root logger to output to sys.stderr via proxy
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove any existing handlers that might write to stdout or duplicate
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Create a stream handler targeting sys.stderr dynamically via proxy
    stderr_handler = logging.StreamHandler(_StderrProxy())
    stderr_handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stderr_handler.setFormatter(formatter)
    root_logger.addHandler(stderr_handler)

    # 2. Reconfigure basicConfig to guarantee sys.stderr stream default
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=_StderrProxy(),
        force=True
    )

    # 3. Ensure known third-party loggers output to stderr and use reasonable levels
    third_party_loggers = ['httpx', 'urllib3', 'asyncio', 'fastmcp', 'mcp', 'uvicorn']
    for logger_name in third_party_loggers:
        tp_logger = logging.getLogger(logger_name)
        tp_logger.handlers = []
        tp_logger.propagate = True

    # 4. Patch builtins.print so any un-redirected print() call defaults to sys.stderr
    _original_print = builtins.print

    def stdio_safe_print(*args, **kwargs):
        if 'file' not in kwargs or kwargs['file'] is None or kwargs['file'] is sys.stdout:
            kwargs['file'] = sys.stderr
        _original_print(*args, **kwargs)

    builtins.print = stdio_safe_print

    logger = logging.getLogger(__name__)
    logger.debug("Stdio-safe stderr logging initialized successfully")

    return root_logger
