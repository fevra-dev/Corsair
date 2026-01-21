"""
Corsair MCP (Model Context Protocol) module.

Exposes scanning capabilities to LLM agents via MCP.
"""

# MCP server is imported on demand to avoid dependency issues
# when MCP is not installed

__all__ = ["get_mcp_server"]


def get_mcp_server():
    """
    Get the MCP server instance.

    Returns:
        FastMCP server instance

    Raises:
        ImportError: If fastmcp is not installed
    """
    from .server import mcp

    return mcp
