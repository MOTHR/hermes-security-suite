"""MCP integrity exceptions."""

from __future__ import annotations


class MCPIntegrityError(Exception):
    """Raised when an MCP response fails an integrity check.

    Attributes:
        server_id: The MCP server identifier (e.g. ``"obsidian"``).
        check_type: Which layer failed (``"format"``, ``"hash"``, ``"signature"``).
        details: Human-readable description of the failure.
    """

    def __init__(
        self,
        message: str,
        *,
        server_id: str = "",
        check_type: str = "",
        details: str = "",
    ) -> None:
        super().__init__(message)
        self.server_id = server_id
        self.check_type = check_type
        self.details = details
