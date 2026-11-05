"""MCP Response Integrity module for Injection-Shield.

Provides three-layer defense against compromised or malicious MCP servers:
1. Format-Anomaly Detection — unexpected response shapes / sizes
2. SHA256 Hash-Pinning — optional public-key verification
3. Trust-Level Management — verified / unverified / unknown per server

v0.4.0 (BUILD-IS-MCP-INTEGRITY)
"""

from __future__ import annotations

from .exceptions import MCPIntegrityError
from .format_baseline import FormatBaseline, detect_format_anomaly
from .integrity import ResponseHasher, compute_response_hash
from .post_tool_hook import verify_response
from .trust_store import TrustLevel, TrustStore

__all__ = [
    "FormatBaseline",
    "MCPIntegrityError",
    "ResponseHasher",
    "TrustLevel",
    "TrustStore",
    "compute_response_hash",
    "detect_format_anomaly",
    "verify_response",
]
