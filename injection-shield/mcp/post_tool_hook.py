"""Post-tool-call integrity verification hook.

This module is the integration point between Injection-Shield's
hook infrastructure and the MCP integrity layers.

v0.4.0 (BUILD-IS-MCP-INTEGRITY)
"""

from __future__ import annotations

import logging
from typing import Any

from .format_baseline import detect_format_anomaly
from .integrity import ResponseHasher
from .trust_store import TrustLevel, TrustStore

logger = logging.getLogger(__name__)

# Active MCP server prefixes we recognise.
# Hermes names tools as ``mcp__<server>__<tool>``.
# ARCH-7 (Orakel review): enumerated prefixes lag behind new MCP servers
# (pipedrive, sevdesk missed). Any ``mcp__<server>__<tool>`` name is an
# MCP tool by construction — match generically.
MCP_SERVER_PREFIX = "mcp__"

# Backwards-compatible alias (tests + downstream import the tuple).
MCP_SERVER_PREFIXES = (
    "mcp__obsidian__",
    "mcp__telegram__",
    "mcp__github__",
    "mcp__vault_search__",
    "mcp__browseos__",
    "mcp__pipedrive__",
    "mcp__sevdesk__",
)


def _extract_server_id(tool_name: str) -> str | None:
    """Map ``mcp__obsidian__read_page`` → ``"obsidian"``.

    Returns ``None`` if *tool_name* is not an MCP tool.
    """
    if not tool_name.startswith(MCP_SERVER_PREFIX):
        return None
    rest = tool_name[len(MCP_SERVER_PREFIX):]
    return rest.split("__", 1)[0] or None


def verify_response(
    tool_name: str,
    result: Any,
    *,
    hasher: ResponseHasher | None = None,
    trust_store: TrustStore | None = None,
) -> dict[str, Any]:
    """Verify an MCP tool response for integrity anomalies.

    This is the primary entry point called by the post_tool_call hook.

    Args:
        tool_name: Full Hermes tool name (e.g. ``"mcp__obsidian__read_page"``).
        result: The raw tool response (dict, str, list, …).
        hasher: Optional :class:`ResponseHasher` instance (default created).
        trust_store: Optional :class:`TrustStore` instance (default created).

    Returns:
        A dict with verification metadata:

        .. code-block:: python

            {
                "server_id": "obsidian",
                "trust_level": "unverified",
                "format_anomaly": {},
                "hash_matched": True,
                "alert": False,
                "alert_reason": "",
            }

    Raises:
        MCPIntegrityError: Only when a severe format anomaly is detected
        and the caller has opted into enforcement (not by default).
    """
    server_id = _extract_server_id(tool_name)
    if server_id is None:
        return {"server_id": "", "trust_level": "", "alert": False}

    if hasher is None:
        hasher = ResponseHasher()
    if trust_store is None:
        trust_store = TrustStore()

    # Layer 1: Format anomaly
    fmt_anomaly = detect_format_anomaly(server_id, result, tool_name, learn=True)

    # Layer 2: Hash pinning
    hasher.log_hash(server_id, tool_name, result)
    hash_matched = hasher.verify_against_log(server_id, result)

    # Layer 3: Trust level
    current_level = trust_store.get(server_id)

    # Auto-promote unknown → unverified on first successful hash match
    if current_level == TrustLevel.UNKNOWN and hash_matched:
        trust_store.set_level(server_id, TrustLevel.UNVERIFIED)
        current_level = TrustLevel.UNVERIFIED

    if hash_matched:
        trust_store.bump_hash_count(server_id)

    # Build result
    alert = bool(fmt_anomaly)
    alert_reason = ""
    if fmt_anomaly:
        reasons: list[str] = []
        if "key_mismatch" in fmt_anomaly:
            reasons.append("key-mismatch")
        if "size_anomaly" in fmt_anomaly:
            reasons.append("size-anomaly")
        alert_reason = ", ".join(reasons)

    return {
        "server_id": server_id,
        "trust_level": current_level.value,
        "format_anomaly": fmt_anomaly,
        "hash_matched": hash_matched,
        "alert": alert,
        "alert_reason": alert_reason,
    }
