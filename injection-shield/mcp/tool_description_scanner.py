"""MCP tool-description scanner (GAP-1, v0.6.0).

OWASP MCP03:2025 — Tool Poisoning. Malicious instructions can be
embedded in MCP tool *metadata* (name, description, inputSchema).
The LLM processes descriptions as natural-language instructions, so a
poisoned description manipulates tool selection, parameters and even
exfiltrates data — without any user-visible text.

Two complementary checks:

1. **Description scan** — every tool description is run through the
   injection-pattern detector chain at scan time.
2. **Rug-pull / drift detection** — a content hash per (server, tool)
   is persisted at first sight. Any later mismatch means the tool
   changed after initial trust was established (classic rug pull) and
   is reported as a high-severity finding.

The scanner is transport-agnostic: callers pass whatever tool metadata
they have (``tools/list`` result, cached descriptions, …). Hermes
currently has no ``tools/list`` hook, so the primary integration points
are the ``cli.py scan-mcp`` command and the periodic drift check in
``plugin.py`` (first tool call per server triggers a re-read of the
trust store's known-description hashes).
"""

from __future__ import annotations

import hashlib
import json
import re
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Schema poisoning markers — structural, not keyword based.
_SUSPICIOUS_SCHEMA_KEYS = {"format", "pattern"}


def _canonical_tool_bytes(tool: dict[str, Any]) -> bytes:
    """Canonical JSON of the security-relevant tool metadata."""
    relevant = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema"),
    }
    return json.dumps(relevant, sort_keys=True, ensure_ascii=False).encode("utf-8")


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """Stable SHA-256 of (name, description, inputSchema)."""
    return hashlib.sha256(_canonical_tool_bytes(tool)).hexdigest()


class ToolDescriptionDriftStore:
    """Persist tool fingerprints per MCP server to detect rug pulls.

    Storage is one JSON file per server, mode 0600, same conventions
    as ``ResponseHasher`` (10 MiB-free, tiny footprint).
    """

    def __init__(self, store_dir: Path | str | None = None) -> None:
        # v0.6.0 (H1, Seraph review): the default must NOT be shared across
        # profiles — a baseline written by one profile would mask drift seen
        # by another. Default resolves per-process HERMES profile home;
        # callers may override explicitly.
        if store_dir:
            base = Path(store_dir)
        else:
            import os
            hermes_home = os.environ.get("HERMES_HOME", "~/.hermes")
            base = Path(hermes_home).expanduser() / "workspace" / "05-Logs-Snapshots" / "mcp-tool-baselines"
        self.base = base
        self.base.mkdir(parents=True, exist_ok=True)

    def _store_path(self, server_id: str) -> Path:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in server_id)
        return self.base / f"{safe}.json"

    def known(self, server_id: str) -> dict[str, str]:
        """Return {tool_name: fingerprint} from the baseline, or {}."""
        path = self._store_path(server_id)
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("drift store unreadable for %s — treating as empty", server_id)
            return {}

    def save(self, server_id: str, fingerprints: dict[str, str]) -> None:
        path = self._store_path(server_id)
        path.write_text(json.dumps(fingerprints, indent=2, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)

    def check_and_update(
        self, server_id: str, tools: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Compare current tools against the stored baseline.

        Returns findings (empty = no drift). Always updates the baseline
        to the current state afterwards — the *finding* is the record,
        suppressing repeated alerts for the same drift is the caller's
        alert-dedup job.
        """
        known = self.known(server_id)
        findings: list[dict[str, Any]] = []
        current: dict[str, str] = {}

        for tool in tools:
            name = tool.get("name", "<unnamed>")
            fp = tool_fingerprint(tool)
            current[name] = fp

            if name not in known:
                findings.append(
                    {
                        "type": "mcp_tool_baseline_created",
                        "server": server_id,
                        "tool": name,
                        "severity": "info",
                    }
                )
            elif known[name] != fp:
                findings.append(
                    {
                        "type": "mcp_tool_description_drift",
                        "server": server_id,
                        "tool": name,
                        "old_fingerprint": known[name],
                        "new_fingerprint": fp,
                        "severity": "high",
                    }
                )
            # else: unchanged, nothing to report

        for removed in set(known) - set(current):
            findings.append(
                {
                    "type": "mcp_tool_removed",
                    "server": server_id,
                    "tool": removed,
                    "severity": "medium",
                }
            )

        self.save(server_id, current)
        return findings


def scan_tool_description(
    tool: dict[str, Any], scan_fn
) -> list[dict[str, Any]]:
    """Run *scan_fn* (the DetectorChain) against a tool description.

    ``scan_fn`` must accept ``(text: str, context: dict | None)`` and
    return a list of violations — that is exactly the
    ``DetectorChain.check`` signature, so the chain stays the single
    source of injection-pattern truth.
    """
    text = " ".join(
        part for part in (
            tool.get("name", ""),
            tool.get("description", ""),
            json.dumps(tool.get("inputSchema") or {}, ensure_ascii=False),
        ) if part
    )
    findings = scan_fn(
        text, context={"source": f"mcp_tool_description:{tool.get('name', '?')}", "hook": "mcp_tools_list"}
    )
    # G-003 (Agent-Smith review): flag structural poisoning — injection
    # text hidden inside JSON-Schema keys that carry validation semantics.
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        for key in _SUSPICIOUS_SCHEMA_KEYS:
            value = schema.get(key)
            if isinstance(value, str) and _INJECTION_MARKER.search(value):
                findings.append(
                    {
                        "type": "mcp_schema_structural_poisoning",
                        "tool": tool.get("name", "?"),
                        "schema_key": key,
                        "severity": "high",
                    }
                )
    for finding in findings:
        # Tool-description injections are high severity by definition —
        # they land in the context window as *trusted* instructions.
        finding["severity"] = "high"
    return findings


_INJECTION_MARKER = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior)|disregard\s+|new\s+instructions?"
    r"|you\s+are\s+now|system\s*[:\-]|exfiltrate|curl\s+.{0,40}\$\(|base64\s+-d)",
)