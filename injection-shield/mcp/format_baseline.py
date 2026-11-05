"""Response format baseline and anomaly detection for MCP servers.

v0.4.0 (BUILD-IS-MCP-INTEGRITY)
"""

from __future__ import annotations

import json
import logging
import statistics
from typing import Any

logger = logging.getLogger(__name__)

# Expected top-level keys per MCP server (tool-agnostic shape).
# These are conservative baselines — most MCP tools return dicts
# with at least one of these keys.
KNOWN_MCP_SERVERS: dict[str, dict[str, Any]] = {
    "obsidian": {"expected_keys": {"content", "path", "filename", "note"}, "typical_size": 2048},
    "telegram": {"expected_keys": {"message", "chat", "from", "update_id", "text"}, "typical_size": 1024},
    "github": {"expected_keys": {"url", "html_url", "id", "login", "sha", "content", "tree"}, "typical_size": 4096},
    "vault_search": {"expected_keys": {"matches", "path", "content", "title"}, "typical_size": 3072},
    "browseos": {"expected_keys": {"url", "title", "content", "links", "headings"}, "typical_size": 8192},
}


class FormatBaseline:
    """Baseline of response shapes observed for a single MCP server.

    Tracks:
    - Expected top-level keys (set intersection over time)
    - Response size history (mean + stddev)
    - Tool name → typical response type mapping
    """

    def __init__(self, server_id: str) -> None:
        self.server_id = server_id
        self.expected_keys: set[str] = set()
        self.size_history: list[int] = []
        self.tool_shapes: dict[str, set[str]] = {}
        # Seed from static knowledge if available
        static = KNOWN_MCP_SERVERS.get(server_id, {})
        if static:
            self.expected_keys = set(static.get("expected_keys", []))
            typical = int(static.get("typical_size", 2048))
            self.size_history = [typical] * 5  # Prime with pseudo-history

    def observe(self, response: Any, tool_name: str = "") -> None:
        """Record a response observation into the baseline."""
        keys = self._extract_keys(response)
        size = self._response_size(response)
        if keys:
            self.expected_keys.update(keys)
        self.size_history.append(size)
        # Keep last 50 observations to bound memory
        if len(self.size_history) > 50:
            self.size_history = self.size_history[-50:]
        if tool_name:
            if tool_name not in self.tool_shapes:
                self.tool_shapes[tool_name] = set()
            self.tool_shapes[tool_name].update(keys)

    def check_anomaly(self, response: Any, tool_name: str = "") -> dict[str, Any]:
        """Return anomaly details, or empty dict if response looks normal.

        Checks:
        1. Key mismatch — response has zero keys from the expected set
        2. Size deviation — response size > 2σ from historical mean
        """
        anomalies: dict[str, Any] = {}
        keys = self._extract_keys(response)
        size = self._response_size(response)

        # Key check (only if we have a non-empty baseline)
        if self.expected_keys and keys:
            intersection = keys & self.expected_keys
            if not intersection:
                anomalies["key_mismatch"] = {
                    "expected_any": sorted(self.expected_keys),
                    "got_keys": sorted(keys),
                }

        # Size check (only with ≥ 3 observations)
        if len(self.size_history) >= 3:
            mean = statistics.mean(self.size_history)
            try:
                stdev = statistics.stdev(self.size_history)
            except statistics.StatisticsError:
                stdev = 0.0
            # Guard against zero stdev (all identical sizes)
            threshold = mean + 2 * max(stdev, mean * 0.1)
            if size > threshold:
                anomalies["size_anomaly"] = {
                    "size": size,
                    "mean": round(mean, 1),
                    "threshold": round(threshold, 1),
                }

        return anomalies

    @staticmethod
    def _extract_keys(response: Any) -> set[str]:
        """Return top-level keys if *response* is a dict."""
        if isinstance(response, dict):
            return set(response.keys())
        return set()

    @staticmethod
    def _response_size(response: Any) -> int:
        """Approximate byte size of the serialised response."""
        try:
            return len(json.dumps(response, ensure_ascii=False, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            return len(str(response).encode("utf-8", errors="replace"))


# Global baselines keyed by server_id
_baselines: dict[str, FormatBaseline] = {}


def _get_baseline(server_id: str) -> FormatBaseline:
    if server_id not in _baselines:
        _baselines[server_id] = FormatBaseline(server_id)
    return _baselines[server_id]


def detect_format_anomaly(
    server_id: str,
    response: Any,
    tool_name: str = "",
    *,
    learn: bool = True,
) -> dict[str, Any]:
    """One-shot format anomaly check.

    Args:
        server_id: MCP server identifier (e.g. ``"obsidian"``).
        response: The tool response to evaluate.
        tool_name: Optional tool name for tool-specific baselines.
        learn: If ``True``, the response is also recorded into the
            baseline so future checks improve.

    Returns:
        Empty dict if no anomaly, otherwise a dict with detected
        anomaly types (``key_mismatch``, ``size_anomaly``).
    """
    baseline = _get_baseline(server_id)
    anomalies = baseline.check_anomaly(response, tool_name)
    if learn:
        baseline.observe(response, tool_name)
    return anomalies
