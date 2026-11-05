"""SHA256 hash-logging and optional public-key pinning for MCP responses.

v0.4.0 (BUILD-IS-MCP-INTEGRITY)
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# ResponseHasher
# --------------------------------------------------------------------------- #


class ResponseHasher:
    """Compute and verify SHA256 hashes of MCP tool responses.

    The hasher canonicalises the response payload (JSON → bytes
    via UTF-8 with sorted keys) so that semantically identical
    payloads produce identical digests regardless of dict ordering.
    """

    def __init__(self, hash_log_dir: Path | str | None = None) -> None:
        if hash_log_dir is None:
            hash_log_dir = Path.home() / ".hermes" / "profiles" / "default" / "workspace" / "05-Logs-Snapshots"
        self.hash_log_dir = Path(hash_log_dir).expanduser()
        self.hash_log_dir.mkdir(parents=True, exist_ok=True)

    def hash_response(self, response: Any) -> str:
        """Return the hex-encoded SHA256 digest of *response*.

        Args:
            response: Any JSON-serialisable value.

        Returns:
            64-char lowercase hex string.
        """
        raw = self._canonical_bytes(response)
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _canonical_bytes(value: Any) -> bytes:
        """Serialise *value* to canonical UTF-8 bytes."""
        if isinstance(value, bytes):
            return value
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        except (TypeError, ValueError):
            return str(value).encode("utf-8", errors="replace")

    def log_hash(
        self,
        server_id: str,
        tool_name: str,
        response: Any,
        *,
        timestamp: str = "",
    ) -> str:
        """Append a hash entry to the per-server hash log.

        Returns:
            The computed digest.
        """
        digest = self.hash_response(response)
        log_path = self._log_path(server_id)
        entry = {
            "timestamp": timestamp or "",
            "tool": tool_name,
            "digest": digest,
        }
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError as exc:
            logger.warning("mcp-integrity: failed to write hash log for %s: %s", server_id, exc)
        return digest

    def read_log(self, server_id: str) -> list[dict[str, Any]]:
        """Read all hash-log entries for *server_id*."""
        log_path = self._log_path(server_id)
        if not log_path.exists():
            return []
        entries: list[dict[str, Any]] = []
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return entries

    def verify_against_log(
        self,
        server_id: str,
        response: Any,
    ) -> bool:
        """Check whether *response* matches any prior hash in the log.

        Returns ``True`` if the log is empty (no baseline yet).
        """
        digest = self.hash_response(response)
        entries = self.read_log(server_id)
        if not entries:
            return True  # No baseline yet → pass
        return any(entry.get("digest") == digest for entry in entries)

    def _log_path(self, server_id: str) -> Path:
        """Sanitise *server_id* into a filesystem-safe filename."""
        safe = "".join(c for c in server_id if c.isalnum() or c in "-_").rstrip("_")
        if not safe:
            safe = "unknown"
        return self.hash_log_dir / f"mcp-{safe}-hashes.jsonl"


# --------------------------------------------------------------------------- #
# Module-level convenience
# --------------------------------------------------------------------------- #

_default_hasher: ResponseHasher | None = None


def _get_default_hasher() -> ResponseHasher:
    global _default_hasher
    if _default_hasher is None:
        _default_hasher = ResponseHasher()
    return _default_hasher


def compute_response_hash(response: Any) -> str:
    """One-shot hash of *response* (no log interaction)."""
    return _get_default_hasher().hash_response(response)
