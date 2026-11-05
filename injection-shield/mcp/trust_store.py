"""Trust-level management for MCP servers.

v0.4.0 (BUILD-IS-MCP-INTEGRITY)
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TRUST_LOG_FILE = "mcp-trust-levels.json"


class TrustLevel(str, Enum):
    """Integrity trust level for an MCP server."""

    VERIFIED = "verified"
    """Hash + public-key signature matched on at least one response."""

    UNVERIFIED = "unverified"
    """Hash-log baseline exists and matches, but no public-key pin."""

    UNKNOWN = "unknown"
    """No provider info, no baseline, or first encounter."""


class TrustStore:
    """Persistent trust-level registry for MCP servers.

    Stores a JSON file mapping server_id → trust metadata:

    .. code-block:: json

        {
          "obsidian": {
            "level": "unverified",
            "first_seen": "2026-08-23T10:00:00+00:00",
            "last_seen": "2026-08-23T12:00:00+00:00",
            "hash_count": 42,
            "public_key_pin": null
          }
        }
    """

    def __init__(self, store_dir: Path | str | None = None) -> None:
        if store_dir is None:
            store_dir = Path.home() / ".hermes" / "profiles" / "default" / "workspace" / "05-Logs-Snapshots"
        self.store_dir = Path(store_dir).expanduser()
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #
    def get(self, server_id: str) -> TrustLevel:
        """Return the current trust level for *server_id*."""
        entry = self._data.get(server_id, {})
        level = entry.get("level")
        if level == TrustLevel.VERIFIED.value:
            return TrustLevel.VERIFIED
        if level == TrustLevel.UNVERIFIED.value:
            return TrustLevel.UNVERIFIED
        return TrustLevel.UNKNOWN

    def set_level(self, server_id: str, level: TrustLevel) -> None:
        """Set *server_id* to *level* and persist."""
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
        if server_id not in self._data:
            self._data[server_id] = {
                "first_seen": now,
                "hash_count": 0,
                "public_key_pin": None,
            }
        self._data[server_id]["level"] = level.value
        self._data[server_id]["last_seen"] = now
        self._save()

    def bump_hash_count(self, server_id: str) -> None:
        """Increment the hash-match counter for *server_id*."""
        if server_id in self._data:
            self._data[server_id]["hash_count"] = self._data[server_id].get("hash_count", 0) + 1
            self._save()

    def set_public_key_pin(self, server_id: str, public_key: str) -> None:
        """Store a pinned public-key fingerprint for *server_id*."""
        if server_id not in self._data:
            self.set_level(server_id, TrustLevel.UNKNOWN)
        self._data[server_id]["public_key_pin"] = public_key
        self._save()

    def summary(self) -> dict[str, dict[str, Any]]:
        """Return a shallow copy of the full registry."""
        return {k: dict(v) for k, v in self._data.items()}

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        path = self.store_dir / TRUST_LOG_FILE
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._data = json.load(f) or {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("mcp-integrity: failed to load trust store: %s", exc)
            self._data = {}

    def _save(self) -> None:
        path = self.store_dir / TRUST_LOG_FILE
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2, sort_keys=True)
        except OSError as exc:
            logger.warning("mcp-integrity: failed to save trust store: %s", exc)
