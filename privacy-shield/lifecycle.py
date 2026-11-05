"""Plugin lifecycle helpers — graceful shutdown + JSON logging.

Morpheus R5 (FIX-PS-R5-STRUCT continuation): the module-level
shutdown hooks, signal handlers, and JSON-formatter plumbing that
used to live at the top of ``plugin.py`` belong in their own
module so the plugin class itself stays focused on hook
orchestration.

The functions are imported by ``plugin.py`` at module import time
so existing call sites (``_register_shutdown_hooks``,
``_maybe_enable_json_logging``) continue to work without the
plugin module being aware of the internal names.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import signal
import sys
from typing import Any

_logger = logging.getLogger(__name__)


# Tracks which plugin instances have already run their shutdown hook
# so duplicate atexit / SIGTERM invocations are idempotent.
_shutdown_done: set[int] = set()


def _shutdown_mapper(mapper: Any, instance_id: int) -> None:
    """Close ``mapper`` once per plugin instance.

    ``mapper.close()`` is a no-op for SQLite-backed tables and flushes
    in-memory tables; it is safe to call repeatedly, but we still guard
    against double-registration noise.
    """
    if instance_id in _shutdown_done:
        return
    _shutdown_done.add(instance_id)
    try:
        mapper.close()
    except Exception:  # pragma: no cover - defensive
        _logger.exception("Privacy-Shield: mapper shutdown failed")


def _sigterm_handler(mapper: Any, instance_id: int) -> Any:
    """Return a SIGTERM handler that closes the mapper gracefully."""

    def handler(signum: int, frame: Any | None) -> None:
        _shutdown_mapper(mapper, instance_id)
        # Re-raise the default termination so the process exits cleanly.
        signal.default_int_handler(signum, frame)

    return handler


def register_shutdown_hooks(mapper: Any, instance_id: int) -> None:
    """Register atexit + SIGTERM hooks for a plugin instance.

    ``signal`` is not available on Windows in all contexts, so the SIGTERM
    registration is wrapped in a broad try/except ImportError/AttributeError.
    """
    atexit.register(_shutdown_mapper, mapper, instance_id)
    try:
        signal.signal(signal.SIGTERM, _sigterm_handler(mapper, instance_id))
    except (ImportError, AttributeError, ValueError, OSError):  # pragma: no cover
        # Windows without SIGTERM, or restricted environments.
        pass


# ── Structured JSON logging (LINK-PS-8) ─────────────────────────────────────


class JsonFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def maybe_enable_json_logging() -> None:
    """Switch the ``privacy_shield`` logger to JSON output when LOG_JSON=1."""
    if os.environ.get("LOG_JSON") != "1":
        return
    root = logging.getLogger("privacy_shield")
    formatter = JsonFormatter()
    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        root.addHandler(handler)
        root.propagate = False
    else:
        for existing in root.handlers:
            existing.setFormatter(formatter)


# ── Backward-compat re-exports for test_graceful_shutdown.py ─────────────
# The test suite predates the lifecycle.py extraction and still imports
# the original private names.  Re-export them at the module level so
# the test file keeps working without modification.
_register_shutdown_hooks = register_shutdown_hooks
_maybe_enable_json_logging = maybe_enable_json_logging
_shutdown_mapper = _shutdown_mapper  # noqa: PLW0127
_sigterm_handler = _sigterm_handler  # noqa: PLW0127


__all__ = [
    "JsonFormatter",
    "maybe_enable_json_logging",
    "register_shutdown_hooks",
]
