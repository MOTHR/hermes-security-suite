"""Privacy-Shield rotating file logger (BUTLER-PS-4 / FIX-PS-R5-OPS).

Provides a dedicated ``logging.handlers.RotatingFileHandler`` for the
``privacy_shield`` logger so that operator logs (warnings, info) cannot
grow without bound. Defaults match Injection-Shield for cross-plugin
consistency:

* ``audit_log_max_bytes`` = 10 MiB
* ``audit_log_backup_count`` = 5 rotated files
* ``audit_log_retention_days`` = 90 days (DSGVO Art. 5(1)(e))

The module is wired in from :class:`PrivacyShieldPlugin.__init__` and is
idempotent: subsequent calls return the same handler without stacking
duplicate Formatter instances on the same logger.

Configuration is read from plugin.yaml (settings keys prefixed
``audit_log_*``) with the documented defaults as fallback. Tests may
pass an explicit ``log_path`` to redirect the stream to ``tmp_path``.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

# Defaults — match the Injection-Shield config so operators can reason
# about both plugins the same way. These are intentionally module-level
# constants (not configurable at runtime) so the Privacy-Shield audit
# contract is stable across Hermes upgrades.
DEFAULT_LOG_PATH = "~/.hermes/profiles/default/workspace/05-Logs-Snapshots/privacy-shield.log"
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_BACKUP_COUNT = 5
DEFAULT_RETENTION_DAYS = 90

_LOGGER_NAME = "privacy_shield"
_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def _resolve_log_path(log_path: Optional[str]) -> Path:
    """Return the absolute Path for the rotating log file."""
    candidate = log_path or DEFAULT_LOG_PATH
    return Path(os.path.expanduser(candidate))


def ensure_log_dir(log_path: Path) -> None:
    """Create the parent directory with chmod 700 (best-effort)."""
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(log_path.parent, 0o700)
    except OSError:
        # Best-effort; if the filesystem refuses the chmod the logger
        # still works, the file just won't be hardened on disk.
        pass


def _ensure_file_perms(log_path: Path) -> None:
    """Tighten the log file to chmod 600 (best-effort).

    ``logging.handlers.RotatingFileHandler`` opens the file in append
    mode without applying a umask; on a permissive umask the file can
    end up world-readable. We re-apply 600 after every open so the
    privacy-shield operator log converges to the documented hardening
    within one process start, even when an older deployment shipped
    the file with looser permissions.
    """
    if not log_path.exists():
        return
    try:
        os.chmod(log_path, 0o600)
    except OSError:
        pass


def build_rotating_handler(
    log_path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> logging.handlers.RotatingFileHandler:
    """Return a fresh :class:`RotatingFileHandler` configured for privacy-shield.

    The handler rotates at ``max_bytes`` and keeps ``backup_count``
    rotated files alongside the active one. Encoding is UTF-8 so emoji
    / German umlauts survive rotation without corruption. The active
    file is chmod-600 so the operator log cannot leak across users on
    a shared host even if the default umask is permissive.
    """
    ensure_log_dir(log_path)
    _ensure_file_perms(log_path)
    handler = logging.handlers.RotatingFileHandler(
        str(log_path),
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )

    # Re-apply chmod on every rotation so backups also stay at 600.
    original_rotate = handler.rotate

    def _rotate_with_perms(source: str, dest: str) -> None:
        original_rotate(source, dest)
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass

    handler.rotate = _rotate_with_perms  # type: ignore[method-assign]

    # First-write chmod: ``RotatingFileHandler.emit`` opens the file
    # lazily on first write, so we wrap ``emit`` to tighten perms once
    # the file is materialised on disk.
    original_emit = handler.emit

    def _emit_with_perms(record: logging.LogRecord) -> None:
        original_emit(record)
        _ensure_file_perms(log_path)

    handler.emit = _emit_with_perms  # type: ignore[method-assign]
    return handler


def attach_rotating_handler(
    log_path: Optional[str] = None,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    prune_now: bool = True,
) -> Optional[logging.Handler]:
    """Attach the rotating handler to ``privacy_shield`` logger.

    Idempotent: if the logger already has a rotating handler attached,
    the existing handler is reused (not stacked). Returns the handler
    so callers can inspect or detach it (mostly used in tests).

    ``prune_now=True`` runs an opportunistic 90-day prune on the
    active log + rotated backups so that the plugin converges to its
    retention contract within one process start, even if the operator
    never wired up the dedicated cron.
    """
    resolved = _resolve_log_path(log_path)
    ps_logger = logging.getLogger(_LOGGER_NAME)

    # Idempotency: skip if a RotatingFileHandler is already attached.
    for existing in ps_logger.handlers:
        if isinstance(existing, logging.handlers.RotatingFileHandler):
            return existing

    handler = build_rotating_handler(
        resolved,
        max_bytes=max_bytes,
        backup_count=backup_count,
    )
    handler.setFormatter(logging.Formatter(_FORMAT))
    handler.setLevel(logging.INFO)
    ps_logger.addHandler(handler)

    if prune_now:
        try:
            prune_expired_entries(resolved, retention_days=retention_days)
        except OSError:
            # Best-effort; do not block plugin init on prune failures.
            pass

    return handler


def prune_expired_entries(
    log_path: Path,
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    """Drop log entries older than ``retention_days`` from log + backups.

    Returns the number of lines removed across all files. The prune is
    intentionally cheap (line-by-line parse of the ``%(asctime)s`` prefix)
    and is safe to run at every plugin init — with the default 10 MiB × 5
    backups the wall-clock cost is sub-100 ms.
    """
    if retention_days <= 0 or not log_path.exists():
        return 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    candidates = [log_path] + sorted(
        log_path.parent.glob(log_path.name + ".*"),
        key=lambda p: p.stat().st_mtime,
    )
    total_removed = 0
    for path in candidates:
        total_removed += _prune_single_file(path, cutoff)
    return total_removed


def _prune_single_file(path: Path, cutoff: datetime) -> int:
    """Rewrite ``path`` in place, dropping lines older than ``cutoff``.

    The first whitespace-separated token of each line is treated as an
    ISO-8601 timestamp (``2026-08-22T09:09:11Z``-style — what
    :class:`logging.Formatter` emits with ``%(asctime)s`` and the
    default ``datefmt``). Lines that don't parse are kept verbatim so
    we never accidentally drop a valid multi-line message.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return 0

    survivors: list[str] = []
    removed = 0
    for line in lines:
        stamp = line.split(" ", 1)[0] if line else ""
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            survivors.append(line)
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if parsed >= cutoff:
            survivors.append(line)
        else:
            removed += 1

    if removed == 0:
        return 0

    tmp = path.with_suffix(path.suffix + ".prune.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            fh.writelines(survivors)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except OSError:
        # If the atomic replace fails, leave the original file untouched.
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        return 0
    return removed


def detach_rotating_handler(logger: Optional[logging.Logger] = None) -> None:
    """Detach the rotating handler (used in tests for clean shutdown)."""
    target = logger or logging.getLogger(_LOGGER_NAME)
    for handler in list(target.handlers):
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            try:
                handler.close()
            except Exception:  # noqa: BLE001
                pass
            target.removeHandler(handler)


def settings_from_config(config: Any) -> dict[str, Any]:
    """Extract rotating-log settings from a :class:`PrivacyShieldConfig`.

    Falls back to module defaults when the keys are absent — keeps the
    contract forward-compatible with deployments that haven't yet added
    the new YAML keys.
    """
    if config is None:
        return {
            "log_path": DEFAULT_LOG_PATH,
            "max_bytes": DEFAULT_MAX_BYTES,
            "backup_count": DEFAULT_BACKUP_COUNT,
            "retention_days": DEFAULT_RETENTION_DAYS,
        }
    return {
        "log_path": getattr(config, "audit_log_path", DEFAULT_LOG_PATH),
        "max_bytes": int(
            getattr(config, "audit_log_max_bytes", DEFAULT_MAX_BYTES)
        ),
        "backup_count": int(
            getattr(config, "audit_log_backup_count", DEFAULT_BACKUP_COUNT)
        ),
        "retention_days": int(
            getattr(config, "audit_log_retention_days", DEFAULT_RETENTION_DAYS)
        ),
    }
