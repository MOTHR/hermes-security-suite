#!/usr/bin/env python3
"""Privacy-Shield Auto-Apply Hook — idempotent, multi-patch Core management.

Applies the Privacy-Shield Defense-in-Depth patches to ``turn_context.py``
and re-applies them after Hermes updates. Each patch is an independent
``PatchSpec`` (distinct marker, anchor, backup prefix) so patches can
coexist, be applied/reverted independently, and survive Hermes updates via
marker+anchor detection with backup + ``compile()`` verify + auto-rollback.

Patches:
  - HARDBLOCK        : fail-safe check (Spec v1.0.1 Section 4)
  - OVERRIDE_CAPTURE : capture ``pre_llm_call`` ``user_message`` override (4b)
  - OVERRIDE_STAMP   : stamp the sanitized text as the ``api_content`` sidecar (4b)

Usage:
    auto_apply_hook.py --dry-run          # Show what would happen (all patches)
    auto_apply_hook.py --apply            # Apply all patches (idempotent)
    auto_apply_hook.py --revert [NAME]    # Revert one patch (by spec name) or all
    auto_apply_hook.py --status           # Show per-patch status
    auto_apply_hook.py --install-cron     # Install 6h cron job
    auto_apply_hook.py --prune-expired    # Delete expired mapping tokens (TTL cleanup)

Exit codes:
    0  Success (applied or already present)
    1  General error
    2  Apply failed + rollback performed
    3  Unknown turn_context.py layout — no blind patching
    4  Backup not found (revert)
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ────────────────────────────────────────────────────

TURN_CONTEXT_PATH = Path.home() / ".hermes" / "hermes-agent" / "agent" / "turn_context.py"
BACKUP_DIR = Path.home() / ".hermes" / "hermes-agent" / "agent"
LOG_PATH = Path.home() / ".hermes" / "privacy" / "auto-apply.log"
LOCK_PATH = Path.home() / ".hermes" / "privacy" / "auto-apply.lock"


# ── Patch specifications ─────────────────────────────────────────────


@dataclass(frozen=True)
class PatchSpec:
    """One idempotent patch applied to turn_context.py.

    Attributes:
        name: short identifier (used by ``--revert NAME`` / status).
        marker: fingerprint comment proving "this patch is present"
            (``is_patch_applied`` substring-checks this). Must be unique
            across specs and not a substring of another spec's marker.
        anchor: stable upstream landmark line; the patch is inserted before
            the first line containing this string (``locate_insertion_point``).
            Must appear exactly once in the target file.
        patch_lines: the lines to insert (with correct indentation).
        backup_prefix: backup files are named
            ``turn_context.py.bak.{backup_prefix}.{timestamp}`` so each patch
            has an independent revert history.
        nearby_hallmarks: at least one of these must appear within ±20 lines
            of the anchor (layout sanity).
        file_hallmarks: at least one of these must appear anywhere in the file
            (proves it is turn_context.py).
    """

    name: str
    marker: str
    anchor: str
    patch_lines: tuple[str, ...]
    backup_prefix: str
    nearby_hallmarks: tuple[str, ...] = field(default_factory=tuple)
    file_hallmarks: tuple[str, ...] = field(default_factory=tuple)


# HARDBLOCK — Defense-in-Depth check (Spec v1.0.1 Section 4)
HARDBLOCK_MARKER = "# Privacy-Shield Defense-in-Depth Check (Spec v1.0.1 Section 4)"
# v0.21.5 (commit 84c2e326f2) moved the pre_llm_call call-site: the old standalone
# anchor comment was removed during the build_turn_context helper split. The call
# ``plugin_user_context = _collect_pre_llm_call_context(`` is now the stable
# landmark (occurs exactly once, same position in the turn prologue).
HARDBLOCK_ANCHOR = "plugin_user_context = _collect_pre_llm_call_context("
HARDBLOCK_PATCH_LINES = (
    "    # Privacy-Shield Defense-in-Depth Check (Spec v1.0.1 Section 4)",
    "    # Wenn Cloud-Provider und Privacy-Shield-Plugin nicht geladen → Hard-Block",
    "    # Verhindert silent PII-Leak bei Plugin-Crash oder Loader-Regression",
    "    try:",
    "        from hermes_cli.plugins import _get_enabled_plugins as _get_enabled_plugins",
    "        from hermes_cli.lifecycle import has_hook as _has_hook",
    "        _privacy_cfg = _get_enabled_plugins() or set()",
    '        if "privacy-shield" in _privacy_cfg and agent.provider not in ("ollama_local", "ollama"):',
    '            if not _has_hook("pre_llm_call"):',
    "                raise RuntimeError(",
    '                    "Privacy-Shield is enabled in config (plugins.enabled includes "',
    "                    \"'privacy-shield') but the privacy-shield plugin is not loaded. \"",
    '                    "Install: hermes plugin install privacy-shield"',
    "                )",
    "    except RuntimeError:",
    "        raise",
    "    except Exception as _exc:",
    '        logger.warning("Privacy-Shield check failed: %s", _exc)',
    "",
)

# OVERRIDE_CAPTURE — read the ``user_message`` key from pre_llm_call results
# (Spec v1.0.1 Section 4b). Runs after the result loop, before ``if _ctx_parts:``.
OVERRIDE_CAPTURE_MARKER = "# Privacy-Shield User-Message Override Capture (Spec v1.0.1 Section 4b)"
OVERRIDE_CAPTURE_ANCHOR = "if _ctx_parts:"
OVERRIDE_CAPTURE_PATCH_LINES = (
    "        # Privacy-Shield User-Message Override Capture (Spec v1.0.1 Section 4b)",
    '        agent._privacy_shield_override = ""',
    "        for _r_ovr in _pre_results:",
    '            if isinstance(_r_ovr, dict) and _r_ovr.get("user_message"):',
    '                agent._privacy_shield_override = str(_r_ovr["user_message"])',
    "                break",
)

# OVERRIDE_STAMP — rebind ``_api_content`` to the sanitized override so the
# existing stamp, the in-place-compaction DB backfill, and turn-N+1 replay all
# carry the sanitized ``api_content`` sidecar (Spec v1.0.1 Section 4b).
OVERRIDE_STAMP_MARKER = "# Privacy-Shield User-Message Override (Spec v1.0.1 Section 4b)"
OVERRIDE_STAMP_ANCHOR = 'if _api_content is not None and _api_content != _turn_user_msg.get("content"):'
OVERRIDE_STAMP_PATCH_LINES = (
    "        # Privacy-Shield User-Message Override (Spec v1.0.1 Section 4b)",
    '        _ps_override = getattr(agent, "_privacy_shield_override", "")',
    "        if isinstance(_ps_override, str) and _ps_override:",
    "            _ps_composed = compose_user_api_content(",
    "                _ps_override, ext_prefetch_cache, plugin_user_context",
    "            ) or _ps_override",
    '            if _ps_composed != _turn_user_msg.get("content"):',
    "                _api_content = _ps_composed",
)


HARDBLOCK_SPEC = PatchSpec(
    name="hardblock",
    marker=HARDBLOCK_MARKER,
    anchor=HARDBLOCK_ANCHOR,
    patch_lines=HARDBLOCK_PATCH_LINES,
    backup_prefix="hardblock",
    # v0.21.5 layout check: the call-site sits directly under the turn-start
    # compaction block; old anchors no longer hold ``agent.provider`` nearby.
    nearby_hallmarks=("run_turn_start_compaction", "agent._flush_messages_to_session_db"),
    file_hallmarks=("def run_agent", "def _run_turn", "def build_turn_context"),
)

OVERRIDE_CAPTURE_SPEC = PatchSpec(
    name="override_capture",
    marker=OVERRIDE_CAPTURE_MARKER,
    anchor=OVERRIDE_CAPTURE_ANCHOR,
    patch_lines=OVERRIDE_CAPTURE_PATCH_LINES,
    backup_prefix="override_capture",
    nearby_hallmarks=("_pre_results", "plugin_user_context"),
    file_hallmarks=("def build_turn_context",),
)

OVERRIDE_STAMP_SPEC = PatchSpec(
    name="override_stamp",
    marker=OVERRIDE_STAMP_MARKER,
    anchor=OVERRIDE_STAMP_ANCHOR,
    patch_lines=OVERRIDE_STAMP_PATCH_LINES,
    backup_prefix="override_stamp",
    nearby_hallmarks=("compose_user_api_content", "_turn_user_msg"),
    file_hallmarks=("def build_turn_context",),
)

ALL_SPECS = (HARDBLOCK_SPEC, OVERRIDE_CAPTURE_SPEC, OVERRIDE_STAMP_SPEC)
SPECS_BY_NAME = {s.name: s for s in ALL_SPECS}

# Backward-compatible module-level singletons (existing tests/fixtures use these).
MARKER_COMMENT = HARDBLOCK_SPEC.marker
LOCATE_ANCHOR = HARDBLOCK_SPEC.anchor
PATCH_LINES = list(HARDBLOCK_SPEC.patch_lines)


# ── Logging ─────────────────────────────────────────────────────────


def _log(entry: dict) -> None:
    """Append a structured JSON log entry."""
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    entry["script_version"] = "1.1.0"
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _log_event(event: str, detail: str = "", exit_code: int = 0, spec: str = "") -> None:
    _log({"event": event, "detail": detail, "exit_code": exit_code, "spec": spec})


# ── File locking ────────────────────────────────────────────────────


def _acquire_lock():
    """Acquire an exclusive file lock to prevent concurrent runs."""
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    fh = open(LOCK_PATH, "w")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fh


def _release_lock(fh):
    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
    fh.close()


# ── Core logic (spec-aware) ─────────────────────────────────────────


def is_patch_applied(filepath: Path, spec: PatchSpec = HARDBLOCK_SPEC) -> bool:
    """Check if the spec's marker comment exists in the file."""
    if not filepath.exists():
        return False
    content = filepath.read_text(encoding="utf-8")
    return spec.marker in content


def locate_insertion_point(lines: list[str], spec: PatchSpec = HARDBLOCK_SPEC) -> int | None:
    """Find the line index where the patch should be inserted (before the anchor).

    Returns the index of the first line containing the anchor, or None.
    """
    for idx, line in enumerate(lines):
        if spec.anchor in line:
            return idx
    return None


def validate_context(
    lines: list[str],
    insert_idx: int | None,
    spec: PatchSpec = HARDBLOCK_SPEC,
) -> tuple[bool, str]:
    """Validate the surrounding context before patching.

    Checks:
      - Anchor line exists
      - At least 2 lines before anchor (sanity check)
      - At least one nearby hallmark within ±20 lines of the anchor
      - At least one file hallmark anywhere in the file
    """
    if insert_idx is None:
        return False, f"{spec.anchor!r} not found — unknown layout"

    if insert_idx < 2:
        return False, "Not enough context lines before anchor"

    # Nearby hallmarks within ±20 lines of the anchor
    if spec.nearby_hallmarks:
        nearby = lines[max(0, insert_idx - 20): min(len(lines), insert_idx + 20)]
        nearby_text = "\n".join(nearby)
        if not any(h in nearby_text for h in spec.nearby_hallmarks):
            return False, f"No nearby hallmark {spec.nearby_hallmarks} — unknown layout"

    # File hallmarks anywhere in the file
    if spec.file_hallmarks:
        joined = "\n".join(lines)
        if not any(h in joined for h in spec.file_hallmarks):
            return False, f"No file hallmark {spec.file_hallmarks} — unknown layout"

    return True, ""


def apply_patch(
    filepath: Path,
    dry_run: bool = False,
    spec: PatchSpec = HARDBLOCK_SPEC,
) -> tuple[bool, str]:
    """Apply the patch. Returns (success, message).

    Steps: check-applied → locate → validate → backup → insert → verify → log.
    """
    if not filepath.exists():
        return False, f"Target file not found: {filepath}"

    # Step 1: Already applied?
    if is_patch_applied(filepath, spec):
        msg = f"[{spec.name}] Patch already applied — nothing to do"
        _log_event("skip_already_applied", msg, spec=spec.name)
        return True, msg

    # Step 2: Locate
    original_lines = filepath.read_text(encoding="utf-8").splitlines()
    insert_idx = locate_insertion_point(original_lines, spec)

    # Step 3: Validate context
    ok, reason = validate_context(original_lines, insert_idx, spec)
    if not ok:
        _log_event("abort_unknown_layout", reason, exit_code=3, spec=spec.name)
        return False, f"[{spec.name}] ABORT: {reason}"

    assert insert_idx is not None  # mypy

    # Step 4: Backup
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"turn_context.py.bak.{spec.backup_prefix}.{timestamp}"
    if dry_run:
        print(f"[DRY-RUN] [{spec.name}] Would create backup: {backup_path}")
    else:
        shutil.copy2(filepath, backup_path)
        print(f"[{spec.name}] Backup created: {backup_path}")

    # Step 5: Insert patch
    new_lines = original_lines[:insert_idx] + list(spec.patch_lines) + original_lines[insert_idx:]
    new_content = "\n".join(new_lines) + "\n"

    if dry_run:
        print(f"[DRY-RUN] [{spec.name}] Would insert {len(spec.patch_lines)} lines before line {insert_idx + 1}")
        print(f"[DRY-RUN] Patch preview:")
        for ln in spec.patch_lines:
            print(f"  + {ln}")
        _log_event("dry_run", f"Would insert {len(spec.patch_lines)} lines at {insert_idx + 1}", spec=spec.name)
        return True, f"[{spec.name}] Dry-run completed — no changes made"

    filepath.write_text(new_content, encoding="utf-8")
    print(f"[{spec.name}] Patch inserted at line {insert_idx + 1} ({len(spec.patch_lines)} lines)")

    # Step 6: Verify
    verify_ok, verify_msg = verify_patch(filepath, spec)
    if not verify_ok:
        # Rollback
        print(f"[{spec.name}] VERIFY FAILED: {verify_msg}")
        print(f"[{spec.name}] Rolling back from {backup_path} ...")
        shutil.copy2(backup_path, filepath)
        _log_event("rollback", f"Verify failed: {verify_msg}", exit_code=2, spec=spec.name)
        return False, f"[{spec.name}] APPLY FAILED + ROLLBACK: {verify_msg}"

    _log_event("applied", f"Inserted {len(spec.patch_lines)} lines at {insert_idx + 1}", spec=spec.name)
    return True, f"[{spec.name}] Patch applied successfully ({len(spec.patch_lines)} lines inserted)"


def verify_patch(filepath: Path, spec: PatchSpec = HARDBLOCK_SPEC) -> tuple[bool, str]:
    """Verify the patch was applied correctly: marker present + valid syntax."""
    if not is_patch_applied(filepath, spec):
        return False, f"[{spec.name}] Marker comment not found after apply"

    # Syntax check (whole file — a patch must not break the module)
    try:
        compile(filepath.read_text(encoding="utf-8"), str(filepath), "exec")
    except SyntaxError as exc:
        return False, f"[{spec.name}] Syntax error: {exc}"

    return True, f"[{spec.name}] Patch verified OK"


def revert_patch(filepath: Path, spec: PatchSpec = HARDBLOCK_SPEC) -> tuple[bool, str]:
    """Restore the most recent backup for this spec.

    Backups are namespaced by ``spec.backup_prefix`` so reverting one patch
    never clobbers another patch's state.
    """
    if not filepath.exists():
        return False, f"Target file not found: {filepath}"

    # Find most recent backup for THIS spec only
    backups = sorted(
        BACKUP_DIR.glob(f"turn_context.py.bak.{spec.backup_prefix}.*"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not backups:
        return False, f"[{spec.name}] No backup found"

    latest = backups[0]
    shutil.copy2(latest, filepath)

    # Verify this spec's marker is gone
    if is_patch_applied(filepath, spec):
        return False, f"[{spec.name}] Rollback from {latest} failed — marker still present"

    _log_event("reverted", f"Restored from {latest.name}", spec=spec.name)
    return True, f"[{spec.name}] Reverted from {latest.name}"


def get_status() -> dict:
    """Return current status for all patches.

    Keeps the historical single-patch keys (``file_exists``, ``patch_applied``,
    ``backups`` — all hardblock-based) for backward compatibility, plus a
    ``patches`` list with per-spec status.
    """
    per_spec = []
    for spec in ALL_SPECS:
        backups = sorted(
            BACKUP_DIR.glob(f"turn_context.py.bak.{spec.backup_prefix}.*"),
            key=lambda p: p.stat().st_mtime,
        )
        per_spec.append({
            "name": spec.name,
            "marker": spec.marker,
            "anchor": spec.anchor,
            "applied": is_patch_applied(TURN_CONTEXT_PATH, spec),
            "backups": [b.name for b in backups],
        })
    return {
        "target_file": str(TURN_CONTEXT_PATH),
        "file_exists": TURN_CONTEXT_PATH.exists(),
        # Backward-compatible hardblock-centric keys:
        "patch_applied": is_patch_applied(TURN_CONTEXT_PATH, HARDBLOCK_SPEC),
        "backups": [b.name for b in sorted(
            BACKUP_DIR.glob("turn_context.py.bak.hardblock.*"),
            key=lambda p: p.stat().st_mtime,
        )],
        "patches": per_spec,
        "log_file": str(LOG_PATH),
    }


def install_cron() -> tuple[bool, str]:
    """Install a 6-hourly cron job for auto-apply (all patches)."""
    script_path = Path(__file__).resolve()
    cron_line = (
        f"0 */6 * * * /usr/bin/python3 {script_path} --apply "
        f">> {LOG_PATH} 2>&1\n"
    )

    # Read current crontab
    result = subprocess.run(
        ["crontab", "-l"],
        capture_output=True,
        text=True,
    )
    current = result.stdout if result.returncode == 0 else ""

    if str(script_path) in current:
        return True, "Cron job already installed"

    new_crontab = current + cron_line
    proc = subprocess.run(
        ["crontab", "-"],
        input=new_crontab,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return False, f"crontab install failed: {proc.stderr}"

    _log_event("cron_installed", f"6h cron for {script_path}")
    return True, "Cron job installed: every 6 hours"


def prune_expired_mappings() -> tuple[bool, str]:
    """Delete all expired mapping tokens from the mapping table.

    Implements Google-Empfehlung TTL cleanup.
    Returns (success, message).
    """
    try:
        # Add plugins dir to path so we can import privacy_shield
        # (symlink privacy_shield -> privacy-shield lives in plugins/)
        plugin_dir = str(Path(__file__).resolve().parent.parent.parent)
        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)

        from privacy_shield.mapping_table import MappingTable
        from privacy_shield.config import load_config

        config = load_config()
        mapper = MappingTable(
            storage_path=config.storage_path,
            encryption_key=config.encryption_key,
        )

        expired_count = mapper.expired_count()
        deleted = mapper.prune_expired()

        msg = (
            f"prune_expired: {expired_count} expired before cleanup, "
            f"{deleted} deleted, {mapper.count()} remaining"
        )
        _log_event("prune_expired", msg)
        return True, msg
    except Exception as exc:
        msg = f"prune_expired failed: {exc}"
        _log_event("prune_expired_error", msg, exit_code=1)
        return False, msg


# ── Multi-patch orchestration ───────────────────────────────────────


def apply_all(filepath: Path, dry_run: bool = False) -> tuple[bool, str, int]:
    """Apply every spec in order. Returns (ok, summary, exit_code).

    Exit code is the worst outcome: 3 (any abort) > 2 (any rollback) > 0.
    """
    messages = []
    worst = 0
    all_ok = True
    for spec in ALL_SPECS:
        ok, msg = apply_patch(filepath, dry_run=dry_run, spec=spec)
        messages.append(msg)
        if not ok:
            all_ok = False
            if "ABORT" in msg:
                worst = max(worst, 3)
            elif "ROLLBACK" in msg:
                worst = max(worst, 2)
            else:
                worst = max(worst, 1)
    return all_ok, "\n".join(messages), worst


def revert_all(filepath: Path) -> tuple[bool, str, int]:
    """Revert every spec in reverse order. Returns (ok, summary, exit_code)."""
    messages = []
    any_fail = False
    for spec in reversed(ALL_SPECS):
        ok, msg = revert_patch(filepath, spec=spec)
        messages.append(msg)
        if not ok:
            any_fail = True
    return not any_fail, "\n".join(messages), (4 if any_fail else 0)


# ── CLI ─────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Privacy-Shield Auto-Apply Hook (multi-patch)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              %(prog)s --status              # Per-patch status
              %(prog)s --dry-run             # Preview all patches
              %(prog)s --apply               # Apply all patches (idempotent)
              %(prog)s --revert              # Revert all patches
              %(prog)s --revert override_capture   # Revert one patch by name
              %(prog)s --install-cron        # Install 6h cron job

            Patch names: hardblock, override_capture, override_stamp
            """
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true", help="Preview changes")
    group.add_argument("--apply", action="store_true", help="Apply all patches")
    group.add_argument("--revert", nargs="?", const="all", default=None,
                       help="Revert all (no arg) or one patch by name")
    group.add_argument("--status", action="store_true", help="Show per-patch status")
    group.add_argument("--install-cron", action="store_true", help="Install cron job")
    group.add_argument("--prune-expired", action="store_true", help="Delete expired mapping tokens")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    lock_fh = None
    try:
        lock_fh = _acquire_lock()

        if args.status:
            status = get_status()
            print(json.dumps(status, indent=2))
            return 0

        if args.dry_run:
            ok, msg, _ = apply_all(TURN_CONTEXT_PATH, dry_run=True)
            print(msg)
            return 0 if ok else 1

        if args.apply:
            ok, msg, code = apply_all(TURN_CONTEXT_PATH, dry_run=False)
            print(msg)
            # "already applied" for every spec counts as success
            if all("already applied" in m.lower() for m in msg.splitlines()):
                return 0
            return code if code else 0

        if args.revert is not None:
            if args.revert == "all":
                ok, msg, code = revert_all(TURN_CONTEXT_PATH)
                print(msg)
                return code
            spec = SPECS_BY_NAME.get(args.revert)
            if spec is None:
                print(f"Unknown patch name: {args.revert!r}. "
                      f"Valid: {', '.join(SPECS_BY_NAME)}", file=sys.stderr)
                return 1
            ok, msg = revert_patch(TURN_CONTEXT_PATH, spec=spec)
            print(msg)
            return 0 if ok else 4

        if args.install_cron:
            ok, msg = install_cron()
            print(msg)
            return 0 if ok else 1

        if args.prune_expired:
            ok, msg = prune_expired_mappings()
            print(msg)
            return 0 if ok else 1

    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    finally:
        if lock_fh:
            _release_lock(lock_fh)

    return 1


if __name__ == "__main__":
    sys.exit(main())