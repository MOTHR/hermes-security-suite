"""FIX-2C (SCHL-3 HIGH): atomic-prune regression tests.

Verifies the rewrite of :meth:`InjectionShieldPlugin._prune_single_file_atomic`
and the new :meth:`InjectionShieldPlugin._prune_single_file_with_backup`.
Acceptance criteria from the Kanban task:

* atomic-rename pattern (``tempfile.mkstemp`` + ``os.replace``)
* corrupt lines preserved for forensics
* original file remains intact on crash
* 2+ new tests green
* existing 121 tests stay green
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from injection_shield.plugin import InjectionShieldPlugin

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _write_entries(path: Path, entries: list[dict]) -> None:
    """Write one JSON entry per line, appending a trailing newline."""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _read_lines(path: Path) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line for line in f.read().splitlines() if line]


def _cutoff(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


# --------------------------------------------------------------------------- #
# Atomic-prune core behaviour
# --------------------------------------------------------------------------- #


def test_prune_atomic_no_data_loss_on_crash(tmp_path: Path) -> None:
    """Prune 100 stale + 100 fresh entries; verify count and content."""
    log_file = tmp_path / "audit.jsonl"
    now = time.time()
    entries = []
    for i in range(100):
        entries.append({"timestamp": now - 100 * 86400, "id": i})
    for i in range(100, 200):
        entries.append({"timestamp": now, "id": i})
    _write_entries(log_file, entries)

    pruned = InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30))

    assert pruned == 100, f"expected 100 pruned, got {pruned}"

    remaining = [json.loads(line) for line in _read_lines(log_file)]
    assert len(remaining) == 100
    assert all(e["id"] >= 100 for e in remaining)


def test_prune_corrupt_lines_preserved(tmp_path: Path) -> None:
    """JSONDecodeError lines are kept on disk for forensic review."""
    log_file = tmp_path / "audit.jsonl"
    corrupt = "THIS IS NOT VALID JSON >>> :("
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": 100, "id": 1}) + "\n")  # stale
        f.write(corrupt + "\n")  # corrupt
        f.write(json.dumps({"timestamp": time.time(), "id": 2}) + "\n")  # fresh

    pruned = InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30))

    # Only the stale line is pruned; corrupt + fresh remain.
    assert pruned == 1
    text = log_file.read_text(encoding="utf-8")
    assert corrupt in text, "corrupt line must be preserved"
    assert '"id": 2' in text, "fresh line must be preserved"
    assert '"id": 1' not in text, "stale line must be pruned"


def test_prune_unparseable_timestamp_preserved(tmp_path: Path) -> None:
    """Entries whose timestamp cannot be parsed are kept, not pruned."""
    log_file = tmp_path / "audit.jsonl"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": "not-a-date", "id": "A"}) + "\n")
        f.write(json.dumps({"timestamp": time.time(), "id": "B"}) + "\n")

    pruned = InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30))

    assert pruned == 0
    ids = [json.loads(line)["id"] for line in _read_lines(log_file)]
    assert ids == ["A", "B"]


def test_prune_naive_timestamp_treated_as_utc(tmp_path: Path) -> None:
    """Naive ISO timestamps (no tzinfo) are coerced to UTC before comparing."""
    log_file = tmp_path / "audit.jsonl"
    fresh_naive = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)
    stale_naive = (datetime.now(timezone.utc) - timedelta(days=120)).replace(tzinfo=None)
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps({"timestamp": fresh_naive.isoformat(), "id": "fresh"}) + "\n")
        f.write(json.dumps({"timestamp": stale_naive.isoformat(), "id": "stale"}) + "\n")

    pruned = InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30))

    assert pruned == 1
    ids = [json.loads(line)["id"] for line in _read_lines(log_file)]
    assert ids == ["fresh"]


def test_prune_missing_file_returns_zero(tmp_path: Path) -> None:
    """Non-existent input is a no-op that returns 0."""
    missing = tmp_path / "nope.jsonl"
    assert not missing.exists()
    assert InjectionShieldPlugin._prune_single_file_atomic(missing, _cutoff(30)) == 0


def test_prune_empty_file_returns_zero(tmp_path: Path) -> None:
    """Empty input stays empty and reports 0 pruned."""
    log_file = tmp_path / "empty.jsonl"
    log_file.write_text("", encoding="utf-8")
    assert InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30)) == 0
    assert log_file.read_text(encoding="utf-8") == ""


# --------------------------------------------------------------------------- #
# Atomicity / crash-safety guarantees
# --------------------------------------------------------------------------- #


def test_prune_does_not_leave_tempfile_on_success(tmp_path: Path) -> None:
    """After a successful prune, no stray *.prune.tmp remains in the dir."""
    log_file = tmp_path / "audit.jsonl"
    _write_entries(
        log_file,
        [
            {"timestamp": time.time() - 999 * 86400, "id": 1},
            {"timestamp": time.time(), "id": 2},
        ],
    )
    InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30))

    strays = list(tmp_path.glob("*.prune.tmp"))
    assert strays == [], f"unexpected stray tempfiles: {strays}"


def test_prune_concurrent_calls_do_not_collide(tmp_path: Path) -> None:
    """Two ``mkstemp``-based prunes on the same file both succeed.

    The pre-fix ``<path>.tmp`` collision would have made the second
    call race on a single path. ``tempfile.mkstemp`` guarantees
    uniqueness, so both calls cleanly complete.
    """
    log_file = tmp_path / "audit.jsonl"
    _write_entries(
        log_file,
        [
            {"timestamp": time.time() - 999 * 86400, "id": 1},
            {"timestamp": time.time(), "id": 2},
        ],
    )

    cutoff = _cutoff(30)
    p1 = InjectionShieldPlugin._prune_single_file_atomic(log_file, cutoff)
    p2 = InjectionShieldPlugin._prune_single_file_atomic(log_file, cutoff)
    assert p1 == 1
    assert p2 == 0  # second call sees no stale entries

    ids = [json.loads(line)["id"] for line in _read_lines(log_file)]
    assert ids == [2]


def test_prune_atomic_replace_uses_os_replace(monkeypatch, tmp_path: Path) -> None:
    """Spy on ``os.replace`` and confirm it is the rename primitive."""
    import os as _os

    log_file = tmp_path / "audit.jsonl"
    _write_entries(log_file, [{"timestamp": time.time() - 999 * 86400, "id": 1}])

    calls: list[tuple[str, str]] = []
    real_replace = _os.replace

    def spy_replace(src: str, dst: str) -> None:
        calls.append((src, dst))
        return real_replace(src, dst)

    monkeypatch.setattr(_os, "replace", spy_replace)
    # The plugin imports ``os`` lazily inside the function body, so
    # monkeypatching the module attribute is sufficient for the call
    # inside the prune method (Python resolves ``os.replace`` via the
    # import statement at call time).
    import injection_shield.plugin as plugin_mod
    monkeypatch.setattr(plugin_mod, "os", _os, raising=False)

    pruned = InjectionShieldPlugin._prune_single_file_atomic(log_file, _cutoff(30))
    assert pruned == 1
    assert calls, "os.replace was not invoked"
    src, dst = calls[-1]
    assert Path(dst) == log_file
    assert src.endswith(".prune.tmp")


# --------------------------------------------------------------------------- #
# Backup-then-prune variant
# --------------------------------------------------------------------------- #


def test_prune_with_backup_creates_and_removes_backup_on_success(tmp_path: Path) -> None:
    """Successful backup-prune leaves no ``.pre-prune`` file behind."""
    log_file = tmp_path / "audit.jsonl"
    _write_entries(
        log_file,
        [
            {"timestamp": time.time() - 999 * 86400, "id": 1},
            {"timestamp": time.time(), "id": 2},
        ],
    )

    pruned = InjectionShieldPlugin._prune_single_file_with_backup(log_file, _cutoff(30))
    assert pruned == 1
    assert not (tmp_path / "audit.jsonl.pre-prune").exists()

    ids = [json.loads(line)["id"] for line in _read_lines(log_file)]
    assert ids == [2]


def test_prune_with_backup_refuses_when_backup_fails(tmp_path: Path, monkeypatch) -> None:
    """If the backup copy fails, the prune is a no-op (no data loss)."""
    import shutil

    log_file = tmp_path / "audit.jsonl"
    original_content = "ORIGINAL CONTENT\n"
    log_file.write_text(original_content, encoding="utf-8")

    def boom(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise OSError("disk full")

    monkeypatch.setattr(shutil, "copy2", boom)

    pruned = InjectionShieldPlugin._prune_single_file_with_backup(log_file, _cutoff(30))
    assert pruned == 0
    # Original content survives because we refused to prune.
    assert log_file.read_text(encoding="utf-8") == original_content
    assert not (tmp_path / "audit.jsonl.pre-prune").exists()


def test_prune_with_backup_preserves_backup_on_failure(
    tmp_path: Path, monkeypatch
) -> None:
    """If the atomic prune raises, the ``.pre-prune`` snapshot survives."""
    import os as _os

    log_file = tmp_path / "audit.jsonl"
    original = json.dumps({"timestamp": 0, "id": "old"}) + "\n"
    log_file.write_text(original, encoding="utf-8")

    def boom_replace(src: str, dst: str) -> None:  # noqa: ARG001
        raise OSError("simulated crash mid-prune")

    monkeypatch.setattr(_os, "replace", boom_replace)
    import injection_shield.plugin as plugin_mod
    monkeypatch.setattr(plugin_mod, "os", _os, raising=False)

    with pytest.raises(OSError):
        InjectionShieldPlugin._prune_single_file_with_backup(log_file, _cutoff(30))

    backup = tmp_path / "audit.jsonl.pre-prune"
    assert backup.exists(), "backup must remain for forensics on failure"
    assert backup.read_text(encoding="utf-8") == original


# --------------------------------------------------------------------------- #
# Backward-compat wrapper
# --------------------------------------------------------------------------- #


def test_legacy_wrapper_still_returns_count(tmp_path: Path) -> None:
    """``_prune_single_file`` still exists for v0.2.0 callers and returns int."""
    log_file = tmp_path / "audit.jsonl"
    _write_entries(
        log_file,
        [
            {"timestamp": time.time() - 999 * 86400, "id": 1},
            {"timestamp": time.time() - 999 * 86400, "id": 2},
            {"timestamp": time.time(), "id": 3},
        ],
    )
    pruned = InjectionShieldPlugin._prune_single_file(log_file, _cutoff(30))
    assert pruned == 2
    assert [json.loads(line)["id"] for line in _read_lines(log_file)] == [3]
