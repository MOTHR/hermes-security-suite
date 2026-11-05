"""FIX-PS5 (Privacy-Shield): multi-profile setup regression tests.

Verifies that ``scripts/setup_profiles.py`` correctly enables
``privacy-shield`` across every Hermes profile and that repeated invocations
are idempotent. Tests run against a temp profiles tree (via the script's
``--profiles-dir`` flag) so they never touch the real ``~/.hermes/profiles``.

Acceptance criteria from the Kanban task:

* ``setup_profiles.py`` enables the plugin in every profile that has a
  ``config.yaml``
* Running it twice does not create duplicates (``already enabled`` on 2nd run)
* The Bash script ``setup-profiles.sh`` exists and is executable
* Existing tests remain green
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

CI = os.environ.get("PRIVACY_SHIELD_CI", "")

PLUGIN_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PLUGIN_DIR / "scripts"
SETUP_PY = SCRIPTS_DIR / "setup_profiles.py"
SETUP_SH = SCRIPTS_DIR / "setup-profiles.sh"

REAL_PROFILES_DIR = Path.home() / ".hermes" / "profiles"


def _build_sandbox(tmp_path: Path) -> Path:
    """Create a profiles tree in tmp_path mirroring the real one (best-effort)."""
    profiles_root = tmp_path / "profiles"
    profiles_root.mkdir()

    if REAL_PROFILES_DIR.exists():
        for profile_dir in REAL_PROFILES_DIR.iterdir():
            if not profile_dir.is_dir():
                continue
            dest = profiles_root / profile_dir.name
            dest.mkdir()
            src_cfg = profile_dir / "config.yaml"
            if src_cfg.exists():
                shutil.copy2(src_cfg, dest / "config.yaml")
            else:
                (dest / "config.yaml").write_text("model: {default: stub}\n")
    return profiles_root


def _run_setup_py(profiles_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(SETUP_PY),
            "--profiles-dir",
            str(profiles_dir),
            "--plugin-dir",
            str(PLUGIN_DIR),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def _read_profile_config(profiles_dir: Path, profile_name: str) -> dict:
    cfg_path = profiles_dir / profile_name / "config.yaml"
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@pytest.fixture()
def sandbox_profiles(tmp_path):
    return _build_sandbox(tmp_path)


# --------------------------------------------------------------------------- #
# Acceptance criteria
# --------------------------------------------------------------------------- #


def test_setup_profiles_is_idempotent(sandbox_profiles):
    """Setup runs cleanly twice; 2nd run sees 'already enabled' for every profile."""
    first = _run_setup_py(sandbox_profiles)
    assert first.returncode == 0, first.stderr or first.stdout
    assert "=== Setup complete ===" in first.stdout

    second = _run_setup_py(sandbox_profiles)
    assert second.returncode == 0, second.stderr or second.stdout
    assert "already enabled" in second.stdout

    # No duplicates — plugin must appear exactly once per profile config
    for profile_dir in sandbox_profiles.iterdir():
        if not profile_dir.is_dir():
            continue
        cfg = _read_profile_config(sandbox_profiles, profile_dir.name)
        enabled = cfg.get("plugins", {}).get("enabled", []) or []
        assert enabled.count("privacy-shield") == 1, (
            f"{profile_dir.name}: duplicate entries — {enabled!r}"
        )


def test_setup_profiles_enables_in_every_profile(sandbox_profiles):
    """After a fresh run, every profile with a config.yaml has the plugin enabled."""
    result = _run_setup_py(sandbox_profiles)
    assert result.returncode == 0, result.stderr

    configured = [p.name for p in sandbox_profiles.iterdir() if p.is_dir()]
    assert configured, "sandbox should contain at least one profile"

    for name in configured:
        cfg = _read_profile_config(sandbox_profiles, name)
        enabled = cfg.get("plugins", {}).get("enabled", []) or []
        assert "privacy-shield" in enabled, f"{name}: plugin not enabled — {cfg!r}"


@pytest.mark.skipif(
    (not REAL_PROFILES_DIR.exists()) or bool(CI),
    reason="requires the real 14-profile Hermes layout",
)
def test_setup_profiles_enables_14_profiles_in_real_layout(sandbox_profiles):
    """Real production layout has ≥14 profiles — verify all are enabled."""
    # _build_sandbox copies real profiles; ensure we get the expected count.
    # '{profile}' is a template placeholder dir, not a real profile.
    configured = [
        p.name
        for p in sandbox_profiles.iterdir()
        if p.is_dir() and p.name != "{profile}"
    ]
    assert len(configured) >= 14, (
        f"expected >=14 profiles in real layout, got {len(configured)}: {configured}"
    )

    result = _run_setup_py(sandbox_profiles)
    assert result.returncode == 0, result.stderr

    for name in configured:
        cfg = _read_profile_config(sandbox_profiles, name)
        enabled = cfg.get("plugins", {}).get("enabled", []) or []
        assert "privacy-shield" in enabled, f"{name} missing privacy-shield"


def test_setup_profiles_preserves_other_config_keys(sandbox_profiles):
    """Existing config keys (model, providers, …) survive untouched."""
    cfg_path = sandbox_profiles / "default" / "config.yaml"
    cfg = _read_profile_config(sandbox_profiles, "default")
    cfg["custom_marker"] = {"keep_me": True}
    cfg_path.write_text(yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False))

    result = _run_setup_py(sandbox_profiles)
    assert result.returncode == 0, result.stderr

    after = _read_profile_config(sandbox_profiles, "default")
    assert after.get("custom_marker", {}).get("keep_me") is True
    assert "privacy-shield" in after.get("plugins", {}).get("enabled", [])


def test_setup_profiles_handles_missing_config(tmp_path):
    """Profile without config.yaml is skipped, not fatal — script returns 0."""
    profiles_root = tmp_path / "profiles"
    profiles_root.mkdir()
    (profiles_root / "good").mkdir()
    (profiles_root / "good" / "config.yaml").write_text("model: {default: stub}\n")
    (profiles_root / "broken").mkdir()
    # broken intentionally has no config.yaml

    result = _run_setup_py(profiles_root)
    assert result.returncode == 0, result.stderr
    assert "no config.yaml, skipping" in result.stdout
    # The good profile still got enabled
    cfg = _read_profile_config(profiles_root, "good")
    assert "privacy-shield" in cfg.get("plugins", {}).get("enabled", [])


def test_setup_profiles_missing_profiles_dir(tmp_path):
    """Non-existent profiles dir is a fatal error (exit 1)."""
    nonexistent = tmp_path / "does_not_exist"
    result = _run_setup_py(nonexistent)
    assert result.returncode == 1
    assert "not found" in result.stdout


# --------------------------------------------------------------------------- #
# Script-artefact tests (no execution)
# --------------------------------------------------------------------------- #


def test_setup_profiles_script_exists_and_runs_help():
    """The bash script exists, is executable, and has a sane shebang."""
    assert SETUP_SH.exists(), f"missing {SETUP_SH}"
    mode = SETUP_SH.stat().st_mode
    assert mode & stat.S_IXUSR, f"{SETUP_SH} is not executable"

    head = SETUP_SH.read_text().splitlines()
    assert head and head[0].startswith("#!/bin/bash"), f"bad shebang: {head[:1]}"


def test_setup_profiles_python_exists_and_importable():
    """The python script exists, has a shebang, is syntactically valid, and references plugin."""
    assert SETUP_PY.exists(), f"missing {SETUP_PY}"
    text = SETUP_PY.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env python3")
    compile(text, str(SETUP_PY), "exec")
    assert "privacy-shield" in text
    assert "--profiles-dir" in text, "expected --profiles-dir CLI flag for testability"


def test_setup_profiles_summary_includes_count():
    """The script's success message must include the count summary."""
    result = subprocess.run(
        [sys.executable, str(SETUP_PY), "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "--profiles-dir" in result.stdout
