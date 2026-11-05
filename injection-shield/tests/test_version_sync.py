"""FIX-IS-DRIFT: tests for scripts/sync_version.py under the new SSO.

Architecture (post-FIX-IS-DRIFT):

* ``__init__.py:__version__`` is the canonical SSO source.
* ``plugin.yaml:version`` is a human-readable mirror, kept in sync by
  this script.
* ``pyproject.toml`` declares ``dynamic = ["version"]`` and reads
  ``injection_shield.__version__`` via
  ``[tool.setuptools.dynamic] attr = "injection_shield.__version__"``.
  At build time setuptools resolves the version from ``__init__.py``
  automatically; the wheel/SDIST names carry that exact version.

The script has three guarantees:

1. ``sync_version.py`` (no args) writes ``__init__.py``'s version into
   ``plugin.yaml``, leaving the canonical source untouched.
2. ``--check`` exits 0 when ``__init__.py`` and ``plugin.yaml`` agree
   on the version, and exits 1 with a clear diff when they don't
   (the "release gate" the original bug report demanded).
3. ``--set X.Y.Z`` updates ``__init__.py`` FIRST (the canonical
   source), then syncs ``plugin.yaml`` — so ``__init__.py`` stays the
   single source of truth.

We exercise each path, plus the idempotency / drift-detector contract
that protects against the very bug this task was created to eliminate.
A separate ``test_drift_fixes.py`` exercises the dynamic-attribution
side of the SSO via the built wheel's ``importlib.metadata.version``.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PLUGIN_ROOT / "scripts"
PLUGIN_YAML = PLUGIN_ROOT / "plugin.yaml"
PYPROJECT = PLUGIN_ROOT / "pyproject.toml"
INIT_PY = PLUGIN_ROOT / "__init__.py"
SYNC_SCRIPT = SCRIPTS_DIR / "sync_version.py"


def _read_yaml_version() -> str:
    text = PLUGIN_YAML.read_text(encoding="utf-8")
    m = re.search(r'^version:\s*"([^"]+)"\s*$', text, re.MULTILINE)
    assert m is not None, "plugin.yaml missing version line"
    return m.group(1)


def _read_init_version() -> str:
    text = INIT_PY.read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if m is None:
        return "<missing>"
    return m.group(1)


@pytest.fixture
def snapshot_versions(tmp_path):
    """Snapshot plugin.yaml and __init__.py before the test mutates
    them, restore after.

    This is critical because the tests intentionally induce drift to
    verify the detector catches it. Without a restore we would pollute
    later test runs.

    pyproject.toml is intentionally NOT snapshotted here: it is the
    dynamic-attribution side of the SSO and is read-only in the new
    design (the script no longer touches it).
    """
    snap_dir = tmp_path / "snap"
    snap_dir.mkdir()
    files = {
        "plugin.yaml": PLUGIN_YAML.read_bytes(),
        "__init__.py": INIT_PY.read_bytes(),
    }
    for name, data in files.items():
        (snap_dir / name).write_bytes(data)

    def restore() -> None:
        for name, data in files.items():
            (PLUGIN_ROOT / name).write_bytes(data)

    yield restore


def _run(*args: str) -> subprocess.CompletedProcess:
    """Run sync_version.py with the given args from the plugin root."""
    return subprocess.run(
        [sys.executable, str(SYNC_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=PLUGIN_ROOT,
        timeout=15,
    )


class TestSyncScriptSmoke:
    """Behaviour every CI run depends on."""

    def test_script_exists_and_is_executable_python(self):
        assert SYNC_SCRIPT.exists()
        text = SYNC_SCRIPT.read_text(encoding="utf-8")
        assert text.startswith("#!/usr/bin/env python3"), text[:40]

    def test_init_and_yaml_agree_after_sync(self):
        """Pre-condition for the rest of the suite: __init__.py and
        plugin.yaml agree on the version.

        If this fails, either someone bypassed the script or the
        previous test left the files in a bad state (the
        snapshot_versions fixture in other tests should prevent the
        latter).
        """
        yaml_v = _read_yaml_version()
        init_v = _read_init_version()
        assert yaml_v == init_v, (
            f"version drift: plugin.yaml={yaml_v}, __init__.py={init_v}"
        )

    def test_sync_idempotent(self):
        """Running sync twice must not change any file after the first run."""
        before_yaml = PLUGIN_YAML.read_text(encoding="utf-8")
        before_init = INIT_PY.read_text(encoding="utf-8")

        result = _run()
        assert result.returncode == 0, result.stderr
        assert "Synced version" in result.stdout

        # After the first sync, a second sync must be a no-op (file
        # contents byte-for-byte equal).
        assert PLUGIN_YAML.read_text(encoding="utf-8") == before_yaml
        assert INIT_PY.read_text(encoding="utf-8") == before_init


class TestCheckMode:
    """The release gate: --check exits 0 if and only if __init__.py and
    plugin.yaml agree."""

    def test_check_returns_zero_when_in_sync(self):
        result = _run("--check")
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_check_returns_one_on_drift(self, snapshot_versions):
        """Inject a drift by editing plugin.yaml directly, verify detector fires."""
        # Force a drift on plugin.yaml only.
        text = PLUGIN_YAML.read_text(encoding="utf-8")
        new_text = re.sub(
            r'^(version:\s*)"[^"]+"',
            r'\1"9.9.9-drift"',
            text,
            count=1,
            flags=re.MULTILINE,
        )
        assert new_text != text, "drift injection failed — regex didn't match"
        PLUGIN_YAML.write_text(new_text, encoding="utf-8")

        try:
            result = _run("--check")
            assert result.returncode == 1, (
                f"--check must exit 1 on drift; got {result.returncode}\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
            assert "DRIFT" in result.stderr or "drift" in result.stderr.lower()
            assert "9.9.9-drift" in result.stderr
        finally:
            snapshot_versions()

    def test_check_restores_to_zero_after_repair(self, snapshot_versions):
        """Drift → fail → sync → pass. End-to-end of the release-gate contract."""
        text = PLUGIN_YAML.read_text(encoding="utf-8")
        new_text = re.sub(
            r'^(version:\s*)"[^"]+"',
            r'\1"9.9.9-drift"',
            text,
            count=1,
            flags=re.MULTILINE,
        )
        PLUGIN_YAML.write_text(new_text, encoding="utf-8")

        try:
            assert _run("--check").returncode == 1
            assert _run().returncode == 0  # sync repairs it
            assert _run("--check").returncode == 0  # now clean
        finally:
            snapshot_versions()


class TestSetMode:
    """`--set X.Y.Z` is the only sanctioned way to bump the version."""

    def test_set_updates_both_sources(self, snapshot_versions):
        # 0.2.2 is a real semver triple; intentionally NOT a semver-with-
        # suffix, because our strict validator rejects those on purpose
        # (see test_set_rejects_non_semver).
        result = _run("--set", "0.2.2")
        try:
            assert result.returncode == 0, result.stderr
            assert _read_init_version() == "0.2.2"
            assert _read_yaml_version() == "0.2.2"
        finally:
            snapshot_versions()

    def test_set_rejects_non_semver(self, snapshot_versions):
        result = _run("--set", "not-a-version")
        try:
            assert result.returncode != 0
            assert "semver" in result.stderr.lower()
            # And nothing was changed.
            assert _read_yaml_version() != "not-a-version"
            assert _read_init_version() != "not-a-version"
        finally:
            snapshot_versions()


class TestPackageImport:
    """The canonical __version__ must actually be importable."""

    def test_init_version_matches_yaml(self):
        # conftest.py adds the parent of PLUGIN_ROOT to sys.path so
        # `import injection_shield` resolves to PLUGIN_ROOT.
        from injection_shield import __version__  # type: ignore[attr-defined]
        assert __version__ == _read_yaml_version()


class TestPyprojectMetadata:
    """pyproject.toml must declare the version dynamically so the wheel
    inherits it from __init__.py at build time."""

    def test_pyproject_declares_dynamic_version(self):
        try:
            import tomllib  # py3.11+
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]

        with PYPROJECT.open("rb") as fh:
            data = tomllib.load(fh)
        # Project version is dynamic — setuptools will read it from
        # ``injection_shield.__version__`` at build time.
        assert "version" not in data["project"], (
            "pyproject.toml [project] must NOT carry a static version — "
            "use dynamic = ['version'] with [tool.setuptools.dynamic]"
        )
        assert "version" in data["project"].get("dynamic", [])

        # And the dynamic attribution is configured to read from
        # injection_shield.__version__ (SSO).
        setuptools = data.get("tool", {}).get("setuptools", {})
        dynamic = setuptools.get("dynamic", {})
        assert dynamic.get("version", {}).get("attr") == "injection_shield.__version__", (
            "pyproject.toml [tool.setuptools.dynamic] must read version from "
            "injection_shield.__version__"
        )
