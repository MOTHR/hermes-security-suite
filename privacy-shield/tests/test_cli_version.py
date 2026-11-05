"""FIX-PS5 (Privacy-Shield): CLI version drift regression tests.

Verifies that ``privacy-shield --version`` reports the package's
``__version__`` rather than a hardcoded string. This guards against the
regression where cli.py hardcoded ``version="1.1.0"`` while
``__init__.py`` and ``pyproject.toml`` advanced to ``1.3.0`` — the bug
that BUTLER-PS-1 / BUTLER-PS-5 caught.

Acceptance criteria from the Kanban task:
    * ``cli --version`` output contains ``__version__``
    * The package's ``__version__`` matches plugin.yaml (single source)
    * ``click.version_option`` uses the dynamic value, not a literal
    * Hardcoded ``v1.0.0`` / ``v1.1.0`` strings no longer appear in
      the source for setup, status, or doctor commands
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _import_package():
    """Import privacy_shield, returning the module object."""
    # Add the plugin dir's parent to sys.path so 'import privacy_shield'
    # resolves via the hyphen-to-underscore convention (conftest does this
    # in normal pytest runs; we replicate it for direct CLI invocations).
    plugins_dir = str(PLUGIN_DIR.parent)
    if plugins_dir not in sys.path:
        sys.path.insert(0, plugins_dir)
    import privacy_shield  # noqa: WPS433 — intentional runtime import
    return privacy_shield


def test_cli_version_matches_package():
    """`privacy-shield --version` must report __version__ (not hardcoded)."""
    pkg = _import_package()
    from privacy_shield.cli import main  # noqa: WPS433

    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0, result.output
    assert pkg.__version__ in result.output, (
        f"CLI --version output {result.output!r} does not contain "
        f"package __version__ {pkg.__version__!r}"
    )


def test_cli_version_string_is_dynamic():
    """`click.version_option` must be bound to __version__, not a literal."""
    cli_text = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    # Pattern: @click.version_option(version=__version__, ...) — must appear
    assert re.search(
        r"@click\.version_option\(\s*version\s*=\s*__version__\s*,",
        cli_text,
    ), "click.version_option must read from __version__ (dynamic)"
    # Anti-pattern: hardcoded string like version="1.1.0" must NOT appear
    assert not re.search(
        r"@click\.version_option\([^)]*version\s*=\s*\"[0-9]+\.[0-9]+\.[0-9]+\"",
        cli_text,
    ), "click.version_option must NOT hardcode a literal version"


def test_cli_status_uses_dynamic_version():
    """`status` command banner must read from __version__."""
    cli_text = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    # The status block should format with __version__
    assert "Privacy-Shield v{__version__}" in cli_text, (
        "status banner must format via f-string + __version__"
    )
    assert "Privacy-Shield v1.1.0" not in cli_text, (
        "stale literal v1.1.0 still in cli.py"
    )


def test_cli_setup_uses_dynamic_version():
    """`setup` command banner must read from __version__."""
    cli_text = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    assert "Privacy-Shield Setup v{__version__}" in cli_text
    assert "Privacy-Shield Setup v1.1.0" not in cli_text


def test_cli_doctor_uses_dynamic_version():
    """`doctor` command banner must read from __version__."""
    cli_text = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    assert "Privacy-Shield Doctor v{__version__}" in cli_text
    assert "Privacy-Shield Doctor v1.0.0" not in cli_text


def test_cli_no_hardcoded_version_strings():
    """No hardcoded ``vN.N.N`` patterns survive in cli.py outside tests."""
    cli_text = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    # Strip comments (lines starting with #) and docstrings to avoid
    # false positives on historical changelog references.
    code_lines = []
    for line in cli_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        code_lines.append(line)
    code = "\n".join(code_lines)
    # Hardcoded v-pattern in code: NOT a dynamic f-string
    offenders = re.findall(r'["\']v\d+\.\d+\.\d+["\']', code)
    assert not offenders, (
        f"Hardcoded version strings found in cli.py code: {offenders}"
    )


def test_package_version_matches_plugin_yaml():
    """__version__ must agree with plugin.yaml (single source of truth)."""
    pkg = _import_package()
    yaml_text = (PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8")
    m = re.search(r'^version:\s*"([^"]+)"\s*$', yaml_text, re.MULTILINE)
    assert m, "plugin.yaml missing top-level version"
    yaml_version = m.group(1)
    assert pkg.__version__ == yaml_version, (
        f"__version__ ({pkg.__version__}) != plugin.yaml version "
        f"({yaml_version}) — run scripts/sync_version.py"
    )


def test_sync_version_check_passes():
    """Running sync_version.py --check must exit 0 (no drift)."""
    sync_script = PLUGIN_DIR / "scripts" / "sync_version.py"
    if not sync_script.exists():
        pytest.skip("sync_version.py not yet created")
    result = subprocess.run(
        [sys.executable, str(sync_script), "--check"],
        capture_output=True, text=True,
        cwd=str(PLUGIN_DIR),
    )
    assert result.returncode == 0, (
        f"sync_version --check failed (drift detected):\n"
        f"  stdout: {result.stdout}\n  stderr: {result.stderr}"
    )


def test_sync_version_script_exists():
    """The sync_version.py artefact must exist and be importable."""
    sync_script = PLUGIN_DIR / "scripts" / "sync_version.py"
    assert sync_script.exists(), f"missing {sync_script}"
    text = sync_script.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env python3")
    compile(text, str(sync_script), "exec")
    # Strict mode and main entries
    assert "def check()" in text
    assert 'argparse' in text
