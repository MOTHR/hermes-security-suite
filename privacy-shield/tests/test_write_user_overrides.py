"""Regression tests for _write_user_overrides (review t_c55ac7f5 F3).

The config.yaml write path used to be an unlocked, in-place read-modify-write.
This module pins the fixed behavior: advisory flock around the RMW cycle,
atomic publish via tempfile + os.replace in the same directory, and the
invariants that must hold regardless (file mode preserved, no temp-file
litter, parse-error keeps the original file, safe_dump formatting unchanged).
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

from privacy_shield.dashboard.plugin_api import _write_user_overrides

# tests/ -> privacy-shield/ -> suite root (hosts the privacy_shield import alias)
_SUITE_ROOT = Path(__file__).resolve().parents[2]

_WORKER_SRC = textwrap.dedent(
    """
    import os
    import sys

    suite_root, tag = sys.argv[1], sys.argv[2]
    sys.path.insert(0, suite_root)
    os.environ["HERMES_HOME"] = sys.argv[3]
    from privacy_shield.dashboard.plugin_api import _write_user_overrides

    for i in range(100):
        updates = {
            "p" + tag + "key" + str(i): "v" + str(i),
            "p" + tag + "shared": str(i),
        }
        _write_user_overrides(updates)
    print("ok")
    """
)


def _hermes_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "hermes_home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def _overrides(home: Path) -> dict:
    full = yaml.safe_load((home / "config.yaml").read_text())
    return full["plugins"]["entries"]["privacy-shield"]


def test_write_creates_missing_config_atomically(tmp_path, monkeypatch):
    home = _hermes_home(tmp_path, monkeypatch)
    _write_user_overrides({"mode": "audit"})
    full = yaml.safe_load((home / "config.yaml").read_text())
    assert full["plugins"]["entries"]["privacy-shield"]["mode"] == "audit"
    # mkstemp-created content: 0600, never world-readable (cf. bug #1699 risk)
    mode = stat.S_IMODE(os.stat(home / "config.yaml").st_mode)
    assert mode == 0o600
    assert not list(home.glob("config.yaml.*.tmp"))


def test_write_preserves_existing_file_mode(tmp_path, monkeypatch):
    home = _hermes_home(tmp_path, monkeypatch)
    cfg = home / "config.yaml"
    cfg.write_text("plugins:\n  entries:\n    other-plugin:\n      enabled: true\n")
    os.chmod(cfg, 0o644)
    _write_user_overrides({"mode": "limited"})
    full = yaml.safe_load(cfg.read_text())
    assert full["plugins"]["entries"]["other-plugin"]["enabled"] is True
    assert full["plugins"]["entries"]["privacy-shield"]["mode"] == "limited"
    assert stat.S_IMODE(cfg.stat().st_mode) == 0o644


def test_write_keeps_original_file_on_parse_error(tmp_path, monkeypatch):
    home = _hermes_home(tmp_path, monkeypatch)
    cfg = home / "config.yaml"
    original = "plugins: [unclosed\n  broken: {yaml"
    cfg.write_text(original)
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _write_user_overrides({"mode": "audit"})
    assert exc.value.status_code == 500
    assert cfg.read_text() == original


def test_write_dump_format_unchanged(tmp_path, monkeypatch):
    home = _hermes_home(tmp_path, monkeypatch)
    _write_user_overrides({"token_style": "deterministic"})
    cfg = home / "config.yaml"
    expected = yaml.safe_dump(
        yaml.safe_load(cfg.read_text()),
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
    )
    # stable_dump output must match the previous writer's format exactly
    assert expected == cfg.read_text()


def test_parallel_writers_no_lost_update(tmp_path, monkeypatch):
    """Two concurrent writer processes must not lose each other's keys.

    Regression for review F3: with the old truncate+rewrite ("w" mode) write,
    a writer that truncates while the other is mid-RMW clobbers its content
    (lost update / torn read). With flock + atomic replace every iteration of
    both children survives, and no child may die from a torn-parse 500.
    """
    home = _hermes_home(tmp_path, monkeypatch)
    children = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER_SRC, str(_SUITE_ROOT), tag, str(home)],
            env={**os.environ, "HERMES_HOME": str(home)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for tag in ("a", "b")
    ]
    for child in children:
        out, err = child.communicate(timeout=180)
        assert child.returncode == 0, (
            f"writer died rc={child.returncode}: {err.decode()[-2000:]}"
        )
        assert out.decode().strip() == "ok"

    keys = _overrides(home)
    for tag in ("a", "b"):
        for i in range(100):
            assert keys[f"p{tag}key{i}"] == f"v{i}", f"lost update: p{tag}key{i}"
    assert list(home.glob("config.yaml.*.tmp")) == []
