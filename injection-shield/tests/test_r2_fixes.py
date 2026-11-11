"""Regression tests for the smith-review-R2 fixes (PR #150309 round 2).

Covers:
- blocker-2: ``tokens`` survives into the post_llm_call audit entry
- blocker-3: ``load_config`` hands out EXPANDED audit-log paths
"""

from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path

import pytest

from injection_shield import InjectionShieldPlugin

PLUGIN_NAME = "injection-shield"


@pytest.fixture
def plugin(tmp_path: Path, monkeypatch) -> InjectionShieldPlugin:
    """Audit-mode plugin writing its audit log into tmp_path (alerts off)."""
    monkeypatch.setenv("INJECTION_SHIELD_ALERT_DISABLE", "1")
    p = InjectionShieldPlugin(profile="default")
    p.audit_log = tmp_path / "audit.log"
    p.mode = "audit"
    return p


def _audit_entries(plugin: InjectionShieldPlugin) -> list[dict]:
    if not plugin.audit_log.exists():
        return []
    out: list[dict] = []
    for line in plugin.audit_log.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        with contextlib.suppress(json.JSONDecodeError):
            out.append(json.loads(line))
    return out


def test_tokens_survive_into_audit_entry(plugin: InjectionShieldPlugin) -> None:
    """Smith R2-blocker-2: tokens must land in the audit entry, not be
    accepted-and-dropped by the adapter/plugin boundary."""
    text = "Here is the key: sk-abcDef123Ghi456Jkl7890"
    result = plugin.post_llm_call(
        response={"text": text}, tokens=1500, session_key="sess-tokens"
    )
    assert result is None
    entries = _audit_entries(plugin)
    assert entries, "violation audit entry missing"
    assert all(e.get("layer") == "post_llm_call" for e in entries)
    assert all(e.get("tokens") == 1500 for e in entries), (
        f"tokens field missing/incorrect: {[e.get('tokens') for e in entries]}"
    )


def test_default_tokens_zero_in_audit_entry(plugin: InjectionShieldPlugin) -> None:
    text = "Here is the key: sk-abcDef123Ghi456Jkl7890"
    plugin.post_llm_call(response={"text": text}, session_key="sess-zero")
    entries = [e for e in _audit_entries(plugin) if e.get("layer") == "post_llm_call"]
    assert entries and all(e.get("tokens") == 0 for e in entries)


def test_load_config_expands_audit_log_path(monkeypatch, tmp_path) -> None:
    """Smith R2-blocker-3: the config layer must expand ~ so a literal-tilde
    path can never leak cwd-relative into an uncontrolled directory."""
    import injection_shield.config as cfg_mod

    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setattr(cfg_mod, "_config_path", lambda: tmp_path / "no-config.yaml")
    cfg = cfg_mod.load_config(profile="default")
    path = cfg["audit_log_path"]
    assert path == os.path.expanduser(path), "path still contains ~"
    assert "~" not in path
    assert os.path.isabs(path)
    assert path.endswith("prompt-injection-attempts.log")


def test_load_config_expands_user_configured_tilde_path(
    monkeypatch, tmp_path
) -> None:
    """Even when the operator configures the path itself (plugin.yaml /
    config.yaml), load_config must hand out an expanded path."""
    import injection_shield.config as cfg_mod

    monkeypatch.delenv("HERMES_HOME", raising=False)
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "plugins:\n"
        "  entries:\n"
        "    injection-shield:\n"
        "      audit_log_path: ~/workspace/prompt-injection-attempts.log\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(cfg_mod, "_config_path", lambda: cfg_file)
    cfg = cfg_mod.load_config(profile="default")
    path = cfg["audit_log_path"]
    assert path == os.path.expanduser("~/workspace/prompt-injection-attempts.log")
    assert "~" not in path
