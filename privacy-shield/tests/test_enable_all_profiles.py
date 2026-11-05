"""Tests for canary / exclude profile filtering (LINK-PS-9)."""

from __future__ import annotations

import privacy_shield.scripts.enable_all_profiles as enable_module
import yaml


def _make_config():
    return {"plugins": {"enabled": []}}


def test_canary_profiles_only_touch_target_set(tmp_path, monkeypatch):
    profiles = tmp_path / "profiles"
    for name in ("alpha", "beta", "gamma"):
        (profiles / name).mkdir(parents=True)
        (profiles / name / "config.yaml").write_text(
            yaml.safe_dump(_make_config()), encoding="utf-8"
        )

    monkeypatch.setattr(enable_module, "PROFILES_DIR", profiles)

    rc = enable_module.main(["--canary-profiles=alpha,beta"])
    assert rc == 0

    for name in ("alpha", "beta"):
        data = yaml.safe_load(
            (profiles / name / "config.yaml").read_text(encoding="utf-8")
        )
        assert "privacy-shield" in data["plugins"]["enabled"]

    data = yaml.safe_load(
        (profiles / "gamma" / "config.yaml").read_text(encoding="utf-8")
    )
    assert "privacy-shield" not in data["plugins"]["enabled"]


def test_exclude_profiles_leave_target_untouched(tmp_path, monkeypatch):
    profiles = tmp_path / "profiles"
    for name in ("alpha", "beta"):
        (profiles / name).mkdir(parents=True)
        (profiles / name / "config.yaml").write_text(
            yaml.safe_dump(_make_config()), encoding="utf-8"
        )

    monkeypatch.setattr(enable_module, "PROFILES_DIR", profiles)

    rc = enable_module.main(["--exclude-profiles=alpha"])
    assert rc == 0

    alpha = yaml.safe_load(
        (profiles / "alpha" / "config.yaml").read_text(encoding="utf-8")
    )
    assert "privacy-shield" not in alpha["plugins"]["enabled"]

    beta = yaml.safe_load(
        (profiles / "beta" / "config.yaml").read_text(encoding="utf-8")
    )
    assert "privacy-shield" in beta["plugins"]["enabled"]


def test_canary_output_contains_canary_label(capsys, tmp_path, monkeypatch):
    profiles = tmp_path / "profiles"
    (profiles / "alpha").mkdir(parents=True)
    (profiles / "alpha" / "config.yaml").write_text(
        yaml.safe_dump(_make_config()), encoding="utf-8"
    )
    (profiles / "beta").mkdir(parents=True)
    (profiles / "beta" / "config.yaml").write_text(
        yaml.safe_dump(_make_config()), encoding="utf-8"
    )

    monkeypatch.setattr(enable_module, "PROFILES_DIR", profiles)

    enable_module.main(["--canary-profiles=alpha"])
    captured = capsys.readouterr()
    assert "CANARY: alpha: ENABLED" in captured.out
    assert "CANARY: beta: SKIPPED" in captured.out
