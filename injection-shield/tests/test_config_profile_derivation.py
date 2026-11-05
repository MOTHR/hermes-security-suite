"""Regression: audit-log profile derivation (2026-09-22 misfiled audit trail)."""

from injection_shield.config import load_config

def test_audit_path_derives_from_hermes_home(monkeypatch, tmp_path):
    """Profile derivation: HERMES_HOME=<profiles>/<name> must name the audit dir."""
    profiles = tmp_path / "profiles"
    home = profiles / "schluesselmacher"
    home.mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(home))
    config = load_config(profile="default")
    assert "schluesselmacher" in config["audit_log_path"]
    assert "default" not in config["audit_log_path"].split("profiles/")[-1]


def test_audit_path_shared_root_falls_back(monkeypatch):
    """HERMES_HOME = shared root (~/.hermes) -> keep 'default' (no profile dir)."""
    import pathlib
    fake_root = pathlib.Path("/tmp/hermes-shared-root-test")
    monkeypatch.setenv("HERMES_HOME", str(fake_root))
    config = load_config(profile="default")
    assert "default" in config["audit_log_path"]
