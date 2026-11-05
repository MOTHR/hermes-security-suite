"""Tests for configuration loading."""

from __future__ import annotations

from pathlib import Path

from injection_shield.config import DEFAULT_CONFIG, load_config, validate_config


def test_default_config_has_expected_keys() -> None:
    config = load_config(profile="test")
    assert config["enabled"] is True
    assert config["mode"] == "audit"
    assert "allowed_domains" in config
    assert "risky_tools" in config
    assert "telegram" in config
    assert "audit_log_path" in config
    assert "{profile}" not in config["audit_log_path"]
    assert "test" in config["audit_log_path"]


def test_default_config_is_safe() -> None:
    assert DEFAULT_CONFIG["mode"] == "audit"
    assert "terminal" in DEFAULT_CONFIG["risky_tools"]
    assert "write_file" in DEFAULT_CONFIG["risky_tools"]


# FIX-1A: Hook-Order-Assertion
# ---------------------------------------------------------------- #
# Injection-Shield MUST run BEFORE Privacy-Shield on pre_llm_call
# (Privacy-Shield priority 200), so the firewall sees original user
# content rather than pseudonymized tokens. post_llm_call runs AFTER
# Privacy-Shield's transform_llm_output (also 200) so credential-leak
# scanning sees the restored PII surface.

def test_plugin_yaml_hook_priority_orders_injection_before_privacy() -> None:
    """FIX-1A: pre_llm_call priority < privacy-shield priority (200)."""
    import yaml

    plugin_yaml = Path(__file__).resolve().parent.parent / "plugin.yaml"
    with open(plugin_yaml, "r", encoding="utf-8") as f:
        meta = yaml.safe_load(f)

    prio = meta.get("hook_priority", {})
    assert "pre_llm_call" in prio, "hook_priority.pre_llm_call missing"
    assert prio["pre_llm_call"] < 200, (
        f"injection-shield pre_llm_call priority={prio['pre_llm_call']} "
        "must be < privacy-shield priority 200 so the firewall runs first"
    )
    assert "post_llm_call" in prio, "hook_priority.post_llm_call missing"
    assert prio["post_llm_call"] >= 200, (
        f"injection-shield post_llm_call priority={prio['post_llm_call']} "
        "must be >= privacy-shield transform_llm_output priority 200 so "
        "credential-leak scanning runs after token restoration"
    )


# FIX-IS-R4-003 (Architect R4 ARCH-IS-003 HIGH)
# ---------------------------------------------------------------- #
# Config validation must surface misconfigurations instead of letting
# the plugin silently fall back to a safe default. The contract
# mirrors Privacy-Shield's ``validate_config()``: pure function,
# returns ``list[str]``, never raises on operator-side typos.


def test_validate_config_accepts_default() -> None:
    """The shipped DEFAULT_CONFIG must validate clean."""
    assert validate_config(DEFAULT_CONFIG) == []


def test_validate_config_accepts_loaded_default_profile() -> None:
    """The config ``load_config('test')`` returns for a fresh profile
    must validate clean too (it is DEFAULT_CONFIG + env-var applied)."""
    config = load_config(profile="test")
    # env-var may not be set in CI; chat_id stays None which is valid.
    assert validate_config(config) == []


def test_validate_config_rejects_unknown_mode() -> None:
    """The classic silent-failure: ``mode: strict`` is a PS-only mode.
    IS used to fall back to 'audit' without telling the operator."""
    config = {**DEFAULT_CONFIG, "mode": "strict"}
    issues = validate_config(config)
    assert any("mode" in i and "strict" in i for i in issues), (
        f"expected mode issue, got {issues!r}"
    )


def test_validate_config_rejects_non_bool_enabled() -> None:
    config = {**DEFAULT_CONFIG, "enabled": "yes"}  # common YAML typo
    issues = validate_config(config)
    assert any("enabled" in i for i in issues), issues


def test_validate_config_rejects_bad_chat_id() -> None:
    config = {
        **DEFAULT_CONFIG,
        "telegram": {**DEFAULT_CONFIG["telegram"], "chat_id": "not-an-int"},
    }
    issues = validate_config(config)
    assert any("chat_id" in i for i in issues), issues


def test_validate_config_rejects_bad_min_severity() -> None:
    config = {
        **DEFAULT_CONFIG,
        "telegram": {**DEFAULT_CONFIG["telegram"], "min_severity": "ultra"},
    }
    issues = validate_config(config)
    assert any("min_severity" in i for i in issues), issues


def test_validate_config_rejects_audit_log_max_bytes_too_small() -> None:
    config = {**DEFAULT_CONFIG, "audit_log_max_bytes": 0}
    issues = validate_config(config)
    assert any("audit_log_max_bytes" in i for i in issues), issues


def test_validate_config_rejects_negative_retention_days() -> None:
    config = {**DEFAULT_CONFIG, "audit_log_retention_days": -1}
    issues = validate_config(config)
    assert any("audit_log_retention_days" in i for i in issues), issues


def test_validate_config_rejects_non_dict_input() -> None:
    issues = validate_config("not a config")  # type: ignore[arg-type]
    assert issues and "must be a dict" in issues[0]


def test_validate_config_rejects_list_input() -> None:
    issues = validate_config(["mode", "audit"])  # type: ignore[arg-type]
    assert issues and "must be a dict" in issues[0]


def test_validate_config_rejects_non_list_domains() -> None:
    config = {**DEFAULT_CONFIG, "allowed_domains": "api.openai.com"}
    issues = validate_config(config)
    assert any("allowed_domains" in i for i in issues), issues


def test_validate_config_accepts_partial_override() -> None:
    """Operator might only set ``mode`` — everything else can stay
    at defaults. That must validate clean."""
    config = {**DEFAULT_CONFIG, "mode": "enforcement"}
    assert validate_config(config) == []


def test_validate_config_rejects_bool_as_int() -> None:
    """Python quirk: ``isinstance(True, int) is True``. We must reject
    ``True``/``False`` when an int is expected, otherwise an operator
    who writes ``audit_log_backup_count: yes`` would silently work
    and store ``1`` instead of erroring out."""
    config = {**DEFAULT_CONFIG, "audit_log_backup_count": True}
    issues = validate_config(config)
    assert any("audit_log_backup_count" in i for i in issues), issues
