"""Config loader for injection-shield.

Reads ~/.hermes/config.yaml -> plugins.entries.injection-shield.
Falls back to safe defaults if not configured.
All optional — plugin never hard-fails on missing config/secrets.

FIX-1D (Orakel CRIT-3): Telegram chat_id is no longer hardcoded. Defaults
to ``enabled=False``; the operator must opt-in by setting ``chat_id`` in
``plugin.yaml`` (under ``plugins.entries.injection-shield.telegram``) or
via the ``INJECTION_SHIELD_TELEGRAM_CHAT_ID`` environment variable. The
bot token is also environment-driven (``TELEGRAM_BOT_TOKEN``); the plugin
NEVER ships credentials in source.

FIX-1D (Orakel CRIT-4): Audit-log retention is governed by
``audit_log_max_bytes`` (default 10 MiB) and ``audit_log_retention_days``
(default 90 — DSGVO Art. 5 "Speicherbegrenzung"). Logs are written via
:class:`logging.handlers.RotatingFileHandler`, rotated at 10 MiB, and
auto-pruned on plugin init.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import yaml
except Exception:  # pragma: no cover - import optional dependency
    yaml = None  # type: ignore[assignment]

# Environment variable that overrides the configured Telegram chat_id.
# Set in the deployment shell (e.g. systemd EnvironmentFile) — never in
# this source tree. If unset, the plugin falls back to the (typically
# unset) plugin.yaml setting, and Telegram alerting stays disabled.
TELEGRAM_CHAT_ID_ENV = "INJECTION_SHIELD_TELEGRAM_CHAT_ID"

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "mode": "audit",  # Start safe: "audit" logs, "enforcement" blocks
    "allowed_domains": [
        "api.openai.com",
        "api.anthropic.com",
        "api.x.ai",
        "ollama.com",
        "en.wikipedia.org",
        "arxiv.org",
        "github.com",
        "pypi.org",
        "hermes-agent.nousresearch.com",
        "api.telegram.org",
        # Research APIs referenced by bundled skill documentation
        # (2026-09-22: curl-POST docs examples fired exfil alerts).
        "api.semanticscholar.org",
    ],
    "risky_tools": ["terminal", "write_file"],
    "telegram": {
        # FIX-1D CRIT-3: Telegram alerting is OFF by default. To enable
        # it the operator must set ``chat_id`` in plugin.yaml or export
        # INJECTION_SHIELD_TELEGRAM_CHAT_ID. The hardcoded Dirk chat_id
        # was a DSGVO-Art. 25 ("Privacy by Default") violation.
        "enabled": False,
        "chat_id": None,  # resolved at runtime from env / config
        "min_severity": "medium",
    },
    "audit_log_path": "~/.hermes/profiles/{profile}/workspace/05-Logs-Snapshots/prompt-injection-attempts.log",
    # FIX-1D CRIT-4: rolling log + auto-prune. 10 MiB per file × 5 backups
    # ≈ 50 MiB worst case; 90-day retention satisfies DSGVO Art. 5(1)(e).
    "audit_log_max_bytes": 10 * 1024 * 1024,  # 10 MiB
    "audit_log_backup_count": 5,               # keep 5 rotated files
    "audit_log_retention_days": 90,            # auto-prune entries older than 90d
    # FIX-XFAIL-F01/F05 (Combined Red-Team 2026-08-22): opt-out knob for
    # the F-class tool-call exfil detector.  ``curl_exfil`` and
    # ``base64_pipe`` are both on by default.  An operator who wants
    # to silence one category in a development workflow can override
    # the set in plugin.yaml / config.yaml — e.g.
    #   tool_call_categories: [base64_pipe]
    # keeps the curl-pattern off while leaving the base64-pipe RCE
    # pattern on.  The set is consumed by ToolCallPatternDetector
    # (see plugin.py).
    "tool_call_categories": ["curl_exfil", "base64_pipe"],
    # FIX-ALERT-NOISE (2026-08-29): Telegram alert de-noise knobs.
    # Egress sightings are medium severity → audit-log only, except the
    # FIRST sighting of a domain per first_seen_resend_hours window,
    # which is messaged with a whitelist action hint. Other alert kinds
    # are rate-limited to one message per alert_rate_limit_seconds.
    "first_seen_resend_hours": 24,
    "alert_rate_limit_seconds": 3600,
    # v0.6.0 (M1, Seraph review): performance/opt-out knobs for the new
    # scan layers. All default ON — the shield scans unless the operator
    # explicitly disables a layer. Validation: booleans (M2).
    "scan_all_tool_results": True,       # GAP-5: scan every tool result
    "scan_multimodal_content": True,     # GAP-4: message content arrays
    "scan_css_concealment": True,        # GAP-3: 7th chain layer
    "scan_mcp_tool_descriptions": True,  # GAP-1: tool poisoning / rug pulls
}

# FIX-IS-R4-003 (Architect R4 ARCH-IS-003 HIGH): the contract every
# field must satisfy, raised to module-level so validate_config() and
# the loader can share a single source of truth. Mirrors the
# Privacy-Shield ``ALLOWED_*`` constants in ``privacy_shield.config``.
ALLOWED_MODES: tuple[str, ...] = ("audit", "enforcement")
ALLOWED_SEVERITY: tuple[str, ...] = ("low", "medium", "high", "critical")


def load_config(profile: str = "default") -> dict[str, Any]:
    """Load injection-shield config with safe defaults.

    Args:
        profile: Profile name substituted into the audit-log path placeholder.
    """
    config = _deep_copy(DEFAULT_CONFIG)

    config_path = _config_path()
    if config_path.exists() and yaml is not None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                full = yaml.safe_load(f) or {}
            user = full.get("plugins", {}).get("entries", {}).get("injection-shield", {})
            config = _merge(config, user)
        except Exception as exc:  # pragma: no cover
            logger.warning("injection-shield: failed to read config.yaml: %s", exc)

    # Expand {profile} placeholder in audit log path. Derive from the active
    # profile directory (gateway sets HERMES_HOME to the profile dir) — NOT
    # from the function default, which is "default" and misfiled every
    # non-default profile's audit trail into profiles/default (production
    # finding 2026-09-22: schluesselmacher alerts had zero audit trail in
    # their own workspace).
    if profile == "default":
        home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
        # Only treat the home as a profile dir when it IS one (profiles/<name>),
        # not the shared root ~/.hermes.
        if home.parent.name == "profiles":
            profile = home.name
    # profile is now either caller-supplied, derived, or the "default" fallback;
    # substitution always runs.
    audit_path = config.get("audit_log_path", DEFAULT_CONFIG["audit_log_path"])
    if isinstance(audit_path, str):
        # Smith R2-blocker-3: the config layer must hand out EXPANDED paths —
        # a literal-~ path written cwd-relative silently relocates the audit
        # trail (data loss / leak into uncontrolled CWD). Callers may expand
        # again; expanduser is idempotent.
        config["audit_log_path"] = os.path.expanduser(
            audit_path.replace("{profile}", profile)
        )

    # FIX-1D CRIT-3: env-var > plugin.yaml > None. Never ship a hardcoded
    # chat_id — only a value the operator explicitly placed in their
    # deployment environment can enable Telegram alerting.
    env_chat_id = os.environ.get(TELEGRAM_CHAT_ID_ENV)
    tg = config.get("telegram", {})
    if env_chat_id:
        try:
            tg["chat_id"] = int(env_chat_id)
            tg["enabled"] = True
        except ValueError:
            logger.warning(
                "injection-shield: %s must be an integer, got %r",
                TELEGRAM_CHAT_ID_ENV,
                env_chat_id,
            )
    if tg.get("chat_id") in (None, "", 0):
        # no opt-in → stay disabled regardless of any stale yaml flag
        tg["enabled"] = False
        tg["chat_id"] = None
    config["telegram"] = tg

    return config


def _config_path() -> Path:
    """Return the Hermes config.yaml path, respecting ``HERMES_HOME``."""
    home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    return home / "config.yaml"


def _deep_copy(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _deep_copy(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_copy(item) for item in obj]
    return obj


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Shallow merge dicts; override lists completely."""
    merged = _deep_copy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = _deep_copy(value)
    return merged


def validate_config(config: dict[str, Any]) -> list[str]:
    """Return a list of human-readable config issues (empty == valid).

    FIX-IS-R4-003 (Architect R4 ARCH-IS-003 HIGH): IS used to silently
    fall back to ``mode="audit"`` when an operator wrote e.g.
    ``mode: strict`` (a Privacy-Shield-only mode). That is a silent
    failure — the operator thought the plugin was enforcing when it
    was only auditing. ``validate_config()`` now surfaces every
    out-of-spec value as an issue string so the operator (or an
    operator-side script) can fail loud instead of fail silent.

    The contract mirrors Privacy-Shield's ``validate_config()``:
    pure function, returns ``list[str]``, no exceptions for ordinary
    mis-configurations, never raises on operator-side typos.
    """
    issues: list[str] = []

    if not isinstance(config, dict):
        return [f"config must be a dict, got {type(config).__name__}"]

    # ``enabled`` — bool, default true
    if "enabled" in config and not isinstance(config["enabled"], bool):
        issues.append(
            f"enabled must be a bool, got {type(config['enabled']).__name__}"
        )

    # ``mode`` — one of ALLOWED_MODES
    mode = config.get("mode", "audit")
    if not isinstance(mode, str):
        issues.append(
            f"mode must be a string, got {type(mode).__name__}"
        )
    elif mode not in ALLOWED_MODES:
        issues.append(
            f"mode {mode!r} is not allowed; expected one of {ALLOWED_MODES}"
        )

    # ``allowed_domains`` — list[str]
    domains = config.get("allowed_domains")
    if domains is not None:
        if not isinstance(domains, list):
            issues.append(
                "allowed_domains must be a list of strings, "
                f"got {type(domains).__name__}"
            )
        else:
            for i, d in enumerate(domains):
                if not isinstance(d, str):
                    issues.append(
                        f"allowed_domains[{i}] must be a string, "
                        f"got {type(d).__name__}"
                    )

    # ``risky_tools`` — list[str]
    risky = config.get("risky_tools")
    if risky is not None:
        if not isinstance(risky, list):
            issues.append(
                "risky_tools must be a list of strings, "
                f"got {type(risky).__name__}"
            )
        else:
            for i, t in enumerate(risky):
                if not isinstance(t, str):
                    issues.append(
                        f"risky_tools[{i}] must be a string, "
                        f"got {type(t).__name__}"
                    )

    # v0.6.0 (M2, Seraph review): boolean scan-layer knobs
    for knob in (
        "scan_all_tool_results",
        "scan_multimodal_content",
        "scan_css_concealment",
        "scan_mcp_tool_descriptions",
    ):
        if knob in config and not isinstance(config[knob], bool):
            issues.append(
                f"{knob} must be a bool, got {type(config[knob]).__name__}"
            )

    # ``telegram`` — dict with bounded shape
    tg = config.get("telegram")
    if tg is not None:
        if not isinstance(tg, dict):
            issues.append(
                f"telegram must be a dict, got {type(tg).__name__}"
            )
        else:
            if "enabled" in tg and not isinstance(tg["enabled"], bool):
                issues.append(
                    "telegram.enabled must be a bool, "
                    f"got {type(tg['enabled']).__name__}"
                )
            if "chat_id" in tg and tg["chat_id"] is not None:
                if not isinstance(tg["chat_id"], int) or isinstance(
                    tg["chat_id"], bool
                ):
                    issues.append(
                        f"telegram.chat_id must be int or null, "
                        f"got {type(tg['chat_id']).__name__}"
                    )
            if "min_severity" in tg:
                sev = tg["min_severity"]
                if not isinstance(sev, str) or sev not in ALLOWED_SEVERITY:
                    issues.append(
                        f"telegram.min_severity {sev!r} is not allowed; "
                        f"expected one of {ALLOWED_SEVERITY}"
                    )

    # ``audit_log_path`` — string (Path() conversion done by callers)
    alp = config.get("audit_log_path")
    if alp is not None and not isinstance(alp, str):
        issues.append(
            f"audit_log_path must be a string, got {type(alp).__name__}"
        )

    # ``audit_log_max_bytes`` — int >= 1024 (don't accept 0/negative)
    mb = config.get("audit_log_max_bytes")
    if mb is not None:
        if not isinstance(mb, int) or isinstance(mb, bool) or mb < 1024:
            issues.append(
                f"audit_log_max_bytes must be an int >= 1024, got {mb!r}"
            )

    # ``audit_log_backup_count`` — int >= 0
    bc = config.get("audit_log_backup_count")
    if bc is not None:
        if not isinstance(bc, int) or isinstance(bc, bool) or bc < 0:
            issues.append(
                f"audit_log_backup_count must be an int >= 0, got {bc!r}"
            )

    # ``audit_log_retention_days`` — int in [1, 3650]
    rd = config.get("audit_log_retention_days")
    if rd is not None:
        if (
            not isinstance(rd, int)
            or isinstance(rd, bool)
            or rd < 1
            or rd > 3650
        ):
            issues.append(
                f"audit_log_retention_days must be an int in [1, 3650], "
                f"got {rd!r}"
            )

    return issues
