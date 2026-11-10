"""Privacy-Shield Configuration.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 3.3

Phase 1 defaults:
- Mode: "limited"
- Token style: deterministic (EMAIL_001)
- Detection: regex-only (no NER in Phase 1)
- Fallback on timeout: block
- Key source: pass wrapper first, env fallback
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Literal

# Canonical token-format constants. The TRUE single-source-of-truth
# lives in ``privacy_shield/__init__.py`` (FIX-XPLUGIN-TOKEN) so other
# plugins can import them without pulling in this module. We re-import
# here only so existing ``config.DEFAULT_HASH_LENGTH`` etc. references
# keep working; new code MUST import from ``privacy_shield`` directly.
from . import DEFAULT_HASH_LENGTH  # noqa: F401 (re-export)

try:
    import yaml
except Exception:  # pragma: no cover - import optional dependency
    yaml = None  # type: ignore[assignment,unused-ignore]

ALLOWED_MODES = ("off", "audit", "limited", "strict", "paranoid")
ALLOWED_REASONING_MODES = ("off", "audit", "restore")
ALLOWED_RESTORE_MISS_STRATEGIES = ("placeholder", "keep")
# v1.7.6 (Decision 1): exact residual-token replacement text. Contains an
# En-Dash (U+2013) — do NOT normalize to a hyphen. Default is the German
# string; EN deployments override via ``restore_miss_placeholder`` in
# config.yaml (bilingual plugin-text rule: DE default, EN override).
#   DE (default): "[maskiertes PII – nicht wiederherstellbar]"
#   EN (override example): "[masked PII – cannot be restored]"
DEFAULT_RESTORE_MISS_PLACEHOLDER = "[maskiertes PII – nicht wiederherstellbar]"
TOKEN_SUFFIX_PATTERN = re.compile(r"[0-9a-f]{" + str(DEFAULT_HASH_LENGTH) + r"}")


@dataclass
class ReasoningBlockConfig:
    """Privacy-Shield v1.6.1 — In-Memory Reasoning-Redaktion.

    Diese Config kontrolliert, wie Reasoning-/Thinking-Blöcke im
    ``post_llm_call``-Hook pseudonymisiert werden. Sie ist absichtlich
    von der Haupt-Konfig getrennt, damit das Reasoning-Feature unabhängig
    vom allgemeinen ``mode`` (limited/strict/...) geschaltet werden kann.

    Default ``restore`` tokenisiert Reasoning-PII in-place im Memory.
    Persistenz-Limitation: ``state.db`` enthält Reasoning-PII kurzzeitig
    vor dem Hook-Feuerung — siehe docs/reasoning-protection.md.
    """

    mode: Literal["off", "audit", "restore"] = "restore"
    confidence_threshold: float = 0.85
    skip_fields: list[str] = field(
        default_factory=lambda: ["codex_reasoning_items"]
    )


@dataclass
class _ModeValidator:
    """Empty sentinel to keep dataclass declarations together."""

    pass


def _default_restore_channels() -> tuple[str, ...]:
    """Return allowed restore channels from environment or pass store.

    Always includes bare user-facing platforms that Hermes actually delivers
    as ``platform`` on ``transform_llm_output``:

    - ``telegram`` / ``desktop`` / ``cli`` — interactive surfaces

    ``cron`` is intentionally NOT a default (PS-CHANNEL-007): scheduled jobs
    may egress to shared logs, webhooks or files, so restoring PII on the
    cron channel requires an explicit operator opt-in via
    ``restore_allowed_channels`` in config.yaml.

    v1.7.6 (Decision 3, Dirk 2026-10-29): ``kanban`` is added as a bare
    default. The kanban channel is board-internal, the chat-ID allowlist
    (``allowed_chats`` / ``allowed_chat_ids`` / telegram-send) remains the
    trust boundary and is untouched — only the single channel entry arrives,
    tool egress (write_file, terminal, MCP, kanban_attach) stays blocked.

    Optionally prepends a scoped ``telegram:<chat_id>`` entry when the chat ID
    is available from ``PRIVACY_SHIELD_RESTORE_CHAT_ID`` or
    ``pass show hermes/telegram/chat_id``.

    Regression (2026-10-06): profiles without an explicit
    ``plugins.entries.privacy-shield.restore_allowed_channels`` override fell
    through to ``()`` whenever pass/env could not resolve a chat ID. Gateway
    delivers bare ``"telegram"``, so restoration was skipped and users saw
    raw ``TOKEN_*`` placeholders. Bare platform defaults close that gap
    without requiring every profile YAML to restate the list.
    """
    # Bare platforms Hermes actually passes as `platform` on the restore hook.
    # Keep this list in sync with gateway/cron/cli delivery labels.
    # PS-CHANNEL-007: 'cron' requires explicit operator opt-in — cron output
    # may go to logs/webhooks/files, not (only) to the user.
    bare: list[str] = ["telegram", "desktop", "cli", "kanban"]

    chat_id = os.environ.get("PRIVACY_SHIELD_RESTORE_CHAT_ID")
    if not chat_id:
        # Same launchd PATH robustness as _load_key_from_pass below.
        pass_bin = _resolve_pass_binary()
        if pass_bin is not None:
            try:
                result = subprocess.run(
                    [pass_bin, "show", "hermes/telegram/chat_id"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    chat_id = result.stdout.strip()
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                pass
    if chat_id:
        return (f"telegram:{chat_id}", *bare)
    return tuple(bare)


@dataclass
class PrivacyShieldConfig:
    """Privacy-Shield configuration with Phase 1 defaults."""

    enabled: bool = True
    mode: str = "limited"

    # Detection
    detection_engine: str = "regex"  # "regex" | "ner" | "hybrid" (Phase 2)

    # Pseudonymization
    token_style: str = "deterministic"  # "deterministic" | "random"
    token_prefix: str = "TOKEN"
    token_cache_max_size: int = 10_000  # LRU eviction bound
    max_session_salts: int = 1_000  # ~16 KB memory budget (16 bytes * 1000)

    # Storage
    # 2026-10-10: memory -> disk. In-memory mappings die with every gateway
    # restart while the CONVERSATION survives (gateway restarts are process
    # restarts, not session ends) — tokens from running conversations became
    # unresolvable after each restart ("mapping miss", incident 2026-10-10).
    # Disk mode persists encrypted mappings; purge now rides on
    # on_session_finalize (see __init__.py) with mapping_ttl_seconds as the
    # crash fallback, so DSGVO retention = session lifetime, not process
    # lifetime.
    storage_mode: str = "disk"  # "memory" | "disk"
    storage_path: str = "~/.hermes/privacy/mapping.db"
    encryption_key: str = ""  # Loaded at init time
    # Default 1h TTL per Google-Empfehlung. With purge-on-session-finalize in
    # place (see __init__.py) this is only the CRASH fallback: a session that
    # never fires on_session_finalize (hard crash) still sheds its mappings
    # within mapping_ttl_seconds. 1h is fine for the fallback; the primary
    # retention control is the finalize hook. Deployments that want no
    # wall-clock fallback at all can raise it in config.yaml.
    mapping_ttl_seconds: int = 3600

    # Egress / restore control
    restore_allowed_channels: tuple[str, ...] = field(default_factory=_default_restore_channels)
    # v1.7.6 (Decision 1): what happens to a residual TOKEN_* span after the
    # restore pass could not resolve it (mapping miss, ambiguous (type,
    # serial) splice candidates, legacy row without serial). "placeholder"
    # replaces the span with ``restore_miss_placeholder`` (fail-closed: the
    # user sees that masking happened, tokens never egress unreadable and
    # silent); "keep" leaves the literal token in the output. Invalid YAML
    # values fall back to the default with a warning (see load_config /
    # validate_config), mirroring ``reasoning.mode`` handling.
    restore_miss_strategy: str = "placeholder"
    restore_miss_placeholder: str = DEFAULT_RESTORE_MISS_PLACEHOLDER
    vault_tool_prefixes: tuple[str, ...] = ("mcp__obsidian__",)
    cache_bypass: bool = True

    # Performance
    max_latency_ms: int = 80
    fallback_on_timeout: str = "block"  # "block" | "allow_unshielded"

    # Confidence-Threshold für Auto-Masking (FIX-4B / Architect NEU-002)
    # Matches mit confidence < confidence_threshold werden NUR geloggt,
    # NICHT pseudonymisiert. Per-Type Overrides setzen einen höheren
    # Threshold für spezifische PII-Typen (Default 1.0 = niemals auto-mask).
    #
    # REVERT 2026-10-11: t_025240da P0-1 senkte diesen Wert auf 0.65, um
    # reale Namen in E-Mails (is_person_name liefert 0.7) zu maskieren.
    # Folge war Übermaskierung der Systemterminologie (Profil-/Agenten-
    # namen) in Telegram-Antworten + Output-Sanitizer frisch gemintete,
    # unrestorable Tokens -> Restore-Misses flottenweit. 0.8 ist wieder
    # Default; das LinkedIn-Mail-Problem ist über die Whitelist zu lösen,
    # nicht über den globalen Threshold.
    confidence_threshold: float = 0.8
    # v1.6.1 - Reasoning-In-Memory-Redaktion (Kompromiss-Pfad).
    # Default restore: Reasoning-PII wird im Memory durch Tokens ersetzt.
    # Persistenz-Limitation: state.db enthaelt PII kurzzeitig vor Hook.
    reasoning: ReasoningBlockConfig = field(
        default_factory=ReasoningBlockConfig
    )

    confidence_overrides: dict[str, float] = field(
        default_factory=lambda: {
            # Cookie/Session-Tokens: 32+ alphanumerische chars matchen zu
            # viele legitime Werte (URL-Slugs, JSON-IDs, Hex-Hashes) →
            # detection-only, niemals auto-mask.
            "cookie_id": 1.0,
            # Kontextuelle DSGVO-Art-9-Treffer (Diagnose, Religion, …) und
            # Salary/Debt/Job-Kontext haben hohe False-Positive-Rate. Sie
            # werden geloggt, aber nie automatisch pseudonymisiert — der
            # User entscheidet selbst, ob er den Kontext teilen will.
            "health_context": 1.0,
            "sensitive_context": 1.0,
            "birthday_context": 1.0,
            "death_context": 1.0,
            "family_context": 1.0,
            "nationality_context": 1.0,
            "job_context": 1.0,
            "salary_context": 1.0,
            "debt_context": 1.0,
            # GPS-Koordinaten sind 0.7 — Overwrite hebt sie ebenfalls auf
            # detection-only (privatsphären-kritisch, false-positive anfällig).
            "gps": 1.0,
        }
    )

    # PDF preprocessor (Phase 1)
    pdf_enabled: bool = True
    # BUTLER-PS-7 / FIX-PS-R5-OPS: default to the secure hermes-private
    # tree, not /tmp, so a fresh install never lands sanitised PDFs in
    # a shared-host tmp with looser permissions. Operators can still
    # override via config.yaml when running in an air-gapped sandbox.
    pdf_restore_dir: str = "~/.hermes/privacy/restore/pdf"
    pdf_max_size_mb: int = 100

    # Image OCR preprocessor (Phase 2)
    image_enabled: bool = True
    # BUTLER-PS-7: same rationale as pdf_restore_dir.
    image_restore_dir: str = "~/.hermes/privacy/restore/image"
    image_max_size_mb: int = 50
    ocr_lang: str = "deu+eng"
    ocr_min_confidence: int = 30

    # Email preprocessor (P1, t_025240da): .eml header/HTML sanitization.
    # Behandelte Bedrohungen: T1 Tracking-Pixel, T2 Click-Tracker-Links,
    # T3_sensitive Header (X-Originating-IP, X-Mailer, Received-IPs).
    email_enabled: bool = True
    # BUTLER-PS-7: same rationale as pdf_restore_dir.
    email_restore_dir: str = "~/.hermes/privacy/restore/email"
    email_max_size_mb: int = 10
    # Tracking pixels: <img> with width<=email_pixel_max_dim AND
    # height<=email_pixel_max_dim is removed from the HTML body.
    email_pixel_max_dim: int = 2
    # When True, tracker hrefs are rewritten to "about:blank"; when False
    # the whole anchor tag is removed.  Both directions exist because
    # removing the element may collapse layout-sensitive newsletters and
    # rewriting keeps the visible text anchored to a dead target.
    email_rewrite_links_to_blank: bool = True

    # Audit (FIX-PS3 — reaktiviert per Butler R5 / BUTLER-PS-2 HIGH).
    # Persistente, side-channel-sichere Audit-Trail (JSONL, chmod 600).
    # Default-Pfad liegt im aktiven Profil-Workspace, damit die Datei im
    # normalen Hermes-Backup-Pfad enthalten ist und nicht in einem
    # geteilten Verzeichnis mit zu lockeren Rechten entsteht.
    audit_jsonl_path: str = "~/.hermes/profiles/default/workspace/privacy-shield-audit.jsonl"
    audit_jsonl_enabled: bool = True

    # BUTLER-PS-4 / FIX-PS-R5-OPS: rotierender Operator-Logger (Rotation
    # + Retention). Defaults spiegeln Injection-Shield für eine konsistente
    # Operations-Sprache über beide Plugins: 10 MiB × 5 Backups + 90-Tage
    # Pruning (DSGVO Art. 5(1)(e) Speicherbegrenzung).
    audit_log_path: str = "~/.hermes/profiles/default/workspace/05-Logs-Snapshots/privacy-shield.log"
    audit_log_max_bytes: int = 10 * 1024 * 1024  # 10 MiB
    audit_log_backup_count: int = 5
    audit_log_retention_days: int = 90

    # FIX-1E: Risky-Tool-Defaults.
    # Tool names whose content reaches the plugin pre_llm_call and that have
    # elevated provider-egress risk: ``web_extract`` can return attacker-controlled
    # pages that inject obfuscated PII prompts, ``write_file`` / ``kanban_attach``
    # write to disk / upload attachments (potential persistence of unmasked PII),
    # ``browser_exec`` / ``execute_code`` run code that may exfiltrate the
    # surrounding prompt context.  When a hook receives a payload that originated
    # from one of these tools, the plugin (a) keeps the shielding pipeline active
    # even when ``mode == 'audit'`` and (b) emits a structured log line so the
    # audit trail records the elevated risk context.
    #
    # Operators can extend this list via the dataclass.  The default is a tuple
    # (immutable) so config-loading cannot accidentally mutate the shared set.
    risky_tool_names: tuple[str, ...] = (
        "web_extract",
        "write_file",
        "kanban_attach",
        "browser_exec",
        "execute_code",
    )

    # FIX-1E: Bypass-Hardening for Risky-Tool calls.  When True, the plugin
    # does NOT short-circuit on ``mode == 'off'`` for risky-tool payloads.  This
    # prevents a misconfigured "off"-mode deployment from accidentally shipping
    # PII into web-extracted pages or attachments.  Vault sources still bypass
    # (they never reach the provider).
    risky_tool_force_shield: bool = True

    # FIX-1E: Code-Snippet False-Positive Tuning.  Patterns that look like PII
    # inside code snippets (test fixtures, example constants, ``__init__``
    # strings, JSON schemas) are down-scored by ``code_context_penalty`` (a
    # multiplicative factor on the pattern's confidence).  Effective confidence
    # is clamped to [0.0, 1.0].  Setting the penalty to 1.0 disables the
    # adjustment; 0.6 is the validated default that keeps all 369 legacy tests
    # green while preventing the new 50-snippet FP suite from triggering.
    code_context_penalty: float = 0.6


def _resolve_pass_binary() -> str | None:
    """Resolve the pass binary robustly for launchd, hardened against tampering.

    C-001 fix: ``os.path.expanduser`` trusts the attacker-controllable ``HOME``
    env var, so a hostile environment could point the fallback at an arbitrary
    binary executed during key loading. The fallback home directory is therefore
    derived from ``pwd.getpwuid(os.getuid())`` instead. The fallback binary
    (with symlinks resolved via ``realpath``) must be owned by the current
    user, not writable by group/other, and located inside a whitelisted
    directory (H-002).

    A ``shutil.which("pass")`` hit is returned as-is: PATH-based resolution is
    the same trust model as any exec, and the whitelist must not break
    legitimately installed pass binaries at arbitrary PATH locations.
    """
    which_hit = shutil.which("pass")
    if which_hit:
        return which_hit

    try:
        import pwd

        home = pwd.getpwuid(os.getuid()).pw_dir
    except (ImportError, KeyError):
        home = str(Path.home())
    candidate = str(Path(home) / ".local" / "bin" / "pass")

    allowed_parents = (
        str(Path.home() / ".local" / "bin"),
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
    )

    real = os.path.realpath(candidate)
    if not os.path.isfile(real) or not os.access(real, os.X_OK):
        return None
    if os.path.dirname(real) not in allowed_parents:
        return None
    try:
        st = os.stat(real)
    except OSError:
        return None
    if st.st_uid != os.getuid():
        return None
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return None
    return candidate


def _load_key_via_hermes() -> str | None:
    """Resolve the encryption key through Hermes' secret-scope machinery.

    The key is declared in ``plugin.yaml`` under ``requires_env`` as
    ``PRIVACY_SHIELD_KEY``; Hermes resolves the value through its configured
    secret sources (env loader, Keychain / pass-store secret-source plugins,
    command source). The plugin must not read ``os.environ`` or invoke the
    ``pass`` binary itself.
    """
    try:
        from agent.secret_scope import get_secret
    except ImportError:
        # Not running inside Hermes (e.g. standalone CLI/tests): no key.
        return None
    try:
        result: str | None = get_secret("PRIVACY_SHIELD_KEY")
        return result
    except Exception:
        # F-4 (orakel review t_c0a50b6f): get_secret raises
        # UnscopedSecretError when multiplexing is active without a bound
        # scope. Treat it like a missing key (Phase-4 contract: never crash
        # Hermes initialization) instead of failing plugin load.
        return None


def _generate_key() -> str:
    """Generate a random 256-bit key.

    This function must ONLY be called from ``privacy-shield setup`` or when
    the explicit workshop fallback is enabled.  It is NOT a production key
    source because the generated key is not persisted.
    """
    import secrets
    return secrets.token_hex(32)


def load_config() -> PrivacyShieldConfig:
    """Load configuration with key resolution.

    Key loading priority:
    1. Hermes secret scope (PRIVACY_SHIELD_KEY via requires_env — env loader,
       Keychain / pass-store secret-source plugins, command source)
    2. PRIVACY_SHIELD_KEY_FILE env var (path to a file containing the key)
    3. Workshop mode (PRIVACY_SHIELD_WORKSHOP=true): auto-generate with warning
    4. Production mode: disable plugin and warn instead of crashing.

    Phase-4 change: the plugin must never crash Hermes initialization because
    of a missing key. In production without a key it falls back to enabled=False
    and logs the setup command.

    DESKTOP-UI v1.5.0: after defaults are built, merge any user overrides from
    ``~/.hermes/config.yaml`` under ``plugins.entries.privacy-shield``. This
    lets the Desktop-Controls backend persist edits where Hermes already looks
    for plugin settings, without adding a new config file.
    """
    import logging
    logger = logging.getLogger(__name__)
    config = PrivacyShieldConfig()

    # Resolve encryption key
    key = _load_key_via_hermes()
    if key:
        config.encryption_key = key

    if not config.encryption_key:
        key_file = os.environ.get("PRIVACY_SHIELD_KEY_FILE")
        if key_file:
            try:
                # F-5 (orakel review t_c0a50b6f): refuse group/other-writable
                # or non-regular files — a plaintext key must not be readable
                # (or replaceable via symlink) by anyone but the owner.
                import stat as _stat

                st = os.stat(key_file)
                # W2-3 (orakel wave-2): the comment promised "readable by no
                # one but the owner" — enforce READ bits and ownership too.
                if not _stat.S_ISREG(st.st_mode):
                    logger.warning(
                        "Privacy-Shield: PRIVACY_SHIELD_KEY_FILE %s is not a "
                        "regular file; ignoring the fallback.",
                        key_file,
                    )
                elif st.st_mode & (
                    _stat.S_IWGRP
                    | _stat.S_IWOTH
                    | _stat.S_IRGRP
                    | _stat.S_IROTH
                ):
                    logger.warning(
                        "Privacy-Shield: PRIVACY_SHIELD_KEY_FILE %s is "
                        "group/other-accessible; refusing the insecure "
                        "key file (chmod 600).",
                        key_file,
                    )
                elif st.st_uid != os.getuid():
                    logger.warning(
                        "Privacy-Shield: PRIVACY_SHIELD_KEY_FILE %s is not "
                        "owned by the current user; refusing.",
                        key_file,
                    )
                else:
                    key = Path(key_file).read_text().strip()
                    if key:
                        config.encryption_key = key
            except OSError as exc:
                logger.debug("Privacy-Shield: KEY_FILE fallback skipped: %s", exc)

    # Workshop mode: generate ephemeral key
    if not config.encryption_key and os.environ.get("PRIVACY_SHIELD_WORKSHOP", "").lower() in ("1", "true", "yes"):
        logger.warning(
            "Privacy-Shield: No encryption key found (pass/env). "
            "Generated ephemeral key — mapping table will be unreadable on restart."
        )
        config.encryption_key = _generate_key()

    # Allow tests and CI to override a few fields via environment.
    # Applied regardless of key state: test isolation must not depend on
    # whether a real key exists in the pass store.
    if "PRIVACY_SHIELD_AUDIT_JSONL_PATH" in os.environ:
        config.audit_jsonl_path = os.environ["PRIVACY_SHIELD_AUDIT_JSONL_PATH"]
    # PRIVACY_SHIELD_AUDIT_LOG_PATH: test-isolation override. Redirects the
    # rotating operator log (plugin.py attach_rotating_handler) so pytest
    # fixtures never write into the production log.
    if "PRIVACY_SHIELD_AUDIT_LOG_PATH" in os.environ:
        config.audit_log_path = os.environ["PRIVACY_SHIELD_AUDIT_LOG_PATH"]
    if "PRIVACY_SHIELD_STORAGE_MODE" in os.environ:
        config.storage_mode = os.environ["PRIVACY_SHIELD_STORAGE_MODE"]
    if "PRIVACY_SHIELD_MODE" in os.environ:
        config.mode = os.environ["PRIVACY_SHIELD_MODE"]
    if "PRIVACY_SHIELD_REASONING_MODE" in os.environ:
        _env_mode = os.environ["PRIVACY_SHIELD_REASONING_MODE"]
        if _env_mode == "off":
            config.reasoning.mode = "off"
        elif _env_mode == "audit":
            config.reasoning.mode = "audit"
        elif _env_mode == "restore":
            config.reasoning.mode = "restore"
        else:
            logger.warning(
                "Privacy-Shield: invalid PRIVACY_SHIELD_REASONING_MODE=%r, "
                "expected one of {off, audit, restore}; using default",
                _env_mode,
            )
    if "PRIVACY_SHIELD_REASONING_CONFIDENCE" in os.environ:
        try:
            config.reasoning.confidence_threshold = float(
                os.environ["PRIVACY_SHIELD_REASONING_CONFIDENCE"]
            )
        except ValueError:
            logger.warning(
                "Privacy-Shield: invalid PRIVACY_SHIELD_REASONING_CONFIDENCE"
            )

    # Production fallback: disable instead of crashing
    if not config.encryption_key:
        logger.warning(
            "Privacy-Shield: No encryption key found. Plugin disabled. "
            "Run 'privacy-shield setup' or set PRIVACY_SHIELD_KEY."
        )
        config.enabled = False
        config.encryption_key = ""  # empty key: mapper must not be used

    # Merge user overrides from Hermes config.yaml regardless of key state;
    # a user might still want to tune thresholds before enabling the key.
    _merge_user_config(config)
    # v1.7.6 (Decision 1): invalid restore_miss_strategy falls back to the
    # default with a warning instead of silently disabling the residual pass
    # semantics — same contract as the reasoning-mode env validation above.
    if config.restore_miss_strategy not in ALLOWED_RESTORE_MISS_STRATEGIES:
        logger.warning(
            "Privacy-Shield: invalid restore_miss_strategy=%r, expected one of "
            "%s; using default 'placeholder'",
            config.restore_miss_strategy,
            "/".join(ALLOWED_RESTORE_MISS_STRATEGIES),
        )
        config.restore_miss_strategy = "placeholder"
    if not isinstance(config.restore_miss_placeholder, str) or not config.restore_miss_placeholder:
        logger.warning(
            "Privacy-Shield: restore_miss_placeholder is empty or not a string "
            "(%s); using default text",
            type(config.restore_miss_placeholder).__name__,
        )
        config.restore_miss_placeholder = DEFAULT_RESTORE_MISS_PLACEHOLDER
    return config


def _coerce_field_value(field_name: str, raw: Any) -> Any:
    """Convert a YAML-loaded value to the type expected by the dataclass.

    Only the fields that commonly come from YAML need special handling:
    tuples (``restore_allowed_channels``, ``vault_tool_prefixes``,
    ``risky_tool_names``) are stored as tuples but YAML emits lists.
    """
    if field_name in (
        "restore_allowed_channels",
        "vault_tool_prefixes",
        "risky_tool_names",
    ):
        if isinstance(raw, (list, tuple)):
            return tuple(str(x) for x in raw)
        if isinstance(raw, str):
            return (raw,)
        return raw
    return raw


def _merge_user_config(config: PrivacyShieldConfig) -> None:
    """Apply overrides from ``~/.hermes/config.yaml`` if present.

    Reads ``plugins.entries.privacy-shield`` and overwrites any dataclass
    field that matches a known config key. Nested ``telegram``-style objects
    are not used by Privacy-Shield, so a flat merge is sufficient.
    """
    if yaml is None:
        return
    hermes_home = Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    config_path = hermes_home / "config.yaml"
    if not config_path.exists():
        return
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            full = yaml.safe_load(f) or {}
    except Exception:
        return
    user = full.get("plugins", {}).get("entries", {}).get("privacy-shield", {})
    if not isinstance(user, dict):
        return
    known = {f.name for f in fields(config)}
    for key, value in user.items():
        if key not in known:
            continue
        if value is None:
            continue
        try:
            coerced = _coerce_field_value(key, value)
            setattr(config, key, coerced)
        except (TypeError, ValueError):
            # Preserve the default if the YAML value is incompatible.
            pass


def validate_config(config: PrivacyShieldConfig) -> list[str]:
    """Validate configuration, return list of issues (empty = valid)."""
    issues = []

    if config.mode not in ALLOWED_MODES:
        issues.append(f"Invalid mode: {config.mode} (expected one of {ALLOWED_MODES})")

    if config.detection_engine not in ("regex", "ner", "hybrid"):
        issues.append(f"Invalid detection_engine: {config.detection_engine}")

    if config.token_style not in ("deterministic", "random"):
        issues.append(f"Invalid token_style: {config.token_style}")

    if config.fallback_on_timeout not in ("block", "allow_unshielded"):
        issues.append(f"Invalid fallback_on_timeout: {config.fallback_on_timeout}")

    if config.max_latency_ms < 1:
        issues.append(f"max_latency_ms must be positive: {config.max_latency_ms}")

    if not 0.0 <= config.confidence_threshold <= 1.0:
        issues.append(
            f"confidence_threshold must be in [0.0, 1.0]: {config.confidence_threshold}"
        )

    if config.reasoning.mode not in ("off", "audit", "restore"):
        issues.append(
            f"Invalid reasoning.mode: {config.reasoning.mode} "
            "(expected one of off/audit/restore)"
        )
    if config.restore_miss_strategy not in ALLOWED_RESTORE_MISS_STRATEGIES:
        issues.append(
            f"Invalid restore_miss_strategy: {config.restore_miss_strategy} "
            f"(expected one of {'/'.join(ALLOWED_RESTORE_MISS_STRATEGIES)})"
        )
    if not isinstance(config.restore_miss_placeholder, str):
        issues.append(
            f"restore_miss_placeholder must be a string, got "
            f"{type(config.restore_miss_placeholder).__name__}"
        )
    elif not config.restore_miss_placeholder:
        issues.append("restore_miss_placeholder must not be empty")
    if not 0.0 <= config.reasoning.confidence_threshold <= 1.0:
        issues.append(
            f"reasoning.confidence_threshold must be in [0.0, 1.0]: "
            f"{config.reasoning.confidence_threshold}"
        )

    for pii_type, threshold in config.confidence_overrides.items():
        if not 0.0 <= threshold <= 1.0:
            issues.append(
                f"confidence_overrides['{pii_type}'] must be in [0.0, 1.0]: {threshold}"
            )

    if not config.encryption_key:
        issues.append("encryption_key is empty")
    if config.storage_mode == "disk" and not config.encryption_key:
        issues.append("disk storage requires an encryption_key")

    return issues


def effective_threshold(config: PrivacyShieldConfig, pii_type: str) -> float:
    """Return the per-type confidence threshold.

    The plugin compares a match's ``confidence`` against this value: matches
    with confidence below the threshold are logged but NOT auto-masked.
    Per-type overrides in ``config.confidence_overrides`` take precedence over
    the global ``config.confidence_threshold``; an override of ``1.0`` means
    "never auto-mask" (detection-only).
    """
    return config.confidence_overrides.get(pii_type, config.confidence_threshold)
