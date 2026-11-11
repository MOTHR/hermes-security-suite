"""Privacy-Shield Plugin — Main Plugin Class.

Phase 1: Limited-Risk + Regex-Detection + Core-Hook Fail-Safe.

Spec reference: Privacy-Shield-AI-Act-Architektur-Spec-v1.md Section 3.1
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import Any

from .audit import AuditLogger
from .cache_bypass import CacheBypassInjector
from .config import PrivacyShieldConfig, load_config
from .detectors.chain_factory import build_default_chain
from .detectors.regex_detector import RegexPIIDetector
from .errors import (
    ParanoidModeBlock,
    StrictModeBlock,
)
from .fs_hardening import ensure_secure_dir
from .lifecycle import maybe_enable_json_logging, register_shutdown_hooks
from .log_utils import (
    bucket_count,
    log_detections,
    log_dropped_detections,
    partition_by_confidence,
)
from .mapping_table import InMemoryMappingTable, MappingTable
from .metrics import (
    get_metrics,  # LINK-PS-8: expose metrics API on the plugin module
    record_restore_miss,
)
from .output_sanitizer import OutputSanitizer
from .processors import AttachmentProcessor, init_attachment_preprocessor
from .pseudonymizer import Pseudonymizer
from .rotating_log import attach_rotating_handler, settings_from_config
from .token_validator import (  # GB-010 defensive verification helpers
    contains_privacy_shield_token,
    find_last_assistant_reasoning,
    has_raw_pii,
)

logger = logging.getLogger(__name__)

# Channels where token restoration is allowed (PII is shown to the end user).
# Everything else keeps tokens pseudonymized to prevent accidental egress.
# The default is populated from config / environment; kept here for backward
# compatibility with tests that import this constant directly.
ALLOWED_RESTORE_CHANNELS: frozenset[str] = frozenset()

# Sources that are trusted and do NOT leave the local machine → no provider egress.
VAULT_TOOL_PREFIXES: tuple[str, ...] = ("mcp__obsidian__",)


# ── Graceful-shutdown bookkeeping + JSON logging live in lifecycle.py ─────
# (Morpheus R5 / FIX-PS-R5-STRUCT: extracted to keep this module focused
# on the plugin class — see ``register_shutdown_hooks`` and
# ``maybe_enable_json_logging``.)
from .lifecycle import (  # noqa: F401
    JsonFormatter,
)


class PrivacyShieldPlugin:
    """Entry-point: registered via Hermes plugin system.

    Implements pre_llm_call + transform_llm_output hooks.
    Phase 4: 47 patterns, in-memory mapping table, egress-aware restoration.
    """

    def __init__(self, config: PrivacyShieldConfig | None = None):
        self.config = config or load_config()
        # FIX-1E: thread the code-context penalty from config into the detector.
        self.detector = RegexPIIDetector(
            code_context_penalty=self.config.code_context_penalty
        )
        # FIX-PS4 / MORPH-PS-1: modernised DetectorChain (fail-separate + overlap resolution).
        self.detector_chain = build_default_chain()
        self.pseudonymizer = Pseudonymizer(
            token_style=self.config.token_style,
            token_prefix=self.config.token_prefix,
        )
        self.mapper: MappingTable | InMemoryMappingTable = self._build_mapper()
        self._provider_warned: set[str] = set()
        # llm_request middleware staging slot: sanitized prompt produced by the
        # last pre_llm_call, consumed by the next outgoing request (one slot).
        self._staged_shields: dict[str, dict[str, Any]] = {}
        self._pdf_preprocessor = self._init_attachment_preprocessor("pdf")
        self._image_preprocessor = self._init_attachment_preprocessor("image")
        self._email_preprocessor = self._init_attachment_preprocessor("email")
        # FIX-PS3: persistenter Audit-Trail. No-Op wenn ``enabled=False``.
        self.audit: AuditLogger | None = (
            AuditLogger(self.config.audit_jsonl_path)
            if self.config.audit_jsonl_enabled
            else None
        )
        # BUTLER-PS-4 / FIX-PS-R5-OPS: rotate the operator log on init.
        # Idempotent across multiple PrivacyShieldPlugin instances.
        try:
            log_cfg = settings_from_config(self.config)
            attach_rotating_handler(
                log_path=log_cfg["log_path"],
                max_bytes=log_cfg["max_bytes"],
                backup_count=log_cfg["backup_count"],
                retention_days=log_cfg["retention_days"],
                prune_now=True,
            )
        except OSError as exc:
            logger.warning("Privacy-Shield rotating logger init failed: %s", exc)

        # FIX-PS-R5-STRUCT (Morpheus R5 / MORPH-PS-3): extracted helpers.
        # output_sanitizer -> post-LLM PII scan; cache_bypass -> cache-key prefix;
        # _pdf_processor / _image_processor -> unified attachment loop.
        self.output_sanitizer = OutputSanitizer(
            detector=self.detector,
            pseudonymizer=self.pseudonymizer,
            mapper=self.mapper,
            partition_by_confidence=self._partition_by_confidence,
        )
        self.cache_bypass = CacheBypassInjector(enabled=self.config.cache_bypass)
        self._pdf_processor = self._make_attachment_processor(self._pdf_preprocessor)
        self._image_processor = self._make_attachment_processor(
            self._image_preprocessor
        )
        self._email_processor = self._make_attachment_processor(
            self._email_preprocessor
        )

        # LINK-PS-6: graceful shutdown hooks (lifecycle.py).
        register_shutdown_hooks(self.mapper, id(self))

        # LINK-PS-8: structured JSON logs when LOG_JSON=1 is set in the environment.
        maybe_enable_json_logging()

    def _make_attachment_processor(
        self, preprocessor: Any | None
    ) -> AttachmentProcessor:
        """Wrap a single pre-processor in an :class:`AttachmentProcessor`.

        Returns a processor with an empty pre-processor list when the
        pre-processor is disabled (``None``) — :meth:`AttachmentProcessor.process`
        short-circuits on an empty list, so the hook needs no separate
        ``if disabled`` branch.
        """
        return AttachmentProcessor(
            preprocessors=[preprocessor] if preprocessor is not None else [],
            detector=self.detector,
            pseudonymizer=self.pseudonymizer,
            mapper=self.mapper,
            confidence_threshold=self.config.confidence_threshold,
        )

    # ── Helpers ─────────────────────────────────────────────────────────

    # BUTLER-PS-7 / FIX-PS-R5-OPS: canonical fallback directory used when
    # the operator-configured ``*_restore_dir`` (default ``~/.hermes/privacy/restore/...``)
    # cannot be secured. We no longer fall back to ``/tmp`` because shared
    # temporary directories are world-readable on multi-user hosts and would
    # defeat the purpose of the sanitised restore staging area. The fallback
    # is a hermes-private tree under ``$HOME/.hermes/privacy/restore``.
    SECURE_RESTORE_FALLBACK = "~/.hermes/privacy/restore"

    def _ensure_secure_restore_dir(self, configured: str, kind: str) -> Path:
        """Ensure ``configured`` exists with mode 0o700, fall back if not.

        BUTLER-PS-7: the previous implementation could leave sanitised PDFs /
        images in a world-readable directory when the configured path already
        existed with looser permissions. We now (a) try the configured path,
        (b) detect any chmod failure, and (c) fall back to
        ``~/.hermes/privacy/restore/<kind>`` which always sits on the
        operator's home filesystem where we own the mode bits. The fallback
        path and its parent are also chmod 0o700.

        PS-REST-003: directory verification and the permission fixup run
        through a no-follow file descriptor (``O_NOFOLLOW|O_DIRECTORY`` +
        ``fstat`` + ``fchmod``, see :func:`fs_hardening.ensure_secure_dir`),
        so a symlink planted at the path — at any point, including between
        creation and verification — can no longer redirect the chmod or the
        later artifact writes to a foreign target; the primary path fails
        and the private fallback is used instead.
        """
        primary = Path(configured).expanduser()
        try:
            ensure_secure_dir(primary, 0o700)
            return primary
        except OSError as exc:
            logger.warning(
                "Privacy-Shield %s: cannot secure restore dir %s without "
                "following links: %s — falling back to %s",
                kind,
                primary,
                exc,
                self.SECURE_RESTORE_FALLBACK,
            )

        # Fallback: home-private directory. Always owned by the operator
        # and on the Hermes backup path so the sanitised artefacts do
        # not leak via shared-host tmp.
        fallback = Path(self.SECURE_RESTORE_FALLBACK).expanduser() / kind
        try:
            ensure_secure_dir(fallback.parent, 0o700)
            ensure_secure_dir(fallback, 0o700)
            return fallback
        except OSError as exc:
            # Last-resort hard fail (per BUTLER-PS-7 spec): better to
            # refuse the restore than to drop PII into a permissive dir.
            raise RuntimeError(
                f"Privacy-Shield {kind}: cannot create secure restore dir "
                f"(tried {primary} and {fallback}): {exc}"
            ) from exc

    def _init_attachment_preprocessor(self, kind: str) -> Any | None:
        """Lazy-init a single attachment pre-processor by *kind*.

        Thin wrapper around :func:`processors.init_attachment_preprocessor`
        so the plugin init code reads as a list of "kinds to enable".
        All the actual loader / spec / restore-dir logic lives in the
        processors module (Morpheus R5 / SMELL-5 dedup).
        """
        return init_attachment_preprocessor(self, kind)

    def _build_mapper(self) -> MappingTable | InMemoryMappingTable:
        """Return a mapping backend based on config.storage_mode."""
        # FIX-4A (NEU-001): Token-pattern parameters are threaded from config
        # to the mapper so a custom ``token_prefix`` (e.g. ``PS``) is honored
        # by both the Pseudonymizer AND the restore-text regex. Without this
        # the restore regex would only match ``TOKEN_`` and PII would leak
        # through tokens in the response.
        token_prefix = self.config.token_prefix
        hash_length = Pseudonymizer.HASH_LENGTH
        counter_digits = Pseudonymizer.COUNTER_DIGITS

        if self.config.storage_mode == "memory":
            return InMemoryMappingTable(
                token_prefix=token_prefix,
                hash_length=hash_length,
                counter_digits=counter_digits,
            )
        if self.config.storage_mode == "disk" and not self.config.encryption_key:
            # PS-MAPPER-004: fail closed. The former 2026-10-10 fail-open
            # fallback silently built an in-memory table for enabled disk-mode
            # configs, which loses all mappings on process restart — tokens
            # become unresolvable. An enabled plugin must never run in this
            # misconfigured state; raise instead so deployment fails loudly.
            if self.config.enabled:
                raise RuntimeError(
                    "Privacy-Shield: cannot start in secure mode — "
                    "'disk' storage requires 'encryption_key'. "
                    "Run 'privacy-shield setup' or set PRIVACY_SHIELD_KEY. "
                    "Refusing to fall back to a non-persistent in-memory "
                    "mapping table (PS-MAPPER-004)."
                )
            # Disabled configs (load_config sets enabled=False when no key
            # resolves) keep their legitimate graceful path: the plugin never
            # processes text in that state, so the backend choice is inert.
            logger.warning(
                "Privacy-Shield: disabled plugin constructed with disk "
                "mapping and no encryption key; using an inert in-memory "
                "table (never used for processing)."
            )
            return InMemoryMappingTable(
                token_prefix=token_prefix,
                hash_length=hash_length,
                counter_digits=counter_digits,
            )
        return MappingTable(
            storage_path=self.config.storage_path,
            encryption_key=self.config.encryption_key,
            token_prefix=token_prefix,
            hash_length=hash_length,
            counter_digits=counter_digits,
        )

    def _is_vault_source(self, content_source: str) -> bool:
        """Vault reads stay local and never reach the provider; skip shielding."""
        return any(
            content_source.startswith(prefix)
            for prefix in self.config.vault_tool_prefixes
        )

    def _is_risky_tool(self, tool_name: str) -> bool:
        """Return True if the originating tool is on the configured risky list.

        FIX-1E: ``web_extract`` / ``write_file`` / ``kanban_attach`` /
        ``browser_exec`` / ``execute_code`` are flagged because their payloads
        have elevated provider-egress risk (attacker-controlled pages, file
        persistence, code-execution side channels).  When a risky tool feeds
        the prompt we log the elevated context and (when configured) bypass
        the ``mode == 'off'`` short-circuit so a misconfigured deployment
        cannot accidentally ship PII into the tool's downstream.
        """
        return tool_name in self.config.risky_tool_names

    def _log_risky_tool_event(self, tool_name: str, ctx: dict[str, Any]) -> None:
        """Emit a structured audit line for risky-tool shielding events.

        Format is intentionally machine-parseable (``key=value`` pairs) so the
        audit pipeline can grep / aggregate without an LLM step.
        """
        logger.info(
            "Privacy-Shield risky-tool: tool=%s session=%s provider=%s "
            "mode=%s risky_force_shield=%s",
            tool_name,
            ctx.get("session_id", ""),
            ctx.get("provider", ""),
            self.config.mode,
            self.config.risky_tool_force_shield,
        )

    # ------------------------------------------------------------------ Attachments

    def _run_attachment_processor(
        self,
        processor: AttachmentProcessor,
        preprocessor: Any | None,
        restore_dir: str,
        restore_extension: str,
        format_label: str,
        prompt: str,
        ctx: dict[str, Any],
    ) -> tuple[Any | None, str, str | None]:
        """Delegate to an :class:`AttachmentProcessor` and surface errors.

        Single helper for the PDF and image attachment paths — they
        differ only in which pre-processor / restore dir they use.
        Returns ``(preprocessor, expanded_prompt, error_summary)``
        with the same semantics as the original
        :meth:`_maybe_process_pdf_attachments` and
        :meth:`_maybe_process_image_attachments` methods.
        """
        if preprocessor is None:
            return None, prompt, None
        ctx = {**ctx, "config": self.config}
        batch = processor.process(
            prompt,
            ctx,
            restore_dir=Path(restore_dir).expanduser(),
            restore_extension=restore_extension,
            format_label=format_label,
        )
        errors = "; ".join(r.error for r in batch.results if r.error)
        return preprocessor, batch.expanded_prompt, errors or None

    def pre_llm_call(
        self, prompt: str, context: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        """Called by Core-Hook before every LLM API call.

        Upstream contract (``agent/turn_context.py``): the only consumed
        returns are ``{"action": "block", "message": ...}`` — which vetoes
        the turn — and ``{"context": ...}`` / plain strings, which are
        injected into the user message. This hook therefore only VETOES
        (strict mode with a known cloud provider, or paranoid mode) and
        otherwise stages its sanitized prompt for the ``llm_request``
        middleware (:meth:`apply_shield_to_request`), which rewrites the
        user message inside the outgoing request payload.
        """
        ctx = context or {}
        config = self.config
        # F-2 (orakel review t_c0a50b6f): the middleware must know the LIVE
        # prompt as it appears on the wire (before attachment expansion) so
        # it can rewrite only the live-prompt portion and keep the core's
        # sidecar context suffix byte-exact.
        ctx["raw_prompt"] = prompt
        if not config.enabled:
            return None

        # FIX-1E: detect risky-tool origin and emit a structured audit
        # event.  ``risky_tool_force_shield`` (config) determines whether
        # we honour the operator's ``mode == 'off'`` shortcut for these
        # payloads.
        is_risky = self._is_risky_tool(
            ctx.get("tool_name", "") or ctx.get("content_source", "")
        )
        if is_risky:
            self._log_risky_tool_event(
                ctx.get("tool_name", "") or ctx.get("content_source", ""), ctx
            )

        # Apply the cheap short-circuits (mode=off, vault source, local
        # provider) before any expensive extraction work.
        if self._should_bypass(ctx, config, is_risky=is_risky):
            return None

        # PDF + image attachments: extract text + pseudonymize + render
        # sanitized copy.  Must run BEFORE the text-path pseudonymizer
        # so the prompt handed to the detector already contains
        # sanitized PDF content rather than raw PII from the file.
        pdf_pre, prompt, pdf_summary = self._run_attachment_processor(
            self._pdf_processor,
            self._pdf_preprocessor,
            self.config.pdf_restore_dir,
            ".pdf",
            "PDF ATTACHMENT",
            prompt,
            ctx,
        )
        if pdf_pre is not None and pdf_summary is not None:
            # PDF parsing failed -> drop the attachment, leave prompt.
            logger.warning(
                "Privacy-Shield PDF: extraction failed, attachment dropped (%s)",
                pdf_summary,
            )
            ctx = {**ctx, "pdf_attachments_dropped": pdf_summary}

        img_pre, prompt, img_summary = self._run_attachment_processor(
            self._image_processor,
            self._image_preprocessor,
            self.config.image_restore_dir,
            ".png",
            "IMAGE ATTACHMENT",
            prompt,
            ctx,
        )
        if img_pre is not None and img_summary is not None:
            logger.warning(
                "Privacy-Shield image: extraction failed, attachment dropped (%s)",
                img_summary,
            )
            ctx = {**ctx, "image_attachments_dropped": img_summary}

        # P1 (t_025240da): .eml attachments — header whitelist + pixel /
        # tracker-link sanitized body.  Runs like PDF/image above; the
        # sanitized .eml artifact lands in email_restore_dir and the
        # expanded prompt carries header-cleaned + pixel-stripped content.
        eml_pre, prompt, eml_summary = self._run_attachment_processor(
            self._email_processor,
            self._email_preprocessor,
            self.config.email_restore_dir,
            ".eml",
            "EMAIL ATTACHMENT",
            prompt,
            ctx,
        )
        if eml_pre is not None and eml_summary is not None:
            logger.warning(
                "Privacy-Shield email: extraction failed, attachment dropped (%s)",
                eml_summary,
            )
            ctx = {**ctx, "email_attachments_dropped": eml_summary}

        return self._shield_prompt(prompt, ctx, is_risky=is_risky)

    def _should_bypass(
        self, ctx: dict[str, Any], config: PrivacyShieldConfig, *, is_risky: bool
    ) -> bool:
        """Return True when the hook should skip shielding entirely.

        Three cheap checks live here: mode=off (with a risky-tool
        exception for ``risky_tool_force_shield``), vault reads that
        never reach a provider, and local Ollama calls.  Pulled out of
        :meth:`pre_llm_call` to keep the hot path readable.
        """
        if config.mode == "off" and not (is_risky and config.risky_tool_force_shield):
            return True
        if self._is_vault_source(ctx.get("content_source", "")):
            return True
        return ctx.get("provider", "") in ("ollama_local", "ollama")

    def _shield_prompt(
        self, prompt: str, ctx: dict[str, Any], *, is_risky: bool
    ) -> dict[str, Any] | None:
        """Apply the full PII detection + pseudonymisation pipeline.

        Sub-routine of :meth:`pre_llm_call` that owns the
        detection / confidence / mode / audit / cache-bypass sequence.
        A returned veto dict means "hard-block the turn" (upstream
        ``pre_llm_call`` contract). Otherwise the sanitized prompt is
        STAGED (single slot keyed by turn) for the ``llm_request``
        middleware — :meth:`apply_shield_to_request` consumes it and
        rewrites the outgoing user message. Returning ``None`` is the
        normal outcome; only blocks are signalled via the return value.
        """
        pii_hits = self.detector.scan(prompt)
        masked_hits, dropped_hits = self._partition_by_confidence(pii_hits)
        if dropped_hits:
            self._log_dropped_detections(dropped_hits, ctx.get("session_id", ""))

        config = self.config
        if config.mode == "audit":
            self._log_detections(
                [
                    {"type": m.type, "token": "", "original_value": m.value}
                    for m in masked_hits
                ],
                ctx.get("session_id", ""),
            )
            return None

        provider = ctx.get("provider", "")
        # STRICT block requires a known cloud provider. Upstream pre_llm_call
        # provides no ``provider`` kwarg; when it is absent the veto cannot be
        # provider-scoped, so strict mode defers to the mask path (PII never
        # leaves the machine — the block only guards against the turn
        # continuing at all). Paranoid vetoes regardless of provider.
        is_cloud_provider = bool(provider) and provider not in ("ollama_local", "ollama")
        # BLOCK-SIGNAL: strict/paranoid blocks are transported via the return
        # contract ({\"action\": \"block\", \"message\": ...}) instead of exceptions —
        # the Core hook dispatcher swallows every exception thrown
        # inside a pre_llm_call hook (plugins_dispatch catch-all).
        if config.mode == "strict" and masked_hits and is_cloud_provider:
            reason = (
                f"Privacy-Shield: {len(masked_hits)} PII match(es) detected in strict mode "
                f"for provider '{provider}'; blocking LLM call."
            )
        elif config.mode == "strict" and masked_hits and not is_cloud_provider:
            reason = None
            if self.audit is not None:
                self.audit.log(
                    event="strict_block_deferred",
                    session_id=ctx.get("session_id", ""),
                    masked_count=len(masked_hits),
                    pii_types=[m.type for m in masked_hits],
                    mode=config.mode,
                    model=ctx.get("model", ""),
                    platform=ctx.get("platform", ""),
                    note=(
                        "Upstream pre_llm_call provides no provider; strict veto "
                        "deferred, PII is masked via llm_request middleware instead."
                    ),
                )
        elif config.mode == "paranoid" and masked_hits:
            reason = (
                f"Privacy-Shield: {len(masked_hits)} PII match(es) detected in paranoid mode; "
                "blocking LLM call."
            )
        else:
            reason = None
        if reason is not None:
            if self.audit is not None:
                self.audit.log(
                    event="llm_call_blocked",
                    session_id=ctx.get("session_id", ""),
                    masked_count=len(masked_hits),
                    pii_types=[m.type for m in masked_hits],
                    mode=config.mode,
                    model=ctx.get("model", ""),
                    platform=ctx.get("platform", ""),
                )
            return {
                "action": "block",
                "message": reason,
            }

        if not masked_hits:
            return None

        sanitized, mapping = self.pseudonymizer.replace(
            prompt, masked_hits, session_id=ctx.get("session_id", "")
        )
        self.mapper.store(
            mapping,
            session_id=ctx.get("session_id", ""),
            ttl_seconds=self.config.mapping_ttl_seconds,
        )
        self._log_detections(mapping, ctx.get("session_id", ""))

        if self.config.cache_bypass:
            sanitized = self.cache_bypass.inject(sanitized, ctx)

        # Stage for the llm_request middleware. The slot is kept across ALL
        # api attempts of the turn (core rebuilds every attempt from the raw
        # messages; see orakel review t_c0a50b6f F-1): never consumed, only
        # replaced by the next turn's pre_llm_call. The audit "applied"
        # event is emitted by :meth:`apply_shield_to_request` on the FIRST
        # actual rewrite per turn — bypassed (local) traffic must not be
        # counted as pseudonymized.
        self._stage_shield(
            turn_id=ctx.get("turn_id", ""),
            payload={
                "sanitized": sanitized,
                "raw_prompt": ctx.get("raw_prompt", ""),
                "orig_len": len(prompt),
                "masked_count": len(mapping),
                "pii_types": [m.get("type", "unknown") for m in mapping],
                "session_id": ctx.get("session_id", ""),
                "model": ctx.get("model", ""),
                "platform": ctx.get("platform", ""),
            },
        )
        return None

    # ── llm_request middleware application ────────────────────────────────

    _STAGED_MAX = 64  # bounded per teknium review 2: one gateway process serves many sessions

    def _stage_shield(self, *, turn_id: str, payload: dict[str, Any]) -> None:
        """Store the sanitized prompt for :meth:`apply_shield_to_request`.

        Keyed BY TURN ID in a bounded dict (teknium review 2, item 1): one
        gateway process serves many sessions/turns concurrently, so a
        single slot let session B's ``pre_llm_call`` overwrite session A's
        staged mask between A's staging and A's api calls — A would ship
        raw personal data. Each live turn owns its dict entry; the
        middleware reads the exact ``turn_id`` entry. The dict is bounded:
        the oldest entry is dropped beyond ``_STAGED_MAX``. Middleware
        never consumes an entry (the core rebuilds the request payload per
        api attempt from the raw messages); entries live until evicted or
        purged by session end (:meth:`on_session_end`).
        """
        key = turn_id or ""
        entry = dict(payload)
        entry["turn_id"] = key
        shields = getattr(self, "_staged_shields", None)
        if not isinstance(shields, dict):
            shields = {}
            self._staged_shields = shields
        while key in shields and shields[key] is not entry:
            # same key re-staged within the turn: newest wins (drop old copy)
            del shields[key]
        shields[key] = entry
        while len(shields) > self._STAGED_MAX:
            oldest = next(iter(shields))
            shields.pop(oldest, None)

    def _read_staged_shield(self, turn_id: str) -> dict[str, Any] | None:
        """Return THIS turn's staged shield (exact turn-id key, read-only).

        Read-only on purpose: the core fires the llm_request middleware once
        PER API ATTEMPT (conversation_loop retry/tool loop); consuming the
        entry on the first attempt would send raw PII from attempt 2 on
        (orakel review t_c0a50b6f F-1, PoC-reproduced). Keying by turn id
        (and matching exactly — Smith review t_5d7e23ce/001) keeps concurrent
        sessions isolated: no wildcard, no single-slot overwrite.
        """
        shields = getattr(self, "_staged_shields", None)
        if not isinstance(shields, dict):
            return None
        result: dict[str, Any] | None = shields.get(turn_id or "")
        return result

    def _sidecar_rewrite(self, content: str, staged: dict[str, Any]) -> str | None:
        """Rewrite the live-prompt portion of a sidecar-composed message.

        The core composes the wire content as ``live_prompt + "\\n\\n" + context``
        (``agent/turn_context.py`` compose_user_api_content) BEFORE the
        middleware runs. Replacing the whole string would drop injected
        context (firewall, prefetch, gateway notes; orakel F-2). When the
        content starts with the raw live prompt, the live portion is
        replaced by the staged sanitized prompt; the bytes behind it — the
        sidecar suffix — are scanned + masked when ``mask_sidecar_suffix``
        is on (R-1/P3) or kept byte-exact when the flag is off. Unknown
        shapes fall back to masking the entire string — never return
        unmasked content.
        """
        sanitized = staged.get("sanitized", "")
        raw = staged.get("raw_prompt") or ""
        if raw and content.startswith(raw):
            suffix = content[len(raw):]
            if suffix and self.config.mask_sidecar_suffix:
                masked_suffix, _count, _types = self._mask_user_text(
                    suffix, staged.get("session_id", "")
                )
                result: str = sanitized + masked_suffix
                return result
            plain: str = sanitized + suffix
            return plain
        # Fallback: mask the full wire content (context included). The
        # context parts are not restorable tokens-bearing text by design;
        # masking them whole is fail-safe, not fail-open.
        masked, count, _types = self._mask_user_text(
            content, staged.get("session_id", "")
        )
        if not count:
            return None
        masked_result: str | None = masked if isinstance(masked, str) else None
        return masked_result

    # ── R-1 history masking (Option b, design report t_cf276f36) ─────────

    _MEMO_MAX = 256  # hard cap: turn-scoped memo, entries = distinct messages

    def _memo_key(self, session_id: str, text: str) -> str:
        return hashlib.sha256(f"{session_id}\x00{text}".encode()).hexdigest()

    def _reset_memo_if_new_turn(self, turn_id: str) -> None:
        """Drop the per-message memo when a new turn starts.

        Lifetime = Turn (design report §4(b)): the memo exists so the core's
        per-attempt payload rebuild does NOT rescan every history byte per
        api attempt (tool loops fire the middleware 10-30x per turn). A new
        turn re-scans and re-stores fresh mapping rows (newest-row-wins
        lookup + fresh ``expires_at``), which is what keeps the restore
        contract alive.
        """
        if turn_id != getattr(self, "_memo_turn", None):
            self._memo_turn = turn_id
            self._memo_cache: dict[str, tuple[str, int, list[str]]] = {}
            self._memo_audited = False

    def _mask_user_text(self, text: str, session_id: str) -> tuple[str, int, list[str]]:
        """Scan + mask one user text outside the staged live prompt.

        Covers history turns and (when ``mask_sidecar_suffix`` is on) the
        sidecar suffix. Memoized per ``(session_id, content-hash)`` with
        turn lifetime: same content -> same deterministic mask, computed
        once per turn per message. Returns ``(new_text, masked_count,
        pii_types)``; ``new_text == text`` when nothing was masked.
        """
        key = self._memo_key(session_id, text)
        memo: dict[str, tuple[str, int, list[str]]] = getattr(
            self, "_memo_cache", {}
        )
        if key in memo:
            return memo[key]
        hits = self.detector.scan(text)
        masked_hits, dropped = self._partition_by_confidence(hits)
        if dropped:
            self._log_dropped_detections(dropped, session_id)
        if not masked_hits:
            entry: tuple[str, int, list[str]] = (text, 0, [])
        else:
            masked, mapping = self.pseudonymizer.replace(
                text, masked_hits, session_id=session_id
            )
            self.mapper.store(
                mapping,
                session_id=session_id,
                ttl_seconds=self.config.mapping_ttl_seconds,
            )
            self._log_detections(mapping, session_id)
            entry = (
                masked,
                len(mapping),
                [m.get("type", "unknown") for m in mapping],
            )
        if len(memo) >= self._MEMO_MAX:
            memo.pop(next(iter(memo)))
        memo[key] = entry
        return entry

    @staticmethod
    def _set_span(msg: dict[str, Any], idx: int | None, text: str) -> None:
        """Write a masked text back: whole content (idx None) or one part."""
        if idx is None:
            msg["content"] = text
        else:
            part = msg["content"][idx]
            msg["content"][idx] = {**part, "text": text}

    def apply_shield_to_request(
        self,
        request: dict[str, Any] | None,
        *,
        provider: str = "",
        session_id: str = "",
        model: str = "",
        platform: str = "",
        turn_id: str = "",
    ) -> dict[str, Any] | None:
        """Rewrite the USER MESSAGES of an outgoing LLM request (``llm_request``
        middleware callback).

        R-1 (design report ``11-R1-History-Masking-Design.md``, Option b):
        ALL user messages — the live prompt AND earlier conversation-history
        turns (string or multimodal ``text``/``input_text`` parts) — are
        masked (``mask_history``, default on), plus the sidecar suffix bytes
        behind the live prompt (``mask_sidecar_suffix``, default on). Without
        a staged shield — live prompt PII-free or a turn-id mismatch — every
        user message is scanned standalone: exactly the scenario in which
        R-1 let raw history PII egress. The core fires this middleware once
        PER api attempt and rebuilds each payload from the raw messages, so
        the staged slot is read-only here and a turn-scoped per-message memo
        keeps the re-scan cheap (orakel review t_c0a50b6f F-1/F-2).
        Returns ``{"request": request}`` when a rewrite was applied, ``None``
        when nothing should change. The middleware contract only propagates
        a payload under the ``request`` key.
        """
        staged = self._read_staged_shield(turn_id)
        if provider in ("ollama_local", "ollama"):
            # Local model traffic is exempt from pseudonymization.
            return None
        if not self.config.enabled:
            return None
        if self.config.mode not in ("limited", "strict", "paranoid"):
            # audit mode is detection-only, off is off: neither may rewrite
            # the wire — including the standalone (no-staged) scan below.
            return None
        if staged is not None and not staged.get("sanitized"):
            staged = None
        mask_history = self.config.mask_history
        if staged is None and not mask_history:
            return None

        messages = request.get("messages") if isinstance(request, dict) else None
        if not isinstance(messages, list):
            return None
        self._reset_memo_if_new_turn(turn_id)

        audit_session = session_id or (staged or {}).get("session_id", "")
        applied = False
        live_via_staged = False
        live_seen = False
        standalone_count = 0
        standalone_types: list[str] = []

        for msg in reversed(messages):
            if not (isinstance(msg, dict) and msg.get("role") == "user"):
                continue
            content = msg.get("content")
            is_live = not live_seen
            live_seen = True

            if isinstance(content, str):
                spans: tuple[tuple[int | None, str], ...] = ((None, content),)
            elif isinstance(content, list):
                spans = tuple(
                    (idx, str(part.get("text", "")))
                    for idx, part in enumerate(content)
                    if isinstance(part, dict)
                    and part.get("type") in ("text", "input_text")
                )
            else:
                # Unknown wire shape. v1.9.1 aborted the middleware here;
                # with history masking a single opaque message must not
                # suppress masking of the remaining user messages.
                if not mask_history:
                    return None
                continue

            if is_live:
                # The core composes raw_prompt (+ suffix) as the FIRST text
                # span of the live message; every further text span belongs
                # to the sidecar context (suffix territory, orakel F-2/P3).
                prompt_spans = spans[:1]
                suffix_spans = spans[1:]
            else:
                prompt_spans = spans
                suffix_spans = ()

            if is_live and staged is not None and prompt_spans:
                idx, text = prompt_spans[0]
                rewritten = self._sidecar_rewrite(text, staged)
                if rewritten is not None:
                    self._set_span(msg, idx, rewritten)
                    applied = True
                    live_via_staged = True
                    prompt_spans = ()
                    if not mask_history:
                        break  # v1.9.1 contract: only the live message
                elif not mask_history:
                    return None
                else:
                    # Fail-safe fallback scan found no hits on this span.
                    prompt_spans = ()

            if mask_history:
                for idx, text in prompt_spans:
                    masked, count, types = self._mask_user_text(text, audit_session)
                    if count:
                        self._set_span(msg, idx, masked)
                        applied = True
                        standalone_count += count
                        standalone_types.extend(types)
                if self.config.mask_sidecar_suffix:
                    for idx, text in suffix_spans:
                        masked, count, types = self._mask_user_text(text, audit_session)
                        if count:
                            self._set_span(msg, idx, masked)
                            applied = True
                            standalone_count += count
                            standalone_types.extend(types)

        if applied and self.audit is not None:
            # One "applied" event per turn (per-attempt rewrites share it).
            # The staged slot carries the gate for a staged live rewrite
            # across attempts; the turn-scoped memo flag covers standalone
            # (no-staged) rewrites — both must fire at most once per turn.
            already_audited = bool(staged and staged.get("audited"))
            if not already_audited and not getattr(self, "_memo_audited", False):
                if staged:
                    staged["audited"] = True
                self._memo_audited = True
                live_staged = staged if live_via_staged and staged else None
                staged_masked = live_staged.get("masked_count", 0) if live_staged else 0
                staged_types = live_staged.get("pii_types", []) if live_staged else []
                self.audit.log(
                    event="pseudonymization_applied",
                    session_id=audit_session,
                    masked_count=staged_masked + standalone_count,
                    pii_types=list(staged_types) + standalone_types,
                    mode=self.config.mode,
                    model=model or (staged or {}).get("model", ""),
                    platform=platform or (staged or {}).get("platform", ""),
                )
        logger.info(
            "Privacy-Shield: %d PII replacements in request messages "
            "(staged %d, standalone %d)",
            (staged.get("masked_count", 0) if live_via_staged and staged else 0)
            + standalone_count,
            staged.get("masked_count", 0) if staged else 0,
            standalone_count,
        )
        if not applied:
            return None
        return {"request": request}

    def _log_detections(self, mapping: list[dict[str, Any]], session_id: str) -> None:
        """Shim around :func:`log_utils.log_detections` (MORPH-PS-3)."""
        log_detections(mapping, session_id)

    def _partition_by_confidence(
        self, pii_hits: list[Any], threshold: float | None = None
    ) -> tuple[list[Any], list[Any]]:
        """Shim around :func:`log_utils.partition_by_confidence` (MORPH-PS-3).

        t_025240da: an explicit ``threshold`` argument (e.g. the
        reasoning-specific ``reasoning.confidence_threshold``) wins over the
        global ``config.confidence_threshold``.  Without this, lowering the
        global threshold for name detection (0.65) would also auto-mask
        ``encoded_pii``/``gps``-adjacent heuristic types that the reasoning
        gate deliberately keeps at 0.85.
        """
        return partition_by_confidence(
            pii_hits,
            self.config.confidence_threshold if threshold is None else threshold,
            self.config.confidence_overrides,
        )

    def _log_dropped_detections(self, dropped_hits: list[Any], session_id: str) -> None:
        """Shim around :func:`log_utils.log_dropped_detections` (MORPH-PS-3)."""
        log_dropped_detections(dropped_hits, session_id)

    @staticmethod
    def _bucket_count(count: int) -> str:
        """Backward-compat shim around :func:`log_utils.bucket_count`.

        Kept as a ``@staticmethod`` on the class because two test files
        (``test_audit_log_persistence`` + ``test_egress_security``)
        import the original name.  See MORPH-PS-3.
        """
        return bucket_count(count)

    # ── Output-side scanning (FIX-1B) ─────────────────────────────────────

    def _sanitize_output_pii(
        self, text: str | None, session_id: str = ""
    ) -> tuple[str | None, int]:
        """Thin shim around :class:`OutputSanitizer` (MORPH-PS-3 extraction).

        Kept for backward compatibility with the
        ``test_post_llm_call_output_scanning`` test suite, which calls
        this method directly.  The real work lives in
        :meth:`OutputSanitizer.sanitize`; behaviour, side-channel
        discipline, and ``(text, 0)`` short-circuit semantics are
        preserved unchanged.
        """
        if not text or not self.config.enabled:
            return text, 0
        return self.output_sanitizer.sanitize(text, session_id)

    @staticmethod
    def _mask_tokens(
        text: str, token_re: re.Pattern[str]
    ) -> tuple[str, list[tuple[int, int]]]:
        """Backward-compat shim around :meth:`OutputSanitizer._mask_tokens`.

        Tests in ``test_post_llm_call_output_scanning`` call this
        static method directly; the implementation now lives in the
        OutputSanitizer module to keep plugin.py free of LLM-response
        internals (MORPH-PS-3).
        """
        from .output_sanitizer import OutputSanitizer

        return OutputSanitizer._mask_tokens(text, token_re)

    def post_llm_call(
        self,
        assistant_response: str | None = None,
        session_id: str | None = None,
        model: str | None = None,
        platform: str | None = None,
        **kwargs: Any,
    ) -> str | None:
        """Audit-log side-effect hook fired after every LLM response.

        Detects fresh PII that the model leaked (hallucinated, smuggled
        in by prompt injection, or simply outside the pre-sanitised
        set). The response is never modified here — mutation happens in
        the ``post_llm_response`` / ``transform_llm_output`` flow where
        restoration is allowed to run.

        Modes:
        - ``off``/disabled: skip (no scan, no log).
        - ``audit``: log detections, never raise.
        - ``limited`` (default): log detections, never raise.
        - ``strict``: raise on cloud providers (non-``ollama``).
        - ``paranoid``: raise on any provider.

        Returns ``None`` so Hermes discards the hook value — the response
        is consumed later by ``transform_llm_output``.
        """
        if not assistant_response:
            return None
        if not self.config.enabled:
            return None
        if self.config.mode == "off":
            return None

        # v1.6.1 — Reasoning-In-Memory-Redaktion via post_llm_call.
        # Hermes uebergibt conversation_history als Referenz; in-place
        # Mutation wirkt auf das Original-messages-Array durch (Spike-001).
        # Reasoning-PII wird hier tokenisiert BEVOR weitere Tools/Exporter
        # oder Output-Stages die Nachrichtenliste lesen.
        conversation_history = kwargs.get("conversation_history")
        if conversation_history is not None:
            self._redact_reasoning_in_history(
                conversation_history,
                session_id=session_id or "",
                model=model or "",
                platform=platform or "",
            )

        detected = self.detector.scan(assistant_response)
        if not detected:
            return None

        masked_hits, dropped_hits = self._partition_by_confidence(detected)
        if not masked_hits:
            # Nothing high-confidence — log dropped hits for visibility
            # but stay silent on the strict / paranoid decision path.
            if dropped_hits:
                self._log_dropped_detections(dropped_hits, session_id or "")
            return None

        count = len(masked_hits)
        bucket = self._bucket_count(count)
        pii_types = list(dict.fromkeys(h.type for h in masked_hits))[:3]
        session_echo = session_id or ""

        # Audit line: no plaintext, only count bucket + type samples.
        logger.warning(
            "Privacy-Shield output PII detected: count_bucket=%s "
            "types=%s session=%s model=%s platform=%s",
            bucket,
            pii_types,
            session_echo,
            model or "",
            platform or "",
        )

        # FIX-PS3: persistenter Audit-Trail für Output-PII-Detections.
        # Gleiche side-channel-Disziplin wie in pre_llm_call — count bucket,
        # type samples (max 3), kein Klartext.
        if self.audit is not None:
            self.audit.log(
                event="output_pii_detected",
                session_id=session_echo,
                masked_count=count,
                pii_types=pii_types,
                mode=self.config.mode,
                model=model or "",
                platform=platform or "",
            )

        provider = model or platform or ""
        is_local = provider.startswith("ollama") or "ollama_local" in (platform or "")

        if self.config.mode == "paranoid":
            raise ParanoidModeBlock(
                f"Privacy-Shield: {count} PII match(es) detected in paranoid "
                f"mode on LLM output; blocking forward propagation."
            )

        if self.config.mode == "strict" and not is_local:
            raise StrictModeBlock(
                f"Privacy-Shield: {count} PII match(es) detected in strict "
                f"mode on cloud-provider response ({provider}); "
                "blocking forward propagation."
            )

        # audit / limited: log only, no mutation.
        return None

    def post_llm_response(
        self,
        text: str,
        session_id: str = "",
        target_channel: str = "",
        **kwargs: Any,
    ) -> str:
        """Restore PII tokens in LLM response back to original values.

        Restoration is restricted to allowed user-facing channels
        (default: configured user-facing channel).  For all other targets the response
        remains pseudonymized, preventing PII egress via write_file,
        kanban_complete, terminal output, or MCP calls.

        FIX-1B: the fresh-PII sanitiser runs BEFORE token restoration so
        that values the LLM leaked (not in the session mapping) are
        replaced with their own tokens and therefore NOT subject to the
        restoration pass — the user sees the token, never the leak.
        """
        if not text or not self.config.enabled:
            return text

        # 1) Fresh-PII sanitisation: must run for EVERY channel.
        #    write_file / kanban / terminal output still needs to be free
        #    of raw PII even when restoration is skipped.
        #    FIX-1B: the sanitizer reports the tokens it minted HERE via
        #    the optional ``fresh_tokens`` out-param so the residual pass
        #    below never touches them (they are intentionally unresolvable
        #    and must stay visible).
        fresh_tokens: set[str] = set()
        sanitized, _count = self.output_sanitizer.sanitize(
            text, session_id=session_id, fresh_tokens=fresh_tokens
        )
        # If sanitiser disabled itself or returned the original, fall back.
        if sanitized is None:
            sanitized = text

        # 2) Token restoration: only on allowed user-facing channels.
        # Channel matching is prefix-aware: the gateway delivers bare platform
        # names ("telegram", "desktop", "cli", "cron") while config entries may
        # carry a chat scope ("telegram:12345"). A configured "telegram:ID"
        # entry must match a bare "telegram" delivery ONLY when a bare
        # "telegram" entry is also configured — otherwise a bare match would
        # leak PII to an unintended chat. Bare platform entries always match.
        # (Fix 2026-09-19: restoration skipped for channel telegram/desktop —
        # 0 restores across all profiles. Fix 2026-10-06: also cover `cron`,
        # which the scheduler stamps as platform while delivery goes to the
        # user, and never ship an empty default whitelist.)
        allowed = tuple(self.config.restore_allowed_channels) + tuple(
            ALLOWED_RESTORE_CHANNELS
        )
        if not self._channel_allowed(target_channel, allowed):
            logger.info(
                "Privacy-Shield: restoration skipped for channel %s (allowed=%s)",
                target_channel,
                list(allowed),
            )
            return sanitized

        restored = self.mapper.restore_text(sanitized, session_id=session_id)

        # v1.7.6 (Decision 1 + 2): residual pass — exclusive to the allowed
        # restore path (after the channel gate). On non-allowed channels
        # tokens stay exactly as the sanitizer left them; no placeholder
        # substitution happens there (egress + fresh-PII behaviour intact).
        restored = self._resolve_residual_tokens(
            restored, session_id=session_id, fresh_tokens=fresh_tokens
        )

        if restored != sanitized:
            logger.info(
                "Privacy-Shield: Restored PII tokens in LLM response "
                "(%d chars -> %d chars, channel=%s, session=%s)",
                len(sanitized),
                len(restored),
                target_channel,
                session_id[:24] if session_id else "",
            )
        else:
            # Visible signal when tokens remain unresolved (missing mapping /
            # session mismatch / LLM-corrupted token). Helps diagnose "token
            # not reverse-translated" reports without dumping PII.
            # v1.7.6 (FIX-1B): sanitizer-minted fresh tokens are resolved
            # per contract and stay visible — they no longer count as
            # "residual", only splice/placeholder misses already reported
            # by _resolve_residual_tokens do.
            residual = [
                m.group(0)
                for m in self.mapper.token_pattern.finditer(restored or "")
                if m.group(0) not in fresh_tokens
            ]
            if residual:
                logger.warning(
                    "Privacy-Shield: response still contains %d unresolved "
                    "TOKEN_* span(s) after restore (channel=%s session=%s) — "
                    "mapping miss or corrupted token",
                    len(residual),
                    target_channel,
                    session_id[:24] if session_id else "",
                )

        return restored

    def _resolve_residual_tokens(
        self,
        text: str,
        session_id: str = "",
        fresh_tokens: set[str] | None = None,
    ) -> str:
        """v1.7.6 residual pass: splice repair or restore-miss placeholder.

        Runs EXCLUSIVELY in the allowed restore path (after the channel
        gate in ``post_llm_response``) — never on non-allowed channels,
        where tokens stay verbatim (egress + FIX-1B behaviour preserved).

        For each residual ``TOKEN_*`` span found via ``mapper.token_pattern``:

        - Sanitizer-fresh tokens (``fresh_tokens``) are skipped (FIX-1B):
          they are intentionally unresolvable and stay visible.
        - Otherwise the session-scoped splice repair tries
          ``mapper.resolve_fuzzy_token(type_lower, serial, session_id)``
          (Decision 2). Exactly one distinct same-session candidate →
          the original value is substituted.
        - Still unresolved → Decision 1: ``restore_miss_strategy``
          ``placeholder`` substitutes ``restore_miss_placeholder``;
          ``keep`` leaves the token verbatim. Every miss increments
          ``record_restore_miss`` and logs a PII-free WARNING line
          (session truncated, type, serial — no token string, no
          plaintext original).
        """
        if not text:
            return text
        matches = list(self.mapper.token_pattern.finditer(text))
        if not matches:
            return text
        if fresh_tokens is None:
            fresh_tokens = set()

        strategy = self.config.restore_miss_strategy
        placeholder = self.config.restore_miss_placeholder
        skip_placeholder = strategy != "placeholder" or not placeholder
        resolver = getattr(self.mapper, "resolve_fuzzy_token", None)

        out: list[str] = []
        last = 0
        misses = 0
        repairs = 0
        for m in matches:
            out.append(text[last : m.start()])
            last = m.end()
            token = m.group(0)
            if token in fresh_tokens:
                out.append(token)
                continue
            token_type = (m.group(1) or "").lower()
            serial_text = m.group(3)
            serial = int(serial_text) if serial_text and serial_text.isdigit() else None
            replacement: str | None = None
            if resolver is not None and session_id and serial is not None:
                try:
                    replacement = resolver(token_type, serial, session_id)
                except Exception:
                    # Fail closed: treat as a miss, never crash the hook.
                    logger.debug(
                        "Privacy-Shield: splice repair attempt failed", exc_info=True
                    )
                    replacement = None
            if replacement is None:
                out.append(placeholder if not skip_placeholder else token)
                misses += 1
                logger.warning(
                    "Privacy-Shield: restore_miss (session=%s, type=%s, serial=%s)",
                    session_id[:16] if session_id else "",
                    token_type or "?",
                    serial if serial is not None else "n/a",
                )
            else:
                out.append(str(replacement))
                repairs += 1
        out.append(text[last:])
        if misses:
            record_restore_miss(misses)
        if misses or repairs:
            # Finding 7g: WARNING when misses > 0 (auditable in security
            # monitoring), INFO for pure repairs.
            log = logger.warning if misses else logger.info
            log(
                "Privacy-Shield: residual pass finished (repaired=%d, misses=%d, "
                "channel_gated_restore_path)",
                repairs,
                misses,
            )
        return "".join(out)

    @staticmethod
    def _channel_allowed(target_channel: str, allowed: tuple[str, ...]) -> bool:
        """Prefix-aware channel matching.

        Exact match always wins. Otherwise the delivery matches when its
        platform part equals a configured bare entry (``telegram``, ``desktop``,
        ``cli``). Fail-closed: a bare ``telegram`` delivery does NOT match a
        scoped ``telegram:<chat_id>``-only configuration — restoration stays
        pinned to the operator's explicit chat until a bare ``telegram`` entry
        is also configured. (Fix 2026-09-19: the gateway delivers bare platform
        names, so ``telegram`` never matched ``telegram:12345`` —
        0 restores across all profiles.)
        """
        if not target_channel:
            return False
        if target_channel in allowed:
            return True
        platform = target_channel.split(":", 1)[0]
        return platform in allowed

    def on_session_end(self, session_id: str) -> None:
        """Hook fired when a session ends: purge the session's mappings.

        Purpose-limitation purge (DSGVO Art. 5(1)(e); operator decision,
        2026-10-10):
        the mapping exists exactly as long as the session it translates.
        Also crypto-shreds the pseudonymizer's per-session salt/counter/
        token-cache entries so the same session cannot be resumed.
        """
        if not session_id:
            self._staged_shields = {}
            return
        purge = getattr(self.mapper, "purge_session", None)
        deleted = (
            purge(session_id)
            if callable(purge)
            else self.mapper.close_session(session_id)
        )
        try:
            self.pseudonymizer.close_session(session_id)
        except Exception:
            logger.debug(
                "Privacy-Shield: pseudonymizer session shred failed", exc_info=True
            )
        # Drop the middleware staging slot too: it holds the raw PII prompt
        # in memory and must never outlive the session
        # (orakel review t_c0a50b6f F-1 lifetime note).
        self._staged_shields = {}
        logger.info(
            "Privacy-Shield: session %s ended, removed %d mappings", session_id, deleted
        )

    def redact_reasoning_on_message(
        self,
        assistant_message: Any,
        *,
        session_id: str = "",
        model: str = "",
        platform: str = "",
    ) -> int:
        """Tokenisiert Reasoning-Felder in-place auf dem Live-Response-Objekt.

        v1.7.0 Pre-Intake-Pfad: Wird aus dem ``post_api_request``-Hook
        aufgerufen — direkt nach Response-Intake, VOR Persist
        (``_persist_session``) und vor ``build_assistant_message``.
        Eine Mutation hier schließt die GB-009-Persistenz-Lücke:
        ``state.db`` erhält nur noch tokenisierte Reasoning-Texte.

        Behandelt: ``reasoning``, ``reasoning_content`` (str-Felder),
        ``reasoning_details`` (Liste von Dicts mit summary/thinking/
        content/text-Keys, OpenRouter-Format) sowie ``<think>``-Blöcke
        in ``content`` (inkrementell nicht sinnvoll teilbar — der
        Content-Stream wird nicht angefasst, stattdessen loggt der
        Audit-Pfad die Detections).

        Runtime-Guards: nur string-wertige Felder; ``skip_fields`` aus
        der Config; ``mode == "off"``/disabled → No-op. Fail-open bei
        Attribut-Fehlern (SDK-Objekt-Varianten).

        Returns: Anzahl tokenisierter Treffer (fuer Audit).
        """
        if assistant_message is None or not self.config.enabled:
            return 0
        if self.config.reasoning.mode == "off":
            return 0

        tokenized = 0
        threshold = self.config.reasoning.confidence_threshold
        fallback_usage: dict[str, str] = {}  # field -> fallback_method
        bypass_fields: list[tuple[str, str]] = []  # (field, bypass_reason)

        # 1) String-Felder am Objekt
        for field in ("reasoning", "reasoning_content"):
            if field in self.config.reasoning.skip_fields:
                continue
            value = None
            try:
                value = getattr(assistant_message, field, None)
            except Exception as exc:  # noqa: BLE001 -- fail-open
                logger.debug("Privacy-Shield: getattr(%s) failed: %s", field, exc)
                continue
            if not isinstance(value, str) or not value:
                # v1.7.1 (Seraph F1): reasoning_content kann NUR in
                # model_extra liegen (SDK-Varianten ohne top-level
                # Attribut) — getattr liefert dann None. Zweite Quelle
                # pruefen, bevor das Feld uebersprungen wird.
                if field == "reasoning_content" and not value:
                    value, count, sanitized = self._redact_model_extra_source(
                        assistant_message, field, session_id, threshold
                    )
                    if sanitized is not None:
                        fallback_usage[field] = "model_extra"
                        tokenized += count
                continue
            sanitized, count = self._tokenize_reasoning(
                value, session_id=session_id, confidence_threshold=threshold
            )
            if sanitized is not None and sanitized != value:
                ok, method = self._set_reasoning_field(
                    assistant_message, field, sanitized, session_id
                )
                if ok:
                    tokenized += count
                    if method != "setattr":
                        self._log_fallback_event(
                            field, method, True, session_id, model, platform
                        )
                else:
                    bypass_fields.append(
                        (field, "provider_data_none_and_model_extra_unwritable")
                    )
                    logger.warning(
                        "Privacy-Shield: reasoning redaction for %s completely "
                        "failed (session=%s)",
                        field,
                        session_id,
                    )
        # 2) reasoning_details: Liste von Dicts (OpenRouter-Format)
        if "reasoning_details" not in self.config.reasoning.skip_fields:
            try:
                details = getattr(assistant_message, "reasoning_details", None) or []
            except Exception:  # noqa: BLE001 -- fail-open
                details = []
            if isinstance(details, list):
                for detail in details:
                    if not isinstance(detail, dict):
                        # v1.7.1 (Orakel): Tuple/andere Immutable werden
                        # bewusst uebersprungen (fail-open, getestet).
                        continue
                    for key in ("summary", "thinking", "content", "text"):
                        value = detail.get(key)
                        if not isinstance(value, str) or not value:
                            continue
                        sanitized, count = self._tokenize_reasoning(
                            value, session_id=session_id, confidence_threshold=threshold
                        )
                        if sanitized is not None and sanitized != value:
                            detail[key] = sanitized
                            tokenized += count

        if tokenized:
            logger.info(
                "Privacy-Shield: %d reasoning PII token(s) redacted "
                "pre-intake (session=%s)",
                tokenized,
                session_id,
            )
            if self.audit is not None:
                self.audit.log(
                    event="reasoning_redaction_applied",
                    session_id=session_id,
                    masked_count=tokenized,
                    mode=self.config.reasoning.mode,
                    model=model,
                    platform=platform,
                    source="reasoning_block_pre_intake",
                    note=(
                        "Pre-Intake-Redaktion via post_api_request: "
                        "state.db erhaelt nur tokenisierte Reasoning-Texte "
                        "(GB-009 geschlossen)."
                    ),
                )
        for field, reason in bypass_fields:
            self._log_bypass_event(field, reason, session_id, model, platform)
        return tokenized

    def _set_reasoning_field(
        self, obj: Any, field: str, value: Any, session_id: str
    ) -> tuple[bool, str]:
        """Setze ein Reasoning-Feld mit Drei-Quellen-Fallback (v1.7.1).

        Liefert (success, method): method ist "setattr", "provider_data"
        oder "model_extra" — fuer das Audit-Event (Smith M-002).

        Quelle 1: setattr (Dataclass-Felder wie ``reasoning``).
        Quelle 2: provider_data dict — NormalizedResponse implementiert
        ``reasoning_content``/``reasoning_details`` als read-only
        Properties über dieses Dict (agent/transports/types.py:80-87);
        Core liest die Werte über die Property aus genau diesem Dict,
        daher persistiert die In-Place-Mutation (GB-009).
        Quelle 3: model_extra — SDK-Varianten, die Reasoning nur dort
        ablegen (Seraph F1).

        provider_data=None wird zu {} initialisiert (Smith C-001),
        Initialisierungs-/Mutations-Fehler sind fail-open mit Warning.
        """
        try:
            setattr(obj, field, value)
            return True, "setattr"
        except (AttributeError, TypeError):
            pass
        except Exception as exc:  # noqa: BLE001 -- fail-open
            logger.warning(
                "Privacy-Shield: reasoning setattr(%s) failed unexpectedly: %s",
                field,
                exc,
            )
        pd = getattr(obj, "provider_data", None)
        if pd is None:
            try:
                obj.provider_data = {}
                pd = obj.provider_data
            except Exception as exc:  # noqa: BLE001 -- fail-open
                logger.debug(
                    "Privacy-Shield: provider_data init failed for %s: %s",
                    field,
                    exc,
                )
        if isinstance(pd, dict):
            pd[field] = value
            logger.info(
                "Privacy-Shield: reasoning %s redacted via provider_data "
                "fallback (session=%s)",
                field,
                session_id,
            )
            return True, "provider_data_dict"
        me = getattr(obj, "model_extra", None)
        if isinstance(me, dict):
            me[field] = value
            logger.info(
                "Privacy-Shield: reasoning %s redacted via model_extra "
                "fallback (session=%s)",
                field,
                session_id,
            )
            return True, "model_extra"
        return False, "none"

    def _redact_model_extra_source(
        self,
        assistant_message: Any,
        field: str,
        session_id: str,
        threshold: float,
    ) -> tuple[Any, int, Any]:
        """Redigiere reasoning_content aus model_extra (Seraph F1, v1.7.1).

        Liefert (value, count, sanitized): value/count der gelesenen
        Quelle (None/0 wenn nicht vorhanden) — sanitized ist None, wenn
        nichts zu tun war. Der Aufrufer behandelt den Erfolg.
        """
        me = getattr(assistant_message, "model_extra", None)
        if not isinstance(me, dict) or field not in me:
            return None, 0, None
        raw = me.get(field)
        if not isinstance(raw, str) or not raw:
            return None, 0, None
        sanitized, count = self._tokenize_reasoning(
            raw, session_id=session_id, confidence_threshold=threshold
        )
        if sanitized is None or sanitized == raw:
            return raw, 0, None
        me[field] = sanitized
        logger.info(
            "Privacy-Shield: reasoning %s (model_extra) redacted (session=%s)",
            field,
            session_id,
        )
        return raw, count, sanitized

    def _log_fallback_event(
        self,
        field: str,
        method: str,
        success: bool,
        session_id: str,
        model: str,
        platform: str,
    ) -> None:
        """Audit-Event fuer genutzten Fallback-Pfad (Smith M-002, v1.7.1).

        Enthaelt keine Klartext-PII — nur Feldname, Methode, Outcome.
        """
        if self.audit is None:
            return
        self.audit.log(
            event="reasoning_redaction_fallback",
            session_id=session_id,
            failed_fields=[field],
            fallback_method=method,
            fallback_success=success,
            mode=self.config.reasoning.mode,
            model=model,
            platform=platform,
            source="reasoning_block_pre_intake",
            note=(
                f"setattr failed on read-only property; redacted via {method} fallback"
            ),
        )

    def _log_bypass_event(
        self,
        field: str,
        reason: str,
        session_id: str,
        model: str,
        platform: str,
    ) -> None:
        """Audit-Event, wenn ein Feld GAR NICHT redigiert werden konnte.

        Silent-Failure-Charakter endet hier: der Bypass ist im Audit-Log
        sichtbar, auch wenn der Turn nicht blockiert wird (fail-open).
        """
        if self.audit is None:
            return
        self.audit.log(
            event="reasoning_redaction_bypass",
            session_id=session_id,
            affected_field=field,
            bypass_reason=reason,
            mode=self.config.reasoning.mode,
            model=model,
            platform=platform,
            source="reasoning_block_pre_intake",
            note="Fallback mutation impossible; field left unredacted",
        )

    def _redact_reasoning_in_history(
        self,
        conversation_history: list[Any],
        *,
        session_id: str,
        model: str,
        platform: str,
    ) -> None:
        """Tokenisiert Reasoning-Felder in-place im conversation_history-Array.

        v1.6.1 Kompromiss-Pfad: Der Hook mutiert Reasoning-Felder
        (``reasoning``, ``reasoning_content``) in Assistant-Nachrichten
        direkt im uebergebenen Array. Da Hermes die gleiche Listen-Referenz
        an nachfolgende Stages weitergibt, wirkt die Mutation auf alle
        Konsumenten durch.

        Runtime-Guard:
        - Nur Nachrichten mit ``role == "assistant"``.
        - Nur string-wertige Felder werden bearbeitet.
        - ``reasoning_details`` und ``codex_reasoning_items`` (komplexe
          verschachtelte Strukturen) werden uebersprungen; sie stehen in
          ``config.reasoning.skip_fields``.
        - Unbekannte Modus-Werte verhalten sich fail-open (keine Mutation).

        Persistenz-Limitation: ``_persist_session`` laeuft vor dem Hook,
        daher kann ``state.db`` Reasoning-PII kurzzeitig enthalten. Diese
        Limitation wird bei jedem nicht-``off``-Modus in den Audit-Log
        geschrieben.
        """
        if not conversation_history:
            return
        if not self.config.enabled:
            return

        pii_tokenized_total = 0

        if self.config.reasoning.mode != "off":
            for msg in conversation_history:
                if not isinstance(msg, dict):
                    continue
                if msg.get("role") != "assistant":
                    continue

                for field in ("reasoning", "reasoning_content"):
                    if field in self.config.reasoning.skip_fields:
                        continue
                    value = msg.get(field)
                    if not isinstance(value, str) or not value:
                        continue
                    sanitized, count = self._tokenize_reasoning(
                        value,
                        session_id=session_id,
                        confidence_threshold=self.config.reasoning.confidence_threshold,
                    )
                    if sanitized is not None and sanitized != value:
                        msg[field] = sanitized
                        pii_tokenized_total += count

            # Einfache Nested-Struktur-Redaktion: codex_reasoning_items
            # enthaelt oft eine Liste von Dicts mit einem Textfeld.
            if "codex_reasoning_items" not in self.config.reasoning.skip_fields:
                for msg in conversation_history:
                    if not isinstance(msg, dict):
                        continue
                    if msg.get("role") != "assistant":
                        continue
                    items = msg.get("codex_reasoning_items")
                    if isinstance(items, list):
                        for item in items:
                            if not isinstance(item, dict):
                                continue
                            for sub_key in ("text", "content", "reasoning"):
                                sub_value = item.get(sub_key)
                                if isinstance(sub_value, str) and sub_value:
                                    sanitized, count = self._tokenize_reasoning(
                                        sub_value,
                                        session_id=session_id,
                                        confidence_threshold=self.config.reasoning.confidence_threshold,
                                    )
                                    if sanitized is not None and sanitized != sub_value:
                                        item[sub_key] = sanitized
                                        pii_tokenized_total += count

        if pii_tokenized_total:
            logger.info(
                "Privacy-Shield: %d reasoning PII token(s) in-place (session=%s)",
                pii_tokenized_total,
                session_id,
            )
            if self.audit is not None:
                self.audit.log(
                    event="reasoning_redaction_applied",
                    session_id=session_id,
                    masked_count=pii_tokenized_total,
                    mode=self.config.reasoning.mode,
                    model=model,
                    platform=platform,
                    source="reasoning_block",
                    note=(
                        "In-Memory-Redaktion. Persistenz-Limitation: "
                        "state.db enthaelt PII kurzzeitig vor Hook-Feuerung. "
                        "Siehe docs/reasoning-protection.md."
                    ),
                )

        # GB-010 defensive verification: confirm the in-place mutation
        # reached the last assistant message.  If the last assistant
        # reasoning still contains raw PII and no token, the post_llm_call
        # hook did not take effect for the value that Hermes-Core later
        # exposes as ``result["last_reasoning"]``.
        last_reasoning = find_last_assistant_reasoning(conversation_history)
        if (
            self.config.reasoning.mode
            != "off"  # NEW: mode-Guard (GB-010 False-Positive)
            and last_reasoning is not None
            and has_raw_pii(last_reasoning)
            and not contains_privacy_shield_token(last_reasoning)
        ):
            logger.warning(
                "Privacy-Shield: Reasoning-Hook hat nicht gegriffen — "
                "möglicher last_reasoning-Leak (session=%s)",
                session_id,
            )

    def _tokenize_reasoning(
        self,
        text: str,
        *,
        session_id: str,
        confidence_threshold: float,
    ) -> tuple[str | None, int]:
        """Scannt einen Reasoning-Text auf PII und ersetzt Treffer durch Tokens.

        Rueckgabe: (sanitized_text, anzahl_tokenisierter_treffer). Bei
        ``mode == "audit"`` wird der Original-Text zurueckgegeben und nur
        geloggt; bei Fehlern fail-open (None, 0).
        """
        if not text:
            return None, 0
        if self.config.reasoning.mode == "off":
            return None, 0

        try:
            detected = self.detector.scan(text)
        except Exception as exc:  # noqa: BLE001 -- detector failure must be fail-open
            logger.warning("Privacy-Shield: reasoning scan failed: %s", exc)
            return None, 0

        if not detected:
            return text, 0

        masked_hits, dropped_hits = self._partition_by_confidence(
            detected, self.config.reasoning.confidence_threshold
        )
        if dropped_hits:
            self._log_dropped_detections(dropped_hits, session_id)

        if self.config.reasoning.mode == "audit":
            self._log_reasoning_detections(masked_hits, session_id, "audit")
            return text, 0

        if not masked_hits:
            return text, 0

        sanitized, mapping = self.pseudonymizer.replace(
            text, masked_hits, session_id=session_id
        )
        if mapping:
            self.mapper.store(
                mapping,
                session_id=session_id,
                ttl_seconds=self.config.mapping_ttl_seconds,
            )
            self._log_detections(mapping, session_id)
            if self.audit is not None:
                self.audit.log(
                    event="pseudonymization_applied",
                    session_id=session_id,
                    masked_count=len(mapping),
                    pii_types=[m.get("type", "unknown") for m in mapping],
                    mode=self.config.mode,
                    model="",
                    platform="",
                    source="reasoning_block",
                    note=(
                        "In-Memory-Redaktion. Persistenz-Limitation: "
                        "state.db enthaelt PII kurzzeitig vor Hook-Feuerung. "
                        "Siehe docs/reasoning-protection.md."
                    ),
                )
        return sanitized, len(mapping)

    def _log_reasoning_detections(
        self, hits: list[Any], session_id: str, mode: str
    ) -> None:
        """Log reasoning-block detections without leaking plaintext values."""
        count = len(hits)
        pii_types = list(dict.fromkeys(h.type for h in hits))[:3]
        bucket = self._bucket_count(count)
        logger.warning(
            "Privacy-Shield reasoning PII detected: count_bucket=%s "
            "types=%s session=%s mode=%s",
            bucket,
            pii_types,
            session_id,
            mode,
        )
        if self.audit is not None:
            self.audit.log(
                event="reasoning_pii_detected",
                session_id=session_id,
                masked_count=count,
                pii_types=pii_types,
                mode=mode,
                source="reasoning_block",
                note=(
                    "In-Memory-Redaktion. Persistenz-Limitation: "
                    "state.db enthaelt PII kurzzeitig vor Hook-Feuerung. "
                    "Siehe docs/reasoning-protection.md."
                ),
            )

    @property
    def pattern_count(self) -> int:
        return self.detector.pattern_count

    def get_metrics(self) -> dict[str, Any]:
        """Return the current Privacy-Shield runtime metrics snapshot.

        LINK-PS-8: exposes cache hit/miss rate and masking volume to
        callers (tests, optional Prometheus exporter, etc.).
        """
        return get_metrics()
