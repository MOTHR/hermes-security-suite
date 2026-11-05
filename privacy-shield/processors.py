"""AttachmentProcessor — unified PDF / image attachment pipeline.

Morpheus R5 (MORPH-PS-3, SMELL-3, SMELL-5): :class:`PrivacyShieldPlugin`
previously held two near-identical ~100-LOC loops for PDF and image
attachments, distinguished only by which pre-processor they called.
This module collapses the duplication into a single class that walks
all registered :class:`BasePreprocessor` instances.

Responsibilities
----------------
* Filter ``ctx["attachments"]`` by each pre-processor's supported MIME
  types (PDF → ``application/pdf``, image → ``image/*``).
* Iterate the filtered attachments, run extraction, score with the
  configured confidence threshold, and pseudonymize via the
  existing ``Pseudonymizer`` + ``MappingTable`` pipeline.
* Render the sanitized artifact (PDF re-render / image underlay) and
  return both the expanded prompt and a list of ``(error, path)``
  tuples so the caller can surface per-attachment failures.
* Treat every failure mode (missing path, unsupported format, OCR
  error, mapping error, OS error during restore) as
  :class:`PreprocessorError` so the plugin's main loop can decide
  between log-only and drop-the-attachment behaviour.

Why a dedicated class
---------------------
* **Testability** — the unit-test for "PDF attachment" can drive the
  processor with a single ``MappingTable`` mock instead of booting
  the full plugin.
* **Single Responsibility** — :class:`PrivacyShieldPlugin` keeps only
  the high-level hook orchestration; everything format-specific
  lives here.
* **Extensibility** — adding Office documents, audio, or video is a
  matter of writing one more :class:`BasePreprocessor` and
  registering it; the loop in :meth:`process` does not change.
"""

from __future__ import annotations

import importlib
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .errors import PreprocessorError
from .fs_hardening import ensure_secure_dir
from .preprocessors.base import BasePreprocessor


logger = logging.getLogger(__name__)


# ── Pre-processor registry (Morpheus R5 / SMELL-5) ──────────────────────
# Each entry maps a ``kind`` (used as restore-dir sub-dir and log tag)
# to the loader, enabled-flag, restore-dir attribute, and constructor
# kwargs builder.  Adding a new format is a one-line append.
ATTACHMENT_PREPROCESSOR_SPECS: dict[str, dict[str, Any]] = {
    "pdf": {
        "module": ".preprocessors.pdf",
        "class_name": "PDFPreprocessor",
        "enabled_attr": "pdf_enabled",
        "restore_dir_attr": "pdf_restore_dir",
        "kwargs": lambda cfg: {"max_size_mb": cfg.pdf_max_size_mb},
    },
    "image": {
        "module": ".preprocessors.image",
        "class_name": "ImagePreprocessor",
        "enabled_attr": "image_enabled",
        "restore_dir_attr": "image_restore_dir",
        "kwargs": lambda cfg: {
            "max_size_mb": cfg.image_max_size_mb,
            "default_lang": cfg.ocr_lang,
            "min_confidence": cfg.ocr_min_confidence,
        },
    },
    # P1 (t_025240da): .eml header/HTML sanitizer (T1 pixel / T2 tracker
    # links / T3 Sensitive headers).  Same unified loop as PDF and image.
    "email": {
        "module": ".preprocessors.email",
        "class_name": "EmailPreprocessor",
        "enabled_attr": "email_enabled",
        "restore_dir_attr": "email_restore_dir",
        "kwargs": lambda cfg: {
            "max_size_mb": cfg.email_max_size_mb,
            "pixel_max_dim": cfg.email_pixel_max_dim,
            "rewrite_links_to_blank": cfg.email_rewrite_links_to_blank,
        },
    },
}


def init_attachment_preprocessor(plugin: Any, kind: str) -> Any | None:
    """Lazy-init a single attachment pre-processor by *kind*.

    Unified worker for both PDF and image pre-processors (Morpheus
    R5 / SMELL-5 dedup).  ``kind`` is the pre-processor identifier
    used for logging and as the restore-dir sub-directory; the
    loader, config keys, and constructor keyword arguments are
    looked up in :data:`ATTACHMENT_PREPROCESSOR_SPECS`.

    The plugin exposes a ``_ensure_secure_restore_dir`` helper that
    handles the BUTLER-PS-7 chmod 0o700 fallback; this function
    delegates restore-dir creation to that helper so behaviour stays
    identical to the original in-class init methods.

    Returns the configured pre-processor instance, or ``None`` when
    the format is disabled, the runtime dependency is missing, the
    constructor raises, or the secure restore directory cannot be
    created.
    """
    spec = ATTACHMENT_PREPROCESSOR_SPECS.get(kind)
    if spec is None:
        raise KeyError(f"Unknown attachment pre-processor kind: {kind!r}")
    cfg = plugin.config
    if not getattr(cfg, spec["enabled_attr"]):
        return None
    try:
        # Anchor relative spec at the plugin's parent package. The loader
        # imports plugins as hermes_plugins.<slug>.plugin (a module, not a
        # package), so anchoring at the class module itself fails with
        # "'hermes_plugins.privacy_shield.plugin' is not a package".
        anchor = plugin.__class__.__module__.rpartition(".")[0]
        module = importlib.import_module(spec["module"], anchor)
    except ImportError as exc:
        logger.info(
            "Privacy-Shield %s: preprocessor module not available (%s); "
            "%s attachments will pass through unshielded.",
            kind, exc, kind,
        )
        return None
    try:
        pre: Any = getattr(module, spec["class_name"])(**spec["kwargs"](cfg))
    except Exception as exc:  # pragma: no cover - defensive  # noqa: BLE001
        logger.warning("Privacy-Shield %s init failed: %s", kind, exc)
        return None
    try:
        plugin._ensure_secure_restore_dir(
            getattr(cfg, spec["restore_dir_attr"]), kind
        )
    except RuntimeError as exc:
        logger.error(
            "Privacy-Shield %s: secure restore dir unavailable: %s. "
            "%s preprocessor disabled.",
            kind, exc, kind,
        )
        return None
    return pre


__all__ = [
    "AttachmentProcessor",
    "AttachmentBatch",
    "AttachmentResult",
    "ATTACHMENT_PREPROCESSOR_SPECS",
    "init_attachment_preprocessor",
]


@dataclass
class AttachmentResult:
    """Outcome of processing a single attachment.

    Attributes:
        original_path: Source path the user supplied (or ``None`` when
            the attachment dict carried no ``path`` key — the error
            path then captures that fact).
        sanitized_path: Path to the rendered sanitized artifact, or
            ``None`` when rendering was skipped (no PII, OCR returned
            no text, or render failed).
        text: Sanitized text fed into the prompt expansion, or
            ``""`` when nothing was extracted.
        error: Human-readable error string (``""`` on success).  When
            non-empty, ``sanitized_path`` is ``None`` and ``text`` is
            ``""``.
    """

    original_path: Path | None
    sanitized_path: Path | None = None
    text: str = ""
    error: str = ""


@dataclass
class AttachmentBatch:
    """Aggregate result of :meth:`AttachmentProcessor.process`.

    Attributes:
        expanded_prompt: Original prompt + ``--- ATTACHMENTS (sanitized) ---``
            block.  When no attachments matched, this equals the input
            prompt.
        results: One :class:`AttachmentResult` per processed attachment
            (in input order).  Successful extractions and failed
            extractions both appear here so callers can log a
            per-attachment summary.
        format_label: Human label for the dominant format (e.g.
            ``"PDF"`` / ``"IMAGE"``).  Used to build the prompt header
            and the audit log; empty when no attachments were
            processed.
    """

    expanded_prompt: str
    results: list[AttachmentResult] = field(default_factory=list)
    format_label: str = ""


class AttachmentProcessor:
    """Single-pass PDF + image attachment processor.

    The constructor accepts a list of pre-processors (each must be a
    :class:`BasePreprocessor`).  Content validation (``is_supported``)
    decides which pre-processor claims a file; MIME metadata is only a
    last-resort claim signal and never routes extraction on its own
    (PS-PIPE-001) — this keeps routing deterministic and lets future
    pre-processors (e.g. Office) take precedence by ordering.

    The processor is **stateless** apart from its references to the
    detector, pseudonymizer, and mapper.  Multiple invocations of
    :meth:`process` on the same instance are safe as long as those
    collaborators are themselves thread-safe (they are — see the
    ``MappingTable`` ``threading.Lock``).
    """

    def __init__(
        self,
        preprocessors: Iterable[BasePreprocessor],
        detector: Any,
        pseudonymizer: Any,
        mapper: Any,
        *,
        confidence_threshold: float | None = None,
    ) -> None:
        self._preprocessors: list[BasePreprocessor] = list(preprocessors)
        self._detector = detector
        self._pseudonymizer = pseudonymizer
        self._mapper = mapper
        self._confidence_threshold = confidence_threshold

    # ------------------------------------------------------------------ public

    def process(
        self,
        prompt: str,
        ctx: dict[str, Any],
        *,
        restore_dir: Path,
        restore_extension: str = ".pdf",
        format_label: str = "ATTACHMENT",
    ) -> AttachmentBatch:
        """Run the unified attachment pipeline.

        Args:
            prompt: The original user prompt (pre-sanitization).
            ctx: Hook context dict; ``ctx["attachments"]`` is the list
                of attachment dicts supplied by the caller.
            restore_dir: Directory for the rendered sanitized
                artifact.  Created with ``mode=0o700`` if it does not
                exist.
            restore_extension: File extension for the rendered
                artifact (e.g. ``".pdf"`` for PDFs, ``".png"`` for
                images).  Used to build the output path
                ``<stem>_sanitized<ext>``.
            format_label: Header label used in the expanded prompt
                (``"PDF ATTACHMENTS"`` / ``"IMAGE ATTACHMENTS"``).

        Returns:
            :class:`AttachmentBatch` with the expanded prompt and
            per-attachment outcomes.  ``expanded_prompt`` is the
            original prompt when no attachments were routed.
        """
        attachments = self._filter_attachments(ctx.get("attachments") or [])
        if not attachments:
            return AttachmentBatch(expanded_prompt=prompt)

        restore_dir = Path(restore_dir).expanduser()
        # PS-TOCTOU-008: verify + fix perms through a no-follow file
        # descriptor so a symlink planted at restore_dir — at any point —
        # cannot redirect the chmod or the later artifact writes out of
        # the permitted base directory.
        restore_dir_secured = True
        try:
            ensure_secure_dir(restore_dir, 0o700)
        except OSError as exc:
            # Not fatal for the in-memory scan, but fail closed for the
            # rendered artifacts: they must never be written through an
            # unverified path.
            restore_dir_secured = False
            logger.warning(
                "AttachmentProcessor: cannot secure restore dir %s without "
                "following links: %s — sanitized artifacts will not be rendered",
                restore_dir, exc,
            )

        session_id = ctx.get("session_id", "")
        mapping_ttl = getattr(ctx.get("config"), "mapping_ttl_seconds", 0) or 0
        results: list[AttachmentResult] = []

        for att in attachments:
            results.append(
                self._process_one(
                    att,
                    session_id=session_id,
                    restore_dir=restore_dir,
                    restore_extension=restore_extension,
                    mapping_ttl=mapping_ttl,
                    render_allowed=restore_dir_secured,
                )
            )

        # Build the expanded prompt only from successful extractions.
        successful = [r for r in results if not r.error and r.sanitized_path]
        if not successful:
            # All attachments failed — return the original prompt so
            # the caller can fall through to the standard text path.
            return AttachmentBatch(
                expanded_prompt=prompt,
                results=results,
                format_label=format_label,
            )

        body_blocks: list[str] = []
        for i, r in enumerate(successful, start=1):
            header = f"[SANITIZED {format_label} {i} — {format_label.lower()}_path={r.sanitized_path}]"
            if r.text:
                body_blocks.append(f"{header}\n{r.text}")
            else:
                body_blocks.append(header)

        body = "\n\n".join(body_blocks)
        expanded = (
            f"{prompt}\n\n--- {format_label}S (sanitized) ---\n{body}"
        )
        return AttachmentBatch(
            expanded_prompt=expanded,
            results=results,
            format_label=format_label,
        )

    # ------------------------------------------------------------------ internals

    def _filter_attachments(
        self, attachments: list[Any]
    ) -> list[dict[str, Any]]:
        """Return the attachments claimed by at least one pre-processor.

        PS-PIPE-001: routing is content-first —``is_supported`` decides
        which pre-processor claims an attachment; MIME metadata is
        attacker-controllable and is never trusted on its own.  A MIME
        match that no content check corroborates keeps the attachment
        claimed only as a last resort, so :meth:`_process_one` emits an
        explicit per-attachment error (``unsupported format`` /
        ``attachment missing path``) instead of silently dropping a
        shielded-format attachment.
        """
        supported: list[dict[str, Any]] = []
        for att in attachments:
            if not isinstance(att, dict):
                continue
            # PS-INPUT-009: type-unsafe access to untrusted MIME metadata
            # (list/dict values) used to raise AttributeError out of the
            # pre_llm_call hook.  Treat non-string MIME as absent.
            mime = att.get("mime_type") or att.get("mime") or ""
            mime = mime.lower() if isinstance(mime, str) else ""
            path = att.get("path")
            content_path = Path(path) if isinstance(path, str) and path else None
            content_claimed = False
            if content_path is not None:
                for pre in self._preprocessors:
                    if pre.is_supported(content_path):
                        supported.append(att)
                        content_claimed = True
                        break
            if content_claimed:
                continue
            if mime and any(
                mime.startswith(m)
                for pre in self._preprocessors
                for m in pre.supported_mime_types()
            ):
                # MIME-only claim: never routes extraction (the runtime
                # ``_route`` content check still decides), but keeps the
                # attachment visible as an explicit result row.
                supported.append(att)
        return supported

    def _process_one(
        self,
        att: dict[str, Any],
        *,
        session_id: str,
        restore_dir: Path,
        restore_extension: str,
        mapping_ttl: int,
        render_allowed: bool = True,
    ) -> AttachmentResult:
        raw_path = att.get("path")
        if raw_path is not None and not isinstance(raw_path, str):
            # PS-INPUT-009: a non-string path previously crashed
            # ``process`` with a TypeError inside ``Path(...)``; report it
            # as an explicit failure instead.
            return AttachmentResult(
                original_path=None,
                error="attachment path is not a string",
            )
        if not raw_path:
            return AttachmentResult(
                original_path=None,
                error="attachment missing path",
            )
        source = Path(raw_path)
        # The first pre-processor that accepts the file handles it.
        pre = self._route(source)
        if pre is None:
            return AttachmentResult(
                original_path=source,
                error=f"{source.name}: unsupported format ({source.suffix})",
            )

        try:
            extracted_text = self._safe_extract_text(pre, source)
        except PreprocessorError as exc:
            return AttachmentResult(original_path=source, error=str(exc))

        # Skip detection when there is no text to scan.
        if not extracted_text.strip():
            return AttachmentResult(original_path=source, text="")

        matches = self._detector.scan(extracted_text)
        masked_hits = self._filter_by_confidence(matches)
        if masked_hits:
            sanitized, mapping = self._pseudonymizer.replace(
                extracted_text, masked_hits, session_id=session_id
            )
            self._mapper.store(
                mapping,
                session_id=session_id,
                ttl_seconds=mapping_ttl,
            )
        else:
            sanitized = extracted_text

        # Render the sanitized artifact (fail closed: never write through
        # an unsecured restore dir — PS-TOCTOU-008).
        if not render_allowed:
            return AttachmentResult(
                original_path=source,
                text=sanitized,
                error=f"{source.name} restore failed: insecure restore dir",
            )
        try:
            restore_path = restore_dir / f"{source.stem}_sanitized{restore_extension}"
            pre.render_sanitized(source, sanitized, restore_path)
        except (OSError, ValueError) as exc:
            # The text is still usable; just report the render failure.
            return AttachmentResult(
                original_path=source,
                text=sanitized,
                error=f"{source.name} restore failed: {exc}",
            )

        return AttachmentResult(
            original_path=source,
            sanitized_path=restore_path,
            text=sanitized,
        )

    def _route(self, source: Path) -> BasePreprocessor | None:
        for pre in self._preprocessors:
            if pre.is_supported(source):
                return pre
        return None

    def _safe_extract_text(self, pre: BasePreprocessor, source: Path) -> str:
        """Call ``pre.extract_text`` and translate exceptions to PreprocessorError."""
        try:
            return pre.extract_text(source)
        except (FileNotFoundError, ValueError) as exc:
            raise PreprocessorError(f"{source.name}: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - belt-and-braces
            # Catching the base Exception here is intentional: a
            # crashing Tesseract / pdfplumber must not break the LLM
            # call.  We surface it as a PreprocessorError so the caller
            # can decide between log-only and drop-the-attachment.
            raise PreprocessorError(f"{source.name}: unexpected {type(exc).__name__}: {exc}") from exc

    def _filter_by_confidence(self, matches: list[Any]) -> list[Any]:
        """Drop matches below the configured confidence threshold.

        Mirrors the plugin's confidence partition but stays in this
        module so the plugin.py does not need to expose its private
        helper.  Per-type overrides (cookie_id, *_context) live in the
        plugin's :class:`PrivacyShieldConfig`; this loop honours only
        the global threshold because the preprocessor does not own the
        config.  The plugin's main detector scan keeps applying the
        per-type overrides for the text path.
        """
        threshold = self._confidence_threshold
        if threshold is None:
            return list(matches)
        # PS-CONF-002: fail CLOSED.  A non-numeric or non-finite threshold
        # (NaN passes the isinstance check but makes every comparison False,
        # silently un-masking nothing = full PII egress) is rejected with a
        # hard ValueError instead of the fail-OPEN fallback recommended by
        # the finding (``return list(matches)`` would leak every match).
        # The range guard doubles as the config-level [0.0, 1.0] invariant.
        if not isinstance(threshold, (int, float)) or not math.isfinite(threshold):
            raise ValueError(
                f"invalid confidence threshold (must be finite in [0.0, 1.0]): {threshold!r}"
            )
        if not 0.0 <= float(threshold) <= 1.0:
            raise ValueError(
                f"confidence threshold out of range [0.0, 1.0]: {threshold!r}"
            )
        return [
            m for m in matches
            if getattr(m, "confidence", 1.0) >= threshold
        ]


__all__ = ["AttachmentProcessor", "AttachmentBatch", "AttachmentResult"]
