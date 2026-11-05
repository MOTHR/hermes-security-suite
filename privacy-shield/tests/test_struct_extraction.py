"""Tests for the FIX-PS-R5-STRUCT (Morpheus R5) extracted helpers.

Covers the new :class:`AttachmentProcessor`,
:class:`OutputSanitizer`, and :class:`CacheBypassInjector` modules
plus the :class:`BasePreprocessor` ABC contract.  Behaviour of the
plugin's pre/post hooks is exercised by the existing
``test_integration`` and ``test_post_llm_call_output_scanning`` suites
— these tests focus on the new modules' contracts in isolation.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from privacy_shield.cache_bypass import CacheBypassInjector
from privacy_shield.errors import (
    MissingKeyError,
    ParanoidModeBlock,
    PolicyViolationError,
    PreprocessorError,
    PrivacyShieldError,
    StrictModeBlock,
)
from privacy_shield.mapping_table import _compile_token_pattern
from privacy_shield.output_sanitizer import OutputSanitizer
from privacy_shield.preprocessors.base import BasePreprocessor
from privacy_shield.processors import (
    AttachmentBatch,
    AttachmentProcessor,
    AttachmentResult,
)


# ─── errors.py ──────────────────────────────────────────────────────────


class TestExceptionHierarchy:
    def test_base_is_exception(self):
        assert issubclass(PrivacyShieldError, Exception)

    def test_strict_block_is_permission_error(self):
        # Backward-compat: tests like test_egress_security use
        # ``pytest.raises(PermissionError)`` for the strict path.
        assert issubclass(StrictModeBlock, PermissionError)
        assert issubclass(StrictModeBlock, PolicyViolationError)
        assert issubclass(StrictModeBlock, PrivacyShieldError)

    def test_paranoid_block_is_permission_error(self):
        assert issubclass(ParanoidModeBlock, PermissionError)
        assert issubclass(ParanoidModeBlock, PolicyViolationError)

    def test_missing_key_is_runtime_error(self):
        # Backward-compat: legacy callers may still ``except RuntimeError``
        # for missing-config paths.
        assert issubclass(MissingKeyError, RuntimeError)
        assert issubclass(MissingKeyError, PrivacyShieldError)

    def test_preprocessor_error_subclass(self):
        assert issubclass(PreprocessorError, PrivacyShieldError)
        assert not issubclass(PreprocessorError, PermissionError)

    def test_catch_via_base_class(self):
        # A single ``except PrivacyShieldError`` branch must catch
        # every plugin-specific failure.
        with pytest.raises(PrivacyShieldError):
            raise StrictModeBlock("test")
        with pytest.raises(PrivacyShieldError):
            raise ParanoidModeBlock("test")
        with pytest.raises(PrivacyShieldError):
            raise MissingKeyError("test")
        with pytest.raises(PrivacyShieldError):
            raise PreprocessorError("test")


# ─── cache_bypass.py ────────────────────────────────────────────────────


class TestCacheBypassInjector:
    def test_disabled_returns_text_unchanged(self):
        injector = CacheBypassInjector(enabled=False)
        ctx = {"session_id": "sess-123"}
        assert injector.inject("hello", ctx) == "hello"

    def test_enabled_prefixes_three_markers(self):
        injector = CacheBypassInjector(enabled=True)
        ctx = {"session_id": "sess-1234567890"}
        out = injector.inject("hello", ctx)
        # Three marker formats: bracket, key-value, HTML comment.
        # ``short`` = session_id[:8] so "sess-1234567890" -> "sess-123".
        assert "[Privacy-Shield Session:sess-1234567890:" in out
        assert "[PS:sess-123:" in out
        assert "<!-- privacy-shield session=sess-123 ts=" in out
        # The original text survives below the marker block.
        assert out.endswith("hello")

    def test_marker_changes_every_inject(self):
        # Two consecutive calls must produce different timestamps
        # (or the marker would not invalidate the per-conversation
        # cache key).
        injector = CacheBypassInjector(enabled=True)
        ctx = {"session_id": "sess-X"}
        first = injector.inject("a", ctx)
        time.sleep(0.01)
        second = injector.inject("a", ctx)
        assert first != second

    def test_empty_session_id_still_produces_marker(self):
        # Empty session_id must not crash — the marker is just less
        # unique, but Hermes' cache key is still invalidated by the
        # timestamp.
        injector = CacheBypassInjector(enabled=True)
        out = injector.inject("payload", {"session_id": ""})
        assert "<!-- privacy-shield session=" in out


# ─── output_sanitizer.py ────────────────────────────────────────────────


class TestOutputSanitizer:
    def _build(self):
        detector = MagicMock()
        pseudonymizer = MagicMock()
        mapper = MagicMock()
        # token_pattern is a real regex so the static helper works.
        mapper.token_pattern = re.compile(r"TOKEN_[A-Z]+_[0-9a-f]{10}(?:_\d{3})?")
        partition = MagicMock(side_effect=lambda hits: (hits, []))
        return detector, pseudonymizer, mapper, partition

    def test_empty_text_short_circuits(self):
        detector, pseud, mapper, partition = self._build()
        san = OutputSanitizer(detector, pseud, mapper, partition_by_confidence=partition)
        assert san.sanitize("") == ("", 0)
        assert san.sanitize(None) == (None, 0)
        # Detector MUST NOT be called for empty input.
        assert not detector.scan.called

    def test_no_pii_returns_original(self):
        detector, pseud, mapper, partition = self._build()
        detector.scan.return_value = []
        san = OutputSanitizer(detector, pseud, mapper, partition_by_confidence=partition)
        text = "Just a clean response, no PII here."
        assert san.sanitize(text, session_id="sess-1") == (text, 0)

    def test_round_trip_mapping_is_skipped(self):
        """Fresh hits whose value is already in the session mapping
        are NOT re-tokenised — that would defeat the restore pass.
        """
        detector, pseud, mapper, partition = self._build()
        hit = MagicMock()
        hit.value = "already-mapped@example.com"
        detector.scan.return_value = [hit]
        mapper.known_original_values.return_value = {"already-mapped@example.com"}
        san = OutputSanitizer(detector, pseud, mapper, partition_by_confidence=partition)
        text = "Echo: already-mapped@example.com"
        result_text, count = san.sanitize(text, session_id="sess-1")
        assert result_text == text  # unchanged
        assert count == 0
        # Pseudonymizer MUST NOT be called for round-trip values.
        assert not pseud.replace.called
        # We deliberately do NOT call mapper.store() for fresh hits
        # — see OutputSanitizer.sanitize docstring (SEC-4 rationale).

    def test_fresh_pii_is_pseudonymized_and_counted(self):
        detector, pseud, mapper, partition = self._build()
        hit = MagicMock()
        hit.value = "new-leak@example.com"
        detector.scan.return_value = [hit]
        mapper.known_original_values.return_value = set()  # not a round-trip
        pseud.replace.return_value = ("Echo: TOKEN_EMAIL_xxx_001", [{"type": "email"}])
        san = OutputSanitizer(detector, pseud, mapper, partition_by_confidence=partition)
        text = "Echo: new-leak@example.com"
        result_text, count = san.sanitize(text, session_id="sess-1")
        assert result_text.startswith("Echo: TOKEN_")
        assert count == 1
        pseud.replace.assert_called_once()

    def test_mask_tokens_preserves_length(self):
        # Used by the plugin's _mask_tokens static shim too.
        text = "Hello TOKEN_EMAIL_abc1234567_001 world"
        token_re = re.compile(r"TOKEN_EMAIL_[0-9a-f]{10}(?:_\d{3})?")
        masked, spans = OutputSanitizer._mask_tokens(text, token_re)
        assert len(masked) == len(text)
        assert masked == "Hello " + " " * (len("TOKEN_EMAIL_abc1234567_001")) + " world"
        assert spans == [(6, 6 + len("TOKEN_EMAIL_abc1234567_001"))]

    def test_ps_mask_006_compound_string_token_is_masked_before_detector_scan(self):
        """PS-MASK-006 end-to-end guard: a token embedded in a compound string
        (``abcTOKEN_PHONE_a1b2c3d4e5_001``) must be masked by ``_mask_tokens``
        BEFORE ``detector.scan`` runs. Previously the lookbehind in the token
        pattern skipped the token, the detector then rematchted the token's
        10-hex hash as hex-PII (cookie_id/gps), causing a corrupting
        re-tokenisation of the output.

        The fake detector flags any scanned text that still contains the raw
        hex hash — i.e. it simulates the real hex-PII detector. If masking
        worked, the detector never sees the hash and nothing is tokenised.
        """
        text = "abcTOKEN_PHONE_a1b2c3d4e5_001"
        detector = MagicMock()
        detector.scan.side_effect = lambda scanned: (
            [MagicMock(value="a1b2c3d4e5")] if "a1b2c3d4e5" in scanned else []
        )
        pseud = MagicMock()
        mapper = MagicMock()
        mapper.token_pattern = _compile_token_pattern("TOKEN", 10, 3)
        partition = MagicMock(side_effect=lambda hits: (hits, []))
        san = OutputSanitizer(detector, pseud, mapper, partition_by_confidence=partition)
        result_text, count = san.sanitize(text, session_id="sess-1")
        assert result_text == text
        assert count == 0
        # The detector MUST NOT have seen the raw hash: nothing to re-tokenise.
        pseud.replace.assert_not_called()


# ─── preprocessors/base.py ──────────────────────────────────────────────


class _FakePreprocessor(BasePreprocessor):
    """Concrete subclass used to verify the ABC contract."""

    def __init__(self, mime: str, supported_ext: str, text: str = "fake"):
        self._mime = mime
        self._ext = supported_ext
        self._text = text

    def supported_mime_types(self) -> frozenset[str]:
        return frozenset({self._mime})

    def is_supported(self, source_path: Path) -> bool:
        return Path(source_path).suffix.lower() == self._ext

    def extract(self, source_path: Path, **kwargs: Any) -> Any:
        return self._text

    def render_sanitized(self, original_path, sanitized_text, output_path):
        output_path.write_text(sanitized_text)
        return output_path


class TestBasePreprocessor:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            BasePreprocessor()  # type: ignore[abstract]

    def test_extract_text_default(self):
        # The default extract_text() handles both str and {text: ...}
        # results so PDF/Image can keep their native return types.
        p_str = _FakePreprocessor("text/plain", ".txt", text="plain text")
        assert p_str.extract_text(Path("/tmp/x.txt")) == "plain text"

        # When extract returns a non-string without .text, default falls back to "".
        class _Bare:
            pass

        p_bare = _FakePreprocessor("text/plain", ".txt", text="placeholder")
        p_bare._text = _Bare()  # type: ignore[assignment]
        assert p_bare.extract_text(Path("/tmp/x.txt")) == ""

        class _ObjWithText:
            text = "nested-text"

        p_obj = _FakePreprocessor("text/plain", ".txt", text="placeholder")
        p_obj._text = _ObjWithText()  # type: ignore[assignment]
        assert p_obj.extract_text(Path("/tmp/x.txt")) == "nested-text"


# ─── processors.py (AttachmentProcessor) ─────────────────────────────────


class TestAttachmentProcessorFiltering:
    def test_no_attachments_returns_original_prompt(self, tmp_path: Path):
        detector = MagicMock()
        processor = AttachmentProcessor(
            preprocessors=[_FakePreprocessor("text/plain", ".txt")],
            detector=detector,
            pseudonymizer=MagicMock(),
            mapper=MagicMock(),
        )
        batch = processor.process(
            "original prompt",
            {"attachments": []},
            restore_dir=tmp_path,
        )
        assert isinstance(batch, AttachmentBatch)
        assert batch.expanded_prompt == "original prompt"
        assert batch.results == []
        # Detector MUST NOT be called when there are no attachments.
        assert not detector.scan.called

    def test_filters_by_mime_type(self, tmp_path: Path):
        pdf = _FakePreprocessor("application/pdf", ".pdf")
        image = _FakePreprocessor("image/png", ".png")
        # Empty detection list — no PII, but the fake pre-processor
        # still produces a successful sanitized block.
        detector = MagicMock(scan=MagicMock(return_value=[]))
        processor = AttachmentProcessor(
            preprocessors=[pdf, image],
            detector=detector,
            pseudonymizer=MagicMock(),
            mapper=MagicMock(),
        )
        # Only the PDF + image attachments should pass the filter;
        # the text/plain attachment is dropped on the floor.
        ctx = {
            "attachments": [
                {"path": str(tmp_path / "doc.pdf"), "mime_type": "application/pdf"},
                {"path": str(tmp_path / "photo.png"), "mime_type": "image/png"},
                {"path": str(tmp_path / "note.txt"), "mime_type": "text/plain"},
            ]
        }
        batch = processor.process("hello", ctx, restore_dir=tmp_path)
        # 2 results — one per matched attachment. The text attachment
        # is dropped because no pre-processor claims it.
        assert len(batch.results) == 2
        # No PII -> the expanded prompt has 2 sanitized blocks
        # appended (PDF + image), all carrying the fake text.  The
        # header uses "ATTACHMENTS" (plural) because the same
        # processor instance is shared.
        assert batch.expanded_prompt.startswith("hello")
        assert batch.expanded_prompt.count("[SANITIZED ATTACHMENT ") == 2

    def test_missing_path_is_recorded_as_error(self, tmp_path: Path):
        pdf = _FakePreprocessor("application/pdf", ".pdf")
        processor = AttachmentProcessor(
            preprocessors=[pdf],
            detector=MagicMock(),
            pseudonymizer=MagicMock(),
            mapper=MagicMock(),
        )
        ctx = {"attachments": [{"mime_type": "application/pdf"}]}  # no "path"
        batch = processor.process("p", ctx, restore_dir=tmp_path)
        assert len(batch.results) == 1
        assert batch.results[0].error == "attachment missing path"

    def test_unsupported_extension_routed_to_error(self, tmp_path: Path):
        pdf = _FakePreprocessor("application/pdf", ".pdf")
        processor = AttachmentProcessor(
            preprocessors=[pdf],
            detector=MagicMock(),
            pseudonymizer=MagicMock(),
            mapper=MagicMock(),
        )
        weird = tmp_path / "weird.bin"
        weird.write_bytes(b"\x00")
        ctx = {"attachments": [{"path": str(weird), "mime_type": "application/pdf"}]}
        batch = processor.process("p", ctx, restore_dir=tmp_path)
        # PDF's is_supported checks .pdf extension; .bin fails.
        assert len(batch.results) == 1
        assert "unsupported format" in batch.results[0].error

    def test_confidence_threshold_filters_hits(self, tmp_path: Path):
        pdf = _FakePreprocessor("application/pdf", ".pdf")
        high = MagicMock(confidence=0.95, value="x")
        low = MagicMock(confidence=0.50, value="y")
        detector = MagicMock()
        detector.scan.return_value = [high, low]
        pseudonymizer = MagicMock()
        pseudonymizer.replace.return_value = ("sanitized", [{"type": "x"}])
        processor = AttachmentProcessor(
            preprocessors=[pdf],
            detector=detector,
            pseudonymizer=pseudonymizer,
            mapper=MagicMock(),
            confidence_threshold=0.8,
        )
        ctx = {
            "attachments": [
                {"path": str(tmp_path / "doc.pdf"), "mime_type": "application/pdf"},
            ]
        }
        batch = processor.process("p", ctx, restore_dir=tmp_path)
        # Only the high-confidence hit is pseudonymized.
        pseudonymizer.replace.assert_called_once()
        args, _kwargs = pseudonymizer.replace.call_args
        assert args[1] == [high]  # only the 0.95 hit, not the 0.50 one
        assert batch.expanded_prompt != "p"

    def test_restore_dir_is_chmod_700(self, tmp_path: Path):
        # The processor must enforce strict perms on the restore dir
        # to prevent tokenized artifacts from leaking to other users.
        # The dir is only created when at least one attachment is
        # processed (so the empty-attachments path returns the
        # original prompt unchanged).
        pdf = _FakePreprocessor("application/pdf", ".pdf")
        processor = AttachmentProcessor(
            preprocessors=[pdf],
            detector=MagicMock(scan=MagicMock(return_value=[])),
            pseudonymizer=MagicMock(),
            mapper=MagicMock(),
        )
        restore = tmp_path / "restore"
        src = tmp_path / "doc.pdf"
        src.write_bytes(b"fake-pdf")
        processor.process(
            "p",
            {"attachments": [{"path": str(src), "mime_type": "application/pdf"}]},
            restore_dir=restore,
        )
        # Directory was created with mode 0o700.
        assert restore.exists()
        mode = restore.stat().st_mode & 0o777
        assert mode == 0o700
