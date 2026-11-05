"""Regression tests for the symlink-race hardening (PS-REST-003, PS-TOCTOU-008).

The audit found a check-then-use pattern around restore-directory
creation: ``mkdir(exist_ok=True)`` followed by a path-based
``os.chmod(0o700)`` follows a symlink planted at the target, redirecting
both the permission fixup and later artifact writes to a foreign
directory. These tests pin the replacement: all verification and chmods
run through a no-follow file descriptor, planted symlinks (including
swaps between create and verify) are rejected deterministically, and
both call sites fail closed without writing through the link.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.fs_hardening import SecureDirError, ensure_secure_dir
from privacy_shield.plugin import PrivacyShieldPlugin
from privacy_shield.preprocessors.base import BasePreprocessor
from privacy_shield.processors import AttachmentProcessor


def _make_plugin() -> PrivacyShieldPlugin:
    cfg = PrivacyShieldConfig(
        enabled=True,
        storage_mode="memory",
        encryption_key="test-key-32-bytes-xxxxxxxxxxxx",
    )
    return PrivacyShieldPlugin(config=cfg)


class _FakePreprocessor(BasePreprocessor):
    """Concrete subclass used to verify the pipeline contract."""

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

    def render_sanitized(
        self, original_path: Path, sanitized_text: str, output_path: Path
    ) -> Path:
        output_path.write_text(sanitized_text, encoding="utf-8")
        return output_path


def _racy_mkdir_factory(target: Path, foreign: Path) -> Any:
    """Return a Path.mkdir replacement that swaps *target* for a symlink.

    Deterministically simulates an attacker winning the race between
    directory creation and no-follow verification.
    """
    real_mkdir = Path.mkdir

    def racy_mkdir(path: Path, *args: Any, **kwargs: Any):
        result = real_mkdir(path, *args, **kwargs)
        if Path(path) == target and not target.is_symlink():
            target.rmdir()
            target.symlink_to(foreign, target_is_directory=True)
        return result

    return racy_mkdir


# ---------------------------------------------------------------- fs_hardening


class TestEnsureSecureDir:
    def test_creates_nested_dir_with_0700(self, tmp_path: Path):
        target = tmp_path / "a" / "b" / "c"
        ensure_secure_dir(target)
        assert target.is_dir()
        assert target.stat().st_mode & 0o777 == 0o700

    def test_fixes_existing_loose_perms(self, tmp_path: Path):
        target = tmp_path / "loose"
        target.mkdir()
        target.chmod(0o777)
        ensure_secure_dir(target)
        assert target.stat().st_mode & 0o777 == 0o700

    def test_rejects_symlink_at_target(self, tmp_path: Path):
        # PS-REST-003 core case: a symlink planted at the target must be
        # rejected — and the linked foreign file must not be chmod'ed.
        foreign = tmp_path / "foreign.txt"
        foreign.write_text("do not touch", encoding="utf-8")
        foreign.chmod(0o644)
        planted = tmp_path / "planted"
        planted.symlink_to(foreign)
        with pytest.raises(SecureDirError):
            ensure_secure_dir(planted)
        assert foreign.stat().st_mode & 0o777 == 0o644

    def test_rejects_regular_file_at_target(self, tmp_path: Path):
        target = tmp_path / "not-a-dir"
        target.write_text("x", encoding="utf-8")
        with pytest.raises(SecureDirError):
            ensure_secure_dir(target)

    def test_no_path_based_chmod_used(self, tmp_path: Path, monkeypatch):
        # All verification + permission fixup must go through the
        # descriptor (fchmod); a path-based os.chmod would follow links.
        target = tmp_path / "fd-only"
        target.mkdir()
        target.chmod(0o777)

        def _forbidden_chmod(*args, **kwargs):  # pragma: no cover
            raise AssertionError("os.chmod must not be used by the fix path")

        monkeypatch.setattr("os.chmod", _forbidden_chmod)
        ensure_secure_dir(target)
        assert target.stat().st_mode & 0o777 == 0o700

    def test_race_window_between_mkdir_and_verify(self, tmp_path: Path, monkeypatch):
        # Deterministic race simulation: an attacker swaps the freshly
        # created directory for a symlink to a foreign file before the
        # no-follow verification runs. The open must fail (ELOOP) and
        # the foreign file must stay untouched.
        foreign = tmp_path / "foreign.txt"
        foreign.write_text("secret", encoding="utf-8")
        foreign.chmod(0o644)
        target = tmp_path / "raced"
        monkeypatch.setattr(
            Path, "mkdir", _racy_mkdir_factory(target, tmp_path / "foreign.txt")
        )
        with pytest.raises(SecureDirError):
            ensure_secure_dir(target)
        assert foreign.stat().st_mode & 0o777 == 0o644


# ---------------------------------------------------------------- plugin.py
# PS-REST-003: _ensure_secure_restore_dir


class TestPluginRestoreDir:
    def test_happy_path_unchanged(self, tmp_path: Path, monkeypatch):
        # Existing non-symlink behaviour is preserved.
        monkeypatch.setattr(
            PrivacyShieldPlugin, "SECURE_RESTORE_FALLBACK", str(tmp_path / "fb")
        )
        plugin = _make_plugin()
        configured = tmp_path / "restore" / "pdf"
        result = plugin._ensure_secure_restore_dir(str(configured), "pdf")
        assert result == configured
        assert result.is_dir()
        assert result.stat().st_mode & 0o777 == 0o700

    def test_symlink_at_primary_falls_back(self, tmp_path: Path, monkeypatch):
        # The planted symlink is rejected; the artifacts go to the
        # home-private fallback instead of through the foreign dir, and
        # the foreign dir is neither chmod'ed nor written into.
        monkeypatch.setattr(
            PrivacyShieldPlugin, "SECURE_RESTORE_FALLBACK", str(tmp_path / "fb")
        )
        foreign = tmp_path / "foreign-dir"
        foreign.mkdir()
        before = foreign.stat().st_mode & 0o777
        foreign.chmod(0o755)
        planted = tmp_path / "pdf-restore"
        planted.symlink_to(foreign, target_is_directory=True)
        plugin = _make_plugin()
        result = plugin._ensure_secure_restore_dir(str(planted), "pdf")
        assert result == Path(tmp_path / "fb") / "pdf"
        assert result.is_dir()
        assert result.stat().st_mode & 0o777 == 0o700
        assert foreign.iterdir() and list(foreign.iterdir()) == []
        assert foreign.stat().st_mode & 0o777 == 0o755
        del before

    def test_symlinked_primary_and_fallback_raises(self, tmp_path: Path, monkeypatch):
        # Last-resort hard fail (BUTLER-PS-7 spec): both candidates are
        # symlink traps — refuse the restore instead of writing through.
        foreign = tmp_path / "foreign-dir"
        foreign.mkdir()
        (tmp_path / "pdf-restore").symlink_to(foreign, target_is_directory=True)
        fallback_base = tmp_path / "fb"
        fallback_base.mkdir()
        (fallback_base / "pdf").symlink_to(foreign, target_is_directory=True)
        monkeypatch.setattr(
            PrivacyShieldPlugin, "SECURE_RESTORE_FALLBACK", str(fallback_base)
        )
        plugin = _make_plugin()
        with pytest.raises(RuntimeError, match="cannot create secure restore dir"):
            plugin._ensure_secure_restore_dir(str(tmp_path / "pdf-restore"), "pdf")


# ---------------------------------------------------------------- processors.py
# PS-TOCTOU-008: AttachmentProcessor.process restore_dir creation


def _make_processor() -> tuple[AttachmentProcessor, _FakePreprocessor]:
    pre = _FakePreprocessor("application/pdf", ".pdf", text="ATTACHMENT CONTENT")
    processor = AttachmentProcessor(
        preprocessors=[pre],
        detector=MagicMock(scan=MagicMock(return_value=[])),
        pseudonymizer=MagicMock(),
        mapper=MagicMock(),
    )
    return processor, pre


class TestAttachmentProcessorRestoreDir:
    @staticmethod
    def _ctx(src: Path) -> dict[str, Any]:
        return {"attachments": [{"path": str(src), "mime_type": "application/pdf"}]}

    def test_clean_dir_still_renders(self, tmp_path: Path):
        # Existing non-symlink behaviour is preserved: normal flow
        # extracts, renders, and enforces 0o700.
        restore = tmp_path / "restore"
        src = tmp_path / "doc.pdf"
        src.write_bytes(b"fake-pdf")
        processor, _pre = _make_processor()
        batch = processor.process("p", self._ctx(src), restore_dir=restore)
        assert not batch.results[0].error
        assert (restore / "doc_sanitized.pdf").exists()
        assert restore.stat().st_mode & 0o777 == 0o700

    def test_symlink_restore_dir_fails_closed(self, tmp_path: Path):
        # PS-TOCTOU-008: symlink planted at restore_dir — the artifact
        # must NOT be written through the link, a per-attachment error
        # surfaces, and the linked foreign dir stays untouched.
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        planted = tmp_path / "restore"
        planted.symlink_to(foreign, target_is_directory=True)
        src = tmp_path / "doc.pdf"
        src.write_bytes(b"fake-pdf")
        processor, _pre = _make_processor()
        batch = processor.process("p", self._ctx(src), restore_dir=planted)
        result = batch.results[0]
        assert "insecure restore dir" in (result.error or "")
        assert result.sanitized_path is None
        assert result.text == "ATTACHMENT CONTENT"  # in-memory scan still usable
        assert not (foreign / "doc_sanitized.pdf").exists()

    def test_race_swap_of_restore_dir_fails_closed(self, tmp_path: Path, monkeypatch):
        # Deterministic race simulation on the processor path: the dir
        # is swapped for a symlink between creation and the no-follow
        # verification. Artifact rendering must fail closed.
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        target = tmp_path / "restore"
        monkeypatch.setattr(Path, "mkdir", _racy_mkdir_factory(target, foreign))
        src = tmp_path / "doc.pdf"
        src.write_bytes(b"fake-pdf")
        processor, _pre = _make_processor()
        batch = processor.process("p", self._ctx(src), restore_dir=target)
        assert "insecure restore dir" in (batch.results[0].error or "")
        assert not (foreign / "doc_sanitized.pdf").exists()

    def test_no_path_based_chmod_in_processor(self, tmp_path: Path, monkeypatch):
        src = tmp_path / "doc.pdf"
        src.write_bytes(b"fake-pdf")
        processor, _pre = _make_processor()
        restore = tmp_path / "restore"
        restore.mkdir()
        restore.chmod(0o777)

        def _forbidden_chmod(*args, **kwargs):  # pragma: no cover
            raise AssertionError("os.chmod must not be used to secure restore dir")

        monkeypatch.setattr("os.chmod", _forbidden_chmod)
        processor.process("p", self._ctx(src), restore_dir=restore)
        assert restore.stat().st_mode & 0o777 == 0o700
