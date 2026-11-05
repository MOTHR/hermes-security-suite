"""Regression tests for the processors.py MEDIUM/LOW audit findings.

Coverage (task t_16a406a8):

* PS-PIPE-001 — MIME first-match routing bypass in ``_filter_attachments``:
  routing is content-first; forged MIME metadata can never route an
  attachment to a preprocessor whose content check fails, and shielded-
  format MIME claims that no content check corroborates still surface as
  an explicit error row instead of being dropped silently.
* PS-INPUT-009 — missing input validation in ``_filter_attachments`` /
  ``_process_one``: non-string MIME metadata and non-string paths are
  handled as invalid input (explicit failure), never crash the hook.

State-transition contract: a failed attachment never reports success
(error non-empty, ``sanitized_path`` empty) and never disappears silently;
partial failures stay isolated and repeated processing is idempotent.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from privacy_shield.preprocessors.base import BasePreprocessor
from privacy_shield.processors import AttachmentBatch, AttachmentProcessor


class _FakePreprocessor(BasePreprocessor):
    """Concrete subclass with extension-based is_supported (like PDF/Image)."""

    def __init__(self, mime: str, supported_ext: str, text: str = "fake"):
        self._mime = mime
        self._ext = supported_ext
        self._text = text
        self.assigned: Path | None = None

    def supported_mime_types(self) -> frozenset[str]:
        return frozenset({self._mime})

    def is_supported(self, source_path: Path) -> bool:
        return Path(source_path).suffix.lower() == self._ext

    def extract(self, source_path: Path, **kwargs) -> str:
        self.assigned = Path(source_path)
        return self._text

    def render_sanitized(self, original_path, sanitized_text, output_path):
        output_path.write_text(sanitized_text, encoding="utf-8")
        return Path(output_path)


def _processor(preprocessors) -> AttachmentProcessor:
    return AttachmentProcessor(
        preprocessors=preprocessors,
        detector=MagicMock(scan=MagicMock(return_value=[])),
        pseudonymizer=MagicMock(),
        mapper=MagicMock(),
    )


# ─── PS-PIPE-001 ─────────────────────────────────────────────────────────


def test_pipe_001_forged_mime_never_routes_to_mismatching_preprocessor(
    tmp_path: Path,
) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    image = _FakePreprocessor("image/png", ".png", text="ocr")
    processor = _processor([pdf, image])
    png = tmp_path / "photo.png"
    png.write_bytes(b"png")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(png), "mime_type": "application/pdf"}]},
        restore_dir=tmp_path / "restore",
    )
    # Content-first routing: the PNG was claimed, but by the image
    # preprocessor — the forged PDF MIME did not select the extractor.
    assert len(batch.results) == 1
    assert batch.results[0].error == ""
    assert pdf.assigned is None
    assert image.assigned == png


def test_pipe_001_forged_mime_without_content_corroboration_is_explicit_error(
    tmp_path: Path,
) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    weird = tmp_path / "weird.bin"
    weird.write_bytes(b"\x00")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(weird), "mime_type": "application/pdf"}]},
        restore_dir=tmp_path / "restore",
    )
    # Not silently dropped: the shielded-format MIME claim yields an
    # explicit failure row instead of a success or a vanishing input.
    assert len(batch.results) == 1
    assert "unsupported format" in batch.results[0].error
    assert batch.results[0].sanitized_path is None
    assert batch.expanded_prompt == "p"


def test_pipe_001_honest_mime_and_content_still_claimed(tmp_path: Path) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(doc), "mime_type": "application/pdf"}]},
        restore_dir=tmp_path / "restore",
    )
    assert len(batch.results) == 1
    assert pdf.assigned == doc


def test_pipe_001_missing_mime_metadata_uses_content_fallback(
    tmp_path: Path,
) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(doc)}]},
        restore_dir=tmp_path / "restore",
    )
    assert len(batch.results) == 1
    assert batch.results[0].error == ""
    assert pdf.assigned == doc


def test_pipe_001_mime_claim_without_path_is_explicit_error() -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    batch = processor.process(
        "p",
        {"attachments": [{"mime_type": "application/pdf"}]},
        restore_dir=Path("/tmp/unused-restore"),
    )
    assert len(batch.results) == 1
    assert batch.results[0].error == "attachment missing path"


def test_pipe_001_foreign_format_stays_unclaimed(tmp_path: Path) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    txt = tmp_path / "note.txt"
    txt.write_text("no pii")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(txt), "mime_type": "text/plain"}]},
        restore_dir=tmp_path / "restore",
    )
    assert batch.results == []
    assert batch.expanded_prompt == "p"
    assert pdf.assigned is None


def test_pipe_001_mime_only_never_selects_extractor(
    tmp_path: Path,
) -> None:
    # Direct invariant on _filter_attachments: every claimed attachment is
    # either content-corroborated or MIME-claimed only (visible error row).
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    image = _FakePreprocessor("image/png", ".png")
    processor = _processor([pdf, image])
    bogus = tmp_path / "bogus.bin"
    bogus.write_bytes(b"\x00")
    claimed = processor._filter_attachments(
        [{"path": str(bogus), "mime_type": "image/png"}]
    )
    assert claimed == [{"path": str(bogus), "mime_type": "image/png"}]


# ─── PS-INPUT-009 ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_mime",
    [
        ["application/pdf"],
        {"mime": "application/pdf"},
        42,
        b"application/pdf",
    ],
)
def test_input_009_non_string_mime_does_not_crash(tmp_path: Path, bad_mime) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    # Before the fix this raised AttributeError (.lower() on a list/dict)
    # straight out of process() / the pre_llm_call hook.
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(doc), "mime_type": bad_mime}]},
        restore_dir=tmp_path / "restore",
    )
    assert len(batch.results) == 1
    assert batch.results[0].error == ""
    assert pdf.assigned == doc


def test_input_009_non_string_path_is_explicit_failure() -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    batch = processor.process(
        "p",
        {"attachments": [{"path": 123, "mime_type": "application/pdf"}]},
        restore_dir=Path("/tmp/unused-restore"),
    )
    assert len(batch.results) == 1
    assert batch.results[0].error == "attachment path is not a string"


def test_input_009_non_string_mime_and_non_dict_attachment(
    tmp_path: Path,
) -> None:
    pdf = _FakePreprocessor("application/pdf", ".pdf")
    processor = _processor([pdf])
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    batch = processor.process(
        "p",
        {
            "attachments": [
                "not-a-dict",
                {"path": str(doc), "mime_type": {"type": "application/pdf"}},
            ]
        },
        restore_dir=tmp_path / "restore",
    )
    # The non-dict entry is skipped, the valid one still processed.
    assert len(batch.results) == 1
    assert batch.results[0].error == ""


# ─── State transitions ────────────────────────────────────────────────────


def test_extraction_failure_reports_error_not_success(tmp_path: Path) -> None:
    class _Broken(_FakePreprocessor):
        def extract(self, source_path: Path, **kwargs) -> str:
            raise ValueError("corrupted payload")

    broken = _Broken("application/pdf", ".pdf")
    processor = _processor([broken])
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(doc), "mime_type": "application/pdf"}]},
        restore_dir=tmp_path / "restore",
    )
    assert len(batch.results) == 1
    row = batch.results[0]
    assert row.error != ""
    assert row.sanitized_path is None
    assert row.text == ""
    # The failure must not claim processing success in the prompt.
    assert batch.expanded_prompt == "p"


def test_render_failure_schreibfehler_negates_success(tmp_path: Path) -> None:
    pseud = MagicMock()
    pseud.replace.return_value = (
        "TOKEN_EMAIL_1234567890_001",
        [{"token": "TOKEN_EMAIL_1234567890_001"}],
    )
    detector = MagicMock()
    detector.scan.return_value = [MagicMock(confidence=0.9)]

    class _NoRender(_FakePreprocessor):
        def render_sanitized(self, original_path, sanitized_text, output_path):
            raise OSError("disk full")

    pre = _NoRender("application/pdf", ".pdf")
    processor = AttachmentProcessor(
        preprocessors=[pre],
        detector=detector,
        pseudonymizer=pseud,
        mapper=MagicMock(),
    )
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(doc), "mime_type": "application/pdf"}]},
        restore_dir=tmp_path / "restore",
    )
    row = batch.results[0]
    # Write error: explicit failure, no sanitized artifact — but the
    # sanitized text stays attached to the row (no silent data loss).
    assert "restore failed" in row.error
    assert row.sanitized_path is None
    assert row.text == "TOKEN_EMAIL_1234567890_001"
    assert batch.expanded_prompt == "p"


def test_duplicate_attachments_process_idempotently(tmp_path: Path) -> None:
    pseud = MagicMock()
    mapping = [{"token": "TOKEN_EMAIL_1234567890_001"}]
    pseud.replace.return_value = ("TOKEN_EMAIL_1234567890_001", mapping)
    detector = MagicMock()
    detector.scan.return_value = [MagicMock(confidence=0.9)]
    mapper = MagicMock()
    pre = _FakePreprocessor("application/pdf", ".pdf")
    processor = AttachmentProcessor(
        preprocessors=[pre],
        detector=detector,
        pseudonymizer=pseud,
        mapper=mapper,
    )
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    att = {"path": str(doc), "mime_type": "application/pdf"}
    batch = processor.process(
        "p", {"attachments": [att, dict(att)]}, restore_dir=tmp_path / "restore"
    )
    # Both duplicate rows processed with identical sanitized output and
    # the mapping stored twice with the same payload (idempotent store).
    assert [r.text for r in batch.results] == [
        "TOKEN_EMAIL_1234567890_001",
        "TOKEN_EMAIL_1234567890_001",
    ]
    assert all(r.error == "" for r in batch.results)
    assert mapper.store.call_count == 2
    assert all(c.args[0] == mapping for c in mapper.store.call_args_list)


def test_partial_failure_isolates_and_resynchronizes(tmp_path: Path) -> None:
    pseud = MagicMock()
    pseud.replace.side_effect = lambda text, hits, session_id=None: (
        f"clean:{text}",
        [{"token": "t"}],
    )
    detector = MagicMock()
    detector.scan.return_value = [MagicMock(confidence=0.9)]
    good = _FakePreprocessor("application/pdf", ".pdf", text="good text")
    mapper = MagicMock()

    class _HalfBroken(_FakePreprocessor):
        """Fails for the first call only, then succeeds (partial outage)."""

        def __init__(self):
            super().__init__("image/png", ".png", text="good image")
            self.calls = 0

        def extract(self, source_path: Path, **kwargs) -> str:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient ocr crash")
            return self._text

    bad_then_good = _HalfBroken()
    processor = AttachmentProcessor(
        preprocessors=[good, bad_then_good],
        detector=detector,
        pseudonymizer=pseud,
        mapper=mapper,
    )
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    png = tmp_path / "photo.png"
    png.write_bytes(b"png")
    batch = processor.process(
        "p",
        {
            "attachments": [
                {"path": str(png), "mime_type": "image/png"},
                {"path": str(doc), "mime_type": "application/pdf"},
            ]
        },
        restore_dir=tmp_path / "restore",
    )
    assert len(batch.results) == 2
    first, second = batch.results
    # The failing image attachment neither reports success nor vanishes…
    assert first.error != "" and first.sanitized_path is None
    # …and the subsequent PDF attachment is still fully resynchronized
    # despite the earlier failure in the same batch.
    assert second.error == "" and second.sanitized_path is not None
    assert second.text == "clean:good text"
    assert "[SANITIZED" in batch.expanded_prompt


def test_successful_processing_contract_unchanged(tmp_path: Path) -> None:
    detector = MagicMock(scan=MagicMock(return_value=[]))
    pre = _FakePreprocessor("application/pdf", ".pdf")
    processor = AttachmentProcessor(
        preprocessors=[pre],
        detector=detector,
        pseudonymizer=MagicMock(),
        mapper=MagicMock(),
    )
    doc = tmp_path / "doc.pdf"
    doc.write_bytes(b"%PDF")
    batch = processor.process(
        "p",
        {"attachments": [{"path": str(doc), "mime_type": "application/pdf"}]},
        restore_dir=tmp_path / "restore",
    )
    assert isinstance(batch, AttachmentBatch)
    row = batch.results[0]
    assert row.error == ""
    assert row.sanitized_path is not None
    assert row.sanitized_path.is_file()
    assert row.text == "fake"
    assert pre.assigned == doc
