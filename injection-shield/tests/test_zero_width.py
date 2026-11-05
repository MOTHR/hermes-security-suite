"""Tests for zero-width character detector."""

from __future__ import annotations

from injection_shield.detectors.zero_width import ZeroWidthDetector


def test_detects_zero_width_space() -> None:
    text = "Hello\u200bWorld"
    detector = ZeroWidthDetector()
    hits = detector.check(text)
    assert len(hits) == 1
    assert hits[0]["type"] == "zero_width"
    assert hits[0]["position"] == 5


def test_detects_multiple_zero_width_chars() -> None:
    text = "a\u200bb\u200cc\ufeffd"
    hits = ZeroWidthDetector().check(text)
    assert len(hits) == 3
    assert [h["char"] for h in hits] == ["'\\u200b'", "'\\u200c'", "'\\ufeff'"]


def test_clean_text_no_hits() -> None:
    assert ZeroWidthDetector().check("Clean text") == []
