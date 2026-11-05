"""Regression tests for the four HIGH audit findings fixed for PR #17.

Coverage (one case per finding, per task t_325c164a):

* PS-EMAIL-001 — HTML attribute injection in ``_emit_tag``
* PS-EMAIL-002 — dangerous URL schemes passing ``_clean_url``
* PS-EMAIL-004 — path traversal / symlink race in ``render_sanitized``
* PS-CONF-002 — NaN confidence-threshold bypass in ``_filter_by_confidence``

All fixtures are synthetic HTML/paths — no real mail, no real PII.
"""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from privacy_shield.preprocessors.email import EmailPreprocessor, _sanitize_html
from privacy_shield.processors import AttachmentProcessor

# ─── PS-EMAIL-001 ────────────────────────────────────────────────────────

class _AttrCollector(HTMLParser):
    """Re-parse sanitized output and collect every emitted attribute."""

    def __init__(self) -> None:
        super().__init__()
        self.attrs: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.attrs.extend(a[0] for a in attrs)

    def handle_startendtag(self, tag, attrs):
        self.attrs.extend(a[0] for a in attrs)


def test_email_001_attr_injection_never_yields_injected_attribute():
    payload = "<img alt='x\" onerror=\"alert(1)\" y=' src=\".\"'>"
    result = _sanitize_html(payload, pixel_max_dim=2, rewrite_links_to_blank=True)
    collector = _AttrCollector()
    collector.feed(result)
    collector.close()
    injected = [name for name in collector.attrs if name.lower() == "onerror"]
    assert not injected, f"onerror survived sanitization: {result!r}"
    # attribute-breaking quotes must be escaped in the emitted attribute
    assert "&quot;" in result


# ─── PS-EMAIL-002 ────────────────────────────────────────────────────────

_DANGEROUS_HREFS = [
    '<a href="javascript:alert(1)">click</a>',
    '<a href="JaVaScRiPt:alert(1)">click</a>',
    '<a href="java\tscript:alert(1)">click</a>',
    '<a href="&#106;avascript:alert(1)">click</a>',
    '<a href=" vbscript:msgbox(1)">v</a>',
    '<a href="file:///etc/passwd">f</a>',
    '<a href="data:text/html,<script>alert(1)</script>">d</a>',
]


@pytest.mark.parametrize("payload", _DANGEROUS_HREFS)
def test_email_002_dangerous_schemes_rewritten_to_blank(payload: str):
    result = _sanitize_html(payload, pixel_max_dim=2, rewrite_links_to_blank=True)
    lower = result.lower()
    for scheme in ("javascript:", "vbscript:", "file:", "data:text/html"):
        assert scheme not in lower, f"{scheme!r} survived: {result!r}"
    assert "about:blank" in result


def test_email_002_legit_schemes_and_inline_images_kept():
    html_doc = (
        '<a href="https://example.com/page">site</a>'
        '<a href="mailto:x@example.com">mail</a>'
        '<a href="#anchor">anchor</a>'
        '<img src="data:image/png;base64,AAAA">'
        '<img src="cid:inline-1">'
    )
    result = _sanitize_html(html_doc, pixel_max_dim=2, rewrite_links_to_blank=True)
    assert 'href="https://example.com/page"' in result
    assert 'href="mailto:x@example.com"' in result
    assert 'href="#anchor"' in result
    assert 'src="data:image/png;base64,AAAA"' in result
    assert 'src="cid:inline-1"' in result


# ─── PS-EMAIL-004 ────────────────────────────────────────────────────────

def test_email_004_render_sanitized_rejects_traversal(tmp_path: Path):
    pre = EmailPreprocessor()
    restore = tmp_path / "restore"
    with pytest.raises(ValueError):
        pre.render_sanitized(
            tmp_path / "orig.eml", "sanitized", restore / ".." / "escaped.eml"
        )
    # nothing was written outside the restore root
    assert not (tmp_path / "escaped.eml").exists()


def test_email_004_render_sanitized_rejects_symlink_parent(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    restore = tmp_path / "restore"
    restore.symlink_to(real_dir)
    pre = EmailPreprocessor()
    with pytest.raises(ValueError):
        pre.render_sanitized(
            tmp_path / "orig.eml", "sanitized", restore / "x_sanitized.eml"
        )
    assert not (real_dir / "x_sanitized.eml").exists()


def test_email_004_render_sanitized_rejects_symlink_file_target(tmp_path: Path):
    restore = tmp_path / "restore"
    restore.mkdir()
    victim = tmp_path / "victim.txt"
    (restore / "y_sanitized.eml").symlink_to(victim)
    pre = EmailPreprocessor()
    with pytest.raises(ValueError):
        pre.render_sanitized(
            tmp_path / "orig.eml", "sanitized", restore / "y_sanitized.eml"
        )
    assert not victim.exists()


def test_email_004_render_sanitized_legit_path_still_written(tmp_path: Path):
    pre = EmailPreprocessor()
    out = pre.render_sanitized(
        tmp_path / "orig.eml", "sanitized body", tmp_path / "restore" / "x_sanitized.eml"
    )
    assert out.is_file()
    assert out.read_text(encoding="utf-8") == "sanitized body"
    mode = out.parent.stat().st_mode & 0o777
    assert mode == 0o700, f"restore dir mode {oct(mode)} != 0o700"


# ─── PS-CONF-002 ─────────────────────────────────────────────────────────

def _make_processor(threshold: float) -> AttachmentProcessor:
    return AttachmentProcessor(
        preprocessors=[],
        detector=None,
        pseudonymizer=None,
        mapper=None,
        confidence_threshold=threshold,
    )


@pytest.mark.parametrize(
    "bad", [float("nan"), float("inf"), float("-inf"), 1.5, -0.1]
)
def test_conf_002_nonfinite_or_invalid_threshold_fails_closed(bad: float):
    high, low = object(), object()
    # fail-closed contract: an invalid threshold is rejected loudly instead
    # of silently dropping every match (NaN) or passing them all through.
    with pytest.raises(ValueError):
        _make_processor(bad)._filter_by_confidence([high, low])


def test_conf_002_valid_threshold_still_filters():
    high = SimpleNamespace(confidence=0.95)
    low = SimpleNamespace(confidence=0.50)
    out = _make_processor(0.8)._filter_by_confidence([high, low])
    assert out == [high]