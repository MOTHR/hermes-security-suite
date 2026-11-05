"""Regression tests for the four MEDIUM audit findings in the
``email.py`` cluster (PR #17 follow-up, per task t_82f60e24).

Coverage:

* PS-EMAIL-003 — header injection via preserved carriage returns
  (``_unfold_header`` + synthesized ``Content-Type`` line)
* PS-EMAIL-005 — attacker-controlled charset crashing with LookupError
* PS-EMAIL-006 — MIME parsing resource exhaustion (nesting depth /
  part count unbounded)
* PS-EMAIL-007 — permanent HTML suppression via broken ``_drop_depth``
  accounting when ``rewrite_links_to_blank`` is False

All fixtures are synthetic mail/HTML — no real mail, no real PII.
"""

from __future__ import annotations

import base64
import tempfile
from email.message import EmailMessage
from pathlib import Path

import pytest
from privacy_shield.preprocessors.email import (
    EmailPreprocessor,
    _safe_charset,
    _sanitize_html,
    _unfold_header,
)


def _write_eml(raw: bytes) -> Path:
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as fh:
        fh.write(raw)
    return Path(fh.name)


# ─── PS-EMAIL-003 — header injection via preserved CR ────────────────────


def _rfc2047_subject(value: str) -> bytes:
    encoded = base64.b64encode(value.encode()).decode()
    return (
        f"Subject: =?utf-8?b?{encoded}?=\n"
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "\n"
        "body\n"
    ).encode()


# RFC2047 decoding yields a value containing a bare \r — the exact shape
# the audit described (consumers splitting on \r see "Injected" as a
# header of its own).
_CR_INJECTED_SUBJECT = "Hello\rInjected-Header: payload-marker"


def test_email_003_rfc2047_cr_never_yields_injected_header():
    pre = EmailPreprocessor()
    result = pre.extract(_write_eml(_rfc2047_subject(_CR_INJECTED_SUBJECT)))
    assert "\r" not in result, f"bare CR survived: {result!r}"
    # no consumer splitting on \r can see an injected header line
    for line in result.split("\n"):
        assert not line.startswith("Injected-Header:")
    # subject content survives, not token-joined into a forgery
    assert "Hello" in result


def test_email_003_unfold_header_strips_all_control_chars():
    dirty = "a\r\n b\x00c\u000bd\nx\ry\x7fz"
    value = _unfold_header(dirty)
    for ch in ("\r", "\n", "\x00", "\x0b", "\x7f"):
        assert ch not in value, f"{ch!r} survived: {value!r}"
    # shape check: folded WSP became a single space, no forged joins
    assert value.startswith("a") and value.endswith("z")


def test_email_003_valid_internationalized_headers_preserved():
    pre = EmailPreprocessor()
    raw = (
        "From: =?utf-8?q?M=C3=BCller,_J=C3=BCrgen?= <juergen@beispiel.de>\n"
        "To: =?utf-8?q?S=C3=B6ren?= <soeren@beispiel.de>\n"
        "Date: Mon, 20 Oct 2026 10:00:00 +0200\n"
        "Message-ID: <2026@beispiel.de>\n"
        "\n"
        "Grüße\n"
    ).encode()
    result = pre.extract(_write_eml(raw))
    assert "Müller, Jürgen" in result  # decoded display name survives
    assert "juergen@beispiel.de" in result
    assert "Sören" in result
    assert "From: " in result and "To: " in result
    assert "Message-ID: <2026@beispiel.de>" in result
    assert "\r" not in result


def test_email_003_header_name_stripped_of_control_chars_in_emitted_line():
    # The rfc822 parser never yields header names with control chars
    # (a \x0b-name parses as body, not header) — the name sanitization
    # in sanitize_message is defense-in-depth; its helpers are tested
    # directly here.
    from privacy_shield.preprocessors.email import _HEADER_CONTROL_RE

    name = _unfold_header("X-Custom\x0bHeader\rJunk")
    assert name == "X-CustomHeader Junk"
    assert not _HEADER_CONTROL_RE.search(name)
    # dropped-path emission is control-free too
    dropped = _HEADER_CONTROL_RE.sub("", _unfold_header("X-Drop\x00Name"))
    assert dropped == "X-DropName"


# ─── PS-EMAIL-005 — charset validation / LookupError crash ───────────────


def test_email_005_unknown_charset_does_not_crash_extract():
    pre = EmailPreprocessor()
    raw = (
        "From: a@b.c\n"
        "Subject: hi\n"
        "Content-Type: text/plain; charset=no-such-charset-99\n"
        "\n"
        "h\x8fllo\n"
    ).encode()
    result = pre.extract(_write_eml(raw))  # pre-fix: LookupError
    assert isinstance(result, str)
    assert "charset=utf-8" in result  # falls back to utf-8 both decode + emit


@pytest.mark.parametrize(
    ("raw_charset", "expected"),
    [
        ("utf-8", "utf-8"),
        ("ISO-8859-1", "ISO-8859-1"),
        ("gb18030", "gb18030"),
        ("no-such-charset-99", "utf-8"),
        ("utf-8\r\nInjected: x", "utf-8"),
        ("utf\x008", "utf-8"),
        ('"utf-8"; boundary=x', "utf-8"),  # no separators/quotes allowed
        ("", "utf-8"),
        (None, "utf-8"),
    ],
)
def test_email_005_safe_charset_boundary(raw_charset, expected):
    assert _safe_charset(raw_charset) == expected


def test_email_005_valid_charsets_still_decode_correctly():
    pre = EmailPreprocessor()
    body = "Grüße aus dem Süden".encode("iso-8859-1")
    raw = (
        b"From: a@b.c\n"
        b"Subject: iso body\n"
        b'Content-Type: text/plain; charset="iso-8859-1"\n'
        b"\n"
    ) + body
    result = pre.extract(_write_eml(raw))
    assert "Grüße aus dem Süden" in result
    assert "charset=iso-8859-1" in result


# ─── PS-EMAIL-006 — MIME structure limits ────────────────────────────────


def _nested_multipart(depth: int) -> bytes:
    inner = EmailMessage()
    inner.set_content("deep leaf")
    msg = inner
    for _ in range(depth):
        outer = EmailMessage()
        outer.make_mixed()
        outer.attach(msg)
        msg = outer
    return msg.as_bytes()


def test_email_006_deeply_nested_multipart_rejected_as_valueerror():
    pre = EmailPreprocessor()
    with pytest.raises(ValueError, match="tief|nest"):
        pre.extract(_write_eml(_nested_multipart(60)))


def test_email_006_multipart_part_explosion_rejected_as_valueerror():
    from email.message import EmailMessage

    flat = EmailMessage()
    flat.make_mixed()
    for i in range(350):
        part = EmailMessage()
        part.set_content(f"part {i}")
        flat.attach(part)
    pre = EmailPreprocessor()
    with pytest.raises(ValueError, match="Part"):
        pre.extract(_write_eml(flat.as_bytes()))


def test_email_006_normal_nested_multipart_still_passes():
    pre = EmailPreprocessor()
    result = pre.extract(_write_eml(_nested_multipart(3)))
    assert isinstance(result, str) and "deep leaf" in result


# ─── PS-EMAIL-007 — broken _drop_depth accounting ────────────────────────


_TRACKER_LINK_DOC = (
    "<p>before "
    '<a href="https://click.example.net/track/1"><b>tracked bold</b> '
    "and <i>tracked italic</i> text</a> "
    'after <a href="https://ok.example.net/page">good link</a> done</p>'
)


def test_email_007_subtree_drop_ends_at_matching_close():
    result = _sanitize_html(
        _TRACKER_LINK_DOC, pixel_max_dim=2, rewrite_links_to_blank=False
    )
    # the whole tracked <a> subtree is gone …
    assert "tracked bold" not in result
    assert "tracked italic" not in result
    assert "click.example.net" not in result
    # … but content AFTER the tracker link survives (pre-fix: dropped
    # for the rest of the document)
    assert "after" in result
    assert "good link" in result
    assert "done" in result
    assert "https://ok.example.net/page" in result


def test_email_007_stray_end_tag_inside_drop_does_not_end_drop():
    result = _sanitize_html(
        '<a href="https://open.example.net/o.gif"><em>leak</em></a>rest',
        pixel_max_dim=2,
        rewrite_links_to_blank=False,
    )
    assert "leak" not in result
    assert "rest" in result  # drop terminated with </a>


def test_email_007_normal_links_unaffected_when_rewrite_enabled():
    result = _sanitize_html(
        _TRACKER_LINK_DOC, pixel_max_dim=2, rewrite_links_to_blank=True
    )
    assert result.count("about:blank") == 1  # only the tracker rewritten
    assert "good link" in result
