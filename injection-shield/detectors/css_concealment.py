"""CSS/DOM concealment detector (GAP-3, v0.6.0).

Unit 42 documented 22 payload-concealment techniques in wild
web-based indirect prompt injection. The dominant class: instructions
hidden via CSS so a human reviewer sees nothing, while a browser-agent
pipeline (DOM-to-text conversion, screenshot OCR fallback, or a raw-HTML
pass) still delivers them to the model.

This detector runs on ``web_extract``/browser output *before* the
content tagger wraps it, and flags concealment signatures. It does NOT
attempt to strip nodes (transforming HTML is the tool layer's job) —
finding + alert is the contract.
"""

from __future__ import annotations

import html
import re
import urllib.parse

from .injection_patterns import InjectionPatternDetector

from typing import Any

from .base import BaseDetector

# CSS declarations / inline styles that render content invisible to a
# human while leaving it machine-readable.
_CONCEALMENT_CSS_PATTERNS = [
    (r"opacity\s*:\s*0(?:\.0+)?\s*(?:[;}\"']|$)", "opacity_zero"),
    (r"visibility\s*:\s*hidden", "visibility_hidden"),
    (r"display\s*:\s*none", "display_none"),
    (r"font-size\s*:\s*0(?:\.0+)?(?:px|em|rem|pt)?\s*[;}\"']", "font_size_zero"),
    (r"font-size\s*:\s*0?\.0+\d*px", "font_size_subpixel"),
    (r"text-indent\s*:\s*-\d{3,}px", "text_indent_offscreen"),
    (r"left\s*:\s*-\d{3,}px", "left_offscreen"),
    (r"top\s*:\s*-\d{3,}px", "top_offscreen"),
    (r"clip(?:-path)?\s*:\s*(?:rect\(0|inset\(100%|circle\(0)", "clipped_invisible"),
    (r"transform\s*:[^;}]{0,80}scale\(0(?:\.0+)?\)", "scaled_to_zero"),
    (r"margin-left\s*:\s*-\d{3,}px", "margin_offscreen"),
    (r"height\s*:\s*0(?:px)?\s*[;}]", "height_zero"),
    (r"width\s*:\s*0(?:px)?\s*[;}]", "width_zero"),
    (r"overflow\s*:\s*hidden[^}]{0,60}(?:height|width)\s*:\s*[01]px?", "overflow_hidden_tiny"),
]

# Same-color trick: color and background(-color) share a value in one block.
_SAME_COLOR = re.compile(
    r"color\s*:\s*(\#[0-9a-fA-F]{3,8}|rgb\([^)]+\)|rgba\([^)]+\))[^}]{0,120}"
    r"background(?:-color)?\s*:\s*\1",
    re.IGNORECASE,
)

_SVG_HIDDEN_TEXT = re.compile(
    r"""<(?:text|tspan)[^>]*(?:fill\s*=\s*["']?(?:none|transparent)|opacity\s*=\s*["']?0)""",
    re.IGNORECASE,
)

_HTML_COMMENT_PAYLOAD = re.compile(
    r"<!--\s*(?:SYSTEM|ADMIN|ASSISTANT|INSTRUCTIONS?)\s*[:\-]", re.IGNORECASE
)


class CssConcealmentDetector(BaseDetector):
    """Flags CSS/DOM concealment payloads in web/browser content."""

    @property
    def name(self) -> str:
        return "css_concealment"

    # G-006 + DG-002 (Agent-Smith wave-2): the payload-marker gate must ask
    # the SAME patterns the InjectionPatternDetector uses, not a hand-maintained
    # subset (7/9 keywords were missing). One shared detector instance answers
    # the gate — single source of truth, no regex re-synthesis drift.
    _PATTERN_DETECTOR = InjectionPatternDetector()

    @classmethod
    def _has_payload_markers(cls, text: str) -> bool:
        return bool(cls._PATTERN_DETECTOR.check(text))

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        if not text:
            return []
        # G-007 (Agent-Smith review): URL-encoded and HTML-entity-encoded
        # CSS bypassed the raw-text regexes. Decode before scanning.
        # DG-003 (Smith wave-2): single unquote missed double-encoded
        # payloads (%253A -> %253A). Decode iteratively, max 5 rounds.
        decoded = text
        for _ in range(5):
            once = urllib.parse.unquote(decoded)
            if once == decoded:
                break
            decoded = once
        if decoded != text:
            text = text + "\n" + decoded
        text = text + "\n" + html.unescape(text)

        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for pattern, kind in _CONCEALMENT_CSS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match and kind not in seen:
                seen.add(kind)
                paired = self._has_payload_markers(text)
                # ALERT-NOISE (2026-09-24): unpaired CSS concealment is normal
                # web development (architect read its own Sierpinski HTML:
                # opacity:0/display:none/height:0 in game UI). Agents reading
                # HTML/CSS fired a medium alert per read → alert storm.
                # Unpaired concealment = low (audit log only); paired with
                # injection payload markers stays high (alert gate).
                findings.append(
                    {
                        "type": "css_concealment",
                        "technique": kind,
                        "match": match.group(0)[:80],
                        "severity": "high" if paired else "low",
                    }
                )

        if _SAME_COLOR.search(text) and "same_color" not in seen:
            findings.append(
                {"type": "css_concealment", "technique": "same_color_text", "severity": "high"}
            )
        # ARCH-3 (Orakel review): positioned-offscreen detection as bounded
        # code logic instead of a combined regex (ReDoS via [^}]{0,120}).
        for pos_match in re.finditer(r"position\s*:\s*(?:absolute|fixed)", text, re.IGNORECASE):
            window = text[pos_match.start() : pos_match.start() + 160]
            if re.search(r"(?:left|top)\s*:\s*-\d{3,}px", window, re.IGNORECASE):
                if "positioned_offscreen" not in seen:
                    seen.add("positioned_offscreen")
                    # DG-004 (Smith wave-2): same severity-pairing gate as
                    # the regex layers — high only with payload markers.
                    findings.append(
                        {
                            "type": "css_concealment",
                            "technique": "positioned_offscreen",
                            "match": pos_match.group(0)[:80],
                            # Same unpaired/low rationale as the regex layers
                            # above (alert-noise fix 2026-09-24).
                            "severity": "high" if self._has_payload_markers(text) else "low",
                        }
                    )
                break

        if _SVG_HIDDEN_TEXT.search(text):
            findings.append(
                {"type": "css_concealment", "technique": "svg_hidden_text", "severity": "high"}
            )
        if _HTML_COMMENT_PAYLOAD.search(text):
            findings.append(
                {"type": "css_concealment", "technique": "comment_payload", "severity": "high"}
            )
        return findings
