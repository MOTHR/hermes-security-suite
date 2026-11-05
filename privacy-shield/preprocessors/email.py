"""Email (.eml) sanitization for Privacy-Shield.

P1 (t_025240da): the three e-mail threats the LIVE-TEST (t_815fd79d) found
missing are handled here:

* T1 — Tracking pixel:  ``<img>`` elements whose declared width AND height
  are <= ``pixel_max_dim`` (default 2) are removed from the HTML body.
* T2 — Click-tracker links:  every ``href``/``src`` pointing at a known
  tracker domain pattern (``click.*``, ``open.*`` newsletter/pixel
  endpoints, ``/track``/``/pixel``/``/o.gif``-style paths) is rewritten to
  ``about:blank`` (or the whole tag is removed when rewriting is disabled).
* T3 — Sensitive headers:  a whitelist keeps From/To/Subject/Date/
  Message-ID; ``X-Originating-IP`` and ``X-Mailer`` are dropped entirely
  and every ``Received`` header is reduced to its IP-bearing host parts
  stripped of timestamps and hop commentary.

Security notes
--------------
* ``extract``/``parse`` catch every parser exception.  A malformed or
  adversarial .eml MUST NOT crash the LLM call — it is surfaced as
  ``ValueError`` so the caller can fall back to the text path.
* ``render_sanitized`` writes the sanitized .eml into a directory owned
  by the plugin (default ``~/.hermes/privacy/restore/email``) with
  ``mode=0o700`` so the sanitized artifact never leaks to other users.
* The sanitizer never touches the original file (BasePreprocessor
  contract) — the sanitized copy goes to *output_path*.
* Only stdlib ``email`` + ``html.parser`` are used — no new runtime
  dependency beyond what Privacy-Shield already requires.
"""

from __future__ import annotations

import codecs
import html
import json
import logging
import os
import re
import stat
import unicodedata
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage, MIMEPart
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .base import BasePreprocessor

logger = logging.getLogger(__name__)

EMAIL_FORMATS: frozenset[str] = frozenset({".eml"})

# Headers worth keeping for the LLM — everything else is dropped.  The
# whitelist is deliberately SMALL: each extra header is a potential
# side-channel (mail-client fingerprint, corporate infra, message
# provenance).
_HEADER_WHITELIST: frozenset[str] = frozenset({
    "from", "to", "subject", "date", "message-id",
})

# Headers removed without any reduction step (full drop, not IP-reduce).
_HEADER_DROP: frozenset[str] = frozenset({
    "x-originating-ip", "x-mailer", "reply-to", "list-unsubscribe",
    "list-unsubscribe-post", "feedback-id", "dkim-signature",
    "dkim-filter", "domainkey-signature", "authentication-results",
    "arc-authentication-results", "x-report-abuse", "x-feedback-id",
})

# Tracker domain shapes (applied to the host of every href/src URL):
#  * click.*   — classic click-redirector subdomain
#  * open.*    — pixel/open-endpoint subdomain
#  * /track|/tracking|/pixel|/open|/click in the URL path
_TRACKER_HOST_RE = re.compile(
    r"^(?:click|open|track|tracking|pixel|email|mailer|newsletter|clicks|"
    r"link|links|url\d*|go|goto|r\d*|t\d*)[.-]",
    re.IGNORECASE,
)
_TRACKER_PATH_RE = re.compile(
    r"/(?:track(?:ing)?|pixel|open|click|beacon|o\.gif|openx|imp|banner|"
    r"newsletter|email|campaign|/u/|/u\.gif)",
    re.IGNORECASE,
)
# URL shorteners / redirectors commonly used to mask tracker hops.
_SHORTENER_HOSTS: frozenset[str] = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at",
})

# Received header: reduce to the IP-bearing tokens.  A Received header is a
# chain of "from X (host [IP]) by Y ...; timestamp" clauses.  We keep only
# bracketed IPs / resolved hostnames and drop the rest so the LLM sees
# routing provenance without timestamp/comment noise.
_RECEIVED_TOKEN_RE = re.compile(
    r"\((?:[-\w.]+\s+)?\[(?:[0-9a-fA-F:.]+)\]\)"   # (host [IP])
    r"|\[(?:[0-9a-fA-F:.]+)\]"                     # [IP]
    r"|(?:\d{1,3}\.){3}\d{1,3}"                    # bare v4
)
_RECEIVED_STRIP_RE = re.compile(
    r"(?i)\b(?:from|by|with|via|id|for)\b|;.*$"
)

# PS-EMAIL-003: control characters that must never survive in an emitted
# header line — CR/LF enable header injection in consumers that split on
# \r as well as \n, NUL and the other C0/C1 controls confuse naive
# rfc822 parsers.  Horizontal TAB stays (legal rfc5322 FWS component).
_HEADER_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# rfc5322 field-name: printable US-ASCII without colon/WSP.
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
# PS-EMAIL-003/005: a charset token emitted into a Content-Type header
# line.  Restricted to the alphabet codecs actually accept; anything
# else (quotes, CR/LF, whitespace) falls back to utf-8.
_SAFE_CHARSET_RE = re.compile(r"[A-Za-z0-9._+-]{1,64}")

# PS-EMAIL-006: structural limits applied after parsing.  Realistic
# e-mail nesting stays well below these bounds; adversarial nesting/
# part-count explodes parser recursion or downstream CPU/memory.
_DEFAULT_MAX_MIME_DEPTH = 20
_DEFAULT_MAX_MIME_PARTS = 300


class _SanitizingHTMLParser(HTMLParser):
    """Collect + rewrite URLs from an HTML body into a cleaned copy.

    Strategy: rebuild the document from the parse events, keeping ALL
    elements except (a) pixel-sized ``<img>`` tags which are dropped and
    (b) URLs whose host/path matches a tracker pattern, which are
    rewritten to ``about:blank`` (or the element dropped when configured).
    Void elements are re-emitted without a closing tag; everything else
    keeps its original casing/spacing as emitted by the parser
    (``convert_charrefs=False`` preserves entity text verbatim).
    """

    VOID_ELEMENTS = frozenset({
        "img", "br", "hr", "meta", "link", "input", "area", "base", "col",
        "embed", "source", "track", "wbr",
    })

    URL_ATTRS = {"href", "src"}

    # URL scheme allowlist (PS-EMAIL-002): any href/src whose scheme is not
    # listed here is rewritten to ``about:blank``.  ``cid``/``data:image`` stay
    # allowed so legit inline images keep working; ``data:text/html`` etc. is
    # blocked like every other scheme.
    ALLOWED_URL_SCHEMES = frozenset({"http", "https", "mailto", "cid"})

    def __init__(
        self,
        pixel_max_dim: int,
        rewrite_links_to_blank: bool,
    ) -> None:
        super().__init__(convert_charrefs=False)
        self.pixel_max_dim = pixel_max_dim
        self.rewrite_links_to_blank = rewrite_links_to_blank
        self.out: list[str] = []
        # Stack of open tags whose entire subtree is being removed.  A
        # counter is not enough (PS-EMAIL-007): nested non-void start
        # tags inside a dropped tracker <a> must be popped off again so
        # the drop ends exactly at the matching </a> and later content
        # survives.  Stray end tags that match nothing are ignored.
        self._drop_stack: list[str] = []
        self.pixel_removed = 0
        self.links_rewritten = 0
        self.links_removed = 0

    # ── URL classification ────────────────────────────────────────────
    def _is_tracker_url(self, url: str) -> bool:
        if not url or url.startswith(("#", "mailto:", "data:")):
            return False
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        host = (parts.hostname or "").lower()
        if not host:
            # relative URLs in newsletter HTML are almost always tracker
            # paths served from the sending domain — treat /track etc. as
            # trackers even hostless.
            return bool(_TRACKER_PATH_RE.search(url))
        if host in _SHORTENER_HOSTS:
            return True
        if _TRACKER_HOST_RE.match(host):
            return True
        return bool(_TRACKER_PATH_RE.search(parts.path or ""))

    def _is_pixel_img(self, tag: str, attrs: list[tuple[str, Any]]) -> bool:
        if tag != "img":
            return False
        dim: dict[str, int | None] = {"width": None, "height": None}
        for name, value in attrs:
            lname = name.lower()
            if lname in dim:
                try:
                    dim[lname] = int(str(value).strip().rstrip("%"))
                except (ValueError, TypeError):
                    # non-numeric dims (e.g. "auto") — not a pixel
                    dim[lname] = None
        return (
            dim["width"] is not None
            and dim["height"] is not None
            and dim["width"] <= self.pixel_max_dim
            and dim["height"] <= self.pixel_max_dim
        )

    def _emit_tag(self, tag: str, attrs: list[tuple[str, Any]], self_closing: bool) -> None:
        parts = [tag]
        for name, value in attrs:
            if value is None:
                parts.append(name)
            else:
                # PS-EMAIL-001: attribute values arrive unescaped from the
                # parser; a raw '"' would terminate the attribute early and
                # let injected attributes survive sanitization.
                parts.append(f'{name}="{html.escape(str(value), quote=True)}"')
        inner = " ".join(parts)
        if self_closing or tag in self.VOID_ELEMENTS:
            self.out.append(f"<{inner}/>")
        else:
            self.out.append(f"<{inner}>")

    # ── HTMLParser events ─────────────────────────────────────────────
    def handle_starttag(self, tag: str, attrs: list[tuple[str, Any]]) -> None:
        if self._drop_stack:
            if tag not in self.VOID_ELEMENTS:
                self._drop_stack.append(tag)
            return
        if self._is_pixel_img(tag, attrs):
            self.pixel_removed += 1
            return  # drop the element entirely (void element, no closing)
        if not self.rewrite_links_to_blank:
            # drop tracker <a>/<img> wholly when rewriting is disabled
            for name, value in attrs:
                if name.lower() in self.URL_ATTRS and self._is_tracker_url(str(value or "")):
                    if tag == "a":
                        self._drop_stack.append("a")
                        self.links_removed += 1
                        return
                    self.links_removed += 1
                    return
        cleaned = [
            (name, self._clean_url(name, value))
            for name, value in attrs
        ]
        self._emit_tag(tag, cleaned, self_closing=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, Any]]) -> None:
        if self._drop_stack:
            return
        if self._is_pixel_img(tag, attrs):
            self.pixel_removed += 1
            return
        cleaned = [(name, self._clean_url(name, value)) for name, value in attrs]
        self._emit_tag(tag, cleaned, self_closing=True)

    def handle_endtag(self, tag: str) -> None:
        if self._drop_stack:
            if tag in self._drop_stack:
                # PS-EMAIL-007: pop everything down to and including the
                # matching open tag — this ends the drop even when the
                # subtree nested non-void elements (or nested <a> tags).
                while self._drop_stack and self._drop_stack.pop() != tag:
                    pass
            return
        if tag not in self.VOID_ELEMENTS:
            self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._drop_stack:
            self.out.append(data)

    def handle_entityref(self, name: str) -> None:
        if not self._drop_stack:
            self.out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        if not self._drop_stack:
            self.out.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        # HTML comments in e-mail often carry tracking scaffolding and
        # conditional hacks — they carry no user value, drop them.
        pass

    # ── URL rewriting ─────────────────────────────────────────────────
    def _is_allowed_scheme(self, url: str) -> bool:
        """Decode-then-check scheme allowlist (PS-EMAIL-002).

        The URL is HTML-entity-decoded (two bounded rounds catches
        double-encoded payloads), stripped of all ASCII whitespace
        (including embedded ``\\t``/``\\n``) and NFKC-normalized BEFORE
        the scheme comparison — checking first and decoding later is
        bypassable.  A URL without a scheme (relative, ``#fragment``)
        carries no scheme risk and is allowed, matching the existing
        skip-path in ``_is_tracker_url``.
        """
        decoded = html.unescape(url)
        for _ in range(2):
            unescaped = html.unescape(decoded)
            if unescaped == decoded:
                break
            decoded = unescaped
        cleaned = "".join(decoded.split())
        cleaned = unicodedata.normalize("NFKC", cleaned)
        try:
            parts = urlsplit(cleaned)
            scheme = parts.scheme.lower()
        except ValueError:
            return False
        if not scheme:
            return True
        if scheme == "data":
            # inline images only — data:text/html & friends stay blocked
            return cleaned.startswith("data:image/")
        return scheme in self.ALLOWED_URL_SCHEMES

    def _clean_url(self, attr_name: str, value: Any) -> Any:
        if value is None or attr_name.lower() not in self.URL_ATTRS:
            return value
        url = str(value)
        if self._is_tracker_url(url) or not self._is_allowed_scheme(url):
            self.links_rewritten += 1
            return "about:blank"
        return url

    def result(self) -> str:
        return "".join(self.out)


def _reduce_received(value: str) -> str:
    """Reduce a Received header to its IP-bearing parts.

    ``from mail-qk1-f172.google.com (mail-qk1-f172.google.com [209.85.222.172])``
    → ``mail-qk1-f172.google.com [209.85.222.172]`` — timestamps, hop
    commentary ("by … with ESMTPS id …") and the trailing ``; date`` are
    dropped; the IP provenance stays for auditability.
    """
    tokens = _RECEIVED_TOKEN_RE.findall(value)
    if not tokens:
        # Keep the first "from <host>" fragment so the hop origin survives
        # even without a bracketed IP (e.g. sender with PTR-less relay).
        m = re.match(r"(?i)\s*from\s+([\w.\-]+)", value)
        return m.group(1) if m else "[reduce: no IP]"
    return "; ".join(t if t.startswith("(") else t for t in tokens)


def _lstat_chmod(path: str, mode: int) -> None:
    """chmod *path* only after lstat proves it is not a symlink (PS-EMAIL-004).

    ``os.chmod`` follows symlinks; an attacker-planted link in the restore
    directory would otherwise take the permission change (and any later
    write) to an arbitrary target.  Raises ``ValueError`` on a symlink so
    callers can fail closed instead of silently following.
    """
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"Privacy-Shield email: symlink is not a safe write target: {path}")
    os.chmod(path, mode, follow_symlinks=False)


def _validate_render_target(output_path: Path) -> Path:
    """Fail closed unless *output_path* stays inside its own parent dir.

    Two invariants, both enforced with ``os.path.commonpath`` (a plain
    ``str.startswith`` prefix test is wrong for sibling-prefix attacks
    like ``/root`` vs ``/root-evil``):

    1. Lexically normalized absolute path (catches ``..`` traversal in
       the caller-supplied path string).
    2. ``os.path.realpath`` of the target (catches any existing symlink
       ancestor chain that would resolve the write outside the root).
    """
    parent = output_path.parent
    if ".." in Path(output_path).parts:
        raise ValueError(
            f"Privacy-Shield email: path traversal in output path: {output_path}"
        )
    root = os.path.realpath(str(parent))
    if not os.path.isdir(root) or os.path.islink(str(parent)):
        raise ValueError(
            f"Privacy-Shield email: unsafe restore parent: {parent}"
        )
    lexical = os.path.normpath(os.path.abspath(str(output_path)))
    resolved = os.path.realpath(str(output_path))
    for candidate in (lexical, resolved):
        if os.path.commonpath([candidate, root]) != root:
            raise ValueError(
                f"Privacy-Shield email: output path escapes restore root: {output_path}"
            )
    return Path(resolved)


class EmailPreprocessor(BasePreprocessor):
    """Header whitelist + pixel/track-URL sanitizer for .eml payloads.

    Parameters
    ----------
    max_size_mb:
        Soft guardrail for the .eml payload; larger files raise ValueError
        (the AttachmentProcessor surfaces it as a per-attachment error).
    pixel_max_dim:
        <img> with declared width AND height <= this dimension is treated
        as a tracking pixel and removed (default 2, per fix-spec).
    rewrite_links_to_blank:
        True → tracked href/src rewritten to ``about:blank``;
        False → the whole tracked element is dropped.
    """

    SUPPORTED_MIME_TYPES: frozenset[str] = frozenset({
        "message/rfc822", "message/news",
    })

    def __init__(
        self,
        max_size_mb: int = 10,
        pixel_max_dim: int = 2,
        rewrite_links_to_blank: bool = True,
        max_mime_depth: int = _DEFAULT_MAX_MIME_DEPTH,
        max_mime_parts: int = _DEFAULT_MAX_MIME_PARTS,
    ) -> None:
        self.max_size_mb = max_size_mb
        self.pixel_max_dim = pixel_max_dim
        self.rewrite_links_to_blank = rewrite_links_to_blank
        self.max_mime_depth = max_mime_depth
        self.max_mime_parts = max_mime_parts

    # ------------------------------------------------------------------ formats

    @property
    def supported_formats(self) -> frozenset[str]:
        return EMAIL_FORMATS

    def supported_mime_types(self) -> frozenset[str]:
        return self.SUPPORTED_MIME_TYPES

    def is_supported(self, source_path: Path) -> bool:
        return Path(source_path).suffix.lower() in EMAIL_FORMATS

    # ------------------------------------------------------------------ extract

    def extract(self, source_path: Path, **kwargs: Any) -> str:
        """Return the sanitized .eml as an rfc822-shaped string.

        The result keeps the raw .eml shape (headers + body) so the
        downstream detector/pseudonymizer sees a regular text document.
        Malformed input raises ``ValueError`` (never crashes the hook).
        """
        return self._sanitize_message_file(Path(source_path))

    # ------------------------------------------------------------------ render

    def render_sanitized(
        self,
        original_path: Path,
        sanitized_text: str,
        output_path: Path,
    ) -> Path:
        """Write the sanitized .eml to *output_path* (0o700 folder)."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # PS-EMAIL-004: fail closed on traversal / symlink attacks before
        # chmod or write ever follow a link.  Raises ValueError, which the
        # AttachmentProcessor reports as a per-attachment error.
        parent = output_path.parent
        _validate_render_target(output_path)
        _lstat_chmod(str(parent), 0o700)
        if os.path.islink(str(output_path)):
            raise ValueError(
                f"Privacy-Shield email: symlink is not a safe write target: {output_path}"
            )
        output_path.write_text(sanitized_text, encoding="utf-8")
        return output_path

    # ------------------------------------------------------------------ internals

    def _sanitize_message_file(self, path: Path) -> str:
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > self.max_size_mb:
            raise ValueError(
                f"Email zu gross ({size_mb:.1f} MB > {self.max_size_mb} MB): {path}"
            )
        try:
            msg = BytesParser(policy=policy.default).parse(
                path.open("rb"),
            )
        except Exception as exc:
            # RecursionError (deeply nested MIME, PS-EMAIL-006) is an
            # Exception subclass — surfaced here as ValueError like every
            # other parser failure, never as a hook crash.
            raise ValueError(f"E-Mail-Parse fehlgeschlagen für {path}: {exc}") from exc
        self._check_mime_structure(msg)
        return self.sanitize_message(msg)

    def _check_mime_structure(self, msg: EmailMessage) -> None:
        """Reject adversarial MIME structure (PS-EMAIL-006).

        The parser itself only catches runaway recursion via the
        RecursionError path above; nesting within recursion budget or an
        explosion of parts must still be bounded explicitly or the
        sanitize/decode chain burns CPU and memory per part.  The walk
        is iterative (no recursion limit of its own).
        """
        parts = 0
        stack: list[tuple[EmailMessage, int]] = [(msg, 1)]
        while stack:
            part, depth = stack.pop()
            parts += 1
            if depth > self.max_mime_depth:
                raise ValueError(
                    f"MIME-Verschachtelung zu tief ({depth} > "
                    f"{self.max_mime_depth})"
                )
            if parts > self.max_mime_parts:
                raise ValueError(
                    f"MIME-Part-Anzahl zu hoch ({parts} > "
                    f"{self.max_mime_parts})"
                )
            if part.is_multipart():
                children = part.get_payload()
                if isinstance(children, list):
                    stack.extend(
                        (child, depth + 1)
                        for child in cast("list[EmailMessage]", children)
                    )

    def sanitize_message(self, msg: EmailMessage) -> str:
        """Whitelist headers, sanitize bodies, return full .eml text."""
        lines: list[str] = []

        # ── T3: header whitelist / reduction ─────────────────────────────
        dropped: list[str] = []
        kept: list[tuple[str, str]] = []
        for name, value in msg.items():
            lname = name.lower()
            if lname in _HEADER_WHITELIST:
                kept.append((name, _unfold_header(value)))
            elif lname in _HEADER_DROP:
                dropped.append(name)
            elif lname == "received":
                kept.append((name, _reduce_received(_unfold_header(value))))
            # everything else: silently dropped (not whitelisted)
            else:
                dropped.append(name)

        for name, value in kept:
            # PS-EMAIL-003: header names/values are attacker-controlled
            # at the trust boundary.  A non-rfc5322 field-name is not
            # emitted as-is (it would land raw in the output line); the
            # control-stripped fallback keeps provenance without
            # injection.  _unfold_header already guarantees a
            # CR/LF/NUL-free value.
            safe_name = _unfold_header(name)
            if not _HEADER_NAME_RE.fullmatch(safe_name):
                safe_name = f"[refused-header] {_HEADER_CONTROL_RE.sub('', safe_name)}"
            lines.append(f"{safe_name}: {value}")
        for name in dropped:
            lines.append(
                f"X-Privacy-Shield-Removed: {_HEADER_CONTROL_RE.sub('', _unfold_header(name))}"
            )
        body_text: MIMEPart | None = None
        try:
            body_text = msg.get_body(preferencelist=("html", "plain"))
        except Exception as exc:  # malformed multipart — fall back to raw walk
            logger.debug("Privacy-Shield email: get_body failed (%s)", exc)

        if body_text is not None:
            content_type = body_text.get_content_type()
            # PS-EMAIL-005: the charset string comes straight from the
            # attacker-controlled Content-Type header.  Validate it at
            # the trust boundary (format + real codec) before it is
            # either decoded against or emitted into the synthesized
            # Content-Type line (PS-EMAIL-003).
            charset = _safe_charset(body_text.get_content_charset())
            payload = body_text.get_payload(decode=True)
            if not isinstance(payload, bytes):
                # str-typed multipart part: no binary payload to extract.
                payload = b""
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeError):
                text = payload.decode("utf-8", errors="replace")
                charset = "utf-8"
            if content_type == "text/html":
                text = _sanitize_html(
                    text,
                    self.pixel_max_dim,
                    self.rewrite_links_to_blank,
                )
                charset = "utf-8"  # re-encoded below
            lines.append("")
            lines.append(f"Content-Type: {content_type}; charset={charset}")
            lines.append("Content-Transfer-Encoding: 8bit")
            lines.append("")
            lines.append(text)
        else:
            # No body part — keep whatever raw payload exists as plain text
            raw = msg.get_payload(decode=True)
            if isinstance(raw, bytes):
                lines.append("")
                fallback_charset = _safe_charset(msg.get_content_charset())
                lines.append(raw.decode(fallback_charset, errors="replace"))

        return "\n".join(lines)


def _safe_charset(raw: str | None) -> str:
    """Validate an attacker-controlled charset token (PS-EMAIL-005).

    ``get_content_charset()`` reproduces the raw Content-Type parameter
    (quotes stripped).  Anything outside the codec alphabet, unresolvable
    via ``codecs.lookup`` or simply absurd falls back to ``utf-8`` —
    the decode and the synthesized header line then can never explode.
    """
    charset = (raw or "").strip("'\" \t\r\n")
    if not _SAFE_CHARSET_RE.fullmatch(charset):
        return "utf-8"
    try:
        codecs.lookup(charset)
    except (LookupError, ValueError):
        return "utf-8"
    return charset


def _unfold_header(value: str) -> str:
    """Collapse folded headers to a single line so the whitelist output
    stays a valid rfc822 header block (no stray blank lines).

    PS-EMAIL-003: the previous chain removed LF and folded WSP but kept
    bare ``\r`` — enough to inject apparent headers into consumers that
    split lines on CR.  Bare CR now becomes a space (so tokens cannot be
    joined into a forged one), NUL and all other C0/C1 controls are
    removed outright.  Folded WSP is replaced by a single space, so no
    attacker data can reconstruct a CR/LF/WSP sequence.
    """
    unfolded = re.sub(r"\r?\n[ \t]+", " ", str(value))
    unfolded = unfolded.replace("\n", " ").replace("\r", " ")
    return _HEADER_CONTROL_RE.sub("", unfolded).strip()


def _sanitize_html(
    html: str, pixel_max_dim: int, rewrite_links_to_blank: bool
) -> str:
    """Run the sanitizing HTML parser and return the cleaned document."""
    parser = _SanitizingHTMLParser(pixel_max_dim, rewrite_links_to_blank)
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:  # malformed HTML — never crash the hook
        logger.warning("Privacy-Shield email: HTML sanitize failed: %s", exc)
        return "[PRIVACY-SHIELD: HTML-BODY ENTFERNT (parse error)]"
    return parser.result()


__all__ = ["EmailPreprocessor"]