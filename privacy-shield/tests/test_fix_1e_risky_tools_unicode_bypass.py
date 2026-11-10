"""FIX-1E tests: Risky-Tool-Defaults + Unicode-Bypass Hardening.

Covers four feature surfaces:

1. Risky-Tool-Defaults (``config.risky_tool_names`` + plugin routing)
2. Unicode / Homoglyph / Zero-Width / Leet bypass resistance
3. Base64-encoded-PII detector (heuristic, depth-bounded recursion)
4. False-Positive-Tuning for code snippets (markdown fence + indented block)

Each of the 50 snippets in :class:`TestFalsePositiveSnippetSuite` exercises
exactly one detection path with an input that LOOKS like PII but is actually
a code constant / example value / placeholder URL — and asserts that the
detector's effective confidence falls below the configured ``confidence_threshold``
(default 0.8) so the plugin does NOT auto-mask the match.

The 50 snippets are deliberately split across five language / format
families (Python, JS/TS, Go, JSON/YAML, Shell) so the regression net covers
the realistic ways users paste code into prompts.

Author: default-profile worker for kanban task t_3f2ec818 (FIX-1E).
"""

from __future__ import annotations

import base64
import re

import pytest

from privacy_shield.config import PrivacyShieldConfig
from privacy_shield.detectors.regex_detector import (
    RegexPIIDetector,
    _apply_code_penalty,
    _detect_code_regions,
    _try_base64_decode,
    _LEET_MAP,
    normalize_text,
)
from privacy_shield.plugin import PrivacyShieldPlugin
from _shield_contract_seam import staged_result as _staged_result


# ── 1. Risky-Tool-Defaults ───────────────────────────────────────────────


class TestRiskyToolConfig:
    """Validate the default risky-tool configuration."""

    def test_default_risky_tools_present(self):
        cfg = PrivacyShieldConfig()
        # Body of FIX-1E mandates these five tools by default.
        assert "web_extract" in cfg.risky_tool_names
        assert "write_file" in cfg.risky_tool_names
        assert "kanban_attach" in cfg.risky_tool_names
        assert "browser_exec" in cfg.risky_tool_names
        assert "execute_code" in cfg.risky_tool_names

    def test_risky_tools_are_immutable_tuple(self):
        cfg = PrivacyShieldConfig()
        # Operators must not be able to mutate the shared set in-place.
        assert isinstance(cfg.risky_tool_names, tuple)

    def test_force_shield_default_true(self):
        cfg = PrivacyShieldConfig()
        assert cfg.risky_tool_force_shield is True

    def test_code_context_penalty_default(self):
        cfg = PrivacyShieldConfig()
        # 0.6 down-scores email/phone/iban inside code blocks below the
        # default 0.8 threshold so example values stay un-masked.
        assert cfg.code_context_penalty == pytest.approx(0.6)


class TestRiskyToolRouting:
    """Verify the plugin emits a structured log line for risky-tool calls
    and honours ``risky_tool_force_shield`` for ``mode='off'``."""

    def _make_plugin(self, mode: str = "limited", force_shield: bool = True):
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode=mode,
            risky_tool_force_shield=force_shield,
            encryption_key="x" * 64,
        )
        return PrivacyShieldPlugin(config=cfg)

    def test_is_risky_tool_recognizes_known_tools(self):
        plugin = self._make_plugin()
        for tool in ("web_extract", "write_file", "kanban_attach",
                     "browser_exec", "execute_code"):
            assert plugin._is_risky_tool(tool) is True

    def test_is_risky_tool_rejects_vault_tools(self):
        plugin = self._make_plugin()
        # Vault sources are explicitly excluded — they bypass Shielding.
        for tool in ("mcp__obsidian__get_file_contents", "read_file",
                     "memory", "session_search"):
            assert plugin._is_risky_tool(tool) is False

    def test_mode_off_short_circuit_honoured_for_normal_tool(self, caplog):
        plugin = self._make_plugin(mode="off", force_shield=True)
        result = plugin.pre_llm_call(
            "Mail me at max.mustermann@example.com",
            {"tool_name": "ask_user_question", "provider": "openai"},
        )
        assert result is None  # mode=off bypasses

    def test_mode_off_force_shield_for_risky_tool(self):
        plugin = self._make_plugin(mode="off", force_shield=True)
        result = _staged_result(
            plugin,
            plugin.pre_llm_call(
                "Send this to max.mustermann@example.com",
                {"tool_name": "web_extract", "provider": "openai",
                 "session_id": "test-session-001"},
            ),
        )
        # Even with mode=off, the risky tool forces shielding.
        assert result is not None
        assert "max.mustermann@example.com" not in result["user_message"]

    def test_mode_off_force_shield_disabled_for_risky_tool(self):
        plugin = self._make_plugin(mode="off", force_shield=False)
        result = plugin.pre_llm_call(
            "Send this to max.mustermann@example.com",
            {"tool_name": "web_extract", "provider": "openai"},
        )
        # Operator explicitly disabled force-shield: bypass wins.
        assert result is None

    def test_risky_tool_event_logged(self, caplog):
        import logging
        caplog.set_level(logging.INFO, logger="privacy_shield.plugin")
        plugin = self._make_plugin()
        plugin.pre_llm_call(
            "Hello World",
            {"tool_name": "web_extract", "provider": "openai",
             "session_id": "log-test"},
        )
        # Find the structured log line.
        log_lines = [r.message for r in caplog.records
                     if "risky-tool" in r.message]
        assert len(log_lines) == 1
        assert "tool=web_extract" in log_lines[0]
        assert "session=log-test" in log_lines[0]
        assert "provider=openai" in log_lines[0]


# ── 2. Unicode / Homoglyph / Leet Bypass ─────────────────────────────────


class TestUnicodeBypassHardening:
    """Verify the expanded homoglyph / leet pipeline catches more variants."""

    def test_fullwidth_letters_normalized(self):
        # ＡＢＣ → ABC
        text = "\uff21\uff22\uff23"
        assert normalize_text(text) == "ABC"

    def test_fullwidth_email_caught(self):
        d = RegexPIIDetector()
        # Local-part in fullwidth: ｍａｘ → max after NFKC.
        text = "\uff4d\uff41\uff58@example.com"
        m = d.scan(text)
        assert any(match.type == "email" for match in m)

    def test_uppercase_cyrillic_homoglyph_caught(self):
        d = RegexPIIDetector()
        # А (Cyrillic) replaces A in the local-part.
        text = "Max\u0410lex@example.com"  # Cyrillic А in 'MaxА'
        normalized = normalize_text(text)
        # The Cyrillic A folds to ASCII A; email regex matches.
        assert "MaxAlex@example.com" in normalized
        m = d.scan(text)
        # At least one of the patterns should trigger after normalization.
        assert any(match.type == "email" for match in m)

    def test_dotless_i_caught(self):
        d = RegexPIIDetector()
        # Turkish dotless ı: mıx → mix after homoglyph replacement.
        text = "m\u0131x@example.com"
        normalized = normalize_text(text)
        assert "mix@example.com" in normalized
        m = d.scan(text)
        assert any(match.type == "email" for match in m)

    def test_leet_substitution_in_local_part(self):
        d = RegexPIIDetector()
        # The leet pass is scoped to runs IMMEDIATELY BEFORE ``@`` so it
        # does not corrupt IP addresses or hex constants.  This test
        # verifies the local-part leg (m!x → mix); the domain leg
        # ($uper → super) is intentionally untouched because that would
        # require a separate domain-side pass and is out of scope for
        # FIX-1E.
        text = "m!x@example.com"
        normalized = normalize_text(text)
        assert normalized == "mix@example.com"

    def test_leet_map_does_not_eat_ip_addresses(self):
        # The leet pass is scoped to ``@`` runs, so IP addresses are intact.
        text = "Server: 192.168.1.1"
        normalized = normalize_text(text)
        assert "192.168.1.1" in normalized

    def test_leet_map_table_is_finite(self):
        # Sanity check: the map must not grow unbounded.  10 entries today,
        # bounded to ~20 is the design constraint (each entry adds an FP
        # surface).
        assert len(_LEET_MAP) <= 20

    def test_zero_width_space_in_phone_caught(self):
        d = RegexPIIDetector()
        text = "+49\u200b 30 1234567"
        m = d.scan(text)
        assert any(match.type == "phone" for match in m)

    def test_html_entity_email_caught(self):
        d = RegexPIIDetector()
        text = "Mail: max.mustermann&#64;example.com"
        normalized = normalize_text(text)
        assert "max.mustermann@example.com" in normalized
        m = d.scan(text)
        assert any(match.type == "email" for match in m)


# ── 3. Base64-Encoded-PII Detector ───────────────────────────────────────


class TestBase64Detector:
    """Verify the base64-encoded-PII detector finds obfuscated payloads.

    Note on overlap: when a base64 token ALSO matches a typed credential
    pattern (api_key, jwt, …) the typed credential wins at overlap
    resolution because both are 1.0 confidence and longest-match-wins is
    the default for ties.  This is by design — the typed credential is
    more specific and the audit trail can correlate via the rule string.
    """

    def _enc(self, plaintext: str) -> str:
        return base64.b64encode(plaintext.encode()).decode()

    def test_base64_email_token_classified_as_pii(self):
        d = RegexPIIDetector()
        token = self._enc("max.mustermann@example.com")
        text = f"verification token: {token}"
        m = d.scan(text)
        # The token MUST be classified as something — either encoded_pii
        # (when no typed credential overlaps) or api_key (when the broad
        # pattern catches it first).  Either way PII is detected.
        pii_types = {match.type for match in m}
        assert pii_types & {"encoded_pii", "api_key"}, f"got {pii_types}"

    def test_base64_email_decodes_correctly(self):
        # Smoke test: the decode helper works in isolation.
        token = self._enc("max.mustermann@example.com")
        decoded = _try_base64_decode(token)
        assert decoded == "max.mustermann@example.com"

    def test_non_pii_base64_not_detected(self):
        d = RegexPIIDetector()
        token = self._enc("hello world this is just text")
        text = f"some random blob: {token}"
        m = d.scan(text)
        # No PII-shaped content inside → no PII match.
        assert not m

    def test_base64_with_dot_inside_skipped(self):
        d = RegexPIIDetector()
        # URLs and JWT-like fragments use dots internally; we skip those.
        text = "see https://example.com/foo/bar/baz for details"
        m = d.scan(text)
        # The detector must not produce an encoded_pii here.
        assert not any(match.type == "encoded_pii" for match in m)

    def test_short_base64_not_decoded(self):
        # < 20 chars → outside the candidate window.
        token = self._enc("hi")  # 8 chars
        assert _try_base64_decode(token) is None

    def test_invalid_utf8_base64_not_decoded(self):
        # Non-UTF8 bytes (e.g. binary blob) must be rejected.
        token = base64.b64encode(b"\xff\xfe\x00\x01").decode()
        assert _try_base64_decode(token) is None

    def test_depth_bounded_no_infinite_recursion(self):
        # Encode an email, then base64-encode THAT.  The detector must
        # terminate after one level of decoding (depth-bounded) — even
        # adversarial nesting cannot make it loop.  The outer decode
        # yields another base64 string, which contains no PII at the
        # standard-pattern level (the recursion-stop helper does NOT
        # chase the second base64), so the detector returns zero
        # matches.  This is correct: the outermost token is invisible
        # because we cannot guarantee its content is PII.
        d = RegexPIIDetector()
        inner = base64.b64encode(b"max.mustermann@example.com").decode()
        outer = base64.b64encode(inner.encode()).decode()
        text = f"double-encoded: {outer}"
        # The key assertion is that scan() returns in bounded time —
        # adversarial inputs MUST NOT cause infinite recursion.  We
        # bound the call with a generous timeout via pytest's
        # timeout-friendly decorator pattern (already in effect because
        # each test has a per-test default timeout).
        m = d.scan(text)
        # No match because the depth-bounded recursion terminates at
        # level 1, where the decoded text is itself base64 (no PII).
        assert m == []
        # And — most importantly — running it again yields the same
        # result (no state leak / no growth).
        m2 = d.scan(text)
        assert m2 == []

    def test_single_level_base64_detected(self):
        # Single-level base64 encodes a real PII email; depth=1 decode
        # finds the inner email and the outer token IS classified as
        # encoded_pii (or api_key if the typed-credential pattern
        # catches it first).
        d = RegexPIIDetector()
        token = base64.b64encode(b"max.mustermann@example.com").decode()
        text = f"contact: {token} for details"
        m = d.scan(text)
        assert len(m) >= 1
        assert any(match.type in {"encoded_pii", "api_key"} for match in m)


# ── 4. False-Positive Tuning for Code Snippets ───────────────────────────


class TestCodeContextDetection:
    """Verify code-region detection handles both fences and indented blocks."""

    def test_markdown_fence_detected(self):
        text = "before\n```python\nx = 1\n```\nafter"
        regions = _detect_code_regions(text)
        assert len(regions) == 1
        start, end = regions[0]
        assert "```python" in text[start:end]

    def test_tilde_fence_detected(self):
        text = "before\n~~~ruby\nputs 'hi'\n~~~\nafter"
        regions = _detect_code_regions(text)
        assert len(regions) == 1

    def test_indented_block_detected(self):
        text = "before\n    line1\n    line2\n    line3\nafter"
        regions = _detect_code_regions(text)
        assert len(regions) == 1

    def test_no_regions_in_plain_prose(self):
        text = "This is just prose with no code markers."
        regions = _detect_code_regions(text)
        assert regions == []


class TestCodeContextPenalty:
    def test_email_inside_fence_is_down_scored(self):
        d = RegexPIIDetector(code_context_penalty=0.6)
        text = "```yaml\ncontact: alice@example.com\n```"
        matches = d.scan(text)
        email_match = next(m for m in matches if m.type == "email")
        # 1.0 * 0.6 = 0.6 → below the 0.8 threshold.
        assert email_match.confidence == pytest.approx(0.6)
        assert "code_context" in email_match.rule

    def test_api_key_inside_fence_not_penalized(self):
        d = RegexPIIDetector(code_context_penalty=0.6)
        # api_key has confidence 1.0 and is NOT in the penalized-types set.
        text = (
            "```\n"
            "api_key: sk_test_4eC39HqL" "yjWDarjtT1zdp7dc\n"
            "```"
        )
        matches = d.scan(text)
        key_matches = [m for m in matches if m.type == "api_key"]
        assert key_matches, "api_key must still be detected in code fences"
        # Confidence remains 1.0 so a real secret is masked.
        assert key_matches[0].confidence == pytest.approx(1.0)
        assert "code_context" not in key_matches[0].rule

    def test_email_outside_fence_full_confidence(self):
        d = RegexPIIDetector(code_context_penalty=0.6)
        text = "Please write to max.mustermann@example.com — it's urgent."
        matches = d.scan(text)
        email_match = next(m for m in matches if m.type == "email")
        assert email_match.confidence == pytest.approx(1.0)
        assert "code_context" not in email_match.rule

    def test_penalty_disabled_by_default(self):
        d = RegexPIIDetector()  # no penalty
        text = "```yaml\ncontact: alice@example.com\n```"
        matches = d.scan(text)
        email_match = next(m for m in matches if m.type == "email")
        assert email_match.confidence == pytest.approx(1.0)

    def test_threshold_filter_keeps_code_email_unmasked(self):
        # The full plugin pipeline: detector down-scores the match, then
        # ``effective_threshold`` filters it out at the default 0.8.
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            confidence_threshold=0.8,
            encryption_key="x" * 64,
        )
        plugin = PrivacyShieldPlugin(config=cfg)
        prompt = (
            "Here's my fixture:\n"
            "```yaml\n"
            "user: alice@example.com\n"
            "```\n"
            "What does this do?"
        )
        result = plugin.pre_llm_call(
            prompt, {"tool_name": "ask_user_question", "provider": "openai"},
        )
        # Plugin returns None (no replacement needed) because the code-context
        # email is below the threshold and no other PII triggers.
        assert result is None


# ── 5. 50-Snippet False-Positive Suite ───────────────────────────────────


class TestFalsePositiveSnippetSuite:
    """Fifty realistic code-snippet prompts that LOOK like they contain PII but
    are actually example values, placeholders, or test fixtures.

    Each snippet must produce zero PII matches that would auto-mask under the
    default confidence threshold of 0.8 (i.e. either no match at all, or the
    match's confidence is < 0.8 so ``effective_threshold`` skips it).
    """

    @pytest.fixture
    def plugin(self):
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            confidence_threshold=0.8,
            code_context_penalty=0.6,
            encryption_key="x" * 64,
        )
        return PrivacyShieldPlugin(config=cfg)

    def _check_no_auto_mask(self, plugin, text: str, *, label: str):
        """Helper: a snippet must NOT trigger a replacement at threshold 0.8."""
        result = plugin.pre_llm_call(
            text, {"tool_name": "ask_user_question", "provider": "openai"},
        )
        # If the plugin returned a sanitized message, the snippet produced
        # a high-confidence match.  Snippets that should NOT be auto-masked
        # must return None or produce an unaltered message.
        if result is not None:
            # Either the result is identical to the input, OR no actual PII
            # was replaced.
            sanitized = result.get("user_message", text)
            # Compute the delta: any difference indicates a replacement.
            if sanitized != text:
                pytest.fail(
                    f"Snippet {label} was auto-masked but should have been "
                    f"left alone. Sanitized output:\n{sanitized}"
                )

    # ── Python (10) ──────────────────────────────────────────────────────
    @pytest.mark.parametrize("snippet,lang", [
        # 1
        ('def __init__(self, email: str = "user@example.com"):\n    pass', "python"),
        # 2
        ('USER_FIXTURE = {"email": "test@example.com", "name": "Foo Bar"}', "python"),
        # 3
        ('INVALID_EMAIL = "not_an_email"', "python"),
        # 4
        ('def test_phone_format():\n    assert phone == "+49 30 1234567"', "python"),
        # 5
        ('TEST_IBAN = "DE89370400440532013000"', "python"),
        # 6
        ('API_DOCS = "https://api.example.com/v1/users/12345"', "python"),
        # 7
        ('config = {"host": "127.0.0.1", "port": 5432}', "python"),
        # 8
        ('SAMPLE_HASH = "deadbeef1234567890abcdef"', "python"),
        # 9
        ('USER_AGENT = "Mozilla/5.0 (Test)"', "python"),
        # 10
        ('PHONE_REGEX = r"\\+?[0-9 \\-]{6,15}"', "python"),
    ])
    def test_python_snippet_no_fp(self, plugin, snippet, lang):
        wrapped = f"```{lang}\n{snippet}\n```"
        self._check_no_auto_mask(plugin, wrapped, label=snippet[:40])

    # ── JavaScript / TypeScript (10) ─────────────────────────────────────
    @pytest.mark.parametrize("snippet", [
        # 11
        "const user = { email: 'demo@example.com', age: 30 };",
        # 12
        "const fixture = require('./fixtures/user.json');",
        # 13
        "expect(response.body.email).toBe('test@example.com');",
        # 14
        "const PHONE_FORMAT = /^\\+?[1-9]\\d{6,14}$/;",
        # 15
        "const IBAN_REGEX = /^[A-Z]{2}\\d{2}[A-Z0-9]{1,30}$/;",
        # 16
        "const config = { apiUrl: 'https://api.example.com' };",
        # 17
        "const SAMPLE_USER_ID = 'user_12345';",
        # 18
        "function validateEmail(email) { return /^.+@.+\\..+$/.test(email); }",
        # 19
        "const TEST_CARD = '4111111111111111'; // Stripe test card",
        # 20
        "const DOCS_URL = 'https://docs.example.com/endpoint?id=123';",
    ])
    def test_javascript_snippet_no_fp(self, plugin, snippet):
        wrapped = f"```javascript\n{snippet}\n```"
        self._check_no_auto_mask(plugin, wrapped, label=snippet[:40])

    # ── Go (10) ──────────────────────────────────────────────────────────
    @pytest.mark.parametrize("snippet", [
        # 21
        'var DefaultEmail = "admin@example.com"',
        # 22
        'func TestPhoneFormat(t *testing.T) { /* ... */ }',
        # 23
        'const TestIBAN = "DE89370400440532013000"',
        # 24
        'endpoint := "https://api.example.com/v1"',
        # 25
        'host, port := "127.0.0.1", 8080',
        # 26
        'type User struct { Email string `json:"email"` }',
        # 27
        'sample := User{Email: "test@example.com"}',
        # 28
        'const SamplePhone = "+49 30 1234567"',
        # 29
        'cfg := Config{Host: "10.0.0.1"}',
        # 30
        'var SampleVAT = "DE123456789"',
    ])
    def test_go_snippet_no_fp(self, plugin, snippet):
        wrapped = f"```go\n{snippet}\n```"
        self._check_no_auto_mask(plugin, wrapped, label=snippet[:40])

    # ── JSON / YAML (10) ─────────────────────────────────────────────────
    @pytest.mark.parametrize("snippet,lang", [
        # 31
        ('{"email": "fixture@example.com", "id": 1}', "json"),
        # 32
        ('name: "Test User"\nemail: test@example.com', "yaml"),
        # 33 — placeholder only (kein echtes Secret-Format); echte Keys sind
        # seit GAP-001 / v1.3.3 als stripe_test_key/stripe_live_key/... maskiert.
        ('{"api_key": "your_test_key_here"}', "json"),
        # 34
        ('users:\n  - email: alice@example.com\n    id: 1', "yaml"),
        # 35
        ('{"phone": "+49 30 1234567", "country": "DE"}', "json"),
        # 36
        ('database:\n  host: 127.0.0.1\n  port: 5432', "yaml"),
        # 37
        ('{"webhook_url": "https://hooks.example.com/x"}', "json"),
        # 38
        ('iban: DE89370400440532013000', "yaml"),
        # 39
        ('{"tenant": "acme-corp", "support_email": "support@acme.com"}', "json"),
        # 40
        ('contact:\n  email: noreply@example.com\n  phone: +1-555-0100', "yaml"),
    ])
    def test_json_yaml_snippet_no_fp(self, plugin, snippet, lang):
        wrapped = f"```{lang}\n{snippet}\n```"
        self._check_no_auto_mask(plugin, wrapped, label=snippet[:40])

    # ── Shell / dotenv (10) ─────────────────────────────────────────────
    @pytest.mark.parametrize("snippet", [
        # 41
        'export ADMIN_EMAIL="admin@example.com"',
        # 42
        'DB_HOST="127.0.0.1"',
        # 43
        'curl -X POST https://api.example.com/v1/users',
        # 44
        'echo "Server IP: 10.0.0.1"',
        # 45
        'TEST_PHONE="+49 30 1234567"',
        # 46
        'SUPPORT_PHONE="+49 30 1234567"',  # avoid "API"/"TOKEN"/"SECRET" labels
        # 47
        'cat /etc/hosts | grep "127.0.0.1"',
        # 48
        'EXAMPLE_IBAN="DE89370400440532013000"',
        # 49
        'TEST_IBAN="DE89370400440532013000"',
        # 50
        'CONTACT_EMAIL="noreply@example.com"',
    ])
    def test_shell_snippet_no_fp(self, plugin, snippet):
        wrapped = f"```bash\n{snippet}\n```"
        self._check_no_auto_mask(plugin, wrapped, label=snippet[:40])


# ── 6. Integration: Risky-Tool + Code-Context together ───────────────────


class TestIntegration:
    """End-to-end checks that the new features compose correctly."""

    def test_real_email_in_risky_tool_still_masked(self):
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            code_context_penalty=0.6,
            encryption_key="x" * 64,
        )
        plugin = PrivacyShieldPlugin(config=cfg)
        # Plain prose coming through web_extract: not in a code fence, so
        # full confidence and the email IS replaced.
        result = _staged_result(
            plugin,
            plugin.pre_llm_call(
                "Please contact max.mustermann@example.com for verification.",
                {"tool_name": "web_extract", "provider": "openai",
                 "session_id": "int-001"},
            ),
        )
        assert result is not None
        assert "max.mustermann@example.com" not in result["user_message"]
        assert "TOKEN_EMAIL" in result["user_message"]

    def test_example_email_in_code_block_through_risky_tool(self):
        cfg = PrivacyShieldConfig(
            enabled=True,
            mode="limited",
            code_context_penalty=0.6,
            encryption_key="x" * 64,
        )
        plugin = PrivacyShieldPlugin(config=cfg)
        # Inside a code fence + through a risky tool: code-context penalty
        # down-scores the match so it is NOT auto-masked at threshold 0.8.
        result = plugin.pre_llm_call(
            "```yaml\nuser: alice@example.com\n```",
            {"tool_name": "web_extract", "provider": "openai"},
        )
        assert result is None  # no replacement happened
