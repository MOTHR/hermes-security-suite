"""Detect credential leaks in text.

ARCH-1 (FIX-2D): ``check`` now accepts the standard ``context``
kwarg so this detector can sit in a :class:`DetectorChain` that
calls ``detector.check(text, context)``. The detector ignores
``context`` — credential shapes are surface-only — but the
signature match is required for chain composition.

GAP-002 (FIX-REDTEAM-GAPS, 2026-08-22): the detector now honours a
per-mode minimum-length knob.  Injection-Shield only ships with
two legacy modes (``audit`` / ``enforcement``) so the legacy
``MIN_CREDENTIAL_LENGTH = 20`` constant was a hard floor that
rejected short-but-real tokens like the redacted ``sk_test_…``
form the Combined Red-Team harness uses.  Five new modes
(``off`` / ``audit`` / ``limited`` / ``strict`` / ``paranoid``)
follow the Privacy-Shield vocabulary from
``privacy_shield.config.ALLOWED_MODES`` so both plugins can be
configured side-by-side without mode mismatch errors.

The mode mapping is intentionally conservative — the existing
``audit`` behaviour (20-char floor) stays the default for
operators who have not opted in to the new modes.  ``strict`` /
``paranoid`` raise the floor to 8 so even short, hand-written
test tokens get flagged.  ``off`` returns no hits at all.
"""

from __future__ import annotations

import re
from typing import Any

from .base import BaseDetector

# Pattern → credential kind.  The minimum-length is supplied per mode
# at __init__ time so the same regex set can be tuned without code change.
#
# Vendor-Pattern-Katalog (GAP-001 / Combined Red-Team 2026-08-22):
#   sk_live_/sk_test_/pk_live_/rk_live_/whsec_  (Stripe-Familie)
#   ghp_/gho_/ghu_/ghs_/ghr_/github_pat_        (GitHub-PAT-Familie)
#   xoxb-/xoxp-/xoxa-/xoxs-/xoxr-               (Slack)
#   npm_                                       (NPM)
#   AKIA…                                      (AWS Access-Key)
#   sk-/sk-lf-                                 (OpenAI / Langfuse)
#   AIza…                                      (Google API)
#   Bearer …                                   (Authorization-Header)
#   -----BEGIN … PRIVATE KEY -----              (PEM / SSH)
_BASE_PATTERNS: list[str] = [
    # OpenAI / Langfuse / generic sk- prefix. Real keys are high-entropy tokens;
    # require a digit inside the token to avoid matching prose like the German
    # word "Empfehlungen" ("sk-Empfehlungen" fired a CRITICAL FP in production).
    # Require a digit AND mixed case inside the token — real keys are
    # high-entropy mixed tokens; structured IDs like "sk-20260728-0042"
    # (all digits) are not. (FP class 2026-09-22: 13 CRITICAL alerts on
    # kanban-export filenames.)
    r"sk-(?=[a-zA-Z0-9]*[0-9])(?=[a-zA-Z0-9]*[a-z])(?=[a-zA-Z0-9]*[A-Z])[a-zA-Z0-9]{%d,}",
    r"sk-lf-[a-zA-Z0-9]{%d,}",
    # Stripe live (geheim) — modern underscore form
    r"sk_live_[a-zA-Z0-9]{%d,}",
    # Stripe live — legacy hyphen form (older Stripe API + redacted examples)
    # Hyphen-allowed because the separator is structural, not part of the secret.
    r"sk-live-[a-zA-Z0-9]{%d,}",
    # Stripe test (oeffentlich, aber sollte trotzdem maskiert werden)
    r"sk_test_[a-zA-Z0-9]{%d,}",
    # Stripe test — legacy hyphen form
    r"sk-test-[a-zA-Z0-9]{%d,}",
    # Stripe public / restricted / webhook-secret
    r"pk_live_[a-zA-Z0-9]{%d,}",
    r"rk_live_[a-zA-Z0-9]{%d,}",
    r"whsec_[a-zA-Z0-9]{%d,}",
    # AWS Access-Key
    r"AKIA[0-9A-Z]{%d}",
    # GitHub PAT (classic + fine-grained) — require a digit (all-letter
    # placeholders like ghp_xxxx in docs must not fire; 2026-09-22 FP).
    r"ghp_(?=[a-zA-Z0-9]*[0-9])[a-zA-Z0-9]{%d,}",
    r"github_pat_(?=[a-zA-Z0-9_]*[0-9])[a-zA-Z0-9_]{%d,}",
    # Slack
    r"xox[bpars]-[a-zA-Z0-9-]{%d,}",
    # NPM
    r"npm_[a-zA-Z0-9]{%d}",
    # Google API
    r"AIza[0-9A-Za-z\-_]{%d}",
    # Authorization-Header (kein hartes Min-Length)
    r"Bearer\s+[a-zA-Z0-9_\-\.]{%d,}",
    # PEM / SSH Private Key (Marker — kein Min-Length)
    r"-----BEGIN\s+(?:RSA\s+PRIVATE|EC\s+PRIVATE|DSA\s+PRIVATE|OPENSSH\s+PRIVATE|PGP\s+PRIVATE|PRIVATE)\s+KEY-----",
]


# Per-mode minimum-length knob.  ``off`` disables detection entirely;
# the order mirrors Privacy-Shield's ALLOWED_MODES so operators can
# move between the two plugins without config-validation errors.
#
# Legacy behaviour (``audit`` mode → 20-char floor) is preserved as the
# default for existing operators who did not opt in to GAP-002.
MIN_CREDENTIAL_LENGTH_BY_MODE: dict[str, int] = {
    "off": 0,        # disabled — detector returns []
    "audit": 20,     # legacy default — Conservative, high-FP-resistance
    "limited": 12,   # balanced (Privacy-Shield default)
    "strict": 8,     # aggressive — flag short test tokens
    "paranoid": 6,   # very aggressive — flag anything that looks structured
    # IS legacy aliases
    "enforcement": 8,  # historic IS mode — equivalent to ``strict``
}

# Default mode for ``CredentialLeakDetector()`` with no args.  Matches
# the previous implicit behaviour: 20-char floor, no Stripe/NPM coverage.
DEFAULT_MODE = "limited"


def _build_patterns(min_length: int) -> list[tuple[re.Pattern[str], str]]:
    """Compile each base pattern with ``min_length`` substituted in.

    Returns ``[(compiled_regex, credential_kind), ...]``.
    """
    compiled: list[tuple[re.Pattern[str], str]] = []
    for pat in _BASE_PATTERNS:
        # Patterns that carry a min-length placeholder use ``%d``;
        # marker patterns (PEM / SSH) have no placeholder.
        if "%d" in pat:
            filled = pat % min_length
        else:
            filled = pat
        # Pick a credential-kind name based on the prefix
        if pat.startswith("sk-lf-"):
            kind = "langfuse_key"
        elif pat.startswith(("sk-live", "sk_live_")):
            kind = "stripe_live_key"
        elif pat.startswith(("sk-test", "sk_test_")):
            kind = "stripe_test_key"
        elif pat.startswith("pk_live_"):
            kind = "stripe_public_key"
        elif pat.startswith("rk_live_"):
            kind = "stripe_restricted_key"
        elif pat.startswith("whsec_"):
            kind = "stripe_webhook_secret"
        elif pat.startswith("AKIA"):
            kind = "aws_access_key"
        elif pat.startswith("ghp_"):
            kind = "github_pat"
        elif pat.startswith("github_pat_"):
            kind = "github_fine_grained_pat"
        elif pat.startswith("xox"):
            kind = "slack_token"
        elif pat.startswith("npm_"):
            kind = "npm_token"
        elif pat.startswith("AIza"):
            kind = "google_api_key"
        elif pat.startswith("Bearer"):
            kind = "bearer_token"
        elif pat.startswith("-----BEGIN"):
            kind = "private_key"
        elif pat.startswith("sk-"):
            kind = "openai_style_key"
        else:
            kind = "credential_leak"
        compiled.append((re.compile(filled), kind))
    return compiled


class CredentialLeakDetector(BaseDetector):
    """Detect credential-shaped strings in LLM/tool output.

    The ``context`` kwarg is accepted for ``BaseDetector`` signature
    compatibility but is not consulted — credential shapes are
    surface-only.

    Parameters
    ----------
    mode:
        One of ``off`` / ``audit`` / ``limited`` / ``strict`` /
        ``paranoid`` / ``enforcement``.  Defaults to ``limited``.
        Unknown modes fall back to ``limited`` and emit no warning
        (silent-fallback to avoid breaking legacy call-sites — the
        IS validator already surfaces mode errors for the plugin
        config).

        ``off`` returns no hits at all (use it to bypass the
        detector without disabling the plugin).  ``paranoid`` /
        ``strict`` lower the min-length floor so short test tokens
        get flagged — closes GAP-002 from the Combined Red-Team
        2026-08-22.
    """

    @property
    def name(self) -> str:
        return "credential_leak"

    def __init__(self, mode: str = DEFAULT_MODE) -> None:
        self.mode = mode if mode in MIN_CREDENTIAL_LENGTH_BY_MODE else DEFAULT_MODE
        min_length = MIN_CREDENTIAL_LENGTH_BY_MODE[self.mode]
        self.min_length = min_length
        if min_length == 0:
            # ``off`` mode — compile a no-op pattern list to avoid
            # surprising callers that touch ``self.regex``.
            self.regex: list[tuple[re.Pattern[str], str]] = []
        else:
            self.regex = _build_patterns(min_length)

    def check(self, text: str, context: dict | None = None) -> list[dict[str, Any]]:
        """Return list of {type, credential_kind, match_prefix, severity}.

        ``context`` is accepted for :class:`BaseDetector` chain
        compatibility and otherwise ignored.

        In ``off`` mode the detector returns ``[]`` immediately so the
        plugin can short-circuit on the caller side without spinning
        the regex engine.
        """
        violations: list[dict[str, Any]] = []
        if not text or self.mode == "off":
            return violations
        for regex, name in self.regex:
            for match in regex.finditer(text):
                snippet = match.group(0)
                violations.append({
                    "type": "credential_leak",
                    "credential_kind": name,
                    "match_prefix": (snippet[:30] + "...") if len(snippet) > 30 else snippet,
                    "severity": "critical",
                })
        return violations
