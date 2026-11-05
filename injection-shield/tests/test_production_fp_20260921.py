"""Regression tests for the schluesselmacher production false positives (2026-09-21/22).

- 'click here' inside fenced code -> user_action
- German word 'Empfehlungen' after 'sk-' -> credential_leak CRITICAL
- digit-only structured IDs after 'sk-' -> credential_leak CRITICAL
"""

from injection_shield.detectors.credential_leak import CredentialLeakDetector
from injection_shield.detectors.injection_patterns import InjectionPatternDetector

CRON_SNIPPET = (
    '"click here", "learn more", "read more", "see also", "related",\n'
    'r\'^(Click here|Learn more|Read more|See also|Related|Back to top)$\',\n'
    'Siehe `.actions-YYYYMMDD.json` fuer maschinenlesbare Task-Empfehlungen.\n'
)


def test_code_fence_click_here_not_flagged():
    d = InjectionPatternDetector()
    fenced = "```python\nnoise = [\"click here\", \"Click here\"]\n```"
    assert d.check_for_user_actions(fenced) == []


def test_inline_code_click_here_not_flagged():
    d = InjectionPatternDetector()
    assert d.check_for_user_actions("see `click here` heading filter") == []


def test_prose_click_here_still_flagged():
    d = InjectionPatternDetector()
    hits = d.check_for_user_actions("Please click here to confirm your subscription")
    assert any(v["type"] == "user_action" for v in hits)


def test_german_word_after_sk_prefix_not_flagged():
    d = CredentialLeakDetector(mode="limited")
    hits = d.check(CRON_SNIPPET, None)
    assert not [v for v in hits if v["credential_kind"] == "openai_style_key"]


def test_digit_only_sk_id_not_flagged():
    d = CredentialLeakDetector(mode="limited")
    hits = d.check("03-Projects/Job-Task-20260728060111.md exportiert", None)
    assert not [v for v in hits if v["credential_kind"] == "openai_style_key"]


def test_real_openai_key_still_detected():
    d = CredentialLeakDetector(mode="limited")
    hits = d.check("key " + 'sk-4f8A2b7C9d1E3f5A6b8C0d2E4f6A8b0C' + " embedded", None)
    assert any(v["credential_kind"] == "openai_style_key" for v in hits)


def test_key_with_digit_inside_still_detected():
    d = CredentialLeakDetector(mode="limited")
    hits = d.check('sk-abcDef123Ghi456Jkl7890', None)
    assert any(v["credential_kind"] == "openai_style_key" for v in hits)


def test_all_alpha_sk_token_not_flagged():
    d = CredentialLeakDetector(mode="limited")
    hits = d.check("sk-Empfehlungen", None)
    assert not [v for v in hits if v["credential_kind"] == "openai_style_key"]
