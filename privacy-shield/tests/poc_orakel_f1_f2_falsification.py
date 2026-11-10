#!/usr/bin/env python3
"""Falsifikations-PoC zu orakel t_c0a50b6f F-1/F-2 gegen den FIX (post-review wave).

Kette laut Review:
 1. pre_llm_call stuft EINMAL pro Turn ein (Slot mit raw_prompt + sanitized).
 2. llm_request-Middleware feuert PRO API-Attempt; Core re-built die Payload
    aus den rohen Messages, Sidecar (raw + "\\n\\n" + Kontext) ist immer drin.
 3. FIX: Slot bleibt erhalten (read-only), Rewrite nur am Live-Prompt-Anteil.

Erwartung (FIX): attempt 2 maskiert UNMITTELBAR; Kontext-Suffix bleibt.
Fail (old bug): attempt 2 unmaskiert.
"""
import sys

sys.path.insert(0, "/Users/minimetro/.hermes/profiles/operator/workspace/hermes-security-suite/privacy-shield")

from privacy_shield.plugin import PrivacyShieldPlugin  # noqa: E402

PII = "hans.mueller@example.de"
FIREWALL_SUFFIX = "\n\n=== INJECTION-SHIELD FIREWALL CONTEXT ==="
RAW = f"Auf Deutsch bitte: 'Meine E-Mail lautet {PII}'"
WIRE = RAW + FIREWALL_SUFFIX

# Konstruktion wie im echten Turn: pre_llm_call stage't einmal.
p = PrivacyShieldPlugin.__new__(PrivacyShieldPlugin)  # __init__ umgehen (keine Side-Effects)
from privacy_shield.config import PrivacyShieldConfig  # noqa: E402
cfg = PrivacyShieldConfig(storage_mode="memory", encryption_key="k" * 32, enabled=True, mode="limited")
p.config = cfg
p.mapper = p._build_mapper()
p.detector = p.detector_chain = None
from privacy_shield.detectors.regex_detector import RegexPIIDetector  # noqa: E402
from privacy_shield.pseudonymizer import Pseudonymizer  # noqa: E402

p.detector = RegexPIIDetector(code_context_penalty=0.0)
p.pseudonymizer = Pseudonymizer(token_style=cfg.token_style, token_prefix=cfg.token_prefix)
p.audit = None
# R-1 Option b (t_37828862): seit dem History-Masking-Fix scannt der
# Default (mask_sidecar_suffix=True) die Bytes hinter dem Live-Prompt —
# der byte-exakte F-2-Kontrakt gilt jetzt mit dem Flag OFF (Suffix-Maskierung
# regressionsgetestet in tests/test_history_masking.py).
cfg.mask_sidecar_suffix = False


def make_result(prompt):
    """Simuliere _shield_prompt-Detection+Staging ohne Audit/Logger-Side-Effects."""
    import privacy_shield.plugin as pp

    hits = p.detector.scan(prompt)
    masked, _dropped = p._partition_by_confidence(hits)
    sanitized, mapping = p.pseudonymizer.replace(prompt, masked, session_id="sess1")
    p._stage_shield(
        turn_id="T1",
        payload={
            "sanitized": sanitized,
            "raw_prompt": prompt,
            "orig_len": len(prompt),
            "masked_count": len(mapping),
            "pii_types": [m.get("type", "unknown") for m in mapping],
            "session_id": "sess1",
            "model": "gpt-x",
            "platform": "telegram",
        },
    )
    return sanitized


make_result(RAW)  # pre_llm_call staging (einmal pro Turn)


def attempt(n: int) -> dict:
    # Core re-buildet pro Attempt: Wire-Content ist IMMER raw + Sidecar-Suffix.
    req = {"messages": [{"role": "user", "content": WIRE}]}
    result = p.apply_shield_to_request(
        req, provider="openai", session_id="sess1", model="gpt-x",
        platform="telegram", turn_id="T1",
    )
    wire = req["messages"][0]["content"]
    print(f"attempt {n}: middleware_return={'applied' if result else 'NONE'}")
    print(f"  wire_content_masked={PII not in wire}")
    print(f"  firewall_context_on_wire={FIREWALL_SUFFIX in wire}")
    return req


a1 = attempt(1)
a2 = attempt(2)  # zweiter API-Attempt im selben Turn (Tool-Loop/Retry)
a3 = attempt(3)

print("\n--- Verdict ---")
leak = any(PII in r["messages"][0]["content"] for r in (a1, a2, a3))
ctx_kept = all(FIREWALL_SUFFIX in r["messages"][0]["content"] for r in (a1, a2, a3))
masked_all = all(PII not in r["messages"][0]["content"] for r in (a1, a2, a3))
print(f"F-1 FIX: alle Attempts maskiert = {masked_all} (Leak irgendwo: {leak})")
print(f"F-2 FIX: Kontext auf jedem Wire = {ctx_kept}")
print(f"POC_RESULT={'FIXED' if masked_all and ctx_kept else 'STILL_BROKEN'}")
print(f"wire attempt-2: {a2['messages'][0]['content'][:80]!r}...")
