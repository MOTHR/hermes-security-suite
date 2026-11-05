# Privacy-Shield v1.7.1 — Three-Source Reasoning Fallback

**Closes the GB-009 re-open found in live operation on 2026-09-21.**

## What happened

v1.7.0's pre-intake redaction succeeded on `reasoning` (dataclass field)
but failed on `reasoning_content`: `NormalizedResponse` implements it as a
**read-only property** backed by the `provider_data` dict
(`agent/transports/types.py:80`). The `setattr` failed open, the token was
discarded, and unredacted reasoning landed in `state.db` — 10 warnings in
one production gateway log (`reasoning setattr(reasoning_content) failed`).

## What v1.7.1 changes

A single `_set_reasoning_field` helper with a **three-source fallback chain**:

1. `setattr` — plain dataclass fields (`reasoning`)
2. `provider_data` dict — mutated in place (the property reads from exactly
   this dict, so the core's `build_assistant_message` sees the redacted value
   and `state.db` only ever stores tokenized text). A `None` `provider_data`
   is initialised to `{}` first.
3. `model_extra` — SDK variants that stash `reasoning_content` only there
   (previously a documented gap: `count == 0`).

## Observability

- New audit event `reasoning_redaction_fallback` whenever a non-setattr source
  performed the redaction (field, method, outcome — no plaintext PII).
- New audit event `reasoning_redaction_bypass` when a field could not be
  redacted at all — the fail-open path is no longer silent.

## Documented trade-off

`codex_reasoning_items` remains in `skip_fields` (signed provider-native
blocks; textual tokenization would invalidate signatures). Plaintext PII in
those items is NOT auto-tokenized. Planned mitigation in v1.7.2: leaf-text
tokenization of text/content subfields or an audit event on non-empty items.
See `docs/reasoning-protection.md`.

## Residual architecture limitation (unchanged, must read)

**The provider sees the reasoning before Privacy-Shield does.** With cloud
reasoning models, reasoning content is transmitted in plaintext and may appear
in provider logs/telemetry. Outside the plugin's control. Mitigation: disable
reasoning for sensitive data or run a local model; review provider DPA/BAA.

## Validation

- 8 new tests (provider_data fallback, None-init, model_extra source,
  Anthropic-style details, tuple skip, no-regression, audit events, codex untouched)
- Full suite: **926 passed, 3 skipped**
- GB-009 chain tests (`build_assistant_message` → persist row) green

## Breaking Changes

None — backward-compatible with v1.6.x/1.7.0 config. New audit events only.

## Credits

Three-reviewer security process: Orakel (architecture), Agent-Smith
(adversarial, PoCs), Seraph (persistence chain + 14-profile sweep).