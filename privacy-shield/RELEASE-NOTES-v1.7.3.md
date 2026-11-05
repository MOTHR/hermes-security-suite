# Privacy-Shield v1.7.3 — Email attachment preprocessor + offset-drift fix (t_025240da)

Closes the offset-drift root cause behind fresh-minted, unrestorable
`TOKEN_*` strings and adds `.eml` attachment sanitization (P1).

## What happened (t_025240da)

1. **Overmasking via threshold change was reverted.** An earlier experiment
   lowered `confidence_threshold` 0.8 → 0.65 so name detections
   (confidence 0.7) pass the masking threshold. Follow-up: the agent's own
   system terminology (profile/agent names) got masked in Telegram replies,
   and the output sanitizer minted fresh, unrestorable tokens — restore
   misses fleet-wide. **Decision: 0.8 remains the default**; the original
   problem (person names in emails, e.g. LinkedIn notifications) is solved
   via the whitelist and the email preprocessor, not via the global
   threshold.

2. **Offset drift.** `normalize_text` is not length-preserving: HTML entity
   unescaping, percent-decoding, whitespace collapse and the
   `[at]`/`[dot]` obfuscation rewrites all shrink the string. Matches found
   in normalized space therefore carry offsets that are wrong for the RAW
   prompt the pseudonymizer mutates.

3. **Email attachments reached the model unsanitized** (`.eml`): tracking
   pixels, click-tracker links and sensitive mail headers
   (`X-Originating-IP`, `X-Mailer`, `Received` chains) — the same threat
   class the PDF/image preprocessor already covered.

## What v1.7.3 changes

- **Added `preprocessors/email.py`** (P1): `.eml` header/HTML sanitizer with
  the same unified attachment loop as PDF and image.
  - T1: tracking pixels (`<img>` up to `email_pixel_max_dim`, default 2) are
    removed from the HTML body.
  - T2: tracker hrefs rewritten to `about:blank`
    (`email_rewrite_links_to_blank`, default true) instead of dropping the
    anchor element.
  - T3: sensitive headers (`X-Originating-IP`, `X-Mailer`, `Received`-IPs)
    stripped; sanitized artifact is written to `email_restore_dir`
    (default `~/.hermes/privacy/restore/email`) for later inspection.
  - Settings: `email_enabled` (default true), `email_max_size_mb` (default 10).
  - Failed extraction drops the attachment (logged with `eml_summary`,
    no PII).
- **Span-tracking normalization (`normalize_text_with_map`)**: reproduces
  `normalize_text` exactly while carrying, for every output character, the
  `(orig_start, orig_end)` span it was produced from — match offsets are
  re-anchored to the raw text before replacement. Validated by an internal
  `_assert_map_matches` invariant.
- **OCR email repair** (`_repair_ocr_email`) in the image preprocessor.
- **Name-detector FP guards:** new German stop words (Bestätige,
  Bestätigung, Empfang, Erhalt, Kontakt, Telefon, Telefonnummer, Mobil,
  Nutzer, Benutzer, Kunde, Kunden) so boilerplate around phone numbers and
  customer references is not detected as person names.
- **`confidence_threshold` stays 0.8** — documented in `config.py`; the
  related out-of-tree test edit was dropped.

## Tests

Full suite: **973 passed, 1 skipped** (was 972 passed before this change
set; span-tracking and email-paths covered by the detector/preprocessor
suites).

## Upgrade notes

No migration required. New settings default to sensible values; deployments
that overrode `confidence_threshold` keep their override. Sessions and
token formats are unchanged.