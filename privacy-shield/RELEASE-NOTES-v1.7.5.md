# Privacy-Shield v1.7.5 — Token-Pattern-Lookbehind-Fix (PS-MASK-006)

Closes the last open MEDIUM/LOW finding from the PR #17 security audit
(PS-MASK-006). After this release, all 11 MEDIUM/LOW findings are closed.

## What's in it

- **PS-MASK-006** (MEDIUM): The negative lookbehind `(?<![A-Za-z0-9])` in
  `_compile_token_pattern` (mapping_table.py) broke token detection when a
  token was immediately preceded by alphanumerics without a delimiter —
  compound strings like `abcTOKEN_PHONE_a1b2c3d4e5_001`. The lookbehind is
  removed: the token prefix (`TOKEN_`/`PS_`) is globally unique in the
  output stream, so prefix + TYPE + hash are sufficient for disambiguation.
- Impact if left unfixed: `_mask_tokens` (output_sanitizer) missed the
  token, the detector rematchted the token hash as hex-PII
  (cookie_id/gps), causing a corrupting re-tokenisation of the output and
  a broken restore.
- Regression tests: pattern level
  (`test_ps_mask_006_token_preceded_by_alphanumerics_no_delimiter`) and
  end-to-end through `_mask_tokens` → `detector.scan` with the
  compound-string payload
  (`test_ps_mask_006_compound_string_token_is_masked_before_detector_scan`).
- CHANGELOG correction: the 1.7.4 heading incorrectly stated "11 closed" —
  1.7.4 closed 10 of the 11 MEDIUM/LOW findings; the eleventh (PS-MASK-006)
  is closed by this v1.7.5 release.

## Verification

- Final combined suite: 1051 passed, 1 skipped, 0 failed
  (env -u PYTHONPATH, hermes-agent venv Python; the system 3.14 Python
  skips 2 additional Hermes-core chain tests — 0 failed in both runs).
- `mypy --strict` clean (mapping_table.py + output_sanitizer.py).
- This PR is NOT merged in this step — merge follows after Re-Audit
  Run-3 over the fix diffs.