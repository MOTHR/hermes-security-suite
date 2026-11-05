# Privacy-Shield v1.7.4 — Security Hardening (Audit-Follow-up-Gate)

Closes all MEDIUM/LOW findings from the PR #17 security audit
(Re-Audit t_93e36a99: all 4 clusters not_blocked). PR #21 (perf
fast-path) and PR #18 (public-readiness scrub) are deliberately NOT
part of this release.

## What's in it

Four security PRs merged sequentially onto main after the merge gate
(t_c0254fcc), in order #19 → #22 → #23 → #20 (merge commits
0ebf26e, 636d00c, f4b63e0, e50d6c0):

- **PS-EMAIL-003** (PR #19): Header injection via preserved CR —
  bare CR → space, C0/C1 control characters stripped, header names
  validated as rfc5322 field-name at the trust boundary.
- **PS-EMAIL-005** (PR #19): LookupError crash via attacker-controlled
  charset — `_safe_charset` (regex + `codecs.lookup`), utf-8 fallback,
  decode backstop.
- **PS-EMAIL-006** (PR #19): MIME resource exhaustion — structure
  limits, iterative walk, `max_mime_depth=20` / `max_mime_parts=300`.
- **PS-EMAIL-007** (PR #19): Broken `_drop_depth` — tag stack with
  matching-pop accounting; subtree suppression ends at the correct tag.
- **PS-REST-003 / PS-TOCTOU-008** (PR #22): Symlink races — fd-based
  `ensure_secure_dir` (`O_NOFOLLOW|O_DIRECTORY` + fstat + fchmod,
  `fs_hardening.py`); `render_allowed` fail-closed in the restore path.
- **PS-CHANNEL-007** (PR #23): `cron` removed from
  `_default_restore_channels` — restore into cron now requires an
  explicit operator opt-in.
- **PS-MAPPER-004** (PR #23): `_build_mapper` fails closed when
  enabled + storage_mode=disk + missing `encryption_key`
  (`RuntimeError`); disabled keeps the Phase-4 graceful-disable
  semantics.
- **PS-PIPE-001** (PR #20): Content-first attachment routing
  (`is_supported`) — forged MIME metadata can no longer route an
  attachment on its own; MIME-only claims are fallback only.
- **PS-INPUT-009** (PR #20): Non-string MIME types/paths produce an
  explicit error line instead of AttributeError/TypeError from the
  pre_llm_call hook.

## Verification

- Final combined suite on main: 1044 passed, 6 skipped, 0 failed.
- Main CI green for all four merge commits plus the CHANGELOG commit.
- Deploy copy (plugins symlink) verified against the tagged commit
  via realpath + marker import test.