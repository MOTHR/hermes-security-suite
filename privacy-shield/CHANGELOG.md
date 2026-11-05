## [Unreleased]

### Performance — Regex-Detector Fast-Path für Identity-Normalisierung (PR #21)

- `detectors/regex_detector.py`: Identity-Mapping-Schnellpfad — Text ohne
  Zeichen-Transformationen (`normalize_text_with_map` liefert `spans=None`)
  umgeht die Span-Tracking-Normalisierung; Overlap-Clamping-Semantik bleibt
  erhalten, Offsets werden nicht verschoben.
- Unabhängiges Review (Seraph, R6-seraph-perf-fastpath.md): Verdict APPROVE,
  4 Findings (LOW/MEDIUM/INFO, keine Blocker) — Follow-ups: direkte Tests für
  `normalize_text_with_map`/`reanchor_match_offsets` (F2, MEDIUM).

## [1.7.5] - 2026-10-25

### Fix — Token-Pattern-Lookbehind entfernt (PS-MASK-006, MEDIUM)

- **PS-MASK-006** (MEDIUM): Der negative Lookbehind `(?<![A-Za-z0-9])` in
  `_compile_token_pattern` (mapping_table.py) brach die Token-Erkennung,
  wenn ein Token ohne Delimiter direkt auf Alphanumerik folgte
  (Compound-String `abcTOKEN_PHONE_a1b2c3d4e5_001`). Der Lookbehind ist
  entfernt: Der Token-Prefix (`TOKEN_`/`PS_`) ist im Output-Stream
  global eindeutig, Prefix + TYPE + Hash genügen zur Disambiguierung. Ohne
  Fix verpasste `_mask_tokens` (output_sanitizer) das Token, der Detektor
  matchte den Token-Hash als hex-PII (cookie_id/gps) → Re-Tokenisierung,
  Output korrupt, Restore gebrochen.
- Regressionstests: Pattern-Level (`test_ps_mask_006_token_preceded_by_
  alphanumerics_no_delimiter`) und End-to-End über `_mask_tokens` →
  `detector.scan` mit Compound-String-Payload
  (`test_ps_mask_006_compound_string_token_is_masked_before_detector_scan`).
- Suite: 1051 passed, 1 skipped, 0 failed (Hermes-Venv-Python); mypy --strict
  (mapping_table.py + output_sanitizer.py) clean.

Korrektur zur 1.7.4-Überschrift: Dort stand fälschlich "11 geschlossen" —
tatsächlich wurden in 1.7.4 **10** der 11 MEDIUM/LOW-Findings geschlossen;
das elfte (PS-MASK-006) folgt erst mit diesem 1.7.5-Release.

## [1.7.4] - 2026-10-23

Security-Hardening-Release: Audit-Follow-up-Gate aus PR #17-Audit.

### Audit-Follow-up-Gate — 10 MEDIUM/LOW-Findings aus PR #17-Audit geschlossen (PR #19, #20, #22, #23, getsequenziell gemerged)

- **PS-EMAIL-003** (PR #19): Header-Injection via preserved CR — bare CR → Space,
  C0/C1-Steuerezeichen entfernt, Header-Namen am Trust Boundary gegen
  rfc5322 field-name validiert, Echo-Zeile steuerzeichenfrei.
- **PS-EMAIL-005** (PR #19): LookupError-Crash via Angreifer-charset —
  `_safe_charset` (Regex + `codecs.lookup`), Fallback utf-8, Decode-Backstop.
- **PS-EMAIL-006** (PR #19): MIME-Resource-Exhaustion — Struktur-Limits,
  iterativer Walk, `max_mime_depth=20` / `max_mime_parts=300`.
- **PS-EMAIL-007** (PR #19): broken `_drop_depth` — Tag-Stack mit
  matching-pop accounting, Subtree-Suppression endet am korrekten Tag.
- **PS-REST-003 / PS-TOCTOU-008** (PR #22): Symlink-Races — fd-basierte
  `ensure_secure_dir` (`O_NOFOLLOW|O_DIRECTORY` + fstat + fchmod,
  `fs_hardening.py`), `render_allowed` fail-closed im Restore-Pfad.
- **PS-CHANNEL-007** (PR #23): `cron` aus `_default_restore_channels`
  entfernt — Restore in cron nur noch per explizitem Operator-Opt-in.
- **PS-MAPPER-004** (PR #23): `_build_mapper` fail-closed bei enabled +
  storage_mode=disk + fehlendem `encryption_key` (`RuntimeError`); disabled
  bewahrt die Phase-4-Graceful-Disable-Semantik.
- **PS-PIPE-001** (PR #20): Content-first Attachment-Routing (`is_supported`)
  — gefälschte MIME-Metadaten können kein Attachment mehr allein routen;
  MIME-only-Claims nur als Fallback.
- **PS-INPUT-009** (PR #20): Non-string MIME-Typen/Pfade → explizite
  Fehlerzeile statt AttributeError/TypeError aus dem pre_llm_call-Hook.
- Merge-Reihenfolge: #19 → #22 → #23 → #20; finale Kombinat-Suite
  (1044 passed, 6 skipped); Deploy-Kopie (plugins-Symlink) auf neuen
  main-Stand verifiziert.

## [1.7.3] - 2026-10-22

### Security + Fix — Email-Attachment-Preprocessor P1, Offset-Drift-Fix (t_025240da)

- **Lücke geschlossen:** `.eml`-Attachments erreichten das Modell unsanitisiert
  (Tracking-Pixel, Click-Tracker-Links, sensible Mail-Header
  `X-Originating-IP`/`X-Mailer`/`Received`). Neuer `EmailPreprocessor` in
  `preprocessors/email.py` schließt an die einheitliche Attachment-Schleife
  (PDF, Bild) an; sanitisierter Text nach `email_restore_dir` (Default
  `~/.hermes/privacy/restore/email`). Settings: `email_enabled` (true),
  `email_restore_dir`, `email_max_size_mb` (10), `email_pixel_max_dim` (2),
  `email_rewrite_links_to_blank` (true). Fehlgeschlagene Extraction dropt das
  Attachment mit `eml_summary` (ohne PII).
- **Offset-Drift geschlossen (Root Cause unrestorer Tokens):**
  `normalize_text` ist nicht längenerhaltend (html.unescape, %-Decoding,
  Whitespace-Collapse, `[at]`/`[dot]`-Rewrites) — Matches im normalisierten
  Raum trugen falsche Offsets für den RAW-Prompt. Neu:
  `normalize_text_with_map` führt für jedes Output-Zeichen das
  `(orig_start, orig_end)`-Span mit, auf dem re-anchored wird
  (`_assert_map_matches` als Invariante).
- **Name-Detector FP-Guards:** zusätzliche deutsche Stop-Wörter (Bestätige,
  Bestätigung, Empfang, Erhalt, Kontakt, Telefon, Telefonnummer, Mobil,
  Nutzer, Benutzer, Kunde, Kunden).
- **`confidence_threshold` bleibt 0.8** (REVERT der 0.65-Experiment-
  Änderung): Übermaskierung von Profil-/Agentennamen + frisch gemintete,
  unrestorer Tokens → Restore-Misses flottenweit. Das ursprüngliche
  Problem (Namen in E-Mails) löst die Whitelist + der Email-Preprocessor,
  nicht der globale Threshold.
- OCR-Repair für E-Mail-ähnlichen Text im Image-Preprocessor
  (`_repair_ocr_email`).

## [1.7.2] - 2026-10-06

### Fix — Token-Restore: Whitelist nie leer + cron-Platform

- **Lücke geschlossen:** `_default_restore_channels()` lieferte `()` wenn pass/env
  keine Chat-ID fand. Profile ohne explizites
  `plugins.entries.privacy-shield.restore_allowed_channels` skippten jeden Restore
  → User sahen `TOKEN_*` statt Klartext.
- **Default-Whitelist** enthält jetzt immer bare Platforms:
  `telegram`, `desktop`, `cli`, `cron` (optional plus `telegram:<chat_id>`).
- **`platform="cron"`** whitelisted: Scheduler stampft `cron`, Delivery geht an den
  User — ohne Eintrag blieben Cron-Antworten tokenisiert.
- Restore-Logs: channel + session-prefix; WARNING wenn nach erlaubtem Restore
  noch `TOKEN_*` übrig (Mapping-Miss / korrupter Token), ohne PII.
- Tests: `test_restoration_runs_for_cron_platform`,
  `test_default_restore_channels_never_empty`.
- Nebenbei: auto-apply-Hook-Anker an Hermes v0.21.5
  (`_collect_pre_llm_call_context`) angepasst.

## [1.7.1] - 2026-09-21

### Security — Reasoning-Schutz: Drei-Quellen-Fallback (provider_data / model_extra)

- **Lücke geschlossen (GB-009-Re-Open):** `NormalizedResponse.reasoning_content` und
  `reasoning_details` sind read-only Properties über `provider_data`. v1.7.0 scheiterte
  am `setattr` (fail-open) und verwarf das Token — unredigiertes Reasoning landete in
  `state.db`. v1.7.1 mutiert `provider_data` direkt als Fallback; Core liest über die
  Property aus genau diesem Dict, die Redaktion persistiert.
- **Lücke geschlossen (Seraph F1):** SDK-Varianten, die `reasoning_content` NUR in
  `model_extra` ablegen, werden jetzt ebenfalls redigiert.
- **Smith C-001:** `provider_data=None` wird vor der Fallback-Mutation zu `{}` initialisiert.
- **Smith M-002:** Neue Audit-Events `reasoning_redaction_fallback` und
  `reasoning_redaction_bypass` — Fail-Open-Pfade sind strukturiert sichtbar,
  Silent-Failure-Charakter endet.
- Neue Tests: 8 (provider_data-Fallback, provider_data=None-Init, model_extra-Quelle,
  Anthropic-Style reasoning_details, Tuple-Skip, No-Regression, Audit-Event, codex-Untouched).
  Full-Suite: 926 passed.

# Changelog

## [1.7.0] - 2026-09-09

### Security — Reasoning-Schutz v2 (Pre-Intake-Redaktion)

- **GB-009 geschlossen (plugin-only):** Neuer `post_api_request`-Hook
  redigiert Reasoning-Felder (`reasoning`, `reasoning_content`,
  `reasoning_details`) in-place auf dem Live-`assistant_message`-Objekt
  **bevor** Hermes-Core `_persist_session` läuft. `state.db` erhält
  nur noch tokenisierte Reasoning-Texte — die v1.6.1
  Persistenz-Limitation entfällt.
- Mechanismus: Hook feuert direkt nach Response-Intake
  (`agent/turn_response_intake.py`), vor `build_assistant_message`
  und vor dem Tool-Loop; die Mutation schlägt auf Persist-Row,
  Replay und `result["last_reasoning"]` durch.
- `post_llm_call`-In-Memory-Redaktion (v1.6.1) bleibt als
  Defense-in-Depth aktiv (deckt conversation_history-Nachzügler ab).
- Fail-open: Setattr-/Attribut-Fehler am SDK-Objekt werden geloggt,
  blockieren den Turn nie.
- Audit-Event `reasoning_redaction_applied` mit
  `source=reasoning_block_pre_intake`.

### Fixed
- `transform_llm_output` erhielt seit Hermes-Core-Umbau kein
  `target_channel` mehr → Restore fiel für alle Channels durch
  (Fallback auf `platform`).
- PDF/Image-Preprocessor-Import unter Loader-Namespace
  (`hermes_plugins.<slug>`) repariert — Attachments werden wieder
  gescannt.
- Relative Imports in `audit/collector.py`/`exporter.py` (eine
  Mapping-Table pro Prozess statt zwei).

---

## [1.6.6] - 2026-08-28

### Security
- Secure-restore fallback docs clarified: `/tmp` is never used as
  fallback (world-readable on multi-user hosts); fallback is always the
  hermes-private `~/.hermes/privacy/restore` tree, chmod 0o700
- Runtime audit data (previously tracked under a literal `~/` path
  artifact) removed from the repo; `~/` added to .gitignore

### Changed
- Docs (INSTALL, USER-GUIDE, CHANGELOG) updated to reflect the
  `~/.hermes/privacy/restore` default instead of `/tmp` paths

---

## [1.6.5] - 2026-08-23

### Changed
- Version bump to 1.6.5 (release PR #7)

---

## [1.6.3] - 2026-08-23

### Changed
- Plugin description shortened and neutralized for Desktop-App display

---

## [1.6.3] - 2026-08-23

### Changed
- Plugin-Beschreibung gekürzt und neutralisiert für Desktop-App-Anzeige

---

## [1.6.2] - 2026-08-23

### Changed
- Removed private references from code comments and test fixtures (sanitization)

### Security
- Public repository surfaces are now free of personal references

---

## [1.6.2] - 2026-08-23

### Changed
- Private Bezüge aus Code-Kommentaren und Test-Fixtures entfernt (Sanitisierung)

### Security
- Öffentliche Repository-Oberflächen sind jetzt frei von persönlichen Bezügen

---

## [1.6.1] - 2026-08-23

### Added
- **Reasoning-In-Memory tokenization** via `post_llm_call` hook. Mutates
  `reasoning` / `reasoning_content` fields in assistant messages in-place
  in the `conversation_history` array; the mutation propagates to the
  original `messages` array (Spike-001 proof).
- **New config class** `ReasoningBlockConfig` in `config.py` with
  `mode` (off/audit/restore, default restore), `confidence_threshold`
  (default 0.85) and `skip_fields` (default `["codex_reasoning_items"]`).
- **14 new tests** in `tests/test_reasoning_block_protection.py`:
  5 paraphrased Stolen-Thoughts examples (API key, email, name +
  context, postal address, login path + token), spike proof
  (mutation propagates), mode tests, latency test (<50 ms),
  audit-log test, runtime-guard tests.
- **28 red-team tests** in `tests/test_red_team_seal_team_bypass.py` —
  Unicode/encoding token-bypass attempts against v1.6.1, all green.
- **GB-010 fix** in `plugin.py` + `token_validator.py` — defensive
  check for `last_reasoning` residual PII after redaction.
- **Dashboard API** `dashboard/plugin_api.py` with endpoints
  `GET /api/plugins/privacy-shield/reasoning` and
  `POST /api/plugins/privacy-shield/reasoning` for desktop controls.
- **Audit-log entry** `source=reasoning_block` with persistence
  limitation note.
- **Documentation**: README "Reasoning Protection (In-Memory)" section,
  new `docs/reasoning-protection.md` with limitation note.

### Changed
- `post_llm_call` now accepts `conversation_history` from `kwargs` and
  calls `_redact_reasoning_in_history`.
- `__version__` → `1.6.1`; `plugin.yaml` → `version: "1.6.1"`.

### Constraints
- No Hermes core patch — everything stays plugin-only.
- `state.db` may contain unmutated reasoning PII briefly before hook
  invocation; this limitation is explicitly documented in
  `docs/reasoning-protection.md`.

---

### Added
- **Reasoning-In-Memory-Tokenisierung** via `post_llm_call`-Hook. Mutiert
  `reasoning` / `reasoning_content` in Assistant-Nachrichten in-place
  im `conversation_history`-Array; die Mutation wirkt auf das Original-
  `messages`-Array durch (Spike-001-Beweis).
- **Neue Config-Klasse** `ReasoningBlockConfig` in `config.py` mit
  `mode` (off/audit/restore, default restore), `confidence_threshold`
  (default 0.85) und `skip_fields` (default `["codex_reasoning_items"]`).
- **14 neue Tests** in `tests/test_reasoning_block_protection.py`:
  5 paraphrasierte Stolen-Thoughts-Beispiele (API-Key, E-Mail, Name +
  Kontext, Postanschrift, Login-Pfad + Token), Spike-Beweis
  (Mutation schlägt durch), Modus-Tests, Latenz-Test (<50 ms),
  Audit-Log-Test, Runtime-Guard-Tests.
- **28 Red-Team-Tests** in `tests/test_red_team_seal_team_bypass.py` —
  Unicode/Encoding-Token-Bypass-Versuche gegen v1.6.1, alle grün.
- **GB-010-Fix** in `plugin.py` + `token_validator.py` — defensiver
  Check auf `last_reasoning` Rest-PII nach Redaktion.
- **Dashboard-API** `dashboard/plugin_api.py` mit Endpunkten
  `GET /api/plugins/privacy-shield/reasoning` und
  `POST /api/plugins/privacy-shield/reasoning` für Desktop-Controls.
- **Audit-Log-Eintrag** `source=reasoning_block` mit Persistenz-
  Limitation-Hinweis.
- **Dokumentation**: README-Abschnitt "Reasoning-Schutz (In-Memory)",
  neue `docs/reasoning-protection.md` mit Limitation-Hinweis.

### Changed
- `post_llm_call` nimmt jetzt `conversation_history` aus `kwargs` entgegen
  und ruft `_redact_reasoning_in_history` auf.
- `__version__` → `1.6.1`; `plugin.yaml` → `version: "1.6.1"`.

### Constraints
- Kein Hermes-Core-Patch — alles bleibt Plugin-only.
- `state.db` kann Reasoning-PII kurzzeitig vor Hook-Feuerung enthalten;
  diese Limitation ist in `docs/reasoning-protection.md` explizit
  dokumentiert.

## [1.5.0] - 2026-08-23 (DESKTOP-CONTROLS: official backend + desktop plugin)

### Added
- **Desktop-Controls backend** (`dashboard/plugin_api.py`) — FastAPI router
  mounted at `/api/plugins/privacy-shield/` with:
  - `GET /config` — editable field schema + effective values
  - `POST /config` — validate and persist overrides to `~/.hermes/config.yaml`
  - `GET /status` — version, enabled state, mode, last audit time
  - `POST /restore-test` — synthetic PII pseudonymize/restore smoke test
- **Bundled desktop plugin** (`desktop-plugin/plugin.js`) — single-file ESM UI
  pane using `@hermes/plugin-sdk` components and theme variables.
- **Config persistence** — `config.load_config()` now reads user overrides from
  `plugins.entries.privacy-shield` in `~/.hermes/config.yaml` so UI edits take
  effect after plugin reload.
- **Install hook** (`setup.py`) — copies `desktop-plugin/` into
  `~/.hermes/desktop-plugins/privacy-shield-controls/` on `pip install` and
  `pip install -e .`.
- **Tests** — `tests/test_dashboard_api.py` (backend endpoints) and a frontend
  file-sanity check.
- **Documentation** — `docs/desktop-controls.md` and README section.

### Changed
- `__version__` → `1.5.0`; `plugin.yaml` → `version: "1.5.0"`.
- `pyproject.toml` + `MANIFEST.in` include `dashboard/` and `desktop-plugin/`
  files in the wheel.

### Verification
- 756 tests green across Python 3.10 / 3.11 / 3.12.
- CI: `lint`, `type`, `security`, `test` all green on PR #1.

## [1.4.1] - 2026-08-23 (BUILD-OWASP-ATLAS: OWASP LLM Top-10 + MITRE ATLAS Mapping)

### Added
- **OWASP LLM Top-10 (2025) + MITRE ATLAS Mapping** (`audit/owasp_atlas_mapping.py`).
  Jeder Audit-Event-Typ wird automatisch mit `owasp_risk` (z.B. `LLM02`) und
  `atlas_technique` (z.B. `AML.T0024`) getaggt.
- **`AuditEvent.owasp_risk` + `atlas_technique`** — Neue Felder in
  `audit/report_data.py`; CSV/JSON/PDF-Export zeigen die Codes.
- **Auto-Mapping im AuditLogger** — `AuditLogger.log()` fügt automatisch die
  korrekten OWASP/ATLAS-Codes basierend auf `event` hinzu.
- **`docs/OWASP-LLM-TOP10-MAPPING.md`** — Compliance-Referenz mit
  Abdeckungsübersicht vs. Mitbewerber (Lakera, Noma, Zenity).
- **30 neue Tests** (`tests/test_owasp_atlas_mapping.py`) — Mapping-Korrektheit,
  Enrichment, Coverage-Summary, Fallback-Verhalten.

### Changed
- `__version__` → `1.4.1`.
- CSV-Export: Spalten `owasp_risk` + `atlas_technique` in der `audit_events`-Section.
- PDF-Export: Event-Tabelle zeigt jetzt `OWASP` und `ATLAS` Spalten.

### Verification
- 748 Tests grün (711 v1.4.0-Baseline + 30 neue Mapping-Tests + 7 Regressionen).
- Bandit: 0 HIGH/MEDIUM.
- ruff: clean (Injection-Shield), Privacy-Shield hat bestehende
  Pre-existing-Lint (collector.py F401, pdf_renderer.py PIE810 — nicht von
  dieser Änderung eingeführt).

## [1.4.0] - 2026-08-23 (BUILD-PS-AUDIT-PDF: Audit-Trail PDF-Export)

### Added
- **Audit-Trail PDF-Export** (`privacy_shield.audit`) — Plugin-only (ADR-007).
  `privacy-shield audit-export` generiert DSGVO/EU-AI-Act-konforme Reports aus
  dem JSONL-Audit-Log. Unterstützt PDF, CSV und JSON.
- **Ed25519-Signatur** (`audit/signer.py`) — Jeder Export kann mit einem
  privaten Schlüssel signiert werden; die Signatur ist mit dem Public Key
  verifizierbar. Für PDF/CSV/JSON wird eine detached `.sig`-Datei geschrieben.
- **`AuditExporter` Python-API** (`audit/exporter.py`) —
  `AuditExporter(config=..., mapper=...).export(...)` mit `sign=True` und
  `format="pdf|csv|json"`.
- **Audit-Sub-Paket** (`audit/`) — Struktur: `__init__.py`, `collector.py`,
  `pdf_renderer.py`, `csv_renderer.py`, `exporter.py`, `signer.py`,
  `report_data.py`. Legacy-Import `from privacy_shield.audit import AuditLogger`
  bleibt funktional.
- **Compliance-Article-Mapping** für DSGVO Art. 25, 32, 35 und EU AI Act
  Art. 9, 11, 12, 14 in `config/audit_articles.yaml`.
- **Demo-PDF** `examples/audit-report-sample.pdf` als Workshop-Material.
- **137 Audit-Tests** — PDF-Rendering, CSV/JSON, Signer, Exporter, CLI,
  Paket-API, Audit-Log-Persistence.

### Changed
- `__version__` → `1.4.0`; `plugin.yaml` → `version: "1.4.0"`.
- `pyproject.toml` liest die Version dynamisch aus
  `privacy_shield.__version__` (`[tool.setuptools.dynamic]`).
- `scripts/sync_version.py` unterstützt jetzt dynamische pyproject-Versionen.
- `README.md` um ausführliche Audit-Export-Section erweitert.

### Verification
- 711 Tests grün (589 v1.3.2-Baseline + 122 neue Audit/Export-Tests).
- py_compile-Smoke-Test für alle `.py`-Dateien erfolgreich.
- Bandit: 0 HIGH/MEDIUM-Findings im Produktions-Code (nur Test-Dateien
  enthalten bekannte LOW/MEDIUM-Patterns wie `exec`/`0.0.0.0`/tempfile).

## [1.3.2] - 2026-08-22 (REPO-SPLIT-PS: Standalone-Repository)

### Added
- **Eigenständiges Repository `MOTHR/hermes-privacy-shield`** — Privacy-Shield
  wurde aus dem Higgins-Monorepo (`dsgvo-privacy-shield`) ausgegliedert und
  ist jetzt ein unabhängiges, versioniertes Python-Package.
- `README.md` und `docs/INSTALL.md` verweisen jetzt auf das neue Repository
  inklusive `pip install git+ssh://git@github.com:MOTHR/hermes-privacy-shield.git@v1.3.2`.

### Changed
- Keine funktionalen Code-Änderungen gegenüber dem letzten
  Higgins-Stand; die Ausgliederung ist ein reines Repository-Move.

### Migration
- Bisherige Remote `MOTHR/dsgvo-privacy-shield` bleibt als Archiv erhalten.
- Neuinstallation/Update erfolgt ab sofort aus `MOTHR/hermes-privacy-shield`.
- Live-Plugin-Pfad `~/.hermes/plugins/privacy-shield` bleibt bis zur
  finalen Umstellung auf das neue Package intakt.

## [1.3.2] - 2026-08-22 (FIX-XPLUGIN-TOKEN: Cross-Plugin Token-Format Kontrakt)

### Added
- **Single-Source-of-Truth Token-Format-Constants in `__init__.py`** —
  `DEFAULT_HASH_LENGTH`, `COUNTER_DIGITS`, `TOKEN_FORMAT_REGEX` und
  `TOKEN_FORMAT_PATTERN` sind jetzt exportiert aus
  `privacy_shield.__init__`. Andere Plugins (insbesondere
  `injection-shield`) koennen diese Konstanten importieren, ohne den
  schweren Detection-Pipeline (`regex_detector` → `presidio` etc.)
  mitzuladen. Schliesslich **ARCH-IS-001 / BUTLER-PS-Cross-Plugin**
  sowie die Luecke in BUTLER-PS (Audit-Log-Korrelation zwischen
  Plugins), die beim Fork von `injection-shield` zu Privacy-Shield
  entstanden ist.

- **`tests/test_xplugin_token_contract.py`** (in injection-shield) — 8
  neue Cross-Plugin-Tests, die **echte** Privacy-Shield-Tokens (per
  `Pseudonymizer._make_token`) durch den Injection-Shield-Detector
  jagen. Vor diesem Patch hat das IS-Test-Set ausschliesslich mit
  handgeschriebenen 8-hex / 4-digit-Fake-Tokens getestet — die echten
  PS v1.3.0-Tokens (10-hex / 3-digit) wurden nie im selben Suite
  verifiziert. Test-Cases:
    1. `test_privacy_shield_exposes_canonical_token_regex` —
       verifiziert dass `privacy_shield.TOKEN_FORMAT_PATTERN` als
       Modul-Export existiert.
    2. `test_injection_shield_pattern_uses_same_canonical_shape` —
       IS-Whitelist matcht die reale PS-Token-Form.
    3. `test_real_ps_tokens_have_v13_shape` — Sanity-Check: PS
       emittiert 10-hex + 3-digit (kein Drift nach Downgrade).
    4. `test_injection_shield_recognises_real_ps_tokens` — Mask-Test
       fuer jeden echten PS-Token aus 4 PII-Typen.
    5. `test_real_ps_tokens_produce_no_injection_hits` — Reine
       PS-Tokens + benigner Wrapper ergeben 0 Hits, 0 User-Actions.
    6. `test_real_injection_next_to_real_token_is_still_detected` —
       Echte Injection neben Token wird weiterhin erkannt (kein
       ueber-maskieren).
    7. `test_legacy_8_4_token_shape_still_tolerated` — Pre-v1.2
       (8-hex / 4-digit) Tokens werden weiterhin whitelisted
       (Rolling-Restart-Schutz).
    8. `test_pre_llm_call_with_real_ps_token_is_clean` —
       End-to-end-Pre-LLM-Call-Scan mit echten Tokens.

### Changed
- **`pseudonymizer.py`** referenziert jetzt die kanonischen Konstanten
  via `from . import DEFAULT_HASH_LENGTH, COUNTER_DIGITS`. Class-level
  `HASH_LENGTH` und `COUNTER_DIGITS` bleiben als Class-Attribute
  erhalten (Backward-Compat fuer externe Aufrufer), werden aber aus dem
  zentralen Modul-Wert abgeleitet.
- **`config.py`** importiert `DEFAULT_HASH_LENGTH` aus `privacy_shield`
  statt es lokal zu definieren. Verhindert Drift zwischen dem
  Konfigurations-Regex (`TOKEN_SUFFIX_PATTERN`) und der tatsaechlichen
  Token-Form.

### Verification
- Privacy-Shield: 548/548 Tests gruen (vorher 493 — die +55 stammen aus
  den letzten PS-Releases, sind orthogonal zu diesem Patch).
- Injection-Shield: 254/254 Tests gruen (vorher 208 — +46 enthalten die
  8 neuen Cross-Plugin-Tests aus diesem Patch).
- Manuelle End-to-End-Verifikation: `Pseudonymizer` emittiert
  `TOKEN_EMAIL_4f2d999ca0_000`, `TOKEN_PHONE_967048f69f_001`, etc.
  (10-hex + 3-digit), `InjectionPatternDetector._mask_tokens()`
  extrahiert sie sauber, `detector.check()` produziert 0 Hits.

## [1.3.1] - 2026-08-22 (FIX-PS3: persistenter Audit-Trail)

### Added
- **Privacy-Shield Audit-Logger (`privacy_shield/audit.py`)** — append-only
  JSONL-Audit-Trail, schreibt pro `pre_llm_call`-Maskierung und
  `post_llm_call`-PII-Detection ein Event.  Side-channel-safe:
  bucketed count (`1-1` / `1-10` / `1-100` / `1-1000` / `10000+`),
  SHA-256-prefixed `session_id_hash` (16 hex, kein Klartext), max 3
  type-samples.  chmod 600 auf der Datei, chmod 700 auf dem Verzeichnis,
  opportunistische Rotation bei > 10 000 Events, fail-soft contract
  (kein raise, PII-Schutz läuft weiter wenn Disk-Write fehlschlägt).
- **Config-Felder** `audit_jsonl_path` (default
  `~/.hermes/profiles/default/workspace/privacy-shield-audit.jsonl`) und
  `audit_jsonl_enabled` (default `True`).  Plugin-YAML exponiert beide
  Felder als Operator-Settings.
- **`tests/test_audit_log_persistence.py`** — 15 neue Tests: file
  creation, chmod 600/700, JSONL round-trip, session hashing, bucketed
  count, type-sample capping, fail-soft contract, plugin integration
  (pre_llm_call emit bei Maskierung, post_llm_call emit bei PII,
  paranoid-mode persistiert vor raise), FIFO-rotation.

### Fixed
- BUTLER-PS-2 HIGH (DSGVO Art. 5(1)(e)): persistenter Audit-Trail war
  seit v1.0.0 im Config-Block auskommentiert — User wiegen sich in
  falscher Sicherheit, 4 Review-Runden haben das nie geprüft.  Re-
  aktiviert mit Side-channel-Disziplin (kein Klartext-PII, kein roher
  Session-String, bucketed Counts).

## [1.3.0] - 2026-08-22 (Phase 2: Image-OCR Pipeline — P0 HigginsOS)

### Added
- **Phase 2 image OCR** — Privacy-Shield can now process image attachments
  (JPEG, PNG, WebP, HEIC, HEIF, TIFF, BMP) end-to-end.  Tesseract 5.5.2 runs
  locally (no cloud egress, no DSGVO concerns) and feeds the extracted text
  through the existing RegexPIIDetector + Pseudonymizer pipeline.  A
  sanitized image (original + token-only underlay) is rendered to
  `config.image_restore_dir` (default `~/.hermes/privacy/restore/image`,
  chmod 700) so the user gets a visual round-trip artifact.
- `preprocessors/image.py` — new module: `ImagePreprocessor`,
  `OCRResult`, `OCRWord` dataclasses.  HEIC support is opt-in via
  `pillow-heif` and degrades gracefully when the package is missing.
- `scripts/generate_test_image.py` — generates a 1200x900 PNG fixture with
  PII for tests + demos.
- `tests/test_image_preprocessor.py` — 13 tests covering supported formats,
  OCR confidence filter, line-break preservation, error paths (missing /
  unsupported / malformed images), lang override, sanitized image render
  (chmod 700, empty text, long-line truncation).
- Config: `image_enabled`, `image_restore_dir`, `image_max_size_mb`,
  `ocr_lang`, `ocr_min_confidence`.  Plugin YAML exposes all five.

### Changed
- `plugin.py:pre_llm_call()` now invokes `_maybe_process_image_attachments`
  immediately after the PDF pass, so the prompt handed to the detector
  already contains sanitized image content.
- `__version__` → 1.3.0; `pyproject.toml` version and dependency list
  updated accordingly.
- `plugin.yaml` declares `pytesseract`, `Pillow`, `pillow-heif` as
  dependencies.

### Security
- All `pytesseract` / `Pillow` exceptions are caught and re-raised as
  `ValueError` so a malformed image cannot crash the LLM call.
- Restore directory is enforced to mode 0o700 every time it is created
  (re-`chmod` even if it already existed with looser perms).
- OCR confidence per word is honoured: words below `ocr_min_confidence`
  (default 30) are dropped before the detector sees the text.  Tesseract's
  own "-1" sentinel for non-text blocks is filtered by the same threshold.
- DoS guard: `image_max_size_mb` (default 50 MB).  Oversize images are
  logged, not blocked — the real cap lives at the upload layer.

### Tests
- 13 new image-preprocessor tests, all green.
- Full suite: 369 passed (356 Phase-1 baseline + 13 new).  Zero regressions.

### Not in this release
- In-place text replacement on the sanitized image (Phase 2.5) — today the
  token-only text is rendered as a 120-px underlay.
- EXIF metadata stripping before sanitization (Phase 2.5).
- OCR for scanned PDFs (Phase 2.5 — text-PDFs already handled by Phase 1).
- Office formats DOCX/XLSX/PPTX (Phase 3).
- Audio transcription (Phase 4).

## [1.2.1] - 2026-08-21 (Memory-Bounded Salts + clear_cache Hardening)

### Security
- **FIX-3B-v2 HIGH-001** — `_session_salts` was unbounded: every new session
  added a 16-byte salt with no eviction policy. Long-running services that see
  many short-lived sessions could leak memory indefinitely.
  → `_session_salts` and `_session_counters` are now `OrderedDict` with LRU
  eviction at `max_session_salts` (default 1000, ~16 KB salt budget).
- **FIX-3B-v2 HIGH-002** — `clear_cache()` only cleared `_token_cache`, leaving
  per-session salts and counters in memory.
  → `clear_cache()` now drops all three internal caches (token cache, salts,
  counters) for a true hard reset.

### Changed
- `Pseudonymizer.__init__` gains `max_session_salts: int | None = None`.
- `Pseudonymizer.DEFAULT_MAX_SESSION_SALTS = 1_000`.
- LRU eviction of a session drops its tokens from `_token_cache` to keep
  cross-cache consistency (no orphan tokens for a forgotten session).
- `close_session()` refactored to share the new `_evict_session_tokens()`
  helper (DRY: same code path for LRU eviction, `clear_cache`, and
  `close_session`).
- `_make_token` cache-hit path also promotes the owning session to MRU in
  both the salts and counters dicts, so an actively reused session is not
  evicted as LRU.
- `PrivacyShieldConfig.max_session_salts: int = 1_000`.
- `plugin.yaml` settings: `max_session_salts` (int, default 1000).

### Tests
- 5 new regression tests in `tests/test_pseudonymizer.py`:
  `test_max_session_salts_minimum_one`, `test_session_salts_bounded_lru`,
  `test_lru_session_eviction_drops_tokens`, `test_lru_session_access_promotes_to_mru`,
  `test_clear_cache_also_clears_session_salts`.
- Suite: 305 passed (300 baseline + 5 new).

## [1.2.0] - 2026-08-21 (Birthday-Collision Fix)

### ⚠️ Breaking Changes

**Token-Format erneut geändert:** Alte Tokens ohne 3-stelligen Session-Counter (`TOKEN_EMAIL_<10-HEX>`, z.B. aus 1.1.0) sind NICHT mehr mit der neuen Form `TOKEN_EMAIL_<10-HEX>_<COUNTER>` kompatibel.

**Migration für Upgrades von 1.1.0:**
1. `privacy-shield status` zeigt aktive Sessions an.
2. `privacy-shield map --close-all` führt zum Crypto-Shredding alter Mappings.
3. Plugin-Reload: `hermes plugins reload privacy-shield`.
4. Alte `mapping.db` wird NICHT mehr restored. Löschen: `rm ~/.hermes/privacy/mapping.db`

**In-Flight Sessions:** Sessions, die vor dem Upgrade liefen, müssen neu gestartet werden. Alte Tokens werden nicht mehr restored.

### Security
- **Birthday-Collision-Schutz durch Session-Counter:** Jeder neu erzeugte Token in einer Session erhält einen eindeutigen, monoton steigenden 3-stelligen Counter-Suffix (`_000` bis `_999`). Damit sind Hash-Kollisionen innerhalb derselben Session mathematisch unmöglich, unabhängig von der Hash-Länge.
- 10-Hex-Hash bleibt erhalten für visuelle Kürze und URL-Freundlichkeit.

### Changed
- `Pseudonymizer` erzeugt jetzt Token im Format `{PREFIX}_{TYPE}_{10-HEX}_{COUNTER}`.
- `MappingTable.restore_text` erkennt das neue Token-Format mit `_\d{3}`-Suffix.

## [1.1.0] - 2026-08-21 (Critical Hardening)

### ⚠️ Breaking Changes

**Token-Format geändert:** Alte `TOKEN_EMAIL_001`-Formate sind NICHT mehr kompatibel mit `TOKEN_EMAIL_<10-HEX>` (SHA-256, 10 Hex-Zeichen).

**Migration für Upgrades von 1.0.x:**
1. `privacy-shield status` zeigt aktive Sessions an.
2. `privacy-shield map --close-all` führt zum Crypto-Shredding alter Mappings.
3. Plugin-Reload: `hermes plugins reload privacy-shield`.
4. Alte `mapping.db` wird NICHT mehr restored. Löschen: `rm ~/.hermes/privacy/mapping.db`

**In-Flight Sessions:** Sessions, die vor dem Upgrade liefen, müssen neu gestartet werden. Alte Tokens werden nicht mehr restored.

### Added
- Unicode-Normalization (NFKC + Homoglyph-Mapping) für (at)/(dot)-Obfuscation.
- 35 neue Patterns (Krypto, DSGVO, Auth-Provider) – Gesamtanzahl 58 Patterns.
- In-Memory Mapping-Table als Primary Mode (disk nur mit Key möglich).
- Cache-Bypass-Tag für Provider-Cache-Invalidation.
- Egress-Whitelist für `restore_text` (nur erlaubte User-Channels).
- Deterministische Tokens mit per-Session Salt und 10-Hex-Hash für Kollisions-Schutz.
- LRU-Eviction für Token-Cache (Default 10.000 Einträge).
- Bucketed Audit-Logging (keine exakten PII-Counts, nur Magnitude-Buckets).

### Security
- ReDoS-Schutz im Credit-Card-Pattern.
- Hash-Collision-Schutz durch 10-Hex-Hash + Session-Salt.
- Logging Side-Channel-Schutz: PII-Counts werden in 1-10 / 11-100 / 101-1000 / 10000+ Buckets geloggt.

### Fixed
- Token-Format-Konsistenz zwischen Pseudonymizer und Mapping-Table (beide jetzt 10-Hex).
- Round-Trip-Restore für alle PII-Typen mit Session-Scope.
- Unicode-Homoglyph-Erkennung für E-Mail-Obfuscation.
