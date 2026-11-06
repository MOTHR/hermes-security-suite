# Security Audit Report — hermes-security-suite

🌐 Deutsch | [English](#english)

## Deutsch

## Scope

| Paket | Auditierte Version (Run) | Ausgelieferte Version | Delta / offenes Audit |
|-------|--------------------------|----------------------|-----------------------|
| privacy-shield | Basis `v1.7.3-email-preprocessor` (Run 1 Audit), behoben bis `v1.7.6` (Run 4 Re-Verifikation) | 1.8.0 | Delta v1.7.6 → 1.8.0 ohne eigenen Audit-Run; auditierte Quellbasis ist der Run-4-Stand (`v1.7.6`) |
| injection-shield | v0.6.0 — **kein formaler Audit-Run** (dreifaches Peer-Review) | 0.7.1 | **Formales Multi-Agent-Audit ausstehend** — die ausgelieferte 0.7.1 ist nicht auditiert |

**Run-ID-Zuordnung (Version → Run → Ergebnis):**

| Version | Run-ID | Ergebnis | GO/NOGO |
|---------|--------|----------|---------|
| privacy-shield `v1.7.3-email-preprocessor` (Audit + Re-Audit) | `privacy-shield-run-1` | 15 confirmed Findings, sämtliche HIGH behoben; Re-Audit ohne neue Findings ≥ MEDIUM | GO |
| privacy-shield `v1.7.6` (Re-Verifikation der Run-1-Fingerprints) | `privacy-shield-run-4` | 0 confirmed Findings; 4/4 Run-1-HIGH bestätigt geschlossen | **GO** |
| privacy-shield `1.8.0` (ausgeliefert) | kein eigener Run | Release-/Packaging-Stand auf Run-4-Quellbasis (`v1.7.6`); Delta als solches gekennzeichnet | Delta (kein eigener Audit-Run) |
| privacy-shield Run 2 / Run 3 | `privacy-shield-run-2` / Run-3-Ledger | Ledger-Belege im Artefaktverzeichnis (siehe Run-4-Sektion) | belegt, Details in Ledgern |
| injection-shield `v0.6.0` | kein eigener Run | Dreifaches Peer-Review (Konsistenz/Integrität, Standards/Spec, Bug-Hunt/Security), 410+ Tests | Peer-Review, kein Audit |
| injection-shield `0.7.1` (ausgeliefert) | kein eigener Run | Delta 0.6.0 → 0.7.1 (Desktop-Paket-Pfad, Manifest-Felder, Lizenz-/Policy-Dateien) | **nicht auditiert — formales Audit ausstehend** (NOGO = keine Audit-Aussage möglich, Peer-Review-Status gilt) |

> **Kurzlektüre:** Was in dieser Suite als „auditiert" bezeichnet werden darf, ist ausschließlich der privacy-shield-Quellstand `v1.7.6` (Run 4, GO) samt Vorgängern Run 1. Die ausgelieferten Paketversionen 1.8.0 (privacy-shield) und 0.7.1 (injection-shield) sind **nicht Gegenstand eines formalen Audits**; für injection-shield steht das formale Multi-Agent-Audit aus.

---

## privacy-shield — Run 1 Audit-Zusammenfassung

**Run-ID**: privacy-shield-run-1
**Source-Ref**: `fix/v1.7.3-email-preprocessor` @ `cca0eb5`
**Agents**: 2 Hunter-Sub-Agents (email-hunter, pipeline-hunter) + Parent-Reconnaissance

### Bestätigte Findings (15 gesamt)

| Severity | Anzahl | Fingerprints |
|----------|--------|--------------|
| HIGH | 4 | PS-EMAIL-001, PS-EMAIL-002, PS-EMAIL-004, PS-CONF-002 |
| MEDIUM | 10 | PS-EMAIL-003, PS-EMAIL-005, PS-EMAIL-006, PS-EMAIL-007, PS-MAPPER-004, PS-MASK-006, PS-PIPE-001, PS-REST-003, PS-TOCTOU-008, PS-CHANNEL-007 |
| LOW | 1 | PS-INPUT-009 |

### HIGH-Findings — Grundursachen

1. **PS-EMAIL-001** — HTML-Attribut-Injection über unescapte Quotes in `_emit_tag`. Der Email-Sanitizer rekonstruierte HTML-Bodies, ohne Quote-Zeichen in Attributwerten zu escapen — beliebige Attribut-Injection möglich.

2. **PS-EMAIL-002** — Gefährliche URL-Schemes (`javascript:`, `vbscript:`, `file:`) passierten den Sanitizer unverändert und blieben nach der Sanitization aktiv.

3. **PS-EMAIL-004** — Race Condition und Path Traversal in `render_sanitized`. Ein Symlink-Race erlaubte beliebige File-Overwrites durch TOCTOU zwischen `mkdir` und `chmod`.

4. **PS-CONF-002** — NaN-Confidence-Threshold-Bypass in `_filter_by_confidence`. Ein NaN-Confidence-Wert ließ alle Detections stillschweigend fallen und legte die gesamte PII-Detection-Pipeline lahm.

### Remediation

Alle 4 HIGH-Findings wurden in Folge-PRs behoben:

| PR | Commits | Behobene HIGH-Findings |
|----|---------|------------------------|
| PR #17 | `cca0eb5` | PS-EMAIL-001 Attribut-Injection |
| PR #18 | `0adb739` | PS-EMAIL-002 URL-Schemes, PS-EMAIL-004 Path Traversal |
| PR #19 | `499d4cd` | PS-CONF-002 NaN-Bypass + PS-EMAIL-003/005/006/007 |

### Re-Audit-Ergebnis

Das Follow-up-Audit gegen den gefixten Branch bestätigte **keine neuen confirmed Findings auf MEDIUM oder höher**. 11 MEDIUM/LOW-Findings verbleiben im Coverage-Ledger, alle mit akzeptiertem Risiko oder als Technical Debt getrackt.

**Empfehlung: GO** — Der Branch ist mit Standard-Release-Testing merge-sicher.

### Test-Coverage beim Re-Audit

- **1038 Tests** bestanden
- `mypy --strict` sauber
- Alle HIGH-Findings mit Regressionstests verifiziert geschlossen

### Positive Security-Patterns

- Mapping-Table nutzt **AES-256-GCM** mit PBKDF2 (600k Iterationen), unique Salt pro Verschlüsselung, keine Nonce-Reuse
- Das Plugin degradiert kontrolliert, wenn kein Encryption-Key gefunden wird
- `max_size_mb`-Guardrails für PDF-, Image- und Email-Attachments
- `_unfold_header` behandelt RFC 5322 folded headers korrekt

### Hardening-Empfehlungen

- Einen gemeinsamen `os.lstat` + `os.chmod`-Helper auf resolved paths extrahieren, um das wiederholte TOCTOU-Muster in `_ensure_secure_restore_dir` und `AttachmentProcessor.process` zu eliminieren
- Typ-Validierung für `mime_type` vor `.lower()` in `_filter_attachments`
- `_build_mapper` sollte fail-closed sein (`RuntimeError`), wenn Disk-Mode ohne Encryption-Key angefragt wird
- Negative Lookbehind im Token-Regex prüfen, um zu garantieren, dass Tokens unabhängig vom Kontext immer maskiert werden

---

## privacy-shield — Run 4 Re-Verifikation (v1.7.6)

**Run-ID**: privacy-shield-run-4
**Source-Ref**: `feature/v1.7.6-restore-splice` @ `06788702f28fd4d1fd71f92def99e52336b10e39` (Merge-Kandidat, PR #26, Merge-Commit `b387d70ffe51345d8b62739d5fa322c9aa0b90aa`)
**Methodik**: Cloudflare `security-audit`-Skill (6 Phasen, adversarial Verifier) — Audit: seraph; anschließend unabhängige adversariale Verifikation durch eine zweite Agent-Instanz
**Datum**: 2026-11-06

### Ergebnis

| Metrik | Wert |
|--------|------|
| Confirmed Findings | 0 |
| Offen confirmed ≥ MEDIUM | 0 |
| Rejected (behoben/mitigiert) | 18 |
| Coverage-Units | 12 |
| Test-Suite | 1066 passed, 7 skipped, 0 failed |
| Validator findings.json | PASS (exit 0) |
| Validator coverage-ledger.json | PASS (exit 0) |

### Details

- **Run-1 HIGH-Fingerprints (4/4 bestätigt geschlossen):** `PS-CONF-002` (NaN-Confidence-Bypass, `math.isfinite()` + Range-Guard), `PS-EMAIL-001` (HTML-Attribut-Injection, `html.escape` mit `quote=True`), `PS-EMAIL-002` (Gefährliche URL-Schemes, `ALLOWED_URL_SCHEMES`-Allowlist), `PS-EMAIL-004` (Path-Traversal/Symlink-Race, `_lstat_chmod` + `islink`-Check) — alle per Quell-Re-Verifikation und Regressionstests geschlossen.
- **Finding 3f (`PS-V176-3F`) adversarial bestätigt mitigiert:** Der token_serial wird pro Kandidaten-Row aus dem eigenen `token_encrypted` neu abgeleitet; bei Mismatch wird die Row repariert und vom Restore ausgeschlossen. Adversarialer PoC (attacker-manipulated serial) PASS — Angreifer-Ziel wird nicht zurückgegeben, Session-Scoping, Uniqueness-Contract und Fail-Closed-Truncation verifiziert.
- **v1.7.6-Log-Level-Fixes:** restore-miss (7d) und Residual-Pass-Summary (7g) loggen jetzt `logger.warning`.
- **11 Run-3-Findings** (Ledger: Run-1 + Run-2 + Run-3-Ledger) revalidiert — alle geschlossen.
- **Unabhängige Verifikation:** alle 5 Prüfbereiche PASS (3f-PoC, 4 Run-1-HIGH, beide Validatoren, Teststand, Delta-Scope) — GO-Empfehlung bestätigt.

### Artefakte & Verweise

- **Run-4:** `security-audits/privacy-shield-run-4/` (REPORT.md, findings.json, coverage-ledger.json, run-metadata.json, poc_3f_mitigation.py, verification-agent-smith.md)
- **Run-1 / Run-2:** `.../security-audits/privacy-shield-run-1/`, `.../security-audits/privacy-shield-run-2/`
- **Run-3 Ledger:** Second-Brain `06-Reports/20261029-Privacy-Shield-Re-Audit-Run3-Coverage-Ledger.md`
- **PR #26** (v1.7.6); Release-Gate: Kanban-Karte `t_804a1c41`

**Empfehlung: GO** — keine offenen confirmed Findings ≥ MEDIUM; bereit für Live-Rollout.

---

## injection-shield — Audit-Status

Das formale Multi-Agent-Security-Audit nach dem privacy-shield-Muster ist **ausstehend**. Aktueller Status: aktive Entwicklung, dreifaches Peer-Review (Konsistenz/Integrität, Standards/Spec, Bug-Hunt/Security) der **v0.6.0** und Regressionssuite 410+ Tests. **Ausgeliefert wird v0.7.1; dieses Delta (Desktop-Paket-Pfad, Manifest-Felder, Lizenz-/Policy-Dateien) ist von keinem formalen Audit gedeckt** — für `injection-shield 0.7.1` wird daher keine Audit-Markierung erhoben.

---

## Allgemeines Security-Modell

Beide Pakete folgen einer **Defense-in-Depth**-Architektur:

```
┌─────────────────────────────────────────────────────┐
│                    User Input                       │
└──────────────┬──────────────────────────┬───────────┘
               │                          │
┌──────────────▼──────────┐  ┌────────────▼───────────┐
│   privacy-shield        │  │   injection-shield     │
│   - PII-Detection       │  │   - Prompt-Injection-  │
│   - Tokenization        │  │     Detection          │
│   - Mapping/AES-256-GCM │  │   - Credential-Leak-   │
│   - Output-Sanitization │  │     Detection          │
│   - Session-Fuzzing     │  │   - Tool-Result-       │
│                         │  │     Scanning           │
└──────────────┬──────────┘  └────────────┬───────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────────────────────────────┐
│                    Hermes Agent                      │
└──────────────────────────────────────────────────────┘
```

## Security-Issues melden

Bitte keine öffentlichen Issues für Sicherheitslücken. Kontaktiere das MOTHR-Security-Team direkt.

---

## English

## Scope

| Package | Version audited (run) | Version delivered | Delta / open audit |
|---------|----------------------|------------------|--------------------|
| privacy-shield | basis `v1.7.3-email-preprocessor` (Run 1 audit), fixed through `v1.7.6` (Run 4 re-verification) | 1.8.0 | delta v1.7.6 → 1.8.0 without a dedicated audit run; the audited source basis is the Run-4 state (`v1.7.6`) |
| injection-shield | v0.6.0 — **no formal audit run** (triple peer review) | 0.7.1 | **formal multi-agent audit pending** — the delivered 0.7.1 is not audited |

**Run-ID mapping (version → run → result):**

| Version | Run ID | Result | GO/NOGO |
|---------|--------|--------|---------|
| privacy-shield `v1.7.3-email-preprocessor` (audit + re-audit) | `privacy-shield-run-1` | 15 confirmed findings, all HIGH fixed; re-audit found no new findings at MEDIUM or above | GO |
| privacy-shield `v1.7.6` (re-verification of the Run-1 fingerprints) | `privacy-shield-run-4` | 0 confirmed findings; 4/4 Run-1 HIGH confirmed closed | **GO** |
| privacy-shield `1.8.0` (delivered) | no dedicated run | release/packaging state on the Run-4 source basis (`v1.7.6`); delta labeled as such | delta (no dedicated audit run) |
| privacy-shield Run 2 / Run 3 | `privacy-shield-run-2` / Run-3 ledger | ledger evidence in the artifacts listing (see Run-4 section) | evidenced, details in ledgers |
| injection-shield `v0.6.0` | no dedicated run | triple peer review (consistency/integrity, standards/spec, bug-hunt/security), 410+ tests | peer review, not an audit |
| injection-shield `0.7.1` (delivered) | no dedicated run | delta 0.6.0 → 0.7.1 (desktop package path, manifest fields, license/policy files) | **not audited — formal audit pending** (NOGO = no audit statement possible; peer-review status applies) |

> **TL;DR:** The only thing this suite may call "audited" is the privacy-shield source state `v1.7.6` (Run 4, GO) together with its Run-1 predecessors. The delivered package versions 1.8.0 (privacy-shield) and 0.7.1 (injection-shield) are **not the subject of a formal audit**; for injection-shield the formal multi-agent audit is pending.

---

## privacy-shield — Run 1 Audit Summary

**Run ID**: privacy-shield-run-1
**Source Ref**: `fix/v1.7.3-email-preprocessor` @ `cca0eb5`
**Agents**: 2 hunter sub-agents (email-hunter, pipeline-hunter) + parent reconnaissance

### Confirmed Findings (15 total)

| Severity | Count | Fingerprints |
|----------|-------|-------------|
| HIGH | 4 | PS-EMAIL-001, PS-EMAIL-002, PS-EMAIL-004, PS-CONF-002 |
| MEDIUM | 10 | PS-EMAIL-003, PS-EMAIL-005, PS-EMAIL-006, PS-EMAIL-007, PS-MAPPER-004, PS-MASK-006, PS-PIPE-001, PS-REST-003, PS-TOCTOU-008, PS-CHANNEL-007 |
| LOW | 1 | PS-INPUT-009 |

### HIGH Findings — Root Causes

1. **PS-EMAIL-001** — HTML attribute injection via unescaped quotes in `_emit_tag`. The email sanitizer HTML body reconstruction did not escape quote characters in attribute values, allowing arbitrary attribute injection.

2. **PS-EMAIL-002** — Dangerous URL schemes (`javascript:`, `vbscript:`, `file:`) pass through the sanitizer unchanged, remaining active after sanitization.

3. **PS-EMAIL-004** — Race condition and path traversal in `render_sanitized`. Symlink race allows arbitrary file overwrite due to TOCTOU between `mkdir` and `chmod`.

4. **PS-CONF-002** — NaN confidence threshold bypass in `_filter_by_confidence`. A NaN confidence value causes all detections to be silently dropped, defeating the entire PII detection pipeline.

### Remediation

All 4 HIGH findings were addressed in subsequent PRs:

| PR | Commits | HIGH Findings Fixed |
|----|---------|-------------------|
| PR #17 | `cca0eb5` | PS-EMAIL-001 attribute injection |
| PR #18 | `0adb739` | PS-EMAIL-002 URL schemes, PS-EMAIL-004 path traversal |
| PR #19 | `499d4cd` | PS-CONF-002 NaN bypass + PS-EMAIL-003/005/006/007 |

### Re-Audit Result

Follow-up audit against the fixed branch confirmed **no new confirmed findings at MEDIUM or above**. 11 MEDIUM/LOW findings remain in the coverage ledger, all with accepted risk or tracked as technical debt.

**Recommended: GO** — Branch is safe to merge with standard release testing.

### Test Coverage at Re-Audit

- **1038 tests** passing
- `mypy --strict` clean
- All HIGH findings verified closed with regression tests

### Positive Security Patterns

- Mapping table uses **AES-256-GCM** with PBKDF2 (600k iterations), unique salt per encryption, no nonce reuse
- Plugin gracefully disables itself when no encryption key is found
- `max_size_mb` guardrails exist for PDF, image, and email attachments
- `_unfold_header` correctly handles RFC 5322 folded headers

### Hardening Recommendations

- Extract a shared `os.lstat` + `os.chmod` helper on resolved paths to eliminate the repeated TOCTOU pattern in `_ensure_secure_restore_dir` and `AttachmentProcessor.process`
- Add type validation for `mime_type` before `.lower()` in `_filter_attachments`
- `_build_mapper` should fail closed (raise `RuntimeError`) when disk mode is requested without an encryption key
- Consider removing the negative lookbehind from the token regex to ensure tokens are always masked regardless of surrounding context

---

## privacy-shield — Run 4 Re-Verification (v1.7.6)

**Run ID**: privacy-shield-run-4
**Source Ref**: `feature/v1.7.6-restore-splice` @ `06788702f28fd4d1fd71f92def99e52336b10e39` (merge candidate, PR #26, merge commit `b387d70ffe51345d8b62739d5fa322c9aa0b90aa`)
**Methodology**: Cloudflare `security-audit` skill (6 phases, adversarial verifier) — audit: seraph; followed by independent adversarial verification from a second agent instance
**Date**: 2026-11-06

### Result

| Metric | Value |
|--------|-------|
| Confirmed findings | 0 |
| Open confirmed ≥ medium | 0 |
| Rejected (fixed/mitigated) | 18 |
| Coverage units | 12 |
| Test suite | 1066 passed, 7 skipped, 0 failed |
| Validator findings.json | PASS (exit 0) |
| Validator coverage-ledger.json | PASS (exit 0) |

### Details

- **Run-1 HIGH fingerprints (4/4 confirmed closed):** `PS-CONF-002` (NaN confidence bypass, `math.isfinite()` + range guard), `PS-EMAIL-001` (HTML attribute injection, `html.escape` with `quote=True`), `PS-EMAIL-002` (dangerous URL schemes, `ALLOWED_URL_SCHEMES` allowlist), `PS-EMAIL-004` (path traversal/symlink race, `_lstat_chmod` + `islink` check) — all closed via source re-verification and regression tests.
- **Finding 3f (`PS-V176-3F`) confirmed mitigated adversarially:** the token_serial is re-derived per candidate row from its own `token_encrypted`; on mismatch the row is repaired and excluded from restoration. Adversarial PoC (attacker-manipulated serial) PASS — attacker's chosen original is not returned; session scoping, uniqueness contract, and fail-closed truncation verified.
- **v1.7.6 log-level fixes:** restore-miss (7d) and residual pass summary (7g) now log via `logger.warning`.
- **11 Run-3 findings** (ledger: Run-1 + Run-2 + Run-3 ledger) revalidated — all closed.
- **Independent verification:** all 5 verification areas PASS (3f PoC, 4 Run-1 HIGH, both validators, test stand, delta scope) — GO recommendation confirmed.

### Artifacts & References

- **Run 4:** `security-audits/privacy-shield-run-4/` (REPORT.md, findings.json, coverage-ledger.json, run-metadata.json, poc_3f_mitigation.py, verification-agent-smith.md)
- **Run 1 / Run 2:** `.../security-audits/privacy-shield-run-1/`, `.../security-audits/privacy-shield-run-2/`
- **Run 3 ledger:** Second Brain `06-Reports/20261029-Privacy-Shield-Re-Audit-Run3-Coverage-Ledger.md`
- **PR #26** (v1.7.6); release gate: Kanban card `t_804a1c41`

**Recommended: GO** — no open confirmed findings at medium or above; ready for live rollout.

---

## injection-shield — Audit Status

The formal multi-agent security audit (same pattern as privacy-shield) is **pending**. Current status: active development, triple peer review (consistency/integrity, standards/spec, bug-hunt/security) of **v0.6.0**, regression suite 410+ tests. **The delivered version is 0.7.1; that delta (desktop package path, manifest fields, license/policy files) is not covered by any formal audit** — no audit claim is therefore made for `injection-shield 0.7.1`.

---

## General Security Model

Both packages follow a **defense-in-depth** architecture:

```
┌─────────────────────────────────────────────────────┐
│                    User Input                       │
└──────────────┬──────────────────────────┬───────────┘
               │                          │
┌──────────────▼──────────┐  ┌────────────▼───────────┐
│   privacy-shield        │  │   injection-shield     │
│   - PII detection       │  │   - Prompt injection   │
│   - Tokenization        │  │     detection          │
│   - Mapping/AES-256-GCM │  │   - Credential leak    │
│   - Output sanitization │  │     detection          │
│   - Session fuzzing     │  │   - Tool-result        │
│                         │  │     scanning           │
└──────────────┬──────────┘  └────────────┬───────────┘
               │                          │
               ▼                          ▼
┌──────────────────────────────────────────────────────┐
│                    Hermes Agent                      │
└──────────────────────────────────────────────────────┘
```

## Reporting Security Issues

Do not file public issues for security vulnerabilities. Contact the MOTHR security team directly.
