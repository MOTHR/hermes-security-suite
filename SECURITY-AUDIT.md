# Security Audit Report — hermes-security-suite

🌐 Deutsch | [English](#english)

## Deutsch

## Scope

| Paket | Repository | Auditierte Version |
|-------|-----------|--------------------|
| privacy-shield | MOTHR/hermes-security-suite (`privacy-shield/`) | Basis `v1.7.3-email-preprocessor`, behoben bis v1.7.5 |
| injection-shield | MOTHR/hermes-security-suite (`injection-shield/`) | v0.6.0 |

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

## injection-shield — Audit-Status

Das formale Multi-Agent-Security-Audit nach dem privacy-shield-Muster ist ausstehend. Aktueller Status: aktive Entwicklung, dreifaches Peer-Review (Konsistenz/Integrität, Standards/Spec, Bug-Hunt/Security) der v0.6.0 und Regressionssuite 410+ Tests.

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

| Package | Repository | Version Audited |
|---------|-----------|----------------|
| privacy-shield | MOTHR/hermes-security-suite (`privacy-shield/`) | basis `v1.7.3-email-preprocessor`, fixed through v1.7.5 |
| injection-shield | MOTHR/hermes-security-suite (`injection-shield/`) | v0.6.0 |

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

## injection-shield — Audit Status

The formal multi-agent security audit (same pattern as privacy-shield) is pending. Current status: active development, triple peer review (consistency/integrity, standards/spec, bug-hunt/security) of v0.6.0, regression suite 410+ tests.

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
