## Privacy-Shield v1.6.1

**Reasoning-In-Memory Tokenization** for OpenAI / Anthropic / Google reasoning blocks.

### What's New

- `post_llm_call` hook registers reasoning fields (`reasoning`, `reasoning_content`) and tokenizes them in-place in Hermes memory
- Prevents propagation to tools, exporters, output stages
- Configurable via `reasoning_block_mode: off | audit | restore`
- Desktop-Controls for reasoning mode and confidence threshold
- Audit-log entries with `source=reasoning_block` for compliance audits

### Installation

```bash
pip install hermes-privacy-shield==1.6.1
```

### Security

A three-phase red-team process has validated the release:
- Token-Bypass-Tests (Unicode/Encoding)
- Cross-Surface-Lateral-Movement-Tests (Audit-Log, Mapping-Table, Provider-Trace, Memory-Layer)
- Re-verification of fixes

See `docs/reasoning-protection.md` for the full list of design limitations and mitigation recommendations.

### Breaking Changes

None — v1.6.1 is backward-compatible with v1.5.0 config. The new `reasoning_mode` field defaults to `restore`.

### Full Changelog

[CHANGELOG.md](CHANGELOG.md)

---

## Privacy-Shield v1.6.1 — Deutsche Version

**Reasoning-In-Memory-Tokenisierung** für OpenAI / Anthropic / Google Reasoning-Blöcke.

### Was ist neu

- `post_llm_call`-Hook registriert Reasoning-Felder (`reasoning`, `reasoning_content`) und tokenisiert sie in-place im Hermes-Memory
- Verhindert Weitergabe an Tools, Exporter, Output-Stages
- Konfigurierbar via `reasoning_block_mode: off | audit | restore`
- Desktop-Controls für Reasoning-Mode und Confidence-Threshold
- Audit-Log-Einträge mit `source=reasoning_block` für Compliance-Audits

### Installation

```bash
pip install hermes-privacy-shield==1.6.1
```

### Sicherheit

Ein Drei-Phasen-Red-Team-Prozess hat das Release validiert:
- Token-Bypass-Tests (Unicode/Encoding)
- Cross-Surface-Lateral-Movement-Tests (Audit-Log, Mapping-Table, Provider-Trace, Memory-Layer)
- Re-Verifikation der Fixes

Siehe `docs/reasoning-protection.md` für die vollständige Liste der Design-Limitationen und Mitigation-Empfehlungen.

### Breaking Changes

Keine — v1.6.1 ist rückwärtskompatibel mit v1.5.0-Config. Das neue Feld `reasoning_mode` defaultet auf `restore`.

### Vollständiges Changelog

[CHANGELOG.md](CHANGELOG.md)
