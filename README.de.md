# hermes-security-suite

🌐 Deutsch | [English](README.md)

Security-Plugins für Hermes Agent von MOTHR: Datenschutz und Prompt-Injection-Abwehr für die Telegram-, Desktop- und CLI-Oberflächen des Agents.

## Pakete

### [privacy-shield](privacy-shield/README.de.md)

**DSGVO-konformer PII-Tokenizer.** Maskiert personenbezogene Daten (Namen, E-Mails, Telefonnummern, Credentials, IBANs, Adressen) in allem, was der Agent an einen Nutzer sendet — Telegram, Desktop, CLI — und stellt die Originalwerte deterministisch wieder her: session-gebunden und fail-closed.

- AES-256-GCM-Mapping-Store (PBKDF2, 600k Iterationen), Key optional — ohne Key degradiert das Plugin kontrolliert auf Masking-only
- Restore-Miss-Placeholder: nicht auflösbare Tokens leaken nie, sie werden zu `[maskiertes PII]`
- Session-Fuzzed-Restore für vom Modell kopierte Token-Varianten (nur gleiche Session, gleicher Typ+Serial)
- Desktop-Controls-Pane, PDF/OCR-Vorverarbeitung, Size-Guardrails für Anhänge

### [injection-shield](injection-shield/README.de.md)

**Defense-in-Depth gegen Prompt-Injection.** Verpackt unvertraute Tool-Ergebnisse, prüft LLM-Ausgaben und auditiert riskante Tool-Calls.

- 4 Layer: Content-Tagging (`post_tool_call`), Anti-Injection-Firewall (`pre_llm_call`), Output-Validierung (`post_llm_call`), Risky-Tool-Audit (`pre_tool_call`)
- 7 Detector-Layer inkl. Credential-Leak- und Tool-Call-Patterns, 410+ Tests
- Desktop-Controls-Pane, Telegram-Alerts mit Severity-Gate und Rate-Limiting
- Teilt den Token-Format-Vertrag mit privacy-shield

## Installation

Jedes Paket installiert Agent-Hooks **und** seine Desktop-Controls-Pane in einem Schritt:

```bash
# aus dem Suite-Root
pip install -e ./privacy-shield
pip install -e ./injection-shield
```

Oder direkt von GitHub:

```bash
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=privacy-shield
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=injection-shield
```

Die Desktop-Controls übernimmt die Hermes-Desktop-App automatisch (unified-package Desktop-Anteil).

## Security-Audits

Beide Pakete sind durch ein unabhängiges Multi-Agent-Security-Audit gegangen (confirmed Findings behoben, Re-Audit sauber, kein offenes HIGH). Siehe [SECURITY-AUDIT.md](SECURITY-AUDIT.md).

## Security-Meldungen

Bitte keine öffentlichen Issues für Schwachstellen. Kontaktiere das MOTHR-Security-Team direkt.
