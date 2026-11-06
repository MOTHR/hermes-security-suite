# hermes-security-suite

🌐 Deutsch | [English](README.md)

**Security Suite für Hermes Agent von MOTHR** — zwei erprobte Plugins, die zusammen die zwei Wege abdecken, auf denen ein Agent Daten verliert oder manipuliert wird: **PII im Ausgangsverkehr** (Privacy-Shield) und **Prompt-Injection über unvertraute Inhalte** (Injection-Shield).

> **⭐ Im Fokus: Stolen-Thoughts Reasoning Protection** — Privacy-Shield ist, soweit wir wissen, das einzige Hermes-Plugin, das PII innerhalb von Modell-*Reasoning-/Thinking-Blöcken* tokenisiert, bevor etwas persistiert wird. Modell-Reasoning enthält regelmäßig echte Namen, E-Mails und Credentials, die in der sichtbaren Antwort nie auftauchen — das ["Stolen Thoughts"](https://stolen-thoughts.com)-Problem (2026), und es betrifft **jeden Cloud-Provider, der Modell-Reasoning ausliefert**. Die Redaktion ist provider-agnostisch: Sie hängt am Response-Intake und matcht Reasoning-Felder (`reasoning`, `reasoning_content`, `reasoning_details`, Codex-Reasoning-Items) unabhängig vom Hersteller — verifiziert mit OpenAI, Anthropic und Google. Die Suite-Hooks redigieren sie **pre-intake**: kein Raw-PII-Fenster erreicht jemals die `state.db`. Siehe [Reasoning Protection](#-stolen-thoughts-reasoning-protection).

> **⚖️ Warum europäische Unternehmen das brauchen:** In der EU ist DSGVO- und EU-AI-Act-Konformität für Agenten kein Nice-to-have, sondern die Voraussetzung überhaupt: Ein Agent, der personenbezogene Daten an Cloud-LLMs sendet oder Anweisungen aus unvertrauten Inhalten ausführt, lässt sich unter Art. 5/25/32 DSGVO und den Transparenz- und Dokumentationspflichten des EU AI Act kaum mit echten Geschäftsdaten betreiben. Diese Suite macht einen Hermes-Agenten zu einem Agenten, dem man Kunden und Mitarbeitende tatsächlich anvertrauen kann: tokenisierter Egress, whitelisted Restore, manipulationssichere Audit-Trails und Compliance-Reports, die ein DPO oder Auditor akzeptiert.

## Pakete

| Paket | Schutz gegen | Aktuelle Version |
|---|---|---|
| [privacy-shield](privacy-shield/README.de.md) | PII-Egress: Namen, E-Mails, Telefonnummern, IBANs, Krypto-Wallets, Tokens leak in LLM-Verkehr, Reasoning-Blöcke, PDFs und Screenshots | **1.8.0** |
| [injection-shield](injection-shield/README.de.md) | Prompt-Injection: bösartige Anweisungen in Webseiten, Tool-Ergebnissen und LLM-Antworten | **0.7.1** |

## Was die Pakete tun

### [privacy-shield](privacy-shield/README.de.md) — DSGVO-konformer PII-Tokenizer

Ersetzt personenbezogene Daten durch deterministische Tokens (`TOKEN_EMAIL_a3f8b2c41d_003`), bevor der Provider sie sieht, und stellt Originalwerte **nur** in kanalisierst du freigegebenen Kanälen wieder her. Fail-closed: Nichts Unauflösbares degradiert zu `[maskiertes PII]`, nie zu Klartext.

**Erkennung & Verarbeitung**
- **58 Detektion-Patterns** in 7 Kategorien: E-Mail, Telefon, IBAN, Krypto-Wallets, JWT/OAuth-Tokens, GitHub-PATs, MAC/IMEI/IMSI und mehr
- **Text, Markdown und Code** in einer Pipeline
- **PDF-Pipeline** — Textextraktion (pdfplumber), Tokenisierung, bereinigtes PDF als Ergebnis
- **Image-OCR** — JPG/PNG/HEIC/WebP/TIFF/BMP via Tesseract, mehrsprachig (deu+eng als Standard)
- **Unicode-Normalisierung** (NFKC + Homoglyph-Mapping), damit Lookalike-Zeichen nicht durchrutschen
- Cache-Bypass-Tag für lokale Lesevorgänge — lokale Daten werden nicht maskiert, da sie die Maschine nie verlassen

**Mapping-Sicherheit & Restore**
- **AES-256-GCM**-verschlüsselter Mapping-Store mit **PBKDF2 (600k Iterationen)**
- **Restore-Miss-Placeholder** — nicht auflösbare Tokens degradieren zu `[maskiertes PII]` mit `restore_miss`-Metric; sie leaken nie
- **Session-Fuzzed-Restore** — repariert vom Modell kopierte Token-Varianten (nur gleiche Session, gleicher Typ+Serial; Serial wird aus dem verschlüsselten Inhalt neu abgeleitet, manipulierte Rows werden ausgeschlossen)
- **Egress-Whitelist** — Restore nur in freigegebenen Kanälen (z. B. deiner Telegram-Chat-ID); alles andere bleibt maskiert

**Betrieb**
- Fünf Modi: `off / audit / limited / strict / paranoid`
- Provider-Erkennung: Ollama-lokaler Verkehr umgeht den Shield (kein Cloud-Egress = nichts zu schützen)
- Desktop-Controls-Pane: Modus, Confidence-Schwellwert, Restore-Kanäle, PDF/OCR-Schalter, Restore-Smoke-Test

### [injection-shield](injection-shield/README.de.md) — Defense-in-Depth gegen Prompt-Injection

Vier Hooks um jeden Hermes-Turn:

1. **Content-Tagging** (`post_tool_call`) — verpackt `web_extract`, `web_search` und MCP-Ergebnisse in `<untrusted_tool_result>`-Tags, damit das Modell Inhalte als Daten behandelt, nicht als Anweisungen
2. **Anti-Injection-Firewall** (`pre_llm_call`) — System-Prompt-Firewall gegen injizierte Direktiven
3. **Output-Validierung** (`post_llm_call`) — scannt Antworten auf Credential-Leaks und Nutzer-Direktiven; blockiert im `enforcement`-Modus
4. **Risky-Tool-Audit** (`pre_tool_call`) — prüft Aufrufe von `terminal`/`write_file` auf Injection-Patterns vor der Ausführung

Dazu: **7 Detector-Layer** (darunter Credential-Leak- und Tool-Call-Patterns, 410+ Tests), Telegram-Alerts mit Severity-Gate und Rate-Limiting, Audit-Log mit Rotation und Retention, Allowed-Domains-Liste und eine Desktop-Controls-Pane (`audit`/`enforcement`-Schalter, Detector-Kategorien, Smoke-Test).

## ⭐ Stolen-Thoughts Reasoning Protection

Reasoning-/Thinking-Blöcke können echte PII und Secrets enthalten, die in der sichtbaren Ausgabe nie erscheinen — das „Stolen Thoughts"-Problem betrifft **jeden Cloud-Provider, der Modell-Reasoning ausliefert**. Privacy-Shield schließt dieses Fenster mit zwei Layern:

- **Layer 1 — Pre-Intake-Redaktion:** der `post_api_request`-Hook feuert direkt nach dem Response-Intake, **bevor** Hermes den Turn persistiert. Reasoning-Felder (`reasoning`, `reasoning_content`, `reasoning_details`) werden in-place auf der Live-Message tokenisiert → die persistierte Session enthält ausschließlich tokenisiertes Reasoning.
- **Layer 2 — In-Memory-Redaktion:** der `post_llm_call`-Hook tokenisiert Reasoning zusätzlich innerhalb der `conversation_history`, damit späte Konsumenten (Tools, Exporter) niemals Raw-Reasoning-PII sehen.

```yaml
plugins:
  entries:
    privacy-shield:
      reasoning_mode: restore    # off | audit | restore (Standard: restore)
      reasoning_confidence_threshold: 0.85
```

Details und Abdeckung: [`privacy-shield/docs/reasoning-protection.md`](privacy-shield/docs/reasoning-protection.md).

## Installation

Jedes Paket installiert Agent-Hooks **und** seine Desktop-Controls-Pane in einem Schritt (Unified Package — die Hermes-Desktop-App kopiert den Desktop-Anteil automatisch):

```bash
# Suite-Checkout, editable
pip install -e ./privacy-shield
pip install -e ./injection-shield

# oder direkt von GitHub (Python ≥ 3.10)
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=privacy-shield
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=injection-shield
```

Verifizieren:

```bash
privacy-shield scan "Kontakt: alice@example.com"
injection-shield --version
hermes plugins validate
```

## Konfiguration (Kurzform)

```yaml
plugins:
  enabled:
    - privacy-shield
    - injection-shield
  entries:
    privacy-shield:
      mode: strict
      restore_allowed_channels:
        - telegram:DEINE_CHAT_ID   # Tokens restore nur hier
    injection-shield:
      mode: audit                  # erst 24 h audit, dann enforcement
      allowed_domains: [api.openai.com, api.anthropic.com, ollama.com]
      telegram:
        enabled: true
        min_severity: medium
```

## Compliance & Reporting

- DSGVO out of the box: AVV-Checkliste und Verzeichnis-Vorlage ([`privacy-shield/docs/dsgvo-mapping.md`](privacy-shield/docs/dsgvo-mapping.md))
- EU-AI-Act-/DSGVO-Compliance-Report aus dem Audit-Trail — PDF/CSV/JSON, Ed25519-signiert, ein Befehl: `privacy-shield audit-export --from 2026-08-01 --to 2026-08-31 --format pdf`

## Security & Qualität

- Unabhängiges Multi-Agent-Security-Audit über beide Pakete; bestätigte Findings behoben, Re-Audit sauber — siehe [SECURITY-AUDIT.md](SECURITY-AUDIT.md)
- Über 1.000 Pytest-Tests in privacy-shield, 410+ in injection-shield; CI auf Python 3.10–3.12 mit Lint und mypy strict
- Geteilter Token-Format-Vertrag (`TOKEN_<TYP>_<10-Hex>_<Serial>`) zwischen beiden Paketen, Source of Truth im Code
- Bucketed Audit-Log (SHA-256-Hashes statt Klartext), memory-bounded Caches, durchgehend fail-closed-Defaults

## Dokumentation

- [`privacy-shield/docs/`](privacy-shield/docs/) — User-Guide, Installation, Security, DSGVO, Reasoning-Protection
- [`injection-shield/docs/`](injection-shield/docs/) — Architektur, Installation, Operations, Troubleshooting
- [SECURITY-AUDIT.md](SECURITY-AUDIT.md) — Audit-Methodik und Findings-Ledger (zweisprachig)

## Lizenz & Support

MIT — siehe [LICENSE](LICENSE). Bitte **keine** öffentlichen Issues für Schwachstellen; kontaktiere die MOTHR-Maintainer direkt.

---

> **English:** [README.md](README.md)
