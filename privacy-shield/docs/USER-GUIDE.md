# Privacy-Shield — Bedienungsanleitung (User Guide)

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Privacy-Shield — Bedienungsanleitung (User Guide)

**Version:** 1.7.0 (2026-09-09)
**Status:** Production-ready 
**Lizenz:** MIT

---

## Inhalt

1. [Einführung — Was ist Privacy-Shield?](#1-einführung--was-ist-privacy-shield)
2. [Installation — Schritt für Schritt](#2-installation--schritt-für-schritt)
3. [Konfiguration — Alle Optionen erklärt](#3-konfiguration--alle-optionen-erklärt)
4. [CLI-Befehle — setup, status, scan, pseudonymize, test](#4-cli-befehle--setup-status-scan-pseudonymize-test)
5. [Hermes-Hook-Integration](#5-hermes-hook-integration)
6. [Use-Cases — 5 konkrete Beispiele](#6-use-cases--5-konkrete-beispiele)
7. [Patterns-Übersicht — alle 58 Pattern-Typen](#7-patterns-übersicht--alle-58-pattern-typen)
8. [Modes — off/audit/limited/strict/paranoid](#8-modes--offauditlimitedstrictparanoid)
9. [PDF + OCR — Konfiguration + Beispiele](#9-pdf--ocr--konfiguration--beispiele)
10. [Troubleshooting — Häufige Fehler](#10-troubleshooting--häufige-fehler)
11. [FAQ — Häufige Fragen](#11-faq--häufige-fragen)
12. [Best-Practices](#12-best-practices)

---

## 1. Einführung — Was ist Privacy-Shield?

Privacy-Shield ist ein Hermes-Plugin, das **personenbezogene Daten (PII)** in deinen LLM-Anfragen automatisch erkennt und durch **pseudonyme Tokens** ersetzt. Die echten Daten verlassen deinen Rechner nicht — die KI-Cloud sieht nur Tokens.

### Wie funktioniert das?

```
Du tippst:    "Kontakt: dirk@example.com, IBAN DE89370400440532013000"
                         ↓ Privacy-Shield
LLM bekommt:  "Kontakt: TOKEN_EMAIL_a3f9b2c1d8_001, TOKEN_IBAN_7e4f2a9b10_002"
                         ↓ LLM antwortet
Du liest:     "Kontakt: dirk@example.com, IBAN DE89370400440532013000"
```

### Warum brauchst du das?

- **DSGVO Art. 28** — Auftragsverarbeitung verlangt Schutzmassnahmen für PII
- **EU AI Act** — Trainingsdaten müssen DSGVO-konform sein
- **Vertrauen** — Du kannst Cloud-LLMs nutzen, ohne Mandanten-/Patienten-Daten preiszugeben
- **Compliance-Audit** — Nachvollziehbar wer wann welche Daten geschickt hat (bucketed, ohne Klartext)

### Was Privacy-Shield **nicht** macht

- Es ersetzt keine Rechtsberatung (siehe AVV-Checkliste)
- Es schützt nicht vor PII in **Antworten** des LLMs (das musst du selbst prüfen)
- Es ist kein VPN oder vollständiger Anonymisierungsdienst — nur **PII-Filter** für LLM-Egress

---

## 2. Installation — Schritt für Schritt

> Eine ausführliche Installations-Anleitung mit allen Edge-Cases findest du in [INSTALL.md](INSTALL.md).

```bash
# 1. Repository klonen (oder nutze deinen vorhandenen Pfad)
cd ~/.hermes/plugins/privacy-shield

# 2. Python-Dependencies installieren
pip install -e .

# 3. Encryption-Key generieren (einmalig)
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 4. Plugin in Hermes aktivieren
# In deiner config.yaml:
#   plugins.enabled: [privacy-shield]

# 5. Verifizieren
privacy-shield --help
privacy-shield scan "Test: d@example.com"
```

**System-Voraussetzungen:**

- Python 3.10 oder höher
- Tesseract 5.5+ (für OCR)
- Hermes 0.1+ (für Hook-Integration)
- `pass` CLI (für Key-Storage) — alternativ `.env`-File

---

## 3. Konfiguration — Alle Optionen erklärt

Die Konfiguration lebt in deiner Hermes `config.yaml` und/oder in `~/.hermes/plugins/privacy-shield/plugin.yaml`.

### Haupteinstellungen (`plugin.yaml`)

| Option | Default | Beschreibung |
|---|---|---|
| `enabled` | `true` | Plugin global aktiviert/deaktiviert |
| `mode` | `limited` | Betriebsmodus: `off` / `audit` / `limited` / `strict` / `paranoid` |
| `detection_engine` | `regex` | Aktuell nur Regex — NER (Phase 3) folgt |
| `token_style` | `deterministic` | `deterministic` (gleicher Input → gleicher Token) oder `random` |
| `fallback_on_timeout` | `block` | Bei Plugin-Error: `block` / `allow` |
| `max_latency_ms` | `80` | Max. Verarbeitungszeit pro Hook-Call |
| `audit_targets` | `["sqlite"]` | Wo Audit-Logs landen |

### PDF + OCR (Phase 1 + 2)

| Option | Default | Beschreibung |
|---|---|---|
| `pdf_enabled` | `true` | PDF-Pipeline aktiviert |
| `image_enabled` | `true` | OCR-Pipeline aktiviert |
| `image_max_size_mb` | `50` | Max. Bildgrösse in MB (DoS-Guard) |
| `image_restore_dir` | `~/.hermes/privacy/restore/image` | Wohin sanitized Images geschrieben werden |
| `ocr_lang` | `deu+eng` | Tesseract-Sprachpakete (Komma-getrennt) |
| `ocr_min_confidence` | `30` | Minimale Tesseract-Confidence (0-100) |

### Token-Storage (Security-Kern)

| Option | Default | Beschreibung |
|---|---|---|
| `key_source` | `pass` | `pass` / `env` / `workshop` |
| `key_pass_path` | `hermes/privacy-shield-key` | Pfad im pass-Store |
| `key_env_var` | `PRIVACY_SHIELD_KEY` | Fallback-Env-Variable |
| `crypto_algorithm` | `AES-256-GCM` | Symmetrisches Verfahren |
| `pbkdf2_iterations` | `100000` | Key-Derivation-Iterations |
| `max_session_salts` | `1000` | LRU-Cache für Session-Salts |
| `max_token_cache` | `10000` | LRU-Cache für Tokens |

### Egress-Whitelist

```yaml
privacy_shield:
  egress_whitelist:
    - channel: telegram
      chat_id: YOUR_CHAT_ID
      restore: true
    - channel: cli
      restore: true
    - channel: api
      restore: false  # kein Restore bei API-Calls
```

Restore passiert **nur** in Channels, die in der Whitelist stehen. Das verhindert versehentliche PII-Leaks.

---

## 4. CLI-Befehle — setup, status, scan, pseudonymize, test

```bash
privacy-shield --help                 # Hilfe
privacy-shield setup --key-install    # Encryption-Key einrichten
privacy-shield status                 # Aktive Sessions + Mapping-Counts
privacy-shield scan "text"            # Was würde erkannt werden? (ohne Ersetzung)
privacy-shield pseudonymize "text"    # Ersetzen + Token-Liste ausgeben
privacy-shield test --text "..."      # Round-Trip-Test (Erkennung → Ersetzung → Restore)
privacy-shield map --list             # Aktuelle Token-Mappings anzeigen
privacy-shield map --close-session <id>  # Session beenden (Crypto-Shredding)
privacy-shield map --close-all        # Alle Sessions beenden
privacy-shield doctor                 # System-Selbsttest
```

### Beispiel: `scan` vs `pseudonymize` vs `test`

```bash
$ privacy-shield scan "Mail an dirk@example.com"
[DETECTED] email: dirk@example.com (1 match)

$ privacy-shield pseudonymize "Mail an dirk@example.com"
[SCAN] email pattern matched
[REPLACE] dirk@example.com → TOKEN_EMAIL_a3f9b2c1d8_001
Mail an TOKEN_EMAIL_a3f9b2c1d8_001

$ privacy-shield test --text "Mail an dirk@example.com"
[ROUND-TRIP] Token: TOKEN_EMAIL_a3f9b2c1d8_001
[RESTORE] → dirk@example.com
[OK] Round-trip successful
```

---

## 5. Hermes-Hook-Integration

Privacy-Shield hängt sich in zwei Hermes-Hooks ein:

- **`pre_llm_call(prompt, context)`** — Wird aufgerufen **bevor** die Anfrage zum LLM geht. Privacy-Shield erkennt PII im Prompt (plus PDFs/Bilder in `context.attachments`), pseudonymisiert, und gibt den sanitisierten Prompt zurück.
- **`transform_llm_output(response, context)`** — Wird aufgerufen **nachdem** das LLM geantwortet hat. Privacy-Shield ersetzt Tokens in der Antwort zurück zu Original-Daten — **nur** wenn der Ziel-Channel in der `egress_whitelist` steht.

### Hook-Flow

```
pre_llm_call():
    1. PDF → pdfplumber → Text
    2. Bild → Tesseract OCR → Text
    3. Plain-Text direkt
    4. RegexPIIDetector.scan() — 58 Patterns
    5. Pseudonymizer.replace()
    6. Mapping-Table.store() (AES-256-GCM, in-memory)
    → return sanitized prompt

LLM call (Provider bekommt nur Tokens)

transform_llm_output():
    1. Channel-Check (egress_whitelist)
    2. Mapping-Table.restore() (Token → Original)
    → return restored response
```

### Provider-Detection

Wenn der Provider ein **lokales Ollama** ist (kein Cloud-Egress), wird Privacy-Shield automatisch übersprungen — kein Shield nötig, weil keine Daten das Netzwerk verlassen.

```yaml
privacy_shield:
  provider_bypass:
    - ollama
    - vllm-local
    - hermes-agent-internal
```

---

## 6. Use-Cases — 5 konkrete Beispiele

### Use-Case 1: Kanzlei (Mandanten-Verträge)

```python
# Workflow
mandant_schickt_pdf("rechnung_mueller_2026.pdf")
  ↓ Hermes lädt Datei
pre_llm_call() extrahiert Text, pseudonymisiert Mandantendaten
  ↓ LLM bekommt: "Rechnung an TOKEN_NAME_xxx_001, IBAN TOKEN_IBAN_xxx_002"
LLM analysiert Vertrag
  ↓ Antwort kommt mit Tokens zurück
transform_llm_output() restauriert im Telegram-Channel (Whitelist)
  ↓ Du liest: "Rechnung an Müller GmbH, IBAN DE89..."
```

### Use-Case 2: Arztpraxis (Befunde)

```python
# Workflow
arzt_fotografiert_befund("befund_schmidt.jpg")
  ↓ Hermes lädt Bild
pre_llm_call() macht OCR (Tesseract deu+eng), pseudonymisiert Patientendaten
  ↓ LLM bekommt: "Patient TOKEN_NAME_xxx_001, geboren TOKEN_DOB_xxx_002..."
LLM klassifiziert Befund
  ↓ Antwort kommt mit Tokens zurück
transform_llm_output() restauriert in deinem geschützten Hermes-Chat
  ↓ Du liest Original-Daten
```

### Use-Case 3: Solo-Berater (Rechnungen)

```python
# Workflow
du_scannst_rechnung("rechnung_steuer_2026.png")
  ↓ Hermes lädt Bild
pre_llm_call() macht OCR + Pseudonymisierung
  ↓ LLM bekommt Tokens
LLM extrahiert: "Rechnungsbetrag, Steuersatz, Datum"
  ↓ Antwort mit Tokens
transform_llm_output() restauriert
  ↓ Du hast strukturierte Daten + Original-Beleg
```

### Use-Case 4: Entwickler (Code-Snippets mit API-Keys)

```python
# Workflow
du_pastest_code("Connect mit API_KEY=ghp_xxxxxxxxxxxx")
  ↓ pre_llm_call() erkennt GitHub-PAT
LLM bekommt: "Connect mit API_KEY=TOKEN_GITHUB_PAT_xxx_001"
  ↓ LLM hilft beim Debugging
transform_llm_output() restauriert im CLI (Whitelist)
  ↓ Du siehst deinen echten Key (nur lokal!)
```

### Use-Case 5: Marketing-Team (Newsletter-Analyse)

```python
# Workflow
csv_mit_kunden_emails("newsletter_subscribers.csv")
  ↓ pre_llm_call() pseudonymisiert alle E-Mails
LLM analysiert Engagement-Muster
  ↓ Antwort: "Segment X hat hohe Öffnungsrate"
transform_llm_output() restauriert nur in team-internem Slack
  ↓ Marketing sieht E-Mails, aber LLM-Provider nie
```

---

## 7. Patterns-Übersicht — alle 58 Pattern-Typen

Privacy-Shield erkennt 58 verschiedene PII-Patterns in 7 Kategorien:

### Kategorie A: Kontakt (Email, Phone, Adresse)
1. `email` — E-Mail-Adressen
2. `phone_de` — Deutsche Telefonnummern (+49, 0049, 0...)
3. `phone_intl` — Internationale Telefonnummern
4. `address_de` — PLZ + Stadt
5. `name` — Personenname (experimentell, Phase 2)

### Kategorie B: Finanzdaten
6. `iban_de` — Deutsche IBAN (mod-97-geprüft)
7. `iban_eu` — EU-IBAN (mod-97-geprüft)
8. `credit_card` — Kreditkartennummer (Luhn-geprüft)
9. `bic` — BIC (ISO 9362)
10. `vat_de` — Deutsche USt-ID
11. `vat_eu` — EU-USt-ID
12. `tax_id_de` — Deutsche Steuer-ID (11 Ziffern)
13. `handelsregisternummer` — HRB-Nummer
14. `steuernummer_alt` — Alte Steuernummer (Bundesländer)

### Kategorie C: Authentifizierung
15. `jwt` — JSON Web Tokens
16. `oauth_token` — OAuth Bearer-Tokens
17. `github_pat` — GitHub Personal Access Tokens (ghp_, gho_, ghu_, ghs_, ghr_)
18. `slack_token` — Slack-Tokens (xoxb-, xoxp-, xoxa-)
19. `aws_access_key` — AWS Access-Keys (AKIA...)
20. `aws_secret_key` — AWS Secret-Keys
21. `google_api_key` — Google API-Keys (AIza...)
22. `stripe_key` — Stripe Live/Test-Keys
23. `stripe_restricted_key` — Stripe Restricted-Keys
24. `private_key_pem` — PEM-encoded Private Keys
25. `ssh_private_key` — OpenSSH Private Keys
26. `pgp_private_key` — PGP Private Key Blocks

### Kategorie D: Crypto-Wallets
27. `btc_address` — Bitcoin-Adressen (Legacy, SegWit, Bech32)
28. `eth_address` — Ethereum-Adressen (0x...)
29. `btc_xpub` — BIP-32 Extended Public Keys
30. `monero_address` — Monero-Adressen
31. `litecoin_address` — Litecoin-Adressen
32. `crypto_tx_hash` — Crypto-Transaktions-Hashes

### Kategorie E: Identifikatoren
33. `ip_v4` — IPv4-Adressen
34. `ip_v6` — IPv6-Adressen
35. `mac_address` — MAC-Adressen
36. `imei` — IMEI (15 Ziffern)
37. `imsi` — IMSI (14-15 Ziffern)
38. `uuid_v4` — UUID v4
39. `session_id` — Session-IDs (Cookie-Format)
40. `cookie_id` — Cookie-IDs (key=value-Format)
41. `passport_de` — Deutsche Reisepass-Nummern
42. `personalausweis_de` — Deutsche Personalausweis-Nummern
43. `fahrgestellnummer` — VIN (17-stellig)

### Kategorie F: Netzwerk-Identifikatoren
44. `url_with_credentials` — URLs mit eingebetteten Credentials
45. `url_with_pii` — URLs mit PII im Path/Query

### Kategorie G: Kontextuelle / Implizite PII
46. `ssn_us` — US Social Security Numbers
47. `date_of_birth` — Geburtsdatum (kontextabhängig)
48. `org_name` — Organisationsname (kontextabhängig)
49. `location` — Standort (kontextabhängig)
50. `context_leak_email` — Implizite E-Mail-Hinweise
51. `context_leak_phone` — Implizite Telefon-Hinweise
52. `context_leak_name` — Implizite Namens-Hinweise

### Erweiterte Patterns (45 BASE_EXTENDED_PATTERNS)
53-58. Weitere Patterns aus `extended_patterns.py` — siehe Source-Code für Details.

> **Hinweis:** Die genauen Confidence-Werte pro Pattern sind in `detectors/extended_patterns.py` definiert. Low-Confidence-Patterns (z.B. `cookie_id`, `name`) werden mit `ocr_min_confidence`-Threshold gefiltert.

---

## 8. Modes — off/audit/limited/strict/paranoid

| Mode | Verhalten | Wann nutzen? |
|---|---|---|
| `off` | Plugin komplett deaktiviert | Debugging, Privacy-Shield-Probleme |
| `audit` | Erkennt + loggt, ersetzt aber nichts | PII-Scan ohne Eingriff (z.B. für DSGVO-Audit) |
| `limited` | **Standard**. Pseudonymisiert mit Tokens | Normaler Alltagsbetrieb |
| `strict` | Blockiert Cloud-/External-Provider bei PII | Wenn gar keine Daten zur Cloud sollen |
| `paranoid` | Blockiert JEDE Anfrage mit PII | Maximale Sicherheit (z.B. Hochsicherheits-Branchen) |

### Mode setzen

```yaml
# config.yaml
privacy_shield:
  mode: limited  # Standard
```

Oder per Env-Variable:
```bash
PRIVACY_SHIELD_MODE=paranoid hermes chat
```

### Mode-Verhalten im Detail

```bash
# limited (default)
"Anfrage mit dirk@example.com" → "Anfrage mit TOKEN_EMAIL_xxx_001"  # OK

# strict
"Anfrage mit dirk@example.com" → [BLOCKED: PII detected, use local LLM]  # Cloud-only block

# paranoid
"Anfrage mit dirk@example.com" → [BLOCKED: PII detected]  # Immer block, egal welcher Provider
```

---

## 9. PDF + OCR — Konfiguration + Beispiele

### PDF-Pipeline (Phase 1)

Privacy-Shield extrahiert Text aus text-basierten PDFs und erstellt ein **sanitisiertes PDF** (mit Tokens statt PII).

**Unterstützt:**
- Text-basierte PDFs (nicht gescannte Bilder!)
- `pdfplumber` für Extraktion
- `reportlab` für Sanitization
- Output: `<original>_sanitized.pdf` in `pdf_restore_dir`

**Beispiel:**
```python
# Du lädst ein PDF in Hermes
mandant_rechnung = open("rechnung_2026.pdf", "rb")

# Privacy-Shield:
# 1. Extrahiert Text via pdfplumber
# 2. Pseudonymisiert PII
# 3. Rendert sanitized PDF via reportlab
# → ~/.hermes/privacy/restore/pdf/rechnung_2026_sanitized.pdf
```

### OCR-Pipeline (Phase 2)

**Unterstützt:**
- Formate: JPEG, PNG, WebP, HEIC, HEIF, TIFF, BMP
- Engine: Tesseract 5.5.2 (lokal, kein Cloud-Egress!)
- Sprachen: `deu+eng` (default), konfigurierbar via `ocr_lang`
- HEIC-Support: opt-in via `pillow-heif` (graceful degradation wenn fehlend)

**Beispiel:**
```python
# Du lädst ein Bild in Hermes
befund_foto = open("befund.jpg", "rb")

# Privacy-Shield:
# 1. Tesseract OCR → Text + Bounding-Boxes
# 2. Filterung: Wörter mit Confidence < ocr_min_confidence (default 30)
# 3. Pseudonymisierung via RegexPIIDetector
# 4. Sanitisiertes Bild (Original + Token-Underlay)
# → ~/.hermes/privacy/restore/image/befund_sanitized.png (chmod 700)
```

### Konfiguration

```yaml
privacy_shield:
  pdf_enabled: true
  image_enabled: true
  image_max_size_mb: 50
  image_restore_dir: ~/.hermes/privacy/restore/image
  ocr_lang: deu+eng       # Komma-getrennt für mehrere Sprachen
  ocr_min_confidence: 30  # 0-100, niedrigere Werte = mehr erkannt aber mehr False-Positives
```

### Troubleshooting OCR

```bash
# Tesseract installieren (macOS)
brew install tesseract tesseract-lang

# Tesseract-Sprachen prüfen
tesseract --list-langs

# Verfügbare Version
tesseract --version  # Sollte 5.5+ sein
```

---

## 10. Troubleshooting — Häufige Fehler

### "Encryption key not found"

**Problem:** Privacy-Shield findet den Key nicht.
**Lösung:**
```bash
# 1. Check pass-Store
pass hermes/privacy-shield-key

# 2. Wenn nicht vorhanden: generieren
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 3. Oder Env-Variable setzen
export PRIVACY_SHIELD_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

### "OCR failed: tesseract not found"

**Problem:** Tesseract ist nicht installiert.
**Lösung:**
```bash
# macOS
brew install tesseract tesseract-lang

# Ubuntu/Debian
sudo apt-get install tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng

# Verifizieren
tesseract --version  # Sollte 5.5+ sein
```

### "Image too large (max 50 MB)"

**Problem:** Bild überschreitet DoS-Guard-Limit.
**Lösung:** Bild komprimieren oder Limit erhöhen:
```yaml
privacy_shield:
  image_max_size_mb: 100  # oder höher
```

### "Plugin not active — Hermes uses direct LLM call"

**Problem:** Privacy-Shield ist nicht in Hermes geladen.
**Lösung:**
```bash
# 1. Check ob Plugin enabled ist
hermes plugins list

# 2. In config.yaml aktivieren
# plugins.enabled: [privacy-shield]

# 3. Hermes reloaden
hermes plugins reload privacy-shield
```

### "Token nicht restored"

**Problem:** Du siehst Tokens statt Original-Daten in der LLM-Antwort.
**Ursache:** Channel ist nicht in der `egress_whitelist`.
**Lösung:**
```yaml
privacy_shield:
  egress_whitelist:
    - channel: cli  # oder telegram, etc.
      restore: true
```

### "Tests schlagen fehl"

**Lösung:**
```bash
# Test-Stand prüfen
cd ~/.hermes/plugins/privacy-shield
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -v 2>&1 | tail -30

# Falls 369 grün sind, ist alles OK
# Falls weniger: welcher Test schlägt fehl? Welcher Fehler?
```

---

## 11. FAQ — Häufige Fragen

### F: Werden meine echten Daten irgendwo gespeichert?

**A:** Nein. Die Mapping-Tabelle lebt nur **in-memory** während der Session. Bei Session-Ende wird sie **crypto-shredded** (Key wird vergessen, Daten sind unentschlüsselbar). Optional kann sie mit Pass-Key auf Disk persistiert werden, aber das ist **nicht** der Default.

### F: Was passiert, wenn die LLM-Antwort Tokens enthält?

**A:** Privacy-Shields `transform_llm_output()` ersetzt Tokens zurück zu Original-Daten **bevor** du sie siehst. Das funktioniert nur, wenn der Channel in der `egress_whitelist` steht.

### F: Kann ich Privacy-Shield umgehen?

**A:** Ja, mit dem **Cache-Bypass-Tag**. Für lokale Daten (z.B. Vault-Reads) wird Privacy-Shield automatisch übersprungen. Du kannst das auch manuell triggern.

### F: Ist Privacy-Shield DSGVO-konform?

**A:** Privacy-Shield ist ein **technisches Hilfsmittel** zur Pseudonymisierung gemäß DSGVO Art. 4 Nr. 5. Es ersetzt **keine** Rechtsberatung. Siehe [AVV-Checkliste](AVV-Checkliste.md) und [VVT-Template](VVT-Template.md) für die organisatorischen Schritte.

### F: Welche LLM-Provider werden unterstützt?

**A:** Alle, die Hermes unterstützt (OpenAI, Anthropic, Google, Mistral, lokales Ollama, etc.). Lokale Provider werden automatisch gebypasst.

### F: Was ist mit Audio/Video?

**A:** Aktuell nicht unterstützt. Roadmap:
- Phase 3: DOCX/XLSX/PPTX
- Phase 4: Audio-Transkription

### F: Kann ich eigene Patterns hinzufügen?

**A:** Ja, in `detectors/extended_patterns.py` (`BASE_EXTENDED_PATTERNS`-Liste). Folge dem `CompiledPattern`-Format.

### F: Was kostet Privacy-Shield?

**A:** Nichts — MIT-Lizenz. Du brauchst nur deinen eigenen LLM-Account.

---

## 12. Best-Practices

### Sicherheit

1. **Key-Rotation** alle 90 Tage (siehe [SECURITY.md](SECURITY.md))
2. **`paranoid`-Mode** für hochsensible Daten (Medizin, Recht, Behörden)
3. **Egress-Whitelist** restriktiv halten — nur Channels, denen du vertraust
4. **Audit-Logs** regelmässig prüfen (SQLite oder extern)
5. **Token-Format-Updates** mit `privacy-shield map --close-all` aktivieren

### Performance

1. **`max_latency_ms: 80`** ist ein guter Default — bei Engpässen höher setzen
2. **LRU-Caches** tunen: `max_session_salts: 1000`, `max_token_cache: 10000`
3. **OCR für grosse Bilder** deaktivieren wenn nicht nötig
4. **PDF-Pipeline** nur bei Bedarf aktivieren (`pdf_enabled: false` wenn keine PDFs)

### Compliance

1. **AVV** (Auftragsverarbeitungsvertrag) mit deinem LLM-Provider abschliessen
2. **VVT** (Verzeichnis der Verarbeitungstätigkeiten) führen — Template in [VVT-Template.md](VVT-Template.md)
3. **DSGVO-Mapping** durchlesen — siehe [dsgvo-mapping.md](dsgvo-mapping.md)
4. **Audit-Logs** mindestens 12 Monate aufbewahren (DSGVO-Standard)

### Development

1. **Tests vor jedem Release**: `~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -q`
2. **Custom Patterns** immer mit Tests abdecken (siehe `tests/test_*_detector.py`)
3. **Security-Review** bei jeder Änderung an Detection-Logik (Phase 2: Seraph)
4. **CHANGELOG.md** aktualisieren bei jedem Release

---

**Weitere Dokumentation:**

- [INSTALL.md](INSTALL.md) — Detaillierte Installation
- [SECURITY.md](SECURITY.md) — Sicherheits-Properties + Threat-Model
- [architecture.md](architecture.md) — Technische Architektur
- [dsgvo-mapping.md](dsgvo-mapping.md) — DSGVO-Compliance-Mapping
- [AVV-Checkliste.md](AVV-Checkliste.md) — Auftragsverarbeitungsvertrag-Checkliste
- [VVT-Template.md](VVT-Template.md) — Verzeichnis der Verarbeitungstätigkeiten

**Support:** GitHub Issues (PRIVAT-Mode)

---

## English

# Privacy-Shield — User Guide

**Version:** 1.7.0 (2026-09-09)
**Status:** Production-ready
**License:** MIT

---

## Contents

1. [Introduction — What is Privacy-Shield?](#1-introduction--what-is-privacy-shield)
2. [Installation — Step by Step](#2-installation--step-by-step)
3. [Configuration — All Options Explained](#3-configuration--all-options-explained)
4. [CLI Commands — setup, status, scan, pseudonymize, test](#4-cli-commands--setup-status-scan-pseudonymize-test)
5. [Hermes-Hook-Integration](#5-hermes-hook-integration)
6. [Use-Cases — 5 Concrete Examples](#6-use-cases--5-concrete-examples)
7. [Patterns Overview — all 58 Pattern Types](#7-patterns-overview--all-58-pattern-types)
8. [Modes — off/audit/limited/strict/paranoid](#8-modes--offauditlimitedstrictparanoid)
9. [PDF + OCR — Configuration + Examples](#9-pdf--ocr--configuration--examples)
10. [Troubleshooting — Common Errors](#10-troubleshooting--common-errors)
11. [FAQ — Frequently Asked Questions](#11-faq--frequently-asked-questions)
12. [Best-Practices](#12-best-practices)

---

## 1. Introduction — What is Privacy-Shield?

Privacy-Shield is a Hermes plugin that **automatically detects personal data (PII)** in your LLM requests and replaces it with **pseudonymous tokens**. The real data never leaves your computer — the AI cloud sees only tokens.

### How does it work?

```
You type:    "Contact: dirk@example.com, IBAN DE89370400440532013000"
                         ↓ Privacy-Shield
LLM gets:   "Contact: TOKEN_EMAIL_a3f9b2c1d8_001, TOKEN_IBAN_7e4f2a9b10_002"
                         ↓ LLM responds
You read:   "Contact: dirk@example.com, IBAN DE89370400440532013000"
```

### Why do you need it?

- **GDPR Art. 28** — Data processing agreements require protective measures for PII
- **EU AI Act** — Training data must be GDPR-compliant
- **Trust** — You can use cloud LLMs without disclosing client/patient data
- **Compliance audit** — Traceable who sent what data when (bucketed, without plaintext)

### What Privacy-Shield does **NOT** do

- It does not replace legal advice (see DPA checklist)
- It does not protect against PII in **responses** from the LLM (you must check this yourself)
- It is not a VPN or full anonymization service — only a **PII filter** for LLM egress

---

## 2. Installation — Step by Step

> A detailed installation guide with all edge cases can be found in [INSTALL.md](INSTALL.md).

```bash
# 1. Clone repository (or use your existing path)
cd ~/.hermes/plugins/privacy-shield

# 2. Install Python dependencies
pip install -e .

# 3. Generate encryption key (once)
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 4. Activate plugin in Hermes
# In your config.yaml:
#   plugins.enabled: [privacy-shield]

# 5. Verify
privacy-shield --help
privacy-shield scan "Test: d@example.com"
```

**System Requirements:**

- Python 3.10 or higher
- Tesseract 5.5+ (for OCR)
- Hermes 0.1+ (for hook integration)
- `pass` CLI (for key storage) — alternatively `.env` file

---

## 3. Configuration — All Options Explained

The configuration lives in your Hermes `config.yaml` and/or in `~/.hermes/plugins/privacy-shield/plugin.yaml`.

### Main Settings (`plugin.yaml`)

| Option | Default | Description |
|---|---|---|
| `enabled` | `true` | Plugin globally enabled/disabled |
| `mode` | `limited` | Operating mode: `off` / `audit` / `limited` / `strict` / `paranoid` |
| `detection_engine` | `regex` | Currently only Regex — NER (Phase 3) follows |
| `token_style` | `deterministic` | `deterministic` (same input -> same token) or `random` |
| `fallback_on_timeout` | `block` | On plugin error: `block` / `allow` |
| `max_latency_ms` | `80` | Max. processing time per hook call |
| `audit_targets` | `["sqlite"]` | Where audit logs go |

### PDF + OCR (Phase 1 + 2)

| Option | Default | Description |
|---|---|---|
| `pdf_enabled` | `true` | PDF pipeline enabled |
| `image_enabled` | `true` | OCR pipeline enabled |
| `image_max_size_mb` | `50` | Max. image size in MB (DoS guard) |
| `image_restore_dir` | `~/.hermes/privacy/restore/image` | Where sanitized images are written |
| `ocr_lang` | `deu+eng` | Tesseract language packs (comma-separated) |
| `ocr_min_confidence` | `30` | Minimum Tesseract confidence (0-100) |

### Token-Storage (Security Core)

| Option | Default | Description |
|---|---|---|
| `key_source` | `pass` | `pass` / `env` / `workshop` |
| `key_pass_path` | `hermes/privacy-shield-key` | Path in pass store |
| `key_env_var` | `PRIVACY_SHIELD_KEY` | Fallback env variable |
| `crypto_algorithm` | `AES-256-GCM` | Symmetric algorithm |
| `pbkdf2_iterations` | `100000` | Key derivation iterations |
| `max_session_salts` | `1000` | LRU cache for session salts |
| `max_token_cache` | `10000` | LRU cache for tokens |

### Egress Whitelist

```yaml
privacy_shield:
  egress_whitelist:
    - channel: telegram
      chat_id: YOUR_CHAT_ID
      restore: true
    - channel: cli
      restore: true
    - channel: api
      restore: false  # no restore for API calls
```

Restore happens **only** in channels that are on the whitelist. This prevents accidental PII leaks.

---

## 4. CLI Commands — setup, status, scan, pseudonymize, test

```bash
privacy-shield --help                 # Help
privacy-shield setup --key-install    # Set up encryption key
privacy-shield status                 # Active sessions + mapping counts
privacy-shield scan "text"            # What would be detected? (without replacement)
privacy-shield pseudonymize "text"    # Replace + output token list
privacy-shield test --text "..."      # Round-trip test (detect -> replace -> restore)
privacy-shield map --list             # Show current token mappings
privacy-shield map --close-session <id>  # End session (crypto-shredding)
privacy-shield map --close-all        # End all sessions
privacy-shield doctor                 # System self-test
```

### Example: `scan` vs `pseudonymize` vs `test`

```bash
$ privacy-shield scan "Mail to dirk@example.com"
[DETECTED] email: dirk@example.com (1 match)

$ privacy-shield pseudonymize "Mail to dirk@example.com"
[SCAN] email pattern matched
[REPLACE] dirk@example.com -> TOKEN_EMAIL_a3f9b2c1d8_001
Mail to TOKEN_EMAIL_a3f9b2c1d8_001

$ privacy-shield test --text "Mail to dirk@example.com"
[ROUND-TRIP] Token: TOKEN_EMAIL_a3f9b2c1d8_001
[RESTORE] -> dirk@example.com
[OK] Round-trip successful
```

---

## 5. Hermes-Hook-Integration

Privacy-Shield hooks into two Hermes hooks:

- **`pre_llm_call(prompt, context)`** — Called **before** the request goes to the LLM. Privacy-Shield detects PII in the prompt (plus PDFs/images in `context.attachments`), pseudonymizes, and returns the sanitized prompt.
- **`transform_llm_output(response, context)`** — Called **after** the LLM has responded. Privacy-Shield replaces tokens in the response back to original data — **only** if the target channel is on the `egress_whitelist`.

### Hook Flow

```
pre_llm_call():
    1. PDF -> pdfplumber -> Text
    2. Image -> Tesseract OCR -> Text
    3. Plain text directly
    4. RegexPIIDetector.scan() — 58 patterns
    5. Pseudonymizer.replace()
    6. Mapping-Table.store() (AES-256-GCM, in-memory)
    -> return sanitized prompt

LLM call (provider gets only tokens)

transform_llm_output():
    1. Channel check (egress_whitelist)
    2. Mapping-Table.restore() (token -> original)
    -> return restored response
```

### Provider Detection

If the provider is a **local Ollama** (no cloud egress), Privacy-Shield is automatically skipped — no shield needed because no data leaves the network.

```yaml
privacy_shield:
  provider_bypass:
    - ollama
    - vllm-local
    - hermes-agent-internal
```

---

## 6. Use-Cases — 5 Concrete Examples

### Use-Case 1: Law Firm (Client Contracts)

```python
# Workflow
client_sends_pdf("invoice_mueller_2026.pdf")
  ↓ Hermes loads file
pre_llm_call() extracts text, pseudonymizes client data
  ↓ LLM gets: "Invoice to TOKEN_NAME_xxx_001, IBAN TOKEN_IBAN_xxx_002"
LLM analyzes contract
  ↓ Response comes back with tokens
transform_llm_output() restores in Telegram channel (whitelist)
  ↓ You read: "Invoice to Müller GmbH, IBAN DE89..."
```

### Use-Case 2: Medical Practice (Medical Records)

```python
# Workflow
doctor_photographs_record("record_schmidt.jpg")
  ↓ Hermes loads image
pre_llm_call() does OCR (Tesseract deu+eng), pseudonymizes patient data
  ↓ LLM gets: "Patient TOKEN_NAME_xxx_001, born TOKEN_DOB_xxx_002..."
LLM classifies record
  ↓ Response comes back with tokens
transform_llm_output() restores in your protected Hermes chat
  ↓ You read original data
```

### Use-Case 3: Solo Consultant (Invoices)

```python
# Workflow
you_scan_invoice("invoice_tax_2026.png")
  ↓ Hermes loads image
pre_llm_call() does OCR + pseudonymization
  ↓ LLM gets tokens
LLM extracts: "Invoice amount, tax rate, date"
  ↓ Response with tokens
transform_llm_output() restores
  ↓ You have structured data + original receipt
```

### Use-Case 4: Developer (Code Snippets with API Keys)

```python
# Workflow
you_paste_code("Connect with API_KEY=«redacted:ghp_…»")
  ↓ pre_llm_call() detects GitHub PAT
LLM gets: "Connect with API_KEY=TOKEN_GITHUB_PAT_xxx_001"
  ↓ LLM helps with debugging
transform_llm_output() restores in CLI (whitelist)
  ↓ You see your real key (local only!)
```

### Use-Case 5: Marketing Team (Newsletter Analysis)

```python
# Workflow
csv_with_customer_emails("newsletter_subscribers.csv")
  ↓ pre_llm_call() pseudonymizes all emails
LLM analyzes engagement patterns
  ↓ Response: "Segment X has high open rate"
transform_llm_output() restores only in team-internal Slack
  ↓ Marketing sees emails, but LLM provider never does
```

---

## 7. Patterns Overview — all 58 Pattern Types

Privacy-Shield detects 58 different PII patterns in 7 categories:

### Category A: Contact (Email, Phone, Address)
1. `email` — Email addresses
2. `phone_de` — German phone numbers (+49, 0049, 0...)
3. `phone_intl` — International phone numbers
4. `address_de` — Zip code + city
5. `name` — Person's name (experimental, Phase 2)

### Category B: Financial Data
6. `iban_de` — German IBAN (mod-97 checked)
7. `iban_eu` — EU IBAN (mod-97 checked)
8. `credit_card` — Credit card number (Luhn checked)
9. `bic` — BIC (ISO 9362)
10. `vat_de` — German VAT ID
11. `vat_eu` — EU VAT ID
12. `tax_id_de` — German tax ID (11 digits)
13. `handelsregisternummer` — Commercial register number
14. `steuernummer_alt` — Old tax number (federal states)

### Category C: Authentication
15. `jwt` — JSON Web Tokens
16. `oauth_token` — OAuth Bearer tokens
17. `github_pat` — GitHub Personal Access Tokens (ghp_, gho_, ghu_, ghs_, ghr_)
18. `slack_token` — Slack tokens (xoxb-, xoxp-, xoxa-)
19. `aws_access_key` — AWS Access Keys (AKIA...)
20. `aws_secret_key` — AWS Secret Keys
21. `google_api_key` — Google API Keys (AIza...)
22. `stripe_key` — Stripe live/test keys
23. `stripe_restricted_key` — Stripe restricted keys
24. `private_key_pem` — PEM-encoded private keys
25. `ssh_private_key` — OpenSSH private keys
26. `pgp_private_key` — PGP private key blocks

### Category D: Crypto Wallets
27. `btc_address` — Bitcoin addresses (Legacy, SegWit, Bech32)
28. `eth_address` — Ethereum addresses (0x...)
29. `btc_xpub` — BIP-32 extended public keys
30. `monero_address` — Monero addresses
31. `litecoin_address` — Litecoin addresses
32. `crypto_tx_hash` — Crypto transaction hashes

### Category E: Identifiers
33. `ip_v4` — IPv4 addresses
34. `ip_v6` — IPv6 addresses
35. `mac_address` — MAC addresses
36. `imei` — IMEI (15 digits)
37. `imsi` — IMSI (14-15 digits)
38. `uuid_v4` — UUID v4
39. `session_id` — Session IDs (cookie format)
40. `cookie_id` — Cookie IDs (key=value format)
41. `passport_de` — German passport numbers
42. `personalausweis_de` — German ID card numbers
43. `fahrgestellnummer` — VIN (17 digits)

### Category F: Network Identifiers
44. `url_with_credentials` — URLs with embedded credentials
45. `url_with_pii` — URLs with PII in path/query

### Category G: Contextual / Implicit PII
46. `ssn_us` — US Social Security Numbers
47. `date_of_birth` — Date of birth (context-dependent)
48. `org_name` — Organization name (context-dependent)
49. `location` — Location (context-dependent)
50. `context_leak_email` — Implicit email hints
51. `context_leak_phone` — Implicit phone hints
52. `context_leak_name` — Implicit name hints

### Extended Patterns (45 BASE_EXTENDED_PATTERNS)
53-58. Additional patterns from `extended_patterns.py` — see source code for details.

> **Note:** The exact confidence values per pattern are defined in `detectors/extended_patterns.py`. Low-confidence patterns (e.g. `cookie_id`, `name`) are filtered with the `ocr_min_confidence` threshold.

---

## 8. Modes — off/audit/limited/strict/paranoid

| Mode | Behavior | When to use? |
|---|---|---|
| `off` | Plugin completely disabled | Debugging, Privacy-Shield problems |
| `audit` | Detects + logs, but replaces nothing | PII scan without intervention (e.g. for GDPR audit) |
| `limited` | **Default**. Pseudonymizes with tokens | Normal everyday operation |
| `strict` | Blocks cloud/external providers on PII | When no data should go to the cloud at all |
| `paranoid` | Blocks ANY request with PII | Maximum security (e.g. high-security industries) |

### Set mode

```yaml
# config.yaml
privacy_shield:
  mode: limited  # Default
```

Or via environment variable:
```bash
PRIVACY_SHIELD_MODE=paranoid hermes chat
```

### Mode Behavior in Detail

```bash
# limited (default)
"Request with dirk@example.com" -> "Request with TOKEN_EMAIL_xxx_001"  # OK

# strict
"Request with dirk@example.com" -> [BLOCKED: PII detected, use local LLM]  # Cloud-only block

# paranoid
"Request with dirk@example.com" -> [BLOCKED: PII detected]  # Always block, regardless of provider
```

---

## 9. PDF + OCR — Configuration + Examples

### PDF Pipeline (Phase 1)

Privacy-Shield extracts text from text-based PDFs and creates a **sanitized PDF** (with tokens instead of PII).

**Supported:**
- Text-based PDFs (not scanned images!)
- `pdfplumber` for extraction
- `reportlab` for sanitization
- Output: `<original>_sanitized.pdf` in `pdf_restore_dir`

**Example:**
```python
# You load a PDF into Hermes
client_invoice = open("invoice_2026.pdf", "rb")

# Privacy-Shield:
# 1. Extracts text via pdfplumber
# 2. Pseudonymizes PII
# 3. Renders sanitized PDF via reportlab
# -> ~/.hermes/privacy/restore/pdf/invoice_2026_sanitized.pdf
```

### OCR Pipeline (Phase 2)

**Supported:**
- Formats: JPEG, PNG, WebP, HEIC, HEIF, TIFF, BMP
- Engine: Tesseract 5.5.2 (local, no cloud egress!)
- Languages: `deu+eng` (default), configurable via `ocr_lang`
- HEIC support: opt-in via `pillow-heif` (graceful degradation if missing)

**Example:**
```python
# You load an image into Hermes
medical_photo = open("record.jpg", "rb")

# Privacy-Shield:
# 1. Tesseract OCR -> Text + Bounding boxes
# 2. Filtering: words with confidence < ocr_min_confidence (default 30)
# 3. Pseudonymization via RegexPIIDetector
# 4. Sanitized image (original + token underlay)
# -> ~/.hermes/privacy/restore/image/record_sanitized.png (chmod 700)
```

### Configuration

```yaml
privacy_shield:
  pdf_enabled: true
  image_enabled: true
  image_max_size_mb: 50
  image_restore_dir: ~/.hermes/privacy/restore/image
  ocr_lang: deu+eng       # Comma-separated for multiple languages
  ocr_min_confidence: 30  # 0-100, lower values = more detected but more false positives
```

### Troubleshooting OCR

```bash
# Install Tesseract (macOS)
brew install tesseract tesseract-lang

# Check Tesseract languages
tesseract --list-langs

# Available version
tesseract --version  # Should be 5.5+
```

---

## 10. Troubleshooting — Common Errors

### "Encryption key not found"

**Problem:** Privacy-Shield cannot find the key.
**Solution:**
```bash
# 1. Check pass store
pass hermes/privacy-shield-key

# 2. If not present: generate
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 3. Or set env variable
export PRIVACY_SHIELD_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

### "OCR failed: tesseract not found"

**Problem:** Tesseract is not installed.
**Solution:**
```bash
# macOS
brew install tesseract tesseract-lang

# Ubuntu/Debian
sudo apt-get install tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng

# Verify
tesseract --version  # Should be 5.5+
```

### "Image too large (max 50 MB)"

**Problem:** Image exceeds DoS guard limit.
**Solution:** Compress image or increase limit:
```yaml
privacy_shield:
  image_max_size_mb: 100  # or higher
```

### "Plugin not active — Hermes uses direct LLM call"

**Problem:** Privacy-Shield is not loaded in Hermes.
**Solution:**
```bash
# 1. Check if plugin is enabled
hermes plugins list

# 2. Enable in config.yaml
# plugins.enabled: [privacy-shield]

# 3. Reload Hermes
hermes plugins reload privacy-shield
```

### "Token not restored"

**Problem:** You see tokens instead of original data in the LLM response.
**Cause:** Channel is not in the `egress_whitelist`.
**Solution:**
```yaml
privacy_shield:
  egress_whitelist:
    - channel: cli  # or telegram, etc.
      restore: true
```

### "Tests are failing"

**Solution:**
```bash
# Check test status
cd ~/.hermes/plugins/privacy-shield
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -v 2>&1 | tail -30

# If 369 are green, everything is OK
# If fewer: which test is failing? What error?
```

---

## 11. FAQ — Frequently Asked Questions

### Q: Are my real data stored anywhere?

**A:** No. The mapping table lives only **in-memory** during the session. At session end it is **crypto-shredded** (key is forgotten, data is undecryptable). Optionally it can be persisted to disk with the pass key, but that is **not** the default.

### Q: What happens if the LLM response contains tokens?

**A:** Privacy-Shield's `transform_llm_output()` replaces tokens back to original data **before** you see them. This only works if the channel is on the `egress_whitelist`.

### Q: Can I bypass Privacy-Shield?

**A:** Yes, with the **cache bypass tag**. For local data (e.g. vault reads), Privacy-Shield is automatically skipped. You can also trigger this manually.

### Q: Is Privacy-Shield GDPR-compliant?

**A:** Privacy-Shield is a **technical tool** for pseudonymization according to GDPR Art. 4 No. 5. It does **not** replace legal advice. See [AVV-Checkliste](AVV-Checkliste.md) and [VVT-Template](VVT-Template.md) for the organizational steps.

### Q: Which LLM providers are supported?

**A:** All that Hermes supports (OpenAI, Anthropic, Google, Mistral, local Ollama, etc.). Local providers are automatically bypassed.

### Q: What about audio/video?

**A:** Currently not supported. Roadmap:
- Phase 3: DOCX/XLSX/PPTX
- Phase 4: Audio transcription

### Q: Can I add custom patterns?

**A:** Yes, in `detectors/extended_patterns.py` (`BASE_EXTENDED_PATTERNS` list). Follow the `CompiledPattern` format.

### Q: How much does Privacy-Shield cost?

**A:** Nothing — MIT license. You only need your own LLM account.

---

## 12. Best-Practices

### Security

1. **Key rotation** every 90 days (see [SECURITY.md](SECURITY.md))
2. **`paranoid` mode** for highly sensitive data (medical, legal, government)
3. **Egress whitelist** keep restrictive — only channels you trust
4. **Audit logs** check regularly (SQLite or external)
5. **Token format updates** activate with `privacy-shield map --close-all`

### Performance

1. **`max_latency_ms: 80`** is a good default — raise if you have bottlenecks
2. **LRU caches** tune: `max_session_salts: 1000`, `max_token_cache: 10000`
3. **OCR for large images** disable if not needed
4. **PDF pipeline** enable only when needed (`pdf_enabled: false` if no PDFs)

### Compliance

1. **DPA** (data processing agreement) with your LLM provider
2. **RoPA** (record of processing activities) — template in [VVT-Template.md](VVT-Template.md)
3. **GDPR mapping** read — see [dsgvo-mapping.md](dsgvo-mapping.md)
4. **Audit logs** keep for at least 12 months (GDPR standard)

### Development

1. **Tests before every release**: `~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -q`
2. **Custom patterns** always cover with tests (see `tests/test_*_detector.py`)
3. **Security review** for every change to detection logic (Phase 2: Seraph)
4. **CHANGELOG.md** update for every release

---

**Further documentation:**

- [INSTALL.md](INSTALL.md) — Detailed installation
- [SECURITY.md](SECURITY.md) — Security properties + threat model
- [architecture.md](architecture.md) — Technical architecture
- [dsgvo-mapping.md](dsgvo-mapping.md) — GDPR compliance mapping
- [AVV-Checkliste.md](AVV-Checkliste.md) — Data processing agreement checklist
- [VVT-Template.md](VVT-Template.md) — Record of processing activities

**Support:** GitHub Issues (PRIVATE mode)
