# Privacy-Shield

🌐 Deutsch | [English](README.md)

DSGVO-/GDPR-konformes Hermes-Plugin zur Tokenisierung personenbezogener Daten (PII) in sichtbarem LLM-Output und Reasoning-Inhalten.

**Version:** 1.7.0 (2026-09-09) — 58 Erkennungsmuster · 820 Tests · PDF + Bild-OCR · Audit-Trail PDF/CSV/JSON-Export mit Ed25519-Signatur · Desktop-Controls-Pane · Reasoning-Pre-Intake-Tokenisierung (state.db-sicher)

## Features

- **58 Erkennungsmuster** in 7 Kategorien (E-Mail, IBAN, Telefon, Crypto-Wallets, JWT, OAuth, GitHub PAT, MAC/IMEI/IMSI, etc.)
- **Text + Markdown + Code** — Plain-Text-Verarbeitung
- **PDF-Pipeline** — Extrahiert Text aus textbasierten PDFs, tokenisiert, erzeugt sanitisiertes PDF
- **Bild-OCR** — JPG/PNG/HEIC/WebP/TIFF/BMP via Tesseract 5.5.2, mehrsprachig (deu+eng default)
- **AES-256-GCM-Verschlüsselung** mit PBKDF2 (100k Iterations) für Token-Mapping
- **In-Memory Mapping-Table** mit Crypto-Shredding (kein Disk-Leak)
- **Egress-Whitelist** — Restore nur in erlaubten Channels (z.B. dein Telegram-Bot)
- **Modes:** off / audit / limited / strict / paranoid
- **Provider-Erkennung** — Ollama-lokal = bypass (kein Cloud-Egress = kein Shield nötig)
- **Unicode-Normalisierung** (NFKC + Homoglyph-Mapping)
- **Cache-Bypass-Tag** für lokale Lesevorgänge (lokale Daten = kein Shield)
- **DSGVO-Konformität** — Out-of-the-box mit AVV-Checkliste + VVT-Vorlage

## Quickstart (5 Minuten)

```bash
# 1. Installieren (via Git — GitHub-Zugang erforderlich)
pip install git+https://github.com/MOTHR/hermes-security-suite#subdirectory=privacy-shield
# oder für Entwicklung mit editierbarem Source
pip install -e .  # in der Monorepo-Paketwurzel ausgefuehrt

# 2. Encryption-Key generieren (einmalig)
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 3. Plugin aktivieren (Hermes-Loader)
# In config.yaml: plugins.enabled: [privacy-shield]

# 4. Testen
privacy-shield --help
privacy-shield scan "Kontakt: alice@example.com"
privacy-shield test --text "Hilf mir mit alice@example.com und IBAN DE89370400440532013000"
```

## Desktop-Controls (v1.5.0+)

Privacy-Shield wird mit einem offiziellen Desktop-Plugin ausgeliefert, über das Einstellungen in der Hermes Desktop-App statt via YAML editiert werden können:

- Plugin an-/ausschalten
- Betriebsmodus wechseln (`off`/`audit`/`limited`/`strict`/`paranoid`)
- Confidence-Threshold anpassen
- Restore-allowed Channels verwalten
- PDF / Bild-OCR / Cache-Bypass toggeln
- Synthetischen Restore-Smoke-Test ausführen

Das Desktop-Plugin liegt unter `desktop-plugin/` und wird bei `pip install` automatisch nach `~/.hermes/desktop-plugins/privacy-shield-controls/` kopiert. **Kein manuelles Kopieren nötig.**

Das Backend ist in `dashboard/plugin_api.py` und wird vom Hermes Dashboard-Plugin-System unter `/api/plugins/privacy-shield/` gemountet.

Ein visueller Walkthrough steht in `docs/desktop-controls.md`.

## Reasoning-Schutz v1.7.0 (Pre-Intake)

Privacy-Shield erstreckt den Schutz auf **Reasoning-/Thinking-Blöcke** von OpenAI, Anthropic und Google. Diese inneren Gedanken können echte PII und Secrets enthalten, die nie im sichtbaren Output auftauchen (das [Stolen-Thoughts](https://stolen-thoughts.com)-Problem, 2026).

### Funktionsweise (zwei Ebenen)

**Ebene 1 — Pre-Intake-Redaktion (v1.7.0, schließt GB-009):**
- Der `post_api_request`-Hook feuert direkt nach dem Response-Intake — **bevor** Hermes den Turn in `state.db` persistiert.
- Er mutiert Reasoning-Felder (`reasoning`, `reasoning_content`, `reasoning_details`) **in-place auf dem Live-Assistant-Message-Objekt**.
- Ergebnis: Die persistierte Session enthält nur tokenisierte Reasoning-Texte — kein Raw-PII-Fenster in `state.db`.

**Ebene 2 — In-Memory-Redaktion (v1.6.1, Defense-in-Depth):**
- Der `post_llm_call`-Hook tokenisiert Reasoning-Felder im `conversation_history`-Array.
- Deckt späte Konsumenten ab, die die History nach dem Intake-Stadium lesen.
- Reasoning-PII wird durch Tokens ersetzt, bevor sie an Tools/Exporter gelangt.

### Konfiguration

```yaml
plugins:
  entries:
    privacy-shield:
      reasoning_mode: restore  # off | audit | restore (default: restore)
      reasoning_confidence_threshold: 0.85
```

**Limitationen:** Siehe [`docs/reasoning-protection.md`](docs/reasoning-protection.md) für die vollständige Liste der Design-Limitationen und Mitigationsschritte.

## Architektur

```
LLM-Anfrage mit PII
    ↓
pre_llm_call() Hook
    ├─ PDF → pdfplumber → Text
    ├─ Bild → Tesseract OCR → Text
    └─ Plain-Text direkt
    ↓
RegexPIIDetector.scan() — 58 Muster
    ↓
Pseudonymizer.replace() — Token statt Original
    ↓
MappingTable.store() — in-memory + AES-256-GCM
    ↓
Provider bekommt nur Tokens
    ↓
LLM antwortet mit Tokens
    ↓
post_api_request() Hook          ← v1.7.0: vor Persistenz
    ├─ Reasoning-Felder am Live-Objekt tokenisiert
    └─ state.db erhält nur tokenisierte Reasoning-Texte
    ↓
transform_llm_output() Hook
    ↓
MappingTable.restore() — Token → Original
    ↓
User sieht Original-Daten (nur in whitelisted Channels)
```

## Sicherheit

- **4 Review-Runden** (unabhängige Profile: Research, Validation, Architektur, Operations, Memory, System-Admin)
- **820 Tests grün** (CI: 3.10/3.11/3.12 + lint + mypy strict + security)
- **0 offene CRITICAL/HIGH/MEDIUM-Findings**
- **AES-256-GCM** mit PBKDF2 100k Iterations
- **Egress-Whitelist** verhindert versehentliche PII-Leaks
- **Bucketed Audit-Log** (SHA-256-Hashes statt Klartext)
- **EU AI Act PDF-Export** — One-Click-Compliance-Report aus dem Audit-Trail
- **Memory-Bounded Caches** (LRU-Eviction)

Siehe [docs/SECURITY.md](docs/SECURITY.md) für Details.

## Audit-PDF-Export

Generiere einen manipulationssicheren EU AI Act / DSGVO-Compliance-Report aus dem JSONL-Audit-Log. Reports lassen sich als PDF, CSV oder JSON rendern und mit Ed25519 signieren.

### CLI

```bash
# PDF-Report (unsigniert)
privacy-shield audit-export \
  --from 2026-08-01 --to 2026-08-31 \
  --user sha256:deadbeef... \
  --format pdf \
  --output report-2026-08.pdf

# Signiertes PDF (Ed25519 detached signature)
privacy-shield audit-export \
  --from 2026-08-01 --to 2026-08-31 \
  --user sha256:deadbeef... \
  --format pdf \
  --sign-with ~/.hermes/keys/audit-signing-key.pem \
  --output report-2026-08.pdf

# Maschinenlesbar CSV / JSON
privacy-shield audit-export \
  --from 2026-08-01 --to 2026-08-31 \
  --user sha256:deadbeef... \
  --format csv \
  --output report-2026-08.csv
```

### Python-API

```python
from pathlib import Path
from privacy_shield.audit import AuditExporter

exporter = AuditExporter()
result = exporter.export(
    output_path="audit.pdf",
    time_range=("2026-08-01", "2026-08-31"),
    sign=True,
    format="pdf",
    signing_key_path=Path.home() / ".hermes" / "keys" / "audit-signing-key.pem",
)
print(result["output_path"], result["signature"])
```

### Report-Inhalt

- Titelseite (Zeitraum, gehashter User-Identifier, Timestamp)
- Zusammenfassung (Gesamt-Calls, PII-Erkennungen, blockierte Aktionen, Modus-Wechsel)
- Token-Mappings (Original-Hash, Token, Typ, Timestamp, Session)
- Audit-Events mit Severity und Bucketed Counts
- Detection-Events (block / warn / restore)
- Modus-Wechsel (wer hat wann welchen Modus geändert)
- Compliance-Abdeckung (DSGVO Art. 25, 32, 35; EU AI Act Art. 9, 11, 12, 14)
- Test-Status (passed / failed / skipped / coverage)
- Integritäts-Footer + detached Ed25519-Signatur (bei `--sign-with`)

Siehe [docs/eu-ai-act-report.md](docs/eu-ai-act-report.md) für die Mapping-Logik.

## Dokumentation

- [Bedienungsanleitung](docs/USER-GUIDE.md) — Ausführliche Anleitung
- [Installation](docs/INSTALL.md) — Setup + Hermes-Integration
- [Security](docs/SECURITY.md) — Sicherheits-Properties + Threat-Model
- [DSGVO](docs/dsgvo-mapping.md) — AVV + VVT-Templates
- [Reasoning-Schutz](docs/reasoning-protection.md) — v1.7.0 Pre-Intake-Redaktion (GB-009 geschlossen)
- [Changelog](CHANGELOG.md) — Versionshistorie

## Multi-Profile-Setup

Aktiviert Privacy-Shield in allen Hermes-Profilen (idempotent):

```bash
python3 scripts/setup_profiles.py
```

## Version-Sync

`plugin.yaml` ist die Single-Source-of-Truth für die Plugin-Version. `pyproject.toml` und `__init__.py` werden via `scripts/sync_version.py` synchronisiert:

```bash
python3 scripts/sync_version.py          # auf plugin.yaml-Version syncen
python3 scripts/sync_version.py --check  # CI-Gate: exit 1 bei Drift
python3 scripts/sync_version.py --set 1.7.0  # alle drei Dateien hochzählen
```

## Lizenz

MIT License — siehe [LICENSE](LICENSE).

## Support

- Repository: https://github.com/MOTHR/hermes-security-suite (suite monorepo)
- Issues: GitHub Issues
- DSGVO-Fragen: docs/AVV-Checkliste.md

---

> **English:** [README.md](README.md) — English version
