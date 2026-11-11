# Privacy-Shield

🌐 [Deutsch](README.de.md) | English

DSGVO-/GDPR-konformes Hermes-Plugin zur Tokenisierung personenbezogener Daten (PII) in sichtbarem LLM-Output und Reasoning-Inhalten.

**Version:** 1.9.3 (2026-11-11) — 58 Erkennungsmuster · reiner Upstream-Plugin-Contract (llm_request-Middleware + pre_llm_call-Veto) · PDF + Bild-OCR · Audit-Trail PDF/CSV/JSON-Export mit Ed25519-Signatur · Desktop-Controls-Pane · Reasoning-Pre-Intake-Tokenisierung (state.db-sicher)

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

## History-Masking (v1.9.2)

Der Shield deckt **jede User-Message** eines ausgehenden LLM-Requests ab, nicht nur den aktuellen Turn: Live-Prompt, frühere Konversations-Turns (Strings und Multimodal-`text`/`input_text`-Parts) sowie der Sidecar-Kontext-Suffix (Memory-Prefetch, Plugin-Kontext) werden gescannt und tokenisiert — pro Message einmal pro Turn. Ein Turn-scoped Per-Message-Memo hält die Kosten bei einem Scan pro Message pro Turn, auch wenn der Core die Middleware pro API-Attempt neu feuert.

```yaml
plugins:
  entries:
    privacy-shield:
      mask_history: true            # Default on; false reproduziert das alte Live-Prompt-only-Verhalten
      mask_sidecar_suffix: true     # Default on; false erhält Sidecar-Kontext byte-exakt
```

**Bekannte Limitation (P4):** Summary-/Aux-Calls des Hermes-Core (Iterations-/Chat-/Codex-Summaries) bauen ihre Provider-Kwargs direkt und bypassen die `llm_request`-Middleware des Plugins — sie bleiben unmaskiert, bis der Upstream-Core-PR alle Request-Bau-Seams durch die Middleware routet (Option c).

## Quickstart (5 Minuten)

```bash
# 1. Installation über das Hermes-Plugin-System (installiert die dashboard+/
#    desktop-Hälften selbst; kein pip in Hermes' venv, kein Core-Patching)
hermes plugins install <quelle>/privacy-shield
hermes plugins enable privacy-shield   # pro Profil

# 2. Encryption-Key bereitstellen
privacy-shield setup                    # generiert einen Key und legt ihn in pass ab
# Oder PRIVACY_SHIELD_KEY über eine beliebige Hermes-Secret-Source deklarieren
# (Keychain / pass-store Secret-Source-Plugin, Command-Source, .env).
# Das Plugin löst ihn über agent.secret_scope auf (requires_env).

# 3. Testen
privacy-shield --help
privacy-shield scan "Kontakt: alice@example.com"
privacy-shield test --text "Hilf mir mit alice@example.com und IBAN DE89370400440532013000"
```

### Standalone-Aufrufe (Cron / Launchd)

Die 1.9.x-CLI löst den Encryption-Key nicht mehr selbst über pass/os.environ
auf (Upstream-Plugin-Contract). Cron-/Launchd-Wrapper provisionieren den Key
selbst: `pass show hermes/privacy-shield-key` → `export PRIVACY_SHIELD_KEY`
vor dem CLI-Call (Muster: `~/.hermes/scripts/privacy-shield-cleanup.sh`), oder
`PRIVACY_SHIELD_KEY_FILE` (reguläre Datei, 0600, eigener Owner). Ohne
Provisionierung endet der Standalone-CLI mit
`MappingTable requires a non-empty encryption_key` — by design.

## Desktop-Controls (v1.5.0+)

Privacy-Shield wird mit einem offiziellen Desktop-Plugin ausgeliefert, über das Einstellungen in der Hermes Desktop-App statt via YAML editiert werden können:

- Plugin an-/ausschalten
- Betriebsmodus wechseln (`off`/`audit`/`limited`/`strict`/`paranoid`)
- Confidence-Threshold anpassen
- Restore-allowed Channels verwalten
- PDF / Bild-OCR / Cache-Bypass toggeln
- Synthetischen Restore-Smoke-Test ausführen

Das Desktop-Plugin liegt unter `desktop/` und wird vom Hermes-Plugin-System selbst installiert (`hermes plugins install` / `hermes plugins enable`). **Kein manuelles Kopieren nach `~/.hermes/desktop-plugins/` nötig oder vorgesehen.**

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

> **Hinweis zum Datenhandling — bitte lesen (Standardverhalten):** der
> Restore-Pass schreibt standardmäßig **echte personenbezogene Daten in die
> Replies zurück** auf den nutzerseitigen Channels `telegram`, `desktop`,
> `cli` und `kanban`. Nach der Wiederherstellung verlässt die Antwort die
> Maschine unredigiert. Wer keinen Klartext-PII in zugestellten Antworten
> will, muss diese Channels aus `restore_allowed_channels` entfernen oder
> Restore abschalten.

### Restore-Miss-Behandlung, Splice-Repair, Kanban-Channel (v1.7.6)

Tokens, die im erlaubten Restore-Pfad nicht auflösbar sind, bleiben nicht
mehr stehen: Mit `restore_miss_strategy: placeholder` (Default) werden sie
durch `[maskiertes PII – nicht wiederherstellbar]` ersetzt (deutscher
Default-Text; `restore_miss_placeholder` als Override für EN-Deployments —
der Text ersetzt ausschließlich den Token-Span, geklebte Suffixe bleiben
erhalten). Jeder Miss wird PII-frei geloggt (WARNING: Session/Typ/Serial,
kein Token-String, kein Klartext) und gezählt (`restore_misses` in
`get_metrics()`, Prometheus `privacy_shield_restore_misses_total`).
`keep` erhält das bisherige Verhalten (Token wörtlich stehen lassen).

Ein vom Modell verunstaltetes Token (Serial korrekt, Hash kaputt) wird über
`(Typ, Serial)` **innerhalb derselben Session** repariert: genau **ein**
unterschiedliches Kandidat-Original → Original eingesetzt; 0 oder ≥ 2
verschiedene Originale (Kollisionen durch Counter-Restart bei LRU-Eviction
sind erwartet) → Restore-Miss-Platzhalter. Niemals über Session-Grenzen;
Legacy-Tokens ohne Serial werden nie repariert (fail-closed). Die
Mapping-Tabelle erhält eine Nullable-Spalte `token_serial` plus Index
`(session_id, type, token_serial)`; ein begrenzter Lazy-Backfill migriert
Legacy-Rows (≤ 200 Rows, höchstens einmal pro (Session, Typ)), und
`scripts/backfill_token_serial.py` konvergiert die ganze Tabelle offline
(resumable, chunked, mit Fortschritt — ein komplettes Entschlüsseln einer
61k-Row-Tabelle ist host- und backendabhängig (PBKDF2 ~40–120 ms/Row;
~86 ms mit hashlib, ~117 ms mit dem cryptography-Backend auf dem
Deploy-Host), weshalb operative Pfade nur wenige Rows pro Query
entschlüsseln).

```yaml
plugins:
  entries:
    privacy-shield:
      restore_miss_strategy: placeholder   # placeholder | keep
      restore_miss_placeholder: "[masked PII – cannot be restored]"  # optionaler EN-Override
      restore_allowed_channels: ["telegram", "desktop", "cli", "kanban"]
```

> **Achtung — expliziter Override ersetzt die komplette Default-Liste:**
> Ein explizites `restore_allowed_channels` in der Konfiguration ersetzt die
> gesamte Default-Liste (`_merge_user_config` überschreibt das ganze Tupel —
> kein Auto-Merge). Ein expliziter Eintrag **ohne** `kanban` deaktiviert die
> Kanban-Wiederherstellung stillschweigend — `kanban` in jeden expliziten
> Eintrag aufnehmen, der weiterhin restoren soll.

`kanban` ist jetzt ein Default-Restore-Channel, damit board-sichtbare
Antworten die Originalwerte zurückholen dürfen. **Vertrauensgrenze
unverändert:** Die Chat-ID-Allowlist (`allowed_chats` /
`allowed_chat_ids` / telegram-send Limits) regelt weiter, wer restaurierte
PII empfängt; ergänzt wurde nur der eine Channel-Eintrag. Tool-Egress
(write_file, terminal, MCP, kanban_attach) bleibt ausdrücklich
restore-frei. Das Fresh-PII-Verhalten ist erhalten (FIX-1B):
Sanitizer-erzeugte Tokens für neue Leaks bleiben sichtbar und werden weder
restauriert noch mit dem Platzhalter ersetzt.

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
MappingTable.store() — in-memory + AES-256-GCM, sanitized Prompt wird STAGED
    ↓
llm_request-Middleware schreibt die User-Message im api_kwargs um
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
- **1066 Tests grün** (CI: 3.10/3.11/3.12 + lint + mypy strict + security)
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

## Profil-Aktivierung

Profile werden einzeln aktiviert — kein config.yaml-Umschreiben:

```bash
hermes -p <profil> plugins enable privacy-shield
```

## Version-Sync

`plugin.yaml` ist die Single-Source-of-Truth für die Plugin-Version. `pyproject.toml` und `__init__.py` werden via `scripts/sync_version.py` synchronisiert:

```bash
python3 scripts/sync_version.py          # auf plugin.yaml-Version syncen
python3 scripts/sync_version.py --check  # CI-Gate: exit 1 bei Drift
python3 scripts/sync_version.py --set 1.7.6  # alle drei Dateien hochzählen
```

## Lizenz

MIT License — siehe [LICENSE](LICENSE).

## Support

- Repository: https://github.com/MOTHR/hermes-privacy-shield
- Issues: GitHub Issues
- DSGVO-Fragen: docs/AVV-Checkliste.md

---

> **English:** [README.md](README.md) — English version
