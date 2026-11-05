# DSGVO-Konzept für Injection-Shield

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# DSGVO-Konzept für Injection-Shield

> Bewertung gemäß DSGVO (EU 2016/679), insbesondere Art. 5, Art. 6, Art. 25, Art. 32.
> Stand: v0.3.0 (FIX-1D close-out für CRIT-3 und CRIT-4).
>
> Vorherige Findings aus dem Orakel-Audit (R3):
> - **CRIT-3** — Hartkodierte Telegram-`chat_id` (Privacy by Default verletzt)
> - **CRIT-4** — Keine Retention / kein Auto-Prune für Audit-Logs
> Beide Findings sind in v0.2.0 (CRIT-3) und v0.2.0 (CRIT-4) geschlossen;
> dieses Dokument ist die belastbare Bewertung der finalen Architektur.

## 1. Verantwortlicher & Auftragsverarbeiter

- **Verantwortlicher** (Art. 4 Nr. 7): Der Betreiber der Hermes-Instanz
  (= Workshop-Teilnehmer bzw. der Operator selbst in Solo-Setups).
- **Auftragsverarbeiter** (Art. 28): Keiner — `injection-shield` läuft
  lokal im selben Python-Prozess wie Hermes. Es gibt keine Drittpartei, an
  die Daten übertragen werden.

## 2. Verarbeitete Daten

| Datenkategorie              | Zweck                              | Rechtsgrundlage (Art. 6)              | Speicherdauer |
|-----------------------------|------------------------------------|---------------------------------------|---------------|
| LLM-Input (Text, transient) | Pattern-Detection                  | Berechtigtes Interesse (Art. 6(1)(f)) | Nur In-Memory |
| LLM-Output (Text, transient)| Pattern-Detection, Credential-Scan | Berechtigtes Interesse                | Nur In-Memory |
| Tool-Args (JSON, transient) | Risky-Tool-Audit                   | Berechtigtes Interesse                | Nur In-Memory |
| Tool-Output (transient)     | Content-Tagging                    | Berechtigtes Interesse                | Nur In-Memory |
| Session-Hash (salted SHA-256) | Audit-Log-Zuordnung              | Berechtigtes Interesse                | 90 Tage       |
| Pattern-Match-Metadaten     | Audit (Typ, Severity, Länge)       | Berechtigtes Interesse                | 90 Tage       |

### Was NICHT gespeichert wird

- ❌ Klartext-Match (nur `match_len` — Anzahl Zeichen)
- ❌ Klartext Session-Key (nur salted SHA-256-Hash)
- ❌ User-Prompt-Inhalt
- ❌ LLM-Antwort-Inhalt
- ❌ Tool-Argumente im Klartext
- ❌ IP-Adressen, Browser-Fingerprints, Tracking-IDs
- ❌ Personenbezogene Daten über das hinaus, was der User bereits an Hermes gegeben hat

## 3. Speicherort

- **Audit-Log**: `~/.hermes/profiles/<profile>/workspace/logs/prompt-injection-attempts.log`
  (+ Rotationen `.log.1` … `.log.5`)
- **File-Permissions**: `0600` (owner read/write only — kein Gruppen-/World-Zugriff)
- **Retention**: 90 Tage, konfigurierbar via
  `plugins.entries.injection-shield.audit_log_retention_days` (Default 90)
- **Rotation**: 10 MiB pro Datei (`audit_log_max_bytes`), 5 Backups
  (`audit_log_backup_count`) → max. 60 MiB Worst-Case pro Profil
- **Atomic-Prune**: Implementiert via `tempfile.mkstemp` + `os.replace`
  (FIX-2C / SCHL-3) — kein Race-Condition-Fenster zwischen "Lines lesen"
  und "Datei schreiben"

## 4. Schutzmaßnahmen (TOMs — Art. 32)

### 4.1 Pseudonymisierung

Session-Keys werden vor dem Logging salted gehasht (SHA-256, Salt pro Plugin-
Instanz). Ein Angreifer mit Lesezugriff auf das Audit-Log kann ohne
gleichzeitigen Zugriff auf den Salt die Hashes keiner konkreten Session
zuordnen.

### 4.2 Datenminimierung (Art. 5(1)(c))

Das Audit-Log enthält ausschließlich:
- Zeitstempel
- Hook-Name
- Pattern-Typ (z. B. `instruction_override`, `credential_leak`)
- Severity (`low` | `medium` | `high` | `critical`)
- Match-Länge (Anzahl Zeichen, **nicht** der Match selbst)
- Session-Hash (salted SHA-256)

Keine Inhalte, keine Tokens, keine User-IDs.

### 4.3 Zugriffskontrolle

- File-Permissions `0600` auf der Audit-Log-Datei
- Hermes läuft unter dem User-Account, der die Datei erstellt — kein
  externer Prozess hat Lesezugriff, sofern das System sauber konfiguriert ist
- Empfehlung: Hermes-Verzeichnis selbst auch mit `0700` sichern
  (`chmod 700 ~/.hermes`)

### 4.4 Storage Limitation (Art. 5(1)(e))

- 90-Tage-Retention durchgesetzt via Auto-Prune beim Plugin-Init
- 10-MiB-Rotation verhindert unkontrolliertes Wachstum
- Worst-Case Disk-Footprint: 60 MiB pro Profil — vernachlässigbar

### 4.5 Integrität & Vertraulichkeit (Art. 32(1)(b))

- Pattern-Detection läuft lokal, kein Netzwerk-Egress
- Audit-Log wird mit `logging.handlers.RotatingFileHandler` geschrieben —
  Standard-Library, kein Custom-Code mit bekannten Buffer-Overflow-Klassen
- Atomic-Prune (FIX-2C) verhindert partiell geschriebene Logs nach Crash

### 4.6 Verfügbarkeit (Art. 32(1)(b))

- `DetectorChain` wrappt jeden Detector in try/except — fail-separate
- Plugin-Crash führt nicht zu LLM-Ausfall; im worst case werden alle Detections
  für den betroffenen Turn ausgelassen, was als `WARNING` im Hermes-Log erscheint

## 5. Auftragsverarbeitung (Art. 28)

`injection-shield` ist **kein Auftragsverarbeiter im Sinne von Art. 28**, weil:

1. Das Plugin ist Teil der lokalen Hermes-Installation des Verantwortlichen
2. Es werden keine Daten an externe Systeme übertragen (außer bei explizit
   aktivierter Telegram-Alerting-Option)
3. Es gibt keinen Drittparteien-Zugriff auf die verarbeiteten Daten

**AVV (Auftragsverarbeitungsvertrag):** Nicht erforderlich, da keine
Auftragsverarbeitung stattfindet.

## 6. Privacy by Default (Art. 25)

| Feature                | Default     | Opt-in-Pfad                                              |
|------------------------|-------------|----------------------------------------------------------|
| Audit-Log              | **AN**      | Nicht deaktivierbar (Sicherheits-Feature)                |
| Telegram-Alerts        | **AUS**     | `INJECTION_SHIELD_TELEGRAM_CHAT_ID` Env-Var ODER `chat_id` in config.yaml + `enabled: true` |
| Risky-Tool-Audit       | AN          | `risky_tools: []` in config.yaml deaktiviert die Liste   |
| `enforcement`-Modus    | **AUS**     | `mode: enforcement` in config.yaml                        |

Die Defaults sind die datenschutzfreundlichsten und gleichzeitig die
sicherheitstechnisch unproblematischsten.

## 7. Auskunftsrecht (Art. 15)

User können jederzeit das Audit-Log einsehen:

```bash
cat ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log
```

Da **keine personenbezogenen Daten** im Klartext gespeichert werden
(siehe §2), ist der DSGVO-Auskunftsbedarf minimal:
- Der User sieht seine eigenen Session-Hashes (kein Rückschluss möglich
  ohne Salt-Zugriff)
- Keine Prompts, keine Outputs, keine Argumente

## 8. Recht auf Löschung (Art. 17)

User können jederzeit das Audit-Log löschen:

```bash
rm ~/.hermes/profiles/*/workspace/logs/prompt-injection-attempts.log*
```

Zusätzlich: Auto-Prune nach 90 Tagen erfüllt Art. 17 ohne User-Aktion.

## 9. Datenpannen-Notification (Art. 33)

Bei einer Datenpanne im Audit-Log (z. B. versehentliche `0777`-Permissions
nach manuellem Eingriff) ist zu beachten:

- **Klartext-Exposition ist begrenzt**: Pattern-Typ + Severity + Zeitstempel +
  Session-Hash. Keine Prompts/Outputs/Klartext-PII.
- **Session-Hash ist salted**: Ohne Salt kein Rückschluss auf Session-Inhalt
- **Meldung an Aufsichtsbehörde**: Innerhalb 72h nach Bekanntwerden, sofern
  "voraussichtlich hohes Risiko" für Rechte & Freiheiten besteht — bei
  Audit-Log-Exposition in der Regel nicht gegeben, da keine Klartext-PII
  betroffen ist.

## 10. Internationale Datenübertragungen (Kapitel V)

- **Audit-Log**: Rein lokal. Keine Übertragung.
- **Telegram-Alerts** (optional): Wenn aktiviert, wird eine Alert-Nachricht
  an die Telegram Bot API (`https://api.telegram.org`) gesendet. Telegram
  wird von der Telegram FZ-LLC (Dubai, VAE) betrieben.
  - **Rechtsgrundlage für Übermittlung**: Art. 49(1)(a) (ausdrückliche
    Einwilligung) durch Setzen der Env-Var / `enabled: true`
  - **Adequacy**: EU-Kommission hat 2024 einen Angemessenheitsbeschluss
    für die VAE erlassen — Verordnung (EU) 2024/581
  - **TLS**: Die Bot-API wird ausschließlich über HTTPS erreicht
  - **Inhalt**: Nur Metadaten (siehe §2), kein Klartext-Prompt/Output

## 11. Datenschutz-Folgenabschätzung (Art. 35)

Eine DSFA ist **nicht zwingend erforderlich**, weil:

- Keine umfangreiche Verarbeitung besonderer Datenkategorien (Art. 9)
- Keine Profiling-Maßnahmen mit Rechtswirkung (Art. 22)
- Keine systematische Überwachung öffentlich zugänglicher Bereiche
- Keine Verarbeitung mit hohem Risiko für Betroffene

Das Plugin ist defensiv (Sicherheits-Feature), nicht offensiv
(kein Tracking, keine Profilbildung).

## 12. Versions-Historie

| Datum       | Version | Änderung                                                                   |
|-------------|---------|----------------------------------------------------------------------------|
| 2026-08-21  | v0.2.0  | FIX-1D CRIT-3: Telegram default off, chat_id via Env-Var                   |
| 2026-08-21  | v0.2.0  | FIX-1D CRIT-4: 90-Tage-Retention, 10-MiB-Rotation, Auto-Prune             |
| 2026-08-22  | v0.3.0  | DSGVO-Konzept-Dokument erstellt (R3 Close-out)                              |

## 13. Kontakt für Datenschutzfragen

Siehe `~/.hermes/DIRK-PROFILE.md` und das Hermes-Datenschutzkonzept im

---

## English

# GDPR Concept for Injection-Shield

> Assessment according to GDPR (EU 2016/679), in particular Art. 5, Art. 6, Art. 25, Art. 32.
> Status: v0.3.0 (FIX-1D close-out for CRIT-3 and CRIT-4).
>
> Previous findings from the Oracle Audit (R3):
> - **CRIT-3** — Hardcoded Telegram `chat_id` (Privacy by Default violated)
> - **CRIT-4** — No retention / no auto-prune for Audit Logs
> Both findings are closed in v0.2.0 (CRIT-3) and v0.2.0 (CRIT-4);
> this document is the reliable assessment of the final architecture.

## 1. Controller & Processor

- **Controller** (Art. 4 No. 7): The operator of the Hermes instance
  (= the workshop participants / the operator themselves in solo setups).
- **Processor** (Art. 28): None — `injection-shield` runs locally in the same
  Python process as Hermes. There is no third party to which data is transferred.

## 2. Processed Data

| Data Category              | Purpose                          | Legal Basis (Art. 6)              | Storage Duration |
|----------------------------|----------------------------------|-------------------------------------|------------------|
| LLM Input (text, transient)| Pattern Detection                | Legitimate Interest (Art. 6(1)(f)) | In-Memory Only   |
| LLM Output (text, transient)| Pattern Detection, Credential Scan | Legitimate Interest                | In-Memory Only   |
| Tool Args (JSON, transient)| Risky Tool Audit                 | Legitimate Interest                | In-Memory Only   |
| Tool Output (transient)    | Content Tagging                  | Legitimate Interest                | In-Memory Only   |
| Session Hash (salted SHA-256) | Audit Log Attribution          | Legitimate Interest                | 90 Days          |
| Pattern Match Metadata     | Audit (type, severity, length)  | Legitimate Interest                | 90 Days          |

### What is NOT Stored

- ❌ Cleartext match (only `match_len` — character count)
- ❌ Cleartext session key (only salted SHA-256 hash)
- ❌ User prompt content
- ❌ LLM response content
- ❌ Tool arguments in cleartext
- ❌ IP addresses, browser fingerprints, tracking IDs
- ❌ Personal data beyond what the user has already given to Hermes

## 3. Storage Location

- **Audit Log**: `~/.hermes/profiles/<profile>/workspace/logs/prompt-injection-attempts.log`
  (+ rotations `.log.1` … `.log.5`)
- **File Permissions**: `0600` (owner read/write only — no group/world access)
- **Retention**: 90 days, configurable via
  `plugins.entries.injection-shield.audit_log_retention_days` (default 90)
- **Rotation**: 10 MiB per file (`audit_log_max_bytes`), 5 backups
  (`audit_log_backup_count`) → max. 60 MiB worst case per profile
- **Atomic Prune**: Implemented via `tempfile.mkstemp` + `os.replace`
  (FIX-2C / SCHL-3) — no race condition window between "read lines"
  and "write file"

## 4. Technical and Organizational Measures (TOMs — Art. 32)

### 4.1 Pseudonymization

Session keys are salted-hashed (SHA-256, salt per plugin instance) before
logging. An attacker with read access to the audit log cannot attribute
hashes to any concrete session without simultaneous access to the salt.

### 4.2 Data Minimization (Art. 5(1)(c))

The audit log contains exclusively:
- Timestamp
- Hook name
- Pattern type (e.g. `instruction_override`, `credential_leak`)
- Severity (`low` | `medium` | `high` | `critical`)
- Match length (character count, **not** the match itself)
- Session hash (salted SHA-256)

No contents, no tokens, no user IDs.

### 4.3 Access Control

- File permissions `0600` on the audit log file
- Hermes runs under the user account that created the file — no
  external process has read access, provided the system is cleanly configured
- Recommendation: secure the Hermes directory itself with `0700`
  (`chmod 700 ~/.hermes`)

### 4.4 Storage Limitation (Art. 5(1)(e))

- 90-day retention enforced via auto-prune at plugin init
- 10 MiB rotation prevents uncontrolled growth
- Worst-case disk footprint: 60 MiB per profile — negligible

### 4.5 Integrity & Confidentiality (Art. 32(1)(b))

- Pattern detection runs locally, no network egress
- Audit log is written with `logging.handlers.RotatingFileHandler` —
  standard library, no custom code with known buffer overflow classes
- Atomic prune (FIX-2C) prevents partially written logs after crash

### 4.6 Availability (Art. 32(1)(b))

- `DetectorChain` wraps each detector in try/except — fail-separate
- Plugin crash does not cause LLM failure; in the worst case all detections
  are skipped for the affected turn, which appears as `WARNING` in the Hermes log

## 5. Data Processing (Art. 28)

`injection-shield` is **not a processor under Art. 28** because:

1. The plugin is part of the controller's local Hermes installation
2. No data is transferred to external systems (except when Telegram alerting
   is explicitly activated)
3. There is no third-party access to the processed data

**DPA (Data Processing Agreement):** Not required, as no data processing
takes place.

## 6. Privacy by Default (Art. 25)

| Feature                | Default     | Opt-in Path                                              |
|------------------------|-------------|----------------------------------------------------------|
| Audit Log              | **ON**      | Not deactivatable (security feature)                     |
| Telegram Alerts        | **OFF**     | `INJECTION_SHIELD_TELEGRAM_CHAT_ID` env var OR `chat_id` in config.yaml + `enabled: true` |
| Risky Tool Audit       | ON          | `risky_tools: []` in config.yaml disables the list       |
| `enforcement` Mode     | **OFF**     | `mode: enforcement` in config.yaml                       |

The defaults are the most privacy-friendly and simultaneously the most
security-unproblematic.

## 7. Right of Access (Art. 15)

Users can view the audit log at any time:

```bash
cat ~/.hermes/profiles/default/workspace/logs/prompt-injection-attempts.log
```

Since **no personal data** is stored in cleartext (see §2), the GDPR
access requirement is minimal:
- The user sees their own session hashes (no inference possible
  without salt access)
- No prompts, no outputs, no arguments

## 8. Right to Erasure (Art. 17)

Users can delete the audit log at any time:

```bash
rm ~/.hermes/profiles/*/workspace/logs/prompt-injection-attempts.log*
```

Additionally: auto-prune after 90 days fulfills Art. 17 without user action.

## 9. Data Breach Notification (Art. 33)

In the event of a data breach in the audit log (e.g. accidental `0777`
permissions after manual intervention), note:

- **Cleartext exposure is limited**: Pattern type + severity + timestamp +
  session hash. No prompts/outputs/cleartext PII.
- **Session hash is salted**: Without salt, no inference about session content
- **Report to supervisory authority**: Within 72h of becoming aware, provided
  "likely high risk" to rights and freedoms exists — generally not the case
  for audit log exposure since no cleartext PII is involved.

## 10. International Data Transfers (Chapter V)

- **Audit Log**: Purely local. No transfer.
- **Telegram Alerts** (optional): When activated, an alert message is sent
  to the Telegram Bot API (`https://api.telegram.org`). Telegram is operated
  by Telegram FZ-LLC (Dubai, UAE).
  - **Legal basis for transfer**: Art. 49(1)(a) (explicit consent) by setting
    the env var / `enabled: true`
  - **Adequacy**: The EU Commission issued an adequacy decision for the UAE
    in 2024 — Regulation (EU) 2024/581
  - **TLS**: The Bot API is reached exclusively via HTTPS
  - **Content**: Only metadata (see §2), no cleartext prompt/output

## 11. Data Protection Impact Assessment (Art. 35)

A DPIA is **not mandatorily required** because:

- No extensive processing of special categories of data (Art. 9)
- No profiling measures with legal effect (Art. 22)
- No systematic monitoring of publicly accessible areas
- No processing with high risk to data subjects

The plugin is defensive (security feature), not offensive
(no tracking, no profiling).

## 12. Version History

| Date       | Version | Change                                                                   |
|------------|---------|----------------------------------------------------------------------------|
| 2026-08-21 | v0.2.0  | FIX-1D CRIT-3: Telegram default off, chat_id via env var                   |
| 2026-08-21 | v0.2.0  | FIX-1D CRIT-4: 90-day retention, 10-MiB rotation, auto-prune             |
| 2026-08-22 | v0.3.0  | GDPR concept document created (R3 close-out)                              |

## 13. Contact for Data Protection Questions

See `~/.hermes/DIRK-PROFILE.md` and the Hermes data protection concept in the
