# EU AI Act Audit Report

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# EU-AI-Act-Audit-Report

Privacy-Shield v1.4.0 kann den gebucketten JSONL-Audit-Trail als
One-Click-Compliance-PDF exportieren. Dieses Dokument erläutert die
regulatorische Zuordnung und den Aufbau des Reports.

## Report-Inhalte

Der PDF-Export (`privacy-shield audit-export`) enthält fünf Abschnitte:

1. **Deckblatt**
   - Report-Titel: *Hermes Privacy-Shield EU AI Act Compliance Audit Report*
   - Berichtszeitraum (`--from` / `--to`)
   - Gehashte Benutzerkennung (`--user`)
   - Erstellungszeitstempel

2. **Zusammenfassungstabelle**
   - **Total Calls**: Anzahl der Audit-Events im gewählten Zeitraum
   - **PII Detections**: Events mit mindestens einem PII-Typ oder einem
     von-null-verschiedenen Masked-Count-Bucket
   - **Blocked Actions**: Events mit `event == "blocked_action"`

3. **EU-AI-Act-Artikel-Zuordnung**
   - Art. 9 — Risikomanagementsystem
   - Art. 11 — Qualitätsmanagement
   - Art. 12 — Aufzeichnungs-/Protokollierungspflichten
   - Art. 14 — Menschliche Aufsicht

4. **Audit-Event-Details**
   - Chronologische Tabelle aller Events im Zeitraum mit Zeitstempel,
     Event-Typ, Session-Hash, Modus, PII-Typen, Modell, Plattform und
     Count-Bucket.

5. **Integritäts-Fußzeile**
   - Deterministische SHA-256-Signatur über die kanonische Report-Eingabe:
     Berichtszeitraum, User-Hash und die vollständige chronologische
     Event-Payload.
   - Ein erneuter Export derselben Quelldaten erzeugt dieselbe Signatur —
     der Report lässt sich gegen das zugrunde liegende JSONL-Audit-Log
     verifizieren.

## Logik der Artikel-Zuordnung

Die Zuordnung ist in `config/audit_articles.yaml` konfiguriert.

| Artikel | Bedingung | Evidence-Felder |
|---|---|---|
| Art. 9 Risikomanagement | `event.severity == "high"` oder `event == "blocked_action"` | `event`, `severity`, `session_id_hash`, `ts` |
| Art. 11 Qualitätsmanagement | Event enthält `pii_types` oder `masked_count_bucket != "0"` | `pii_types`, `masked_count_bucket`, `model`, `mode` |
| Art. 12 Protokollierung | jedes Audit-Event | `ts`, `event`, `session_id_hash`, `platform`, `model` |
| Art. 14 Menschliche Aufsicht | `event` in Approval-/Human-Review-Menge oder `action == "approved"` | `event`, `action`, `session_id_hash`, `ts` |

Die Report-Tabelle zeigt jeden Artikel, seinen Titel und die Compliance-Evidenz,
die er liefert. Die eigentliche Klassifikation steuert die YAML-Datei —
künftige regulatorische Interpretationen lassen sich so ohne Code-Änderung
aktualisieren.

## Feld-Zuordnung

Der Audit-Logger schreibt JSONL-Zeilen mit folgenden Feldern:

- `ts` UNIX-Zeitstempel -> Report **Timestamp**
- `session_id_hash` -> Report **User Hash**
- `platform` -> Report **Tool / Platform**
- `pii_types` -> Report **PII Detected**
- `event` -> Report **Action**
- `masked_count_bucket` -> Report **Result**

Diese Zuordnung ist zusätzlich in `config/audit_articles.yaml` unter
`field_map` deklariert, damit nachgelagerte Tools Privacy-Shield-Events auf
ein generisches Audit-Schema normalisieren können.

## Deterministische Signatur

Die Signatur-Fußzeile ist **keine** digitale Signatur. Es ist ein
reproduzierbarer Hash, der belegt, dass das PDF aus einem bestimmten Satz
von Events und Parametern erzeugt wurde.

```
SHA-256( JSON( {period, user_hash, events} ) )
```

Dabei wird das JSON mit sortierten Keys und minimalen Separatoren
kanonisiert. Da das Audit-Log niemals Klartext-PII speichert, leckt die
Signatur keine sensiblen Daten, bindet den Report aber an das Quellog.

---

## English

# EU AI Act Audit Report

Privacy-Shield v1.4.0 can export the bucketed JSONL audit trail as a one-click
compliance PDF. This document explains the regulatory mapping and the
report contents.

## Report Contents

The PDF export (`privacy-shield audit-export`) contains five sections:

1. **Cover page**
   - Report title: *Hermes Privacy-Shield EU AI Act Compliance Audit Report*
   - Reporting period (`--from` / `--to`)
   - Hashed user identifier (`--user`)
   - Generation timestamp

2. **Summary table**
   - **Total Calls**: number of audit events in the selected period
   - **PII Detections**: events that recorded at least one PII type or a
     non-zero masked-count bucket
   - **Blocked Actions**: events with `event == "blocked_action"`

3. **EU AI Act Article Mapping**
   - Art. 9 — Risk Management System
   - Art. 11 — Quality Management
   - Art. 12 — Record-Keeping / Logging
   - Art. 14 — Human Oversight

4. **Audit Event Details**
   - Chronological table of every event in the period with timestamp, event
     type, session hash, mode, PII types, model, platform and count bucket.

5. **Integrity Footer**
   - Deterministic SHA-256 signature computed over the canonical report input:
     reporting period, user hash and the full chronological event payload.
   - Re-exporting the same source data yields the same signature, so the
     report can be verified to match the underlying JSONL audit log.

## Article Mapping Logic

The mapping is configured in `config/audit_articles.yaml`.

| Article | Condition | Evidence fields |
|---|---|---|
| Art. 9 Risk Management | `event.severity == "high"` or `event == "blocked_action"` | `event`, `severity`, `session_id_hash`, `ts` |
| Art. 11 Quality Management | event contains `pii_types` or `masked_count_bucket != "0"` | `pii_types`, `masked_count_bucket`, `model`, `mode` |
| Art. 12 Logging | every audit event | `ts`, `event`, `session_id_hash`, `platform`, `model` |
| Art. 14 Human Oversight | `event` in approval / human-review set or `action == "approved"` | `event`, `action`, `session_id_hash`, `ts` |

The report table shows each article, its title and the compliance evidence it
provides. The actual classification is driven by the YAML file so future
regulatory interpretations can be updated without code changes.

## Field Mapping

The audit logger writes JSONL lines with these fields:

- `ts` UNIX timestamp -> report **Timestamp**
- `session_id_hash` -> report **User Hash**
- `platform` -> report **Tool / Platform**
- `pii_types` -> report **PII Detected**
- `event` -> report **Action**
- `masked_count_bucket` -> report **Result**

This mapping is also declared in `config/audit_articles.yaml` under `field_map`
so downstream tooling can normalise Privacy-Shield events to a generic audit
schema.

## Deterministic Signature

The signature footer is **not** a digital signature. It is a reproducible hash
that proves the PDF was generated from a specific set of events and parameters.

```
SHA-256( JSON( {period, user_hash, events} ) )
```

Where the JSON is canonicalised with sorted keys and minimal separators.
Because the audit log never stores plaintext PII, the signature does not leak
sensitive data, but it still binds the report to the source log.

## Out-of-Scope

- Compliance templates for Banking / Medical / HR -> Phase 3
- Cloud storage of reports -> Phase 4
- Multi-user aggregation -> later release
