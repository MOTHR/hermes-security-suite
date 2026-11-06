# Privacy-Shield Architektur

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Privacy-Shield Architektur

**Spec-Version:** v1.0.0

## Uebersicht

Privacy-Shield ist ein Defense-in-Depth System. Es schuetzt persoenliche Daten auf zwei Ebenen:

1. Plugin-Ebene: Erkennung und Tokenisierung von PII
2. Core-Ebene: Hard-Block, falls das Plugin fehlt

Diese zweistufige Absicherung ist notwendig. Ein Update kann das Plugin deaktivieren. Der Core-Hook blockiert dann alle LLM-Anfragen.

## Komponenten

### 1. Plugin (privacy-shield/)

- __init__.py — Plugin-Entry-Point
- plugin.py — Hook-Registration (pre_llm_call)
- config.py — Konfiguration mit Phase-1-Defaults
- detectors/ — Regex-basierte PII-Erkennung
- pseudonymizer.py — Deterministische Token-Erzeugung
- mapping_table.py — SQLite + AES-256-GCM Speicherung

### 2. Core-Hook (run_agent.py)

Ein duenner Patch in `turn_context.py`. Er prueft vor jedem LLM-Call:

```python
if config.privacy_shield.enabled and not has_pre_llm_call_hook():
    raise PrivacyShieldMissingError(
        "Privacy-Shield Plugin fehlt. "
        "Installiere: hermes plugin install privacy-shield"
    )
```

Der Hook ist optional. Er blockiert nur, wenn Privacy-Shield aktiv sein sollte.

### 3. Auto-Apply (Update-Resilience)

Nach einem `hermes update` wird `turn_context.py` ueberschrieben. Der Core-Hook verschwindet.

```
Cron (alle 6h) -> auto_apply_hook.py --apply -> Pruefe Patch-Status
                                     -> Falls fehlend: Patch
                                     -> Syntax-Check
                                     -> Verify
                                     -> Log
```

Das Script ist idempotent. Mehrfach-Ausfuehrung ist harmlos.

## Security-Modell

### Annahmen

- Der Rechner des Nutzers ist vertrauenswuerdig
- Der KI-Anbieter (Cloud-LLM) ist NICHT vertrauenswuerdig
- Plugin-Code laeuft im gleichen Prozess wie Hermes

### Bedrohungen

| Bedrohung | Schutz |
|---|---|
| PII gelangt ungeschuetzt zur Cloud | Regex-Filter + Tokenisierung |
| Plugin wird deaktiviert | Core-Hard-Block |
| Update entfernt Core-Hook | Auto-Apply-Cron |
| Auto-Apply schlaegt fehl | Telegram-Alert |
| Lokale Mapping-Tabelle wird gestohlen | AES-256-GCM Verschluesselung |

## Update-Resilience im Detail

### auto_apply_hook.py

Das Python-Script bietet folgende Modi:

| Flag | Zweck |
|------|-------|
| `--status` | Zeigt aktuellen Status an |
| `--dry-run` | Zeigt was gemacht wuerde |
| `--apply` | Wendet Patch an (idempotent) |
| `--revert` | Stellt letzten Backup wieder her |
| `--install-cron` | Richtet Cron-Job ein |

### Exit-Codes

| Code | Bedeutung |
|------|-----------|
| 0 | Erfolg |
| 1 | Fehler |
| 2 | Fehler + Rollback |
| 3 | Unbekanntes Layout |
| 4 | Backup nicht gefunden |

### Rollback-Mechanismus

Vor jedem Patch wird ein Backup erstellt:

```
turn_context.py.bak.<timestamp>
```

Falls der Patch einen Syntaxfehler erzeugt, wird automatisch Rollback durchgefuehrt.

## Datenfluss

```
Nutzer-Input
      |
      v
Core-Hook prueft: Plugin vorhanden?
      |--- Nein: Hard-Block (Fehlermeldung)
      |
      v
pre_llm_call Hook
      |
      v
Regex-Detektor scannt Text
      |
      v
PII gefunden? -> Pseudonymizer erzeugt Token
      |                                    |
      |--- Nein: Text unveraendert         |
      |                                    |
      v                                    v
Tokenisierte Anfrage -> LLM-API    Mapping-Tabelle speichert Token<->Original
      |
      v
LLM-Antwort
      |
      v
De-Tokenisierung (Rueckuebersetzung aus Mapping-Tabelle)
      |
      v
Anzeige fuer Nutzer
```

## Speicherung

Die Mapping-Tabelle speichert Token<->Original-Paare in SQLite.

- Verschluesselung: AES-256-GCM
- Schluesselquelle: pass hermes/privacy-shield (bevorzugt) oder PRIVACY_SHIELD_KEY
- Tabelle wird regelmaessig aufgeraeumt (retention_days)

## Spec-Referenz

Interne AI-Act-Architektur-Spec, v1 (nicht veröffentlicht).

## Phase-2-Ausblick

High-Risk-Modus und Human-Review-Queue sind Phase 2 — nicht in dieser Version (v1.0.0) enthalten.

---

## English

# Privacy-Shield Architecture

**Spec-Version:** v1.0.0

## Overview

Privacy-Shield is a defense-in-depth system. It protects personal data on two levels:

1. Plugin level: Detection and tokenization of PII
2. Core level: Hard block if the plugin is missing

This two-layer protection is necessary. An update can disable the plugin. The core hook then blocks all LLM requests.

## Components

### 1. Plugin (privacy-shield/)

- __init__.py — Plugin entry point
- plugin.py — Hook registration (pre_llm_call)
- config.py — Configuration with Phase 1 defaults
- detectors/ — Regex-based PII detection
- pseudonymizer.py — Deterministic token generation
- mapping_table.py — SQLite + AES-256-GCM storage

### 2. Core Hook (run_agent.py)

A thin patch in `turn_context.py`. It checks before every LLM call:

```python
if config.privacy_shield.enabled and not has_pre_llm_call_hook():
    raise PrivacyShieldMissingError(
        "Privacy-Shield plugin is missing. "
        "Install with: hermes plugin install privacy-shield"
    )
```

The hook is optional. It blocks only if Privacy-Shield should be active.

### 3. Auto-Apply (Update Resilience)

After a `hermes update`, `turn_context.py` is overwritten. The core hook disappears.

```
Cron (every 6h) -> auto_apply_hook.py --apply -> Check patch status
                                       -> If missing: patch
                                       -> Syntax check
                                       -> Verify
                                       -> Log
```

The script is idempotent. Running it multiple times is harmless.

## Security Model

### Assumptions

- The user's computer is trusted
- The AI provider (cloud LLM) is NOT trusted
- Plugin code runs in the same process as Hermes

### Threats

| Threat | Protection |
|---|---|
| PII reaches cloud unprotected | Regex filter + tokenization |
| Plugin is disabled | Core hard block |
| Update removes core hook | Auto-apply cron |
| Auto-apply fails | Telegram alert |
| Local mapping table is stolen | AES-256-GCM encryption |

## Update Resilience in Detail

### auto_apply_hook.py

The Python script offers the following modes:

| Flag | Purpose |
|------|---------|
| `--status` | Shows current status |
| `--dry-run` | Shows what would be done |
| `--apply` | Applies patch (idempotent) |
| `--revert` | Restores last backup |
| `--install-cron` | Sets up cron job |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | Error + rollback |
| 3 | Unknown layout |
| 4 | Backup not found |

### Rollback Mechanism

A backup is created before every patch:

```
turn_context.py.bak.<timestamp>
```

If the patch produces a syntax error, rollback is performed automatically.

## Data Flow

```
User Input
      |
      v
Core hook checks: Plugin present?
      |--- No: Hard block (error message)
      |
      v
pre_llm_call Hook
      |
      v
Regex detector scans text
      |
      v
PII found? -> Pseudonymizer generates token
      |                                    |
      |--- No: Text unchanged              |
      |                                    |
      v                                    v
Tokenized request -> LLM API    Mapping table stores token<->original
      |
      v
LLM Response
      |
      v
De-tokenization (translation from mapping table)
      |
      v
Display for user
```

## Storage

The mapping table stores token<->original pairs in SQLite.

- Encryption: AES-256-GCM
- Key source: pass hermes/privacy-shield (preferred) or PRIVACY_SHIELD_KEY
- Table is regularly cleaned up (retention_days)

## Spec Reference

Internal AI-Act architecture spec, v1 (not published).

## Phase 2 Outlook

High-risk mode and human review queue are Phase 2 — not included in this version (v1.0.0).
