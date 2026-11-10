# Privacy-Shield Architektur

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Privacy-Shield Architektur

**Spec-Version:** v1.0.0

## Uebersicht

Privacy-Shield ist ein Defense-in-Depth System. Es schuetzt persoenliche Daten auf zwei Ebenen:

1. Plugin-Ebene: Erkennung und Tokenisierung von PII (pre_llm_call + llm_request-Middleware)
2. Provider-Ebene: Nur Tokens verlassen die Maschine; lokale Provider (Ollama) werden ausgespart

Das Plugin nutzt ausschliesslich die Upstream-Hook-/Middleware-Contracts des Hermes Agent
(pre_llm_call-Veto, llm_request-Middleware, transform_llm_output, post_api_request,
on_session_finalize). Es werden KEINE Core-Dateien gepatcht und KEINE Crontab-Eintraege
angelegt — ein `hermes update` kann die Funktionalitaet daran nicht veraendern.

## Komponenten

### 1. Plugin (privacy-shield/)

- __init__.py — Plugin-Entry-Point, Hook- + Middleware-Registration
- plugin.py — pre_llm_call-Pipeline + llm_request-Middleware-Anwendung
- config.py — Konfiguration mit Phase-1-Defaults
- detectors/ — Regex-basierte PII-Erkennung
- pseudonymizer.py — Deterministische Token-Erzeugung
- mapping_table.py — SQLite + AES-256-GCM Speicherung

Der Hook ist optional. Er blockiert nur, wenn Privacy-Shield aktiv sein sollte.

## Security-Modell

### Annahmen

- Der Rechner des Nutzers ist vertrauenswuerdig
- Der KI-Anbieter (Cloud-LLM) ist NICHT vertrauenswuerdig
- Plugin-Code laeuft im gleichen Prozess wie Hermes

### Bedrohungen

| Bedrohung | Schutz |
|---|---|
| PII gelangt ungeschuetzt zur Cloud | Regex-Filter + Tokenisierung (Middleware greift vor dem API-Request) |
| Plugin wird deaktiviert | LLM-Requests laufen unmodifiziert (fail-open); Veto-Schutz via `strict`/`paranoid` per pre_llm_call |
| Lokale Mapping-Tabelle wird gestohlen | AES-256-GCM Verschluesselung |

## Datenfluss

```
Nutzer-Input
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
      |                                    | (strict/paranoid: {"action": "block",
      v                                    |  "message": ...} = Turn-Veto)
      v                                    v
      v                              Mapping-Tabelle speichert Token<->Original,
llm_request Middleware schreibt die       sanitized Prompt wird fuer den
User-Message im api_kwargs um       -->   naechsten Request gestaged
      |
      v
Tokenisierte Anfrage -> LLM-API
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
- Schluesselquelle: PRIVACY_SHIELD_KEY via Hermes secret_scope (requires_env; z.B. Keychain oder pass-store Secret-Source-Plugin)
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

1. Plugin level: detection and tokenization of PII (pre_llm_call + llm_request middleware)
2. Provider level: only tokens leave the machine; local providers (Ollama) are exempt

The plugin uses only the upstream hook/middleware contracts of the Hermes Agent
(pre_llm_call veto, llm_request middleware, transform_llm_output, post_api_request,
on_session_finalize). It does NOT patch core files and does NOT create crontab
entries — a `hermes update` cannot break its functionality.

## Components

### 1. Plugin (privacy-shield/)

- __init__.py — plugin entry point, hook + middleware registration
- plugin.py — pre_llm_call pipeline + llm_request middleware application
- config.py — configuration with Phase 1 defaults
- detectors/ — regex-based PII detection
- pseudonymizer.py — deterministic token generation
- mapping_table.py — SQLite + AES-256-GCM storage

The hook is optional. It vetoes only when Privacy-Shield should be active.

## Security Model

### Assumptions

- The user's computer is trusted
- The AI provider (cloud LLM) is NOT trusted
- Plugin code runs in the same process as Hermes

### Threats

| Threat | Protection |
|---|---|
| PII reaches cloud unprotected | Regex filter + tokenization (middleware runs before the API request) |
| Plugin is disabled | LLM requests run unmodified (fail-open); veto protection via `strict`/`paranoid` pre_llm_call |
| Local mapping table is stolen | AES-256-GCM encryption |

## Data Flow

```
User Input
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
      |                                    | (strict/paranoid: {"action": "block",
      v                                    |  "message": ...} = turn veto)
      v                                    v
      v                              Mapping table stores token<->original,
llm_request middleware rewrites the        sanitized prompt is staged for the
user message in api_kwargs        -->      next outgoing request
      |
      v
Tokenized request -> LLM API
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
- Key source: PRIVACY_SHIELD_KEY via Hermes secret_scope (requires_env; e.g. Keychain or pass-store secret-source plugin)
- Table is regularly cleaned up (retention_days)

## Spec Reference

Internal AI-Act architecture spec, v1 (not published).

## Phase 2 Outlook

High-risk mode and human review queue are Phase 2 — not included in this version (v1.0.0).
