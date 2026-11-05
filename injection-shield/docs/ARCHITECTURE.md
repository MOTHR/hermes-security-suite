# Injection-Shield Architecture

🌐 [Deutsch](#deutsch) | [English](#english)

## Deutsch

# Injection-Shield-Architektur

## Überblick

`injection-shield` ist ein Prompt-Injection-Defense-in-Depth-Plugin für Hermes Agent.
Es implementiert 5 kooperierende Verteidigungsschichten, orchestriert durch eine
`DetectorChain` (Chain-of-Responsibility, fail-separate Semantik) und 4
Hermes-Hooks (`pre_tool_call`, `post_tool_call`, `pre_llm_call`,
`post_llm_call`).

Designziele:

1. **Defense in Depth.** Keine einzelne Schicht ist ausreichend. Ein Angreifer muss
   Content-Tagging, die Instruktions-Firewall, Ausgabevalidierung,
   Zero-Width-/Steganografie-Erkennung und Credential-Leak-Erkennung gleichzeitig
   umgehen.
2. **Fail-Separate.** Ein Absturz in einem Detektor darf niemals das restliche
   Shield herunterreißen — `DetectorChain.check()` wrapped jeden Detektor in ein
   try/except und logged den Fehler auf WARNING.
3. **Lokal nur.** Das Plugin läuft vollständig auf dem Benutzersystem. Keine
   Telemetrie, keine Analytics, keine externen Uploads. Telegram-Benachrichtigungen
   sind strikt Opt-in.
4. **DSGVO-konform standardmäßig.** PII wird niemals im Klartext geloggt.
   Audit-Logs haben eine 90-Tage-Aufbewahrung und rotieren bei 10 MiB.
   Dateimodus 0600.

## Schichten

Jede Schicht ist ein eigenständiger `BaseDetector` (siehe `detectors/base.py`).
Die Kette komponiert sie so, dass eine fehlerhafte Schicht ausgetauscht werden
kann, ohne den Rest zu berühren.

| # | Detektor | Modul | Verantwortlichkeit |
|---|----------|-------|---------------------|
| 1 | `ContentTagger` | `detectors/content_tagger.py` | Unvertraute Tool-Ausgaben in `<untrusted_tool_result>`-Tags wrappen |
| 2 | `InstructionFirewall` | `detectors/instruction_firewall.py` | System-Prompt-Firewall injizieren, die LLM erinnert, Direktiven zu ignorieren |
| 3 | `OutputValidator` | `detectors/output_validator.py` | LLM-Ausgabe auf User-Action-Direktiven und Leaks validieren |
| 4 | `ZeroWidthDetector` | `detectors/zero_width.py` | Zero-Width-/Variations-Selektor-Steganografie erkennen |
| 5 | `CredentialLeakDetector` | `detectors/credential_leak.py` | Versehentliche Credential-/Secret-Offenlegung erkennen |

Der `InjectionPatternDetector` (siehe `detectors/injection_patterns.py`) ist der
breite Regex-Pattern-Detektor (Instruction-Following-Imperative, Base64-/Base64url-
Payloads, normalisierungsresistente Unicode-Tricks) — verwendet von `OutputValidator`
und `pre_tool_call`-Audits.

`UnicodeNormalizer` (`detectors/unicode_normalizer.py`) ist der Front-Line-Text-
Pre-Prozessor — er entfernt Variationsselektoren und Combining-Marks, bevor die
anderen Detektoren laufen, und eliminiert damit den SCHL-1-Bypass.

## Hooks

| Hook | Was läuft |
|------|----------|
| `pre_tool_call` | Risky-Tool-Audit (Standard: `terminal`, `write_file`). Pattern-Matches → log + alert. |
| `post_tool_call` | Content-Tagging (`ContentTagger`) für `web_*`, `mcp__*` und andere unvertraute Quellen. |
| `pre_llm_call` | Instruktions-Firewall-Prompt-Injection + Zero-Width-Scan auf Benutzereingabe. |
| `post_llm_call` | Ausgabevalidierung: Injection-Patterns, Zero-Width, Credential-Leak, User-Action-Direktiven. |

## Datenfluss

```
        ┌──────────┐    pre_tool_call    ┌──────────────────────┐
User ──▶│  Hermes  │────────────────────▶│ InjectionShield      │
        │  Agent   │                     │   • risky-tool audit │
        │  Loop    │◀──── post_tool_call │   • content tagging  │
        └──────────┘                     └──────────────────────┘
              │                                  │
              │ pre_llm_call                    │
              ▼                                  ▼
        ┌──────────┐                     ┌──────────────────────┐
        │   LLM    │                     │ DetectorChain        │
        │  Call    │                     │   • normalize        │
        └──────────┘                     │   • firewall         │
              │                          │   • zero-width       │
              │ post_llm_call            │   • patterns         │
              ▼                          │   • credentials      │
        ┌──────────┐                     │   • output-validate  │
        │ Response │◀─── enforce/allow ───└──────────────────────┘
        └──────────┘
```

## Modul-Layout

```
~/.hermes/plugins/injection-shield/
├── __init__.py
├── plugin.py                # Hermes-Plugin-Entry-Point (Hooks)
├── config.py                # YAML-Loader + sichere Defaults
├── plugin.yaml              # Plugin-Metadaten
├── pyproject.toml           # Packaging
├── detectors/
│   ├── __init__.py
│   ├── base.py              # BaseDetector + DetectorChain
│   ├── content_tagger.py    # Schicht 1
│   ├── instruction_firewall.py  # Schicht 2
│   ├── output_validator.py  # Schicht 3
│   ├── zero_width.py        # Schicht 4
│   ├── credential_leak.py   # Schicht 5
│   ├── injection_patterns.py    # Breiter Regex-Detektor (verwendet von 3 & pre_tool_call)
│   └── unicode_normalizer.py    # Pre-Prozessor (SCHL-1-Fix)
├── docs/
│   ├── ARCHITECTURE.md      # diese Datei
│   ├── INSTALL.md
│   ├── OPERATIONS.md
│   ├── TROUBLESHOOTING.md
│   └── DSGVO-KONZEPT.md
├── tests/                   # 131+ pytest-Fälle
└── evidence/                # Live-Test-Artefakte für Incident-20260821-KriPo-Berlin
```

## Detector-Failure-Isolation

`DetectorChain.check()` wrapped jeden Detektor:

```python
for detector in self.detectors:
    try:
        violations.extend(detector.check(text, context))
    except Exception as exc:
        logger.warning("DetectorChain: detector %s failed: %s", ..., exc)
```

Ein ReDoS-Blow-up im E-Mail-Regex, ein UnicodeDecodeError im Zero-Width-
Detektor oder ein Tippfehler in einem neuen Detektor degradieren alle zu
„diese Schicht ist still für diese Runde" — sie propagieren niemals hoch
in die LLM-Schleife.

## Public API

```python
from injection_shield import InjectionShieldPlugin   # die Hermes-Hook-Klasse
from injection_shield.detectors import (
    BaseDetector,
    DetectorChain,
    ContentTagger,
    InstructionFirewall,
    OutputValidator,
    ZeroWidthDetector,
    CredentialLeakDetector,
    InjectionPatternDetector,
    is_untrusted_source,
)
```

Siehe `__init__.py` für die autoritative Export-Liste.

---

## English

# Injection-Shield Architecture

## Overview

`injection-shield` is a prompt-injection defense-in-depth plugin for Hermes Agent.
It implements 5 cooperating defense layers orchestrated through a
`DetectorChain` (Chain-of-Responsibility, fail-separate semantics) and 4
Hermes hooks (`pre_tool_call`, `post_tool_call`, `pre_llm_call`,
`post_llm_call`).

Design goals:

1. **Defense in depth.** No single layer is sufficient. An attacker must evade
   content tagging, the instruction firewall, output validation, zero-width /
   steganography detection, and credential-leak detection simultaneously.
2. **Fail-separate.** A crash in one detector must never take the rest of the
   shield down — `DetectorChain.check()` wraps every detector in a try/except
   and logs the failure at WARNING.
3. **Local-only.** The plugin runs entirely on the user system. No telemetry,
   no analytics, no external uploads. Telegram alerts are strictly opt-in.
4. **DSGVO-compliant by default.** PII is never logged in cleartext. Audit logs
   have a 90-day retention and rotate at 10 MiB. File mode 0600.

## Layers

Each layer is a standalone `BaseDetector` (see `detectors/base.py`). The chain
composes them so a buggy layer can be swapped out without touching the rest.

| # | Detector             | Module                              | Responsibility                                                  |
|---|----------------------|-------------------------------------|-----------------------------------------------------------------|
| 1 | `ContentTagger`      | `detectors/content_tagger.py`       | Wrap untrusted tool output in `<untrusted_tool_result>` tags    |
| 2 | `InstructionFirewall`| `detectors/instruction_firewall.py` | Inject system-prompt firewall reminding LLM to ignore directives|
| 3 | `OutputValidator`    | `detectors/output_validator.py`     | Validate LLM output for user-action directives & leaks          |
| 4 | `ZeroWidthDetector`  | `detectors/zero_width.py`           | Detect zero-width / variation-selector steganography            |
| 5 | `CredentialLeakDetector` | `detectors/credential_leak.py`   | Detect accidental credential / secret exposure                  |

The `InjectionPatternDetector` (see `detectors/injection_patterns.py`) is the
broad regex pattern detector (instruction-following imperatives, base64 / base64url
payloads, normalisation-resistant Unicode tricks) — used by `OutputValidator`
and `pre_tool_call` audits.

`UnicodeNormalizer` (`detectors/unicode_normalizer.py`) is the front-line text
pre-processor — it strips variation selectors and combining marks before the
other detectors run, eliminating the SCHL-1 bypass.

## Hooks

| Hook             | What runs                                                                                 |
|------------------|-------------------------------------------------------------------------------------------|
| `pre_tool_call`  | Risky-tool audit (default: `terminal`, `write_file`). Pattern matches → log + alert.      |
| `post_tool_call` | Content tagging (`ContentTagger`) for `web_*`, `mcp__*`, and other untrusted sources.     |
| `pre_llm_call`   | Instruction firewall prompt injection + zero-width scan on user input.                    |
| `post_llm_call`  | Output validation: injection patterns, zero-width, credential leak, user-action directives.|

## Data Flow

```
        ┌──────────┐    pre_tool_call    ┌──────────────────────┐
User ──▶│  Hermes  │────────────────────▶│ InjectionShield      │
        │  Agent   │                     │   • risky-tool audit │
        │  Loop    │◀──── post_tool_call │   • content tagging  │
        └──────────┘                     └──────────────────────┘
              │                                  │
              │ pre_llm_call                    │
              ▼                                  ▼
        ┌──────────┐                     ┌──────────────────────┐
        │   LLM    │                     │ DetectorChain        │
        │  Call    │                     │   • normalize        │
        └──────────┘                     │   • firewall         │
              │                          │   • zero-width       │
              │ post_llm_call            │   • patterns         │
              ▼                          │   • credentials      │
        ┌──────────┐                     │   • output-validate  │
        │ Response │◀─── enforce/allow ───└──────────────────────┘
        └──────────┘
```

## Module Layout

```
~/.hermes/plugins/injection-shield/
├── __init__.py
├── plugin.py                # Hermes plugin entrypoint (hooks)
├── config.py                # YAML loader + safe defaults
├── plugin.yaml              # plugin metadata
├── pyproject.toml           # packaging
├── detectors/
│   ├── __init__.py
│   ├── base.py              # BaseDetector + DetectorChain
│   ├── content_tagger.py    # Layer 1
│   ├── instruction_firewall.py  # Layer 2
│   ├── output_validator.py  # Layer 3
│   ├── zero_width.py        # Layer 4
│   ├── credential_leak.py   # Layer 5
│   ├── injection_patterns.py    # Broad regex detector (used by 3 & pre_tool_call)
│   └── unicode_normalizer.py    # Pre-processor (SCHL-1 fix)
├── docs/
│   ├── ARCHITECTURE.md      # this file
│   ├── INSTALL.md
│   ├── OPERATIONS.md
│   ├── TROUBLESHOOTING.md
│   └── DSGVO-KONZEPT.md
├── tests/                   # 131+ pytest cases
└── evidence/                # Live-test artefacts for Incident-20260821-KriPo-Berlin
```

## Detector Failure Isolation

`DetectorChain.check()` wraps every detector:

```python
for detector in self.detectors:
    try:
        violations.extend(detector.check(text, context))
    except Exception as exc:
        logger.warning("DetectorChain: detector %s failed: %s", ..., exc)
```

A ReDoS blow-up in the email regex, a UnicodeDecodeError in the zero-width
detector, or a typo in a new detector all degrade to "this layer is silent for
this turn" — they never propagate up into the LLM loop.

## Public API

```python
from injection_shield import InjectionShieldPlugin   # the Hermes hook class
from injection_shield.detectors import (
    BaseDetector,
    DetectorChain,
    ContentTagger,
    InstructionFirewall,
    OutputValidator,
    ZeroWidthDetector,
    CredentialLeakDetector,
    InjectionPatternDetector,
    is_untrusted_source,
)
```

See `__init__.py` for the authoritative export list.
