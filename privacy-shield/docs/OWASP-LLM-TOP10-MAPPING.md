# OWASP LLM Top-10 (2025) + MITRE ATLAS Mapping

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# OWASP LLM Top-10 (2025) + MITRE ATLAS Mapping

**Privacy-Shield v1.4.1 / Injection-Shield v0.3.3**

Dieses Dokument bildet die Abdeckung unserer Security-Plugins gegen die
OWASP LLM Top-10 Risiken und MITRE ATLAS Techniken ab. Es ist die primäre
Compliance-Referenz für Kunden, Auditoren und Workshop-Teilnehmer.

---

## Übersicht: Was wir abdecken vs. was wir nicht abdecken

| OWASP | Abgedeckt | Plugin | ATLAS |
|-------|-----------|--------|-------|
| LLM01 Prompt Injection | ✅ | Injection-Shield | AML.T0051 |
| LLM02 Sensitive Information Disclosure | ✅ | Privacy-Shield | AML.T0024 |
| LLM03 Training Data Poisoning | ❌ n/a (Runtime) | — | — |
| LLM04 Model Denial of Service | ✅ | Injection-Shield v0.3.3 | — |
| LLM05 Improper Output Handling | ❌ n/a (Input-Fokus) | — | — |
| LLM06 Excessive Agency | ✅ | Injection-Shield | AML.T0051 |
| LLM07 System Prompt Leakage | ✅ | Privacy-Shield | AML.T0024 |
| LLM08 Vector and Embedding Weaknesses | ❌ n/a | — | — |
| LLM09 Misinformation | ❌ out-of-scope | — | — |
| LLM10 Model Theft | ❌ n/a | — | — |

**Covered: 4 / 10** — Wir decken die Runtime-relevanten Risiken ab
(Input-Schutz, Output-Schutz, DoS, Agency). Training-Poisoning, Vector-
Weaknesses und Model-Theft sind Out-of-Scope für Runtime-Plugins.

---

## Detaillierte Mapping-Tabelle

### Privacy-Shield v1.4.1

| Event | OWASP | ATLAS | Beschreibung |
|-------|-------|-------|--------------|
| `pseudonymization_applied` | LLM02 | AML.T0024 | PII erkannt und maskiert vor LLM-Egress |
| `output_pii_detected` | LLM02 | AML.T0024 | PII im LLM-Output erkannt; Block/Restore |
| `blocked_action` | LLM02 | AML.T0024 | Hard-Block bei High-Confidence PII |
| `strict_mode_block` | LLM02 | AML.T0024 | Strict-Mode-Threshold überschritten |
| `paranoid_mode_block` | LLM02 | AML.T0024 | Paranoid-Mode-Threshold überschritten |
| `restore` | LLM07 | AML.T0024 | Token-Restore nach LLM-Response |
| `token_restore_loop` | LLM07 | AML.T0024 | Wiederholte Restore-Versuche erkannt |
| `mode_change` | LLM06 | AML.T0024 | Betriebsmodus geändert (Risk-Eskalation) |
| `approval_required` | LLM06 | AML.T0024 | Menschliche Freigabe erforderlich |
| `approval_granted` | LLM06 | AML.T0024 | Freigabe erteilt |
| `approval_denied` | LLM06 | AML.T0024 | Freigabe verweigert |
| `human_review` | LLM06 | AML.T0024 | Menschliche Prüfung protokolliert |
| `cross_plugin_token_sync` | LLM06 | AML.T0024 | Cross-Plugin Token-Austausch |

### Injection-Shield v0.3.3

| Detection | OWASP | ATLAS | Beschreibung |
|-----------|-------|-------|--------------|
| InjectionPatternDetector (66+ Patterns) | LLM01 | AML.T0051 | Prompt-Injection Pattern-Erkennung |
| InstructionFirewall | LLM01 | AML.T0051 | Instruction-Override Block |
| ToolCallPatternDetector | LLM01 | AML.T0051 | Tool-Call-basierte Exfiltration |
| ZeroWidthDetector | LLM01 | AML.T0051 | Steganographic Injection (Zero-Width) |
| CredentialLeakDetector | LLM01 | AML.T0051 | Credential-Exfiltration |
| ContentTagger + is_untrusted_source | LLM01 | AML.T0051 | Content-Trust-Scoring |
| Loop-Detection / Circuit-Breaker | LLM04 | — | Model Denial of Service Prevention |
| Risky-Pattern-Detection | LLM06 | AML.T0051 | Excessive Agency Erkennung |

---

## Audit-Log: Automatisches Tagging

Ab v1.4.1 (Privacy-Shield) und v0.3.3 (Injection-Shield) werden alle
Audit-Log-Einträge automatisch mit `owasp_risk` und `atlas_technique`
getaggt. Beispiel JSONL:

```json
{"ts": 1787440000.123, "event": "pseudonymization_applied",
 "session_id_hash": "ab12cd34...", "mode": "limited",
 "masked_count_bucket": "1-10", "pii_types": ["email"],
 "owasp_risk": "LLM02", "atlas_technique": "AML.T0024"}
```

Compliance-Auditor filtern: `"Zeig mir alle LLM01-Detections"` ->
alle Injection-Shield Events mit `owasp_risk: "LLM01"`.

---

## CSV/PDF/JSON Export

Audit-Reports enthalten jetzt zwei zusätzliche Spalten:

| timestamp | event | ... | severity | **owasp_risk** | **atlas_technique** |
|-----------|-------|-----|----------|---------------|---------------------|
| 2026-08-23 10:00 | pseudonymization_applied | ... | medium | LLM02 | AML.T0024 |
| 2026-08-23 10:05 | blocked_action | ... | high | LLM02 | AML.T0024 |

PDF-Reports zeigen OWASP + ATLAS Codes in der Event-Tabelle.

---

## Differentiator vs. Mitbewerber

| Vendor | OWASP-Mapping | MITRE ATLAS | Self-Hosted | Preis |
|--------|---------------|-------------|-------------|-------|
| Lakera | ✅ | ✅ | ❌ Cloud | €1.500+/Monat |
| Noma | ✅ | ✅ | ❌ Cloud | Enterprise |
| Zenity | ✅ | ✅ | ❌ Cloud | Enterprise |
| **Hermes Stack** | **✅** | **✅** | **✅** | **€499 einmalig** |

---

## Referenzen

- OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS: https://atlas.mitre.org/techniques/AML.T0051
- ADR-007: Plugin-Only-Strategie
- Feature-Gap: `02-Knowledge/operations/security/20260823-ai-agent-security-market-feature-gap-2026.md`

---

*Document version: 1.4.1-2026-08-23*

---

## English

# OWASP LLM Top-10 (2025) + MITRE ATLAS Mapping

**Privacy-Shield v1.4.1 / Injection-Shield v0.3.3**

This document maps the coverage of our security plugins against the
OWASP LLM Top-10 risks and MITRE ATLAS techniques. It is the primary
compliance reference for customers, auditors, and workshop participants.

---

## Overview: What We Cover vs. What We Don't Cover

| OWASP | Covered | Plugin | ATLAS |
|-------|---------|--------|-------|
| LLM01 Prompt Injection | ✅ | Injection-Shield | AML.T0051 |
| LLM02 Sensitive Information Disclosure | ✅ | Privacy-Shield | AML.T0024 |
| LLM03 Training Data Poisoning | ❌ n/a (runtime) | — | — |
| LLM04 Model Denial of Service | ✅ | Injection-Shield v0.3.3 | — |
| LLM05 Improper Output Handling | ❌ n/a (input focus) | — | — |
| LLM06 Excessive Agency | ✅ | Injection-Shield | AML.T0051 |
| LLM07 System Prompt Leakage | ✅ | Privacy-Shield | AML.T0024 |
| LLM08 Vector and Embedding Weaknesses | ❌ n/a | — | — |
| LLM09 Misinformation | ❌ out-of-scope | — | — |
| LLM10 Model Theft | ❌ n/a | — | — |

**Covered: 4 / 10** — We cover the runtime-relevant risks
(input protection, output protection, DoS, Agency). Training poisoning, vector
weaknesses, and model theft are out-of-scope for runtime plugins.

---

## Detailed Mapping Table

### Privacy-Shield v1.4.1

| Event | OWASP | ATLAS | Description |
|-------|-------|-------|-------------|
| `pseudonymization_applied` | LLM02 | AML.T0024 | PII detected and masked before LLM egress |
| `output_pii_detected` | LLM02 | AML.T0024 | PII in LLM output detected; block/restore |
| `blocked_action` | LLM02 | AML.T0024 | Hard block on high-confidence PII |
| `strict_mode_block` | LLM02 | AML.T0024 | Strict mode threshold exceeded |
| `paranoid_mode_block` | LLM02 | AML.T0024 | Paranoid mode threshold exceeded |
| `restore` | LLM07 | AML.T0024 | Token restore after LLM response |
| `token_restore_loop` | LLM07 | AML.T0024 | Repeated restore attempts detected |
| `mode_change` | LLM06 | AML.T0024 | Operating mode changed (risk escalation) |
| `approval_required` | LLM06 | AML.T0024 | Human approval required |
| `approval_granted` | LLM06 | AML.T0024 | Approval granted |
| `approval_denied` | LLM06 | AML.T0024 | Approval denied |
| `human_review` | LLM06 | AML.T0024 | Human review logged |
| `cross_plugin_token_sync` | LLM06 | AML.T0024 | Cross-plugin token exchange |

### Injection-Shield v0.3.3

| Detection | OWASP | ATLAS | Description |
|-----------|-------|-------|-------------|
| InjectionPatternDetector (66+ Patterns) | LLM01 | AML.T0051 | Prompt injection pattern detection |
| InstructionFirewall | LLM01 | AML.T0051 | Instruction override block |
| ToolCallPatternDetector | LLM01 | AML.T0051 | Tool-call-based exfiltration |
| ZeroWidthDetector | LLM01 | AML.T0051 | Steganographic injection (zero-width) |
| CredentialLeakDetector | LLM01 | AML.T0051 | Credential exfiltration |
| ContentTagger + is_untrusted_source | LLM01 | AML.T0051 | Content trust scoring |
| Loop-Detection / Circuit-Breaker | LLM04 | — | Model denial of service prevention |
| Risky-Pattern-Detection | LLM06 | AML.T0051 | Excessive agency detection |

---

## Audit Log: Automatic Tagging

As of v1.4.1 (Privacy-Shield) and v0.3.3 (Injection-Shield), all
audit log entries are automatically tagged with `owasp_risk` and `atlas_technique`.
Example JSONL:

```json
{"ts": 1787440000.123, "event": "pseudonymization_applied",
 "session_id_hash": "ab12cd34...", "mode": "limited",
 "masked_count_bucket": "1-10", "pii_types": ["email"],
 "owasp_risk": "LLM02", "atlas_technique": "AML.T0024"}
```

Compliance auditors filter: `"Show me all LLM01 detections"` ->
all Injection-Shield events with `owasp_risk: "LLM01"`.

---

## CSV/PDF/JSON Export

Audit reports now contain two additional columns:

| timestamp | event | ... | severity | **owasp_risk** | **atlas_technique** |
|-----------|-------|-----|----------|---------------|---------------------|
| 2026-08-23 10:00 | pseudonymization_applied | ... | medium | LLM02 | AML.T0024 |
| 2026-08-23 10:05 | blocked_action | ... | high | LLM02 | AML.T0024 |

PDF reports show OWASP + ATLAS codes in the event table.

---

## Differentiator vs. Competitors

| Vendor | OWASP Mapping | MITRE ATLAS | Self-Hosted | Price |
|--------|---------------|-------------|-------------|-------|
| Lakera | ✅ | ✅ | ❌ Cloud | €1,500+/month |
| Noma | ✅ | ✅ | ❌ Cloud | Enterprise |
| Zenity | ✅ | ✅ | ❌ Cloud | Enterprise |
| **Hermes Stack** | **✅** | **✅** | **✅** | **€499 one-time** |

---

## References

- OWASP LLM Top 10: https://genai.owasp.org/llm-top-10/
- MITRE ATLAS: https://atlas.mitre.org/techniques/AML.T0051
- ADR-007: Plugin-Only Strategy
- Feature-Gap: `02-Knowledge/operations/security/20260823-ai-agent-security-market-feature-gap-2026.md`

---

*Document version: 1.4.1-2026-08-23*
