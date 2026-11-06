# DSGVO und EU AI Act Compliance-Mapping

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# DSGVO und EU AI Act Compliance-Mapping

**Hinweis:** Diese Tabelle listet nur Artikel, bei denen Privacy-Shield einen MECHANISCHEN Beitrag leistet. Keine Marketing-Aussagen ohne technische Basis.

## DSGVO

| Artikel | Anforderung | Privacy-Shield Mechanismus |
|---|---|---|
| Art. 5 (1) c | Datenminimierung: Nur notwendige Daten | Regex-Filter entfernt PII vor LLM-Call. Nur Tokenisierte Daten verlassen den lokalen Rechner. |
| Art. 25 | Privacy by Design: Datenschutz durch Technik | pre_llm_call Hook als Core-Integration. Hard-Block, falls Plugin fehlt. |
| Art. 32 (1) | Sicherheit der Verarbeitung: Stand der Technik | Defense-in-Depth: Plugin + Core-Hook + Auto-Apply. Verschluesselte Mapping-Tabelle (AES-256-GCM). |

## EU AI Act

| Artikel | Anforderung | Privacy-Shield Mechanismus |
|---|---|---|
| Art. 10 (3) | Datenqualitaet: Fehlerfreie Trainingsdaten | Kein direkter Bezug. Privacy-Shield filtert Input, keine Trainingsdaten. |
| Art. 12 (1) | Protokollierung: Nachvollziehbarkeit | SQLite Audit-Log speichert jede Tokenisierung mit Zeitstempel. Phase 2: Vault-Audit-Trail. |
| Art. 52 (1) | Transparenz: Nutzer muss wissen, dass er mit KI interagiert | Kein direkter Bezug. Privacy-Shield schuetzt Daten, informiert nicht ueber KI-Nutzung. |

## Nicht abgedeckt (ehrliche Limitation)

| Artikel | Warum nicht abgedeckt |
|---|---|
| DSGVO Art. 6 (Rechtsgrundlage) | Privacy-Shield filtert Daten, es prueft keine Rechtsgrundlage |
| DSGVO Art. 7 (Einwilligung) | Kein Mechanismus zur Einwilligungsverwaltung |
| DSGVO Art. 15 (Auskunft) | Kein automatischer Auskunftsprozess |
| DSGVO Art. 17 (Loeschung) | Mapping-Tabelle hat retention_days, aber kein "Recht auf Vergessen"-Feature |
| EU AI Act Art. 9 (Risikomanagement) | Kein Risikomanagement-System |
| EU AI Act Art. 13 (Transparenz-Dokumentation) | Keine automatische Dokumentationserstellung |

## Spec-Referenz

Interne AI-Act-Architektur-Spec, v1 (nicht veröffentlicht).

---

## English

# GDPR and EU AI Act Compliance Mapping

**Note:** This table lists only articles where Privacy-Shield makes a MECHANICAL contribution. No marketing claims without technical basis.

## GDPR

| Article | Requirement | Privacy-Shield Mechanism |
|---|---|---|
| Art. 5 (1) c | Data minimization: Only necessary data | Regex filter removes PII before LLM call. Only tokenized data leaves the local machine. |
| Art. 25 | Privacy by Design: Data protection through technology | pre_llm_call hook as core integration. Hard block if plugin is missing. |
| Art. 32 (1) | Security of processing: State of the art | Defense-in-Depth: Plugin + Core-Hook + Auto-Apply. Encrypted mapping table (AES-256-GCM). |

## EU AI Act

| Article | Requirement | Privacy-Shield Mechanism |
|---|---|---|
| Art. 10 (3) | Data quality: Error-free training data | No direct relevance. Privacy-Shield filters input, not training data. |
| Art. 12 (1) | Logging: Traceability | SQLite audit log stores each tokenization with timestamp. Phase 2: Vault audit trail. |
| Art. 52 (1) | Transparency: User must know they are interacting with AI | No direct relevance. Privacy-Shield protects data, does not inform about AI usage. |

## Not Covered (Honest Limitation)

| Article | Why not covered |
|---|---|
| GDPR Art. 6 (Legal basis) | Privacy-Shield filters data, it does not check legal basis |
| GDPR Art. 7 (Consent) | No consent management mechanism |
| GDPR Art. 15 (Access) | No automated access process |
| GDPR Art. 17 (Erasure) | Mapping table has retention_days, but no "right to be forgotten" feature |
| EU AI Act Art. 9 (Risk management) | No risk management system |
| EU AI Act Art. 13 (Transparency documentation) | No automatic documentation generation |

## Spec Reference

Internal AI-Act architecture spec, v1 (not published).
