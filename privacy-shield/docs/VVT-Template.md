# VVT-Eintrag: KI-gestuetzte Textverarbeitung mit Privacy-Shield

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# VVT-Eintrag: KI-gestuetzte Textverarbeitung mit Privacy-Shield

> **Anleitung:** Dieses Template ist ein Auszug fuer Ihr internes Verzeichnis von Verarbeitungstaetigkeiten (VVT) nach DSGVO Art. 30. Fuellen Sie die Platzhalter mit Ihren eigenen Daten aus. Der Eintrag beschreibt, wie Sie KI-Tools nutzen, ohne persoenliche Daten ungeschuetzt in die Cloud zu senden.
>
> **Hinweis:** Privacy-Shield ist eine technische und organisatorische Massnahme (TOM). Es ersetzt keine Rechtsberatung. Bei Unsicherheit: Datenschutzbeauftragten oder Anwalt konsultieren.

---

## 1. Verantwortlicher

| Feld | Ihre Angabe |
|---|---|
| Name / Firma | `[FIRMA oder VORNAME NACHNAME]` |
| Adresse | `[STRASSE, PLZ ORT]` |
| Kontakt | `[E-MAIL, TELEFON]` |
| Rolle | Verantwortlicher im Sinne von DSGVO Art. 4 Nr. 7 |

---

## 2. Zweck der Verarbeitung

| Feld | Ihre Angabe |
|---|---|
| Was wird gemacht? | KI-gestuetzte Erstellung, Bearbeitung und Zusammenfassung von Texten (E-Mails, Dokumente, Recherche, Content-Produktion) |
| Warum? | Effizienzsteigerung durch automatisierte Textverarbeitung. Persoenliche Daten duerfen dabei nicht ungeschuetzt an Cloud-Anbieter gelangen. |
| Rechtsgrundlage (Art. 6 DSGVO) | `[Art. 6 (1) b (Vertrag) / Art. 6 (1) f (berechtigtes Interesse) / Art. 6 (1) a (Einwilligung) — je nach Fall]` |

---

## 3. Kategorien betroffener Personen

| Kategorie | Beispiele |
|---|---|
| Kunden / Mandanten | Namen, E-Mail-Adressen, Telefonnummern, Adressen, Vertraege |
| Geschaeftspartner | Kontaktdaten, IBAN, Steuer-IDs |
| Mitarbeiter (falls zutreffend) | Personalakten, Gehalt, Krankenkassendaten |
| Eigene Daten | Eigene Kontaktdaten, die im Prompt erwaehnt werden |

> **Hinweis:** Nur die Kategorien auflisten, die tatsaechlich in Ihren KI-Prompts vorkommen koennen.

---

## 4. Kategorien personenbezogener Daten

| Datenkategorie | Beispiele | Privacy-Shield erkennt? |
|---|---|---|
| Kontaktdaten | E-Mail-Adressen, Telefonnummern | Ja (Phase 1) |
| Identifikationsdaten | IP-Adressen, Steuer-IDs | Ja (Phase 1) |
| Finanzdaten | IBAN, Kreditkartennummern | Ja (Phase 1) |
| Adressdaten | Strasse, PLZ, Ort | Ja (Phase 1) |
| Namen | Vornamen, Nachnamen aus Satzkontext | Nein (Phase 2) |
| Gesundheitsdaten | Krankenakten, Diagnosen | Nein — nicht empfohlen mit Phase 1 |
| Biometrische Daten | Gesichtserkennung, Fingerabdruck | Nein — nicht geeignet |

> **Wichtig:** Phase 1 erkennt keine Namen aus dem Fliesstext. Wenn Sie Kundennamen maskieren moechten, muessen Sie das manuell pruefen oder auf Phase 2 warten.

---

## 5. Kategorien von Empfaengern

| Empfaenger | Was wird uebermittelt? | Datenfluss |
|---|---|---|
| Cloud-LLM-Anbieter (z. B. OpenAI, Anthropic, Google) | **Nur pseudonymisierte Token** (z. B. `EMAIL_001`, `PHONE_001`). Keine echten Daten. | Tokenisierte Anfrage -> LLM-API -> Antwort |
| Lokale Speicherung (Ihr Rechner) | Originale Daten + Mapping-Tabelle (verschluesselt) | Bleibt auf Ihrem Geraet |

> **Erklaerung:** Privacy-Shield ersetzt persoenliche Daten durch Token, BEVOR die Anfrage den Anbieter erreicht. Der Anbieter sieht nur Platzhalter. Die Zuordnung Token -> echte Daten liegt nur auf Ihrem Rechner.

---

## 6. Drittlandsuebermittlung (Art. 44 ff. DSGVO)

| Feld | Angabe |
|---|---|
| Findet eine Uebermittlung in ein Drittland statt? | Ja — Cloud-LLM-Anbieter betreiben Server u. a. in den USA |
| Schutzmechanismus | Privacy-Shield als TOM zur Pseudonymisierung vor der Uebermittlung. Zusaetzlich: Standardvertragsklauseln (SCC) des Anbieters pruefen. |
| Zusaetzliche Massnahmen | `[Pruefen: Bietet der Anbieter EU-Datenspeicherung? Ist ein DPA (Data Processing Agreement) abgeschlossen?]` |

---

## 7. Loeschfristen

| Datenbestand | Frist | Begruendung |
|---|---|---|
| Mapping-Tabelle (Token <-> Original) | **1 Stunde nach letzter Nutzung** (Standard: 3600 Sekunden) | Nach dem Chat-Ende muessen die Zuordnungen geloescht werden. Google-Empfehlung: Strikte TTL. |
| Audit-Log (SQLite) | **365 Tage** (konfigurierbar) | Nachweis fuer Compliance-Audits. Laenger nur bei rechtlicher Verpflichtung. |
| LLM-Antworten (lokal gespeichert) | `[SELBST DEFINIEREN: z. B. 30 Tage nach Projektende]` | Nur speichern, wenn noetig. |

> **Anpassung:** Die TTL koennen Sie in der Config-Datei aendern: `~/.hermes/plugins/privacy-shield/config.yaml` -> `mapping_ttl_seconds`. Default ist 3600 (1 Stunde).

---

## 8. Technische und Organisatorische Massnahmen (TOMs)

### 8.1 Pseudonymisierung: Privacy-Shield

| Aspekt | Beschreibung |
|---|---|
| Was? | Plugin fuer Hermes/Hermes, das persoenliche Daten vor dem LLM-Call durch Token ersetzt |
| Wie? | Regex-basierte Erkennung + deterministische Tokenisierung + AES-256-GCM-verschluesselte Mapping-Tabelle |
| Wo? | Lokal auf dem Rechner des Nutzers. Kein Cloud-Call fuer die Erkennung. |
| Schluesselverwaltung | Verschluesselungsschluessel lokal generiert (pass-Passwort-Store oder Umgebungsvariable). Kein Schluessel in der Cloud. |

### 8.2 Defense-in-Depth

| Ebene | Massnahme |
|---|---|
| Ebene 1 — Plugin | Erkennung und Tokenisierung im `pre_llm_call`-Hook |
| Ebene 2 — Core-Hook | Harte Blockade, falls das Plugin fehlt (Update-Schutz) |
| Ebene 3 — Auto-Apply | Automatische Wiederherstellung des Core-Hooks nach Hermes-Updates |
| Ebene 4 — Alert | Telegram-Benachrichtigung bei Fehlern |

### 8.3 Zusaetzliche TOMs (selbst ergaenzen)

| Massnahme | Status |
|---|---|
| Zugriffskontrolle: Rechner mit Passwort / BitLocker / FileVault | `[ ] Ja [ ] Nein` |
| Verschluesselte Festplatte | `[ ] Ja [ ] Nein` |
| Regelmaessige Backups der Mapping-Tabelle | `[ ] Ja [ ] Nein` |
| Hermes-Updates regelmaessig einspielen | `[ ] Ja [ ] Nein` |
| Audit-Log pruefen (monatlich) | `[ ] Ja [ ] Nein` |

---

## 9. Risikobewertung (Art. 32 DSGVO)

| Risiko | Wahrscheinlichkeit | Auswirkung | Mitigation | Restrisiko |
|---|---|---|---|---|
| PII gelangt ungeschuetzt zur Cloud | Niedrig (durch Core-Hard-Block) | Hoch | Regex-Filter + Tokenisierung | Token-Patterns sind fuer Anbieter sichtbar — aber ohne Mapping-Tabelle nicht zuordbar |
| Plugin wird deaktiviert / Update entfernt Hook | Mittel | Hoch | Auto-Apply-Cron + Alert | Falls Auto-Apply und Alert beide ausfallen: ungeschuetzte Uebermittlung moeglich |
| Lokale Mapping-Tabelle gestohlen | Niedrig | Hoch | AES-256-GCM + lokaler Schluessel | Schluesselverlust = entschluesselbar. Backup-Sicherung wichtig. |
| Namen nicht erkannt (Phase 1) | Hoch | Mittel | Manuelle Pruefung + Phase 2 (NER) | Satzkontext-Namen bleiben unmaskiert |
| LLM-Anbieter speichert Token-Patterns | Unbekannt | Mittel | SCC pruefen, Anbieter-Auswahl | Keine technische Kontrolle moeglich |

> **Restrisiko-Summary:** Privacy-Shield reduziert das Risiko erheblich, aber es eliminiert es nicht vollstaendig. Ein Restrisiko bleibt, insbesondere bei nicht erkannten Namen und bei der theoretischen Moeglichkeit, dass ein Anbieter Token-Patterns speichert und spaeter zuordnet. Dieses Restrisiko muss dokumentiert und ggf. im AVV anerkannt werden.

---

## 10. Checkliste: Ist der VVT-Eintrag vollstaendig?

- [ ] Verantwortlicher eingetragen
- [ ] Rechtsgrundlage genannt
- [ ] Betroffenen-Kategorien aufgelistet
- [ ] Empfaenger (Cloud-Anbieter) dokumentiert
- [ ] Loeschfristen definiert (insb. TTL der Mapping-Tabelle)
- [ ] Privacy-Shield als TOM beschrieben
- [ ] Risikobewertung mit Restrisiko-Anmerkung
- [ ] Drittlandsuebermittlung geprueft (SCC / DPA)
- [ ] AVV mit LLM-Anbieter liegt vor oder ist beantragt

---

## Referenzen

- `docs/architecture.md` — Technische Details zu Privacy-Shield
- `docs/dsgvo-mapping.md` — Welche DSGVO-Artikel Privacy-Shield mechanisch abdeckt
- `docs/AVV-Checkliste.md` — Was im AVV mit dem LLM-Anbieter stehen muss
- `config.yaml` — Konfiguration der TTL und weiterer Parameter

---

## English

# RoPA Entry: AI-Assisted Text Processing with Privacy-Shield

> **Instructions:** This template is an excerpt for your internal record of processing activities (RoPA) under GDPR Art. 30. Fill in the placeholders with your own data. The entry describes how you use AI tools without sending personal data unprotected to the cloud.
>
> **Note:** Privacy-Shield is a technical and organizational measure (TOM). It does not replace legal advice. If in doubt: consult a data protection officer or lawyer.

---

## 1. Controller

| Field | Your Entry |
|---|---|
| Name / Company | `[COMPANY or FIRST NAME LAST NAME]` |
| Address | `[STREET, ZIP CITY]` |
| Contact | `[EMAIL, PHONE]` |
| Role | Controller within the meaning of GDPR Art. 4 No. 7 |

---

## 2. Purpose of Processing

| Field | Your Entry |
|---|---|
| What is done? | AI-assisted creation, editing, and summarization of texts (emails, documents, research, content production) |
| Why? | Efficiency gains through automated text processing. Personal data must not be transmitted unprotected to cloud providers. |
| Legal basis (Art. 6 GDPR) | `[Art. 6 (1) b (contract) / Art. 6 (1) f (legitimate interest) / Art. 6 (1) a (consent) — depending on the case]` |

---

## 3. Categories of Data Subjects

| Category | Examples |
|---|---|
| Customers / Clients | Names, email addresses, phone numbers, addresses, contracts |
| Business partners | Contact details, IBAN, tax IDs |
| Employees (if applicable) | Personnel files, salary, health insurance data |
| Own data | Your own contact details mentioned in the prompt |

> **Note:** Only list categories that can actually occur in your AI prompts.

---

## 4. Categories of Personal Data

| Data category | Examples | Privacy-Shield detects? |
|---|---|---|
| Contact data | Email addresses, phone numbers | Yes (Phase 1) |
| Identification data | IP addresses, tax IDs | Yes (Phase 1) |
| Financial data | IBAN, credit card numbers | Yes (Phase 1) |
| Address data | Street, zip code, city | Yes (Phase 1) |
| Names | First names, last names from sentence context | No (Phase 2) |
| Health data | Medical records, diagnoses | No — not recommended with Phase 1 |
| Biometric data | Face recognition, fingerprints | No — not suitable |

> **Important:** Phase 1 does not detect names from running text. If you want to mask customer names, you must check manually or wait for Phase 2.

---

## 5. Categories of Recipients

| Recipient | What is transmitted? | Data flow |
|---|---|---|
| Cloud LLM provider (e.g. OpenAI, Anthropic, Google) | **Only pseudonymized tokens** (e.g. `EMAIL_001`, `PHONE_001`). No real data. | Tokenized request -> LLM API -> Response |
| Local storage (your computer) | Original data + mapping table (encrypted) | Stays on your device |

> **Explanation:** Privacy-Shield replaces personal data with tokens BEFORE the request reaches the provider. The provider sees only placeholders. The assignment token -> real data resides only on your computer.

---

## 6. Third-Country Transfer (Art. 44 ff. GDPR)

| Field | Entry |
|---|---|
| Is there a transfer to a third country? | Yes — cloud LLM providers operate servers in the USA, among other places |
| Safeguard | Privacy-Shield as a TOM for pseudonymization before transfer. Additionally: Check provider's Standard Contractual Clauses (SCC). |
| Additional measures | `[Check: Does the provider offer EU data storage? Is a DPA (Data Processing Agreement) in place?]` |

---

## 7. Retention Periods

| Data set | Period | Justification |
|---|---|---|
| Mapping table (token <-> original) | **1 hour after last use** (default: 3600 seconds) | After chat ends, assignments must be deleted. Google recommendation: strict TTL. |
| Audit log (SQLite) | **365 days** (configurable) | Evidence for compliance audits. Longer only if legally required. |
| LLM responses (stored locally) | `[DEFINE YOURSELF: e.g. 30 days after project end]` | Store only if necessary. |

> **Adjustment:** You can change the TTL in the config file: `~/.hermes/plugins/privacy-shield/config.yaml` -> `mapping_ttl_seconds`. Default is 3600 (1 hour).

---

## 8. Technical and Organizational Measures (TOMs)

### 8.1 Pseudonymization: Privacy-Shield

| Aspect | Description |
|---|---|
| What? | Plugin for Hermes/Hermes that replaces personal data with tokens before the LLM call |
| How? | Regex-based detection + deterministic tokenization + AES-256-GCM-encrypted mapping table |
| Where? | Locally on the user's computer. No cloud call for detection. |
| Key management | Encryption key generated locally (pass password store or environment variable). No key in the cloud. |

### 8.2 Defense-in-Depth

| Layer | Measure |
|---|---|
| Layer 1 — Plugin | Detection and tokenization in the `pre_llm_call` hook |
| Layer 2 — Core Hook | Hard block if the plugin is missing (update protection) |
| Layer 3 — Auto-Apply | Automatic restoration of the core hook after Hermes updates |
| Layer 4 — Alert | Telegram notification on errors |

### 8.3 Additional TOMs (add yourself)

| Measure | Status |
|---|---|
| Access control: computer with password / BitLocker / FileVault | `[ ] Yes [ ] No` |
| Encrypted hard drive | `[ ] Yes [ ] No` |
| Regular backups of the mapping table | `[ ] Yes [ ] No` |
| Apply Hermes updates regularly | `[ ] Yes [ ] No` |
| Check audit log (monthly) | `[ ] Yes [ ] No` |

---

## 9. Risk Assessment (Art. 32 GDPR)

| Risk | Likelihood | Impact | Mitigation | Residual risk |
|---|---|---|---|---|
| PII reaches cloud unprotected | Low (due to core hard block) | High | Regex filter + tokenization | Token patterns are visible to provider — but without mapping table not attributable |
| Plugin disabled / update removes hook | Medium | High | Auto-apply cron + alert | If auto-apply and alert both fail: unprotected transmission possible |
| Local mapping table stolen | Low | High | AES-256-GCM + local key | Key loss = decryptable. Backup of key is important. |
| Names not detected (Phase 1) | High | Medium | Manual review + Phase 2 (NER) | Context-based names remain unmasked |
| LLM provider stores token patterns | Unknown | Medium | Check SCCs, select provider | No technical control possible |

> **Residual risk summary:** Privacy-Shield significantly reduces risk, but does not fully eliminate it. Residual risk remains, particularly with undetected names and the theoretical possibility that a provider stores token patterns and later attributes them. This residual risk must be documented and potentially acknowledged in the DPA.

---

## 10. Checklist: Is the RoPA Entry Complete?

- [ ] Controller entered
- [ ] Legal basis stated
- [ ] Data subject categories listed
- [ ] Recipients (cloud provider) documented
- [ ] Retention periods defined (esp. mapping table TTL)
- [ ] Privacy-Shield described as TOM
- [ ] Risk assessment with residual risk note
- [ ] Third-country transfer reviewed (SCC / DPA)
- [ ] DPA with LLM provider is in place or requested

---

## References

- `docs/architecture.md` — Technical details of Privacy-Shield
- `docs/dsgvo-mapping.md` — Which GDPR articles Privacy-Shield covers mechanically
- `docs/AVV-Checkliste.md` — What must be in the DPA with the LLM provider
- `config.yaml` — Configuration of TTL and other parameters
