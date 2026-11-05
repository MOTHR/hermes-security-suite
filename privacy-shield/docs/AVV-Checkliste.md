# AVV-Checkliste: Auftragsverarbeitung mit Cloud-LLM-Anbieter

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# AVV-Checkliste: Auftragsverarbeitung mit Cloud-LLM-Anbieter

> **Anleitung:** Diese Checkliste hilft Ihnen, einen Auftragsverarbeitungsvertrag (AVV) mit Ihrem Cloud-LLM-Anbieter abzuschliessen oder zu pruefen. Der AVV ist Pflicht nach DSGVO Art. 28, sobald ein Dienstleister (hier: der LLM-Anbieter) personenbezogene Daten in Ihrem Auftrag verarbeitet.
>
> **Wichtig:** Auch pseudonymisierte Daten koennen personenbezogen sein, solange die Zuordnung moeglich ist. Deshalb brauchen Sie einen AVV — auch mit Privacy-Shield.
>
> **Hinweis:** Diese Checkliste ist keine Rechtsberatung. Bei Unsicherheit: Anwalt oder Datenschutzbeauftragten einschalten.

---

## 1. Brauche ich ueberhaupt einen AVV?

| Frage | Ja / Nein | Erklaerung |
|---|---|---|
| Sende ich Daten an einen Cloud-LLM? | Ja | Dann ist der Anbieter Auftragsverarbeiter. |
| Werden die Daten vor dem Senden maskiert / pseudonymisiert? | Ja (durch Privacy-Shield) | Das reduziert das Risiko, aber es entbindet nicht vom AVV. |
| Kann der Anbieter die Token zuordnen? | Nein (bei Privacy-Shield) | Die Mapping-Tabelle liegt nur lokal bei Ihnen. |
| Muss ich trotzdem einen AVV abschliessen? | **Ja** | Auch pseudonymisierte Daten fallen unter Art. 28, wenn eine Wiederzuordnung prinzipiell moeglich ist (und das ist sie — durch Sie). |

> **Fazit:** Privacy-Shield ist eine gute TOM, aber kein Ersatz fuer den AVV. Der AVV bleibt Pflicht.

---

## 2. Was muss im AVV stehen? (DSGVO Art. 28 Abs. 3)

### 2.1 Pflicht-Inhalte (Checkliste)

- [ ] **Gegenstand und Dauer der Verarbeitung**
  - Was: KI-gestuetzte Textverarbeitung (Prompts und Antworten)
  - Dauer: Laufzeit des Vertrags + eventuelle Nachfristen fuer Loeschung

- [ ] **Art und Zweck der Verarbeitung**
  - Art: Automatisierte Verarbeitung durch Large Language Model (LLM)
  - Zweck: Generierung, Zusammenfassung und Bearbeitung von Texten

- [ ] **Art der personenbezogenen Daten**
  - E-Mail-Adressen (als Token, z. B. `EMAIL_001`)
  - Telefonnummern (als Token, z. B. `PHONE_001`)
  - IP-Adressen, IBAN, Steuer-IDs (als Token)
  - Namen (nur manuell maskiert oder ab Phase 2 automatisch)
  - **Wichtig:** Im AVV sollten Sie klarstellen, dass die Daten pseudonymisiert uebermittelt werden.

- [ ] **Kategorien betroffener Personen**
  - Kunden, Mandanten, Geschaeftspartner, Mitarbeiter (je nach Ihrem Use-Case)

- [ ] **Pflichten des Auftragsverarbeiters (Anbieters)**
  - Nur nach Ihren documented instructions verarbeiten
  - Vertraulichkeit sichern
  - Loeschung oder Rueckgabe nach Vertragsende
  - Unterauftragsverarbeiter nur mit Ihrer Genehmigung

- [ ] **Ihre Rechte als Verantwortlicher**
  - Pruefrecht (Audit)
  - Meldung von Datenpannen
  - Loeschung auf Anfrage
  - Auskunft auf Anfrage

- [ ] **Unterauftragsverarbeiter**
  - Pruefen: Nutzt der Anbieter Sub-Contractors (z. B. Cloud-Provider wie Azure, AWS)?
  - Muessen im AVV oder in einer Anlage genannt werden.

---

## 3. Datenschutz-Addendum (DPA): Zusaetzliche Klauseln fuer LLM-Anbieter

Standard-AVVs decken oft nicht die Besonderheiten von KI-Diensten ab. Fordern Sie ein DPA (Data Processing Addendum) oder ergaenzen Sie den AVV um folgende Punkte:

### 3.1 Modell-Training und Datenverwendung

- [ ] **Kein Training auf meinen Daten**
  - Klausel: "Der Anbieter verwendet Prompts und Outputs des Kunden nicht zum Training von Foundation-Models."
  - Pruefen: Ist das im Standard-DPA des Anbieters enthalten? (OpenAI, Anthropic: teilweise ja, aber pruefen.)

- [ ] **Retention-Zeit**
  - Klausel: "Prompts und Outputs werden maximal [X Stunden/Tage] auf Servern des Anbieters vorgehalten und danach geloescht."
  - Pruefen: Was sagt der Anbieter zur Speicherzeit? (OpenAI API: typisch 30 Tage fuer Abuse-Monitoring.)

### 3.2 Standort und Drittlandsuebermittlung

- [ ] **Server-Standort**
  - Frage: Wo werden die Daten verarbeitet? (EU, USA, andere?)
  - Optimal: EU-only Processing. Wenn nicht moeglich: SCC (Standard Contractual Clauses) plus zusaetzliche technische Massnahmen.

- [ ] **Standardvertragsklauseln (SCC)**
  - Pruefen: Sind SCCs zwischen Ihnen und dem Anbieter vereinbart?
  - Zusaetzlich: Schrems II — ist ein angemessenes Datenschutzniveau gewaehrleistet?

### 3.3 Sub-Processor-Liste

- [ ] **Aktuelle Sub-Processors**
  - Frage: Welche Sub-Contractors nutzt der Anbieter?
  - Beispiele: Cloud-Infrastruktur (AWS, Azure, Google Cloud), Content-Moderation, Abuse-Detection
  - Recht: Sie muessen entweder generell zustimmen oder bei neuen Sub-Processors informiert werden.

---

## 4. Privacy-Shield im AVV-Kontext: Was aendert sich?

### 4.1 Datenfluss-Darstellung

```
Ihr Rechner                          Cloud-Anbieter
|- Original-Prompt (mit echten Daten)
|   |
|   v
|- Privacy-Shield Plugin
|   |- Erkennt: E-Mail, Telefon, IBAN...
|   |- Ersetzt durch: EMAIL_001, PHONE_001, IBAN_001
|   |- Speichert Mapping lokal (verschluesselt)
|       v
|- Tokenisierter Prompt ---------------> LLM-API
|                                      (Anbieter sieht nur Token)
|       v
|- LLM-Antwort (mit Token)
|   v
|- De-Tokenisierung (lokal)
|   |- EMAIL_001 -> max@mustermann.de
|       v
|- Fertiger Text fuer Sie
```

### 4.2 Was sollten Sie im AVV vermerken?

| Aspekt | Formulierungsvorschlag |
|---|---|
| Pseudonymisierung vor Uebermittlung | "Der Verantwortliche setzt ein lokales Pseudonymisierungs-Tool (Privacy-Shield) ein, bevor Daten an den Auftragsverarbeiter uebermittelt werden. Der Auftragsverarbeiter empfaengt ausschliesslich Token (z. B. `EMAIL_001`), keine Klartext-Daten." |
| Mapping-Tabelle | "Die Zuordnung Token <-> Original liegt ausschliesslich beim Verantwortlichen auf dessen lokalem System. Der Auftragsverarbeiter hat keinen Zugriff auf die Mapping-Tabelle und kann die Token nicht deanonymisieren." |
| Restrisiko | "Die Pseudonymisierung reduziert das Risiko einer Identifizierung erheblich, beseitigt es nicht vollstaendig. Ein theoretisches Restrisiko bleibt, insbesondere bei Satzkontext-Namen oder bei langfristiger Speicherung von Token-Patterns durch den Auftragsverarbeiter. Beide Parteien erkennen dieses Restrisiko an." |
| Keine Wiederzuordnung durch Anbieter | "Der Auftragsverarbeiter verpflichtet sich, keine technischen oder organisatorischen Massnahmen zu ergreifen, die eine Wiederzuordnung der Token zu den Originaldaten ermoeglichen wuerden." |

---

## 5. Restrisiko anerkennen: Die ehrliche Position

Privacy-Shield ist stark — aber nicht unfehlbar. Im AVV sollten Sie (und der Anbieter) folgende Restrisiken anerkennen:

### 5.1 Bekannte Restrisiken

| Restrisiko | Warum? | Was tun? |
|---|---|---|
| **Namen im Satzkontext** | Phase 1 erkennt keine Namen aus dem Fliesstext. "Max Mustermann" bleibt unmaskiert. | Manuelle Pruefung vor dem Senden. Phase 2 (NER) abwarten oder selbst implementieren. |
| **Token-Patterns speichern** | Der Anbieter koennte Token-Muster langfristig speichern. Ohne Mapping-Tabelle nicht zuordbar — aber ein Muster ist sichtbar. | SCC pruefen. Anbieter-Auswahl: Wer hat klare Retention-Policies? |
| **Schluesselverlust** | Wenn Ihr lokaler Verschluesselungsschluessel verloren geht, ist die Mapping-Tabelle entschluesselbar (falls jemand die Datei hat). | Schluessel sicher speichern (pass-Store, Password-Manager). Backup der Schluessel, nicht der Mapping-Tabelle. |
| **Side-Channel-Angriffe** | Theoretisch: Anbieter kann ueber Prompt-Laenge, Token-Anzahl oder Satzstruktur auf Inhalte schliessen. | Niedriges Risiko, aber nicht null. Dokumentieren als Restrisiko. |
| **Plugin-Ausfall** | Wenn Privacy-Shield deaktiviert wird oder ein Update den Core-Hook entfernt, gehen Daten ungeschuetzt. | Auto-Apply-Cron aktivieren. Monatlichen Check einplanen. |

### 5.2 Formulierung fuer den AVV oder ein Anhang-Dokument

> **Restrisiko-Anmerkung (Vorschlag fuer Anlage zum AVV):**
>
> t> Die Parteien erkennen an, dass die Pseudonymisierung durch Privacy-Shield das Risiko einer unbefugten Offenlegung personenbezogener Daten erheblich reduziert, aber nicht vollstaendig eliminiert. Ein Restrisiko bleibt bestehen, insbesondere:
> - bei nicht erkannten Namen aus dem Satzkontext (Phase 1),
> - bei der theoretischen Moeglichkeit, dass der Auftragsverarbeiter Token-Patterns langfristig speichert,
> - bei einem Ausfall der Pseudonymisierungssoftware auf Seiten des Verantwortlichen.
> Der Verantwortliche verpflichtet sich, dieses Restrisiko in seiner internen Risikobewertung zu dokumentieren und regelmaessig zu pruefen.

---

## 6. Anbieter-Spezifische Pruefpunkte

### 6.1 OpenAI (ChatGPT API)

- [ ] DPA verfuegbar unter: [https://openai.com/policies/data-processing-agreement](https://openai.com/policies/data-processing-agreement)
- [ ] Kein Training auf API-Daten (Business Associate Agreement)
- [ ] Retention: 30 Tage fuer Abuse-Monitoring
- [ ] Sub-Processors: Microsoft Azure (u. a.)
- [ ] EU-Datenspeicherung: Nicht garantiert. SCC gelten.

### 6.2 Anthropic (Claude API)

- [ ] DPA verfuegbar unter: [https://www.anthropic.com/legal/commercial-terms](https://www.anthropic.com/legal/commercial-terms)
- [ ] Kein Training auf API-Daten
- [ ] Retention: Pruefen — aehnlich OpenAI
- [ ] Sub-Processors: AWS, Google Cloud
- [ ] EU-Datenspeicherung: Pruefen

### 6.3 Google (Gemini API)

- [ ] DPA: Google Cloud Data Processing Addendum
- [ ] Retention: Pruefen
- [ ] Sub-Processors: Google eigene Infrastruktur
- [ ] EU-Datenspeicherung: Google Cloud bietet EU-Regionen

### 6.4 Andere Anbieter (z. B. lokale / EU-Anbieter)

- [ ] EU-basierter Anbieter? (z. B. Aleph Alpha, Mistral)
- [ ] DPA vorhanden?
- [ ] Server-Standort in der EU?
- [ ] Keine Drittlandsuebermittlung noetig?

> **Empfehlung:** Pruefen Sie vor Vertragsabschluss, ob der Anbieter ein fertiges DPA-Dokument anbietet. Die meisten grossen Anbieter tun das. Lesen Sie es — oder lassen Sie es von einem Anwalt lesen.

---

## 7. Checkliste: Ist Ihr AVV vollstaendig?

- [ ] Verantwortlicher und Auftragsverarbeiter namentlich genannt
- [ ] Gegenstand und Dauer festgelegt
- [ ] Art, Zweck, Datenkategorien, Betroffenenkategorien dokumentiert
- [ ] Pflichten des Auftragsverarbeiters aufgefuehrt
- [ ] Unterauftragsverarbeiter genannt oder Genehmigungsmechanismus definiert
- [ ] Pseudonymisierung durch Privacy-Shield beschrieben
- [ ] Restrisiko anerkannt und dokumentiert
- [ ] Drittlandsuebermittlung geprueft (SCC, Schrems II)
- [ ] Kein-Training-Klausel enthalten
- [ ] Retention-Zeit definiert
- [ ] Audit-Recht vereinbart
- [ ] Meldung von Datenpannen geregelt
- [ ] Loeschung / Rueckgabe nach Vertragsende geklaert

---

## 8. Unterschied: VVT vs. AVV — Kurzerklaerung

| | VVT (Verzeichnis der Verarbeitungstaetigkeiten) | AVV (Auftragsverarbeitungsvertrag) |
|---|---|---|
| **Wer fuehrt?** | Sie (Verantwortlicher) | Sie + Anbieter (zusammen) |
| **Was steht drin?** | WAS verarbeite ich? (interne Uebersicht) | WIE arbeitet der Anbieter fuer mich? (Vertrag) |
| **Wofuer?** | Art. 30 DSGVO — Nachweis gegenueber Behoerden | Art. 28 DSGVO — Rechtssicherheit im Verhaeltnis Anbieter |
| **Privacy-Shield Rolle** | TOM im VVT beschrieben | Pseudonymisierung im AVV vermerkt |
| **Datei im Projekt** | `docs/VVT-Template.md` | `docs/AVV-Checkliste.md` (diese Datei) |

---

## Referenzen

- `docs/VVT-Template.md` — Template fuer Ihr internes Verzeichnis
- `docs/dsgvo-mapping.md` — Welche DSGVO-Artikel Privacy-Shield mechanisch abdeckt
- `docs/architecture.md` — Technische Details zum Datenfluss
- `config.yaml` — Konfiguration: TTL, Audit-Retention, Schluesselverwaltung

---

*Version 1.0 — Privacy-Shield Fix-10. Erstellt fuer Workshop-Teilnehmer als Handout.*

---

## English

# DPA Checklist: Data Processing with Cloud LLM Provider

> **Instructions:** This checklist helps you establish or review a Data Processing Agreement (DPA) with your cloud LLM provider. A DPA is required under GDPR Art. 28 whenever a service provider (here: the LLM provider) processes personal data on your behalf.
>
> **Important:** Even pseudonymized data can be personal data as long as re-identification is possible. Therefore you need a DPA — even with Privacy-Shield.
>
> **Note:** This checklist is not legal advice. If in doubt: consult a lawyer or data protection officer.

---

## 1. Do I even need a DPA?

| Question | Yes / No | Explanation |
|---|---|---|
| Am I sending data to a cloud LLM? | Yes | Then the provider is a data processor. |
| Is the data masked / pseudonymized before sending? | Yes (via Privacy-Shield) | This reduces risk, but does not exempt you from the DPA requirement. |
| Can the provider map the tokens back? | No (with Privacy-Shield) | The mapping table resides only locally with you. |
| Do I still need to sign a DPA? | **Yes** | Even pseudonymized data falls under Art. 28 if reassignment is in principle possible (and it is — via you). |

> **Conclusion:** Privacy-Shield is a good TOM, but not a substitute for the DPA. The DPA remains mandatory.

---

## 2. What must be in the DPA? (GDPR Art. 28 Para. 3)

### 2.1 Mandatory Contents (Checklist)

- [ ] **Subject matter and duration of processing**
  - What: AI-assisted text processing (prompts and responses)
  - Duration: Contract term + any post-termination periods for deletion

- [ ] **Nature and purpose of processing**
  - Nature: Automated processing by Large Language Model (LLM)
  - Purpose: Generation, summarization, and editing of texts

- [ ] **Type of personal data**
  - Email addresses (as tokens, e.g. `EMAIL_001`)
  - Phone numbers (as tokens, e.g. `PHONE_001`)
  - IP addresses, IBAN, tax IDs (as tokens)
  - Names (only manually masked or automatically from Phase 2)
  - **Important:** In the DPA, clarify that data is transmitted pseudonymized.

- [ ] **Categories of data subjects**
  - Customers, clients, business partners, employees (depending on your use case)

- [ ] **Processor obligations**
  - Process only according to your documented instructions
  - Ensure confidentiality
  - Delete or return upon contract termination
  - Sub-processors only with your authorization

- [ ] **Your rights as controller**
  - Right to audit
  - Data breach notification
  - Deletion upon request
  - Information upon request

- [ ] **Sub-processors**
  - Check: Does the provider use sub-contractors (e.g. cloud providers like Azure, AWS)?
  - Must be listed in the DPA or an annex.

---

## 3. Data Privacy Addendum (DPA): Additional Clauses for LLM Providers

Standard DPAs often do not cover the specifics of AI services. Request a DPA addendum or supplement the DPA with the following:

### 3.1 Model Training and Data Use

- [ ] **No training on my data**
  - Clause: "The provider shall not use customer prompts and outputs for training foundation models."
  - Check: Is this included in the provider's standard DPA? (OpenAI, Anthropic: partially yes, but verify.)

- [ ] **Retention period**
  - Clause: "Prompts and outputs shall be retained for a maximum of [X hours/days] on the provider's servers and deleted thereafter."
  - Check: What does the provider say about retention? (OpenAI API: typically 30 days for abuse monitoring.)

### 3.2 Location and Third-Country Transfer

- [ ] **Server location**
  - Question: Where is the data processed? (EU, USA, other?)
  - Optimal: EU-only processing. If not possible: SCC (Standard Contractual Clauses) plus additional technical measures.

- [ ] **Standard Contractual Clauses (SCC)**
  - Check: Are SCCs agreed between you and the provider?
  - Additionally: Schrems II — is an adequate level of data protection ensured?

### 3.3 Sub-Processor List

- [ ] **Current sub-processors**
  - Question: Which sub-contractors does the provider use?
  - Examples: Cloud infrastructure (AWS, Azure, Google Cloud), content moderation, abuse detection
  - Legal: You must either consent generally or be notified of new sub-processors.

---

## 4. Privacy-Shield in the DPA Context: What Changes?

### 4.1 Data Flow Description

```
Your Computer                          Cloud Provider
|- Original prompt (with real data)
|   v
|- Privacy-Shield Plugin
|   |- Detects: email, phone, IBAN...
|   |- Replaces with: EMAIL_001, PHONE_001, IBAN_001
|   |- Stores mapping locally (encrypted)
|       v
|- Tokenized prompt ---------------------> LLM API
|                                      (provider sees only tokens)
|       v
|- LLM response (with tokens)
|   v
|- De-tokenization (local)
|   |- EMAIL_001 -> max@example.com
|       v
|- Finished text for you
```

### 4.2 What Should You Note in the DPA?

| Aspect | Suggested Wording |
|---|---|
| Pseudonymization before transmission | "The controller uses a local pseudonymization tool (Privacy-Shield) before transmitting data to the processor. The processor receives exclusively tokens (e.g. `EMAIL_001`), no plaintext data." |
| Mapping table | "The assignment token <-> original resides exclusively with the controller on their local system. The processor has no access to the mapping table and cannot deanonymize the tokens." |
| Residual risk | "Pseudonymization significantly reduces the risk of identification but does not fully eliminate it. A theoretical residual risk remains, particularly with context-based names or with long-term storage of token patterns by the processor. Both parties acknowledge this residual risk." |
| No reassignment by provider | "The processor commits to not taking any technical or organizational measures that would enable reassignment of tokens to the original data." |

---

## 5. Acknowledging Residual Risk: The Honest Position

Privacy-Shield is powerful — but not infallible. In the DPA, you (and the provider) should acknowledge the following residual risks:

### 5.1 Known Residual Risks

| Residual Risk | Why? | What to Do? |
|---|---|---|
| **Names in sentence context** | Phase 1 does not detect names from running text. "Max Mustermann" remains unmasked. | Manual review before sending. Wait for Phase 2 (NER) or implement yourself. |
| **Storing token patterns** | The provider could store token patterns long-term. Without the mapping table, not attributable — but a pattern is visible. | Check SCCs. Provider selection: Who has clear retention policies? |
| **Key loss** | If your local encryption key is lost, the mapping table is decryptable (if someone has the file). | Store key securely (pass store, password manager). Backup the key, not the mapping table. |
| **Side-channel attacks** | Theoretically: Provider can infer content from prompt length, token count, or sentence structure. | Low risk, but not zero. Document as residual risk. |
| **Plugin failure** | If Privacy-Shield is disabled or an update removes the core hook, data goes unprotected. | Enable auto-apply cron. Schedule monthly checks. |

### 5.2 Wording for the DPA or an Annex Document

> **Residual Risk Note (Proposed Annex to DPA):**
>
> The parties acknowledge that pseudonymization via Privacy-Shield significantly reduces the risk of unauthorized disclosure of personal data but does not fully eliminate it. Residual risk remains, in particular:
> - with undetected names from sentence context (Phase 1),
> - with the theoretical possibility that the processor stores token patterns long-term,
> - with a failure of the pseudonymization software on the controller's side.
> The controller commits to documenting this residual risk in its internal risk assessment and reviewing it regularly.

---

## 6. Provider-Specific Review Points

### 6.1 OpenAI (ChatGPT API)

- [ ] DPA available at: [https://openai.com/policies/data-processing-agreement](https://openai.com/policies/data-processing-agreement)
- [ ] No training on API data (Business Associate Agreement)
- [ ] Retention: 30 days for abuse monitoring
- [ ] Sub-processors: Microsoft Azure (among others)
- [ ] EU data storage: Not guaranteed. SCCs apply.

### 6.2 Anthropic (Claude API)

- [ ] DPA available at: [https://www.anthropic.com/legal/commercial-terms](https://www.anthropic.com/legal/commercial-terms)
- [ ] No training on API data
- [ ] Retention: Verify — similar to OpenAI
- [ ] Sub-processors: AWS, Google Cloud
- [ ] EU data storage: Verify

### 6.3 Google (Gemini API)

- [ ] DPA: Google Cloud Data Processing Addendum
- [ ] Retention: Verify
- [ ] Sub-processors: Google's own infrastructure
- [ ] EU data storage: Google Cloud offers EU regions

### 6.4 Other Providers (e.g. local / EU providers)

- [ ] EU-based provider? (e.g. Aleph Alpha, Mistral)
- [ ] DPA available?
- [ ] Server location in the EU?
- [ ] No third-country transfer needed?

> **Recommendation:** Before signing the contract, check whether the provider offers a ready-made DPA document. Most major providers do. Read it — or have a lawyer read it.

---

## 7. Checklist: Is Your DPA Complete?

- [ ] Controller and processor named
- [ ] Subject matter and duration defined
- [ ] Nature, purpose, data categories, and data subject categories documented
- [ ] Processor obligations listed
- [ ] Sub-processors named or authorization mechanism defined
- [ ] Pseudonymization via Privacy-Shield described
- [ ] Residual risk acknowledged and documented
- [ ] Third-country transfer reviewed (SCC, Schrems II)
- [ ] No-training clause included
- [ ] Retention period defined
- [ ] Audit rights agreed
- [ ] Data breach notification regulated
- [ ] Deletion / return upon contract termination clarified

---

## 8. Difference: RoPA vs. DPA — Brief Explanation

| | RoPA (Record of Processing Activities) | DPA (Data Processing Agreement) |
|---|---|---|
| **Who maintains it?** | You (controller) | You + provider (jointly) |
| **What's in it?** | WHAT am I processing? (internal overview) | HOW does the provider work for me? (contract) |
| **Purpose?** | Art. 30 GDPR — accountability to authorities | Art. 28 GDPR — legal certainty in provider relationship |
| **Privacy-Shield role** | TOM described in RoPA | Pseudonymization noted in DPA |
| **File in project** | `docs/VVT-Template.md` | `docs/AVV-Checkliste.md` (this file) |

---

## References

- `docs/VVT-Template.md` — Template for your internal records
- `docs/dsgvo-mapping.md` — Which GDPR articles Privacy-Shield covers mechanically
- `docs/architecture.md` — Technical details of the data flow
- `config.yaml` — Configuration: TTL, audit retention, key management

---

*Version 1.0 — Privacy-Shield Fix-10. Created for workshop participants as a handout.*
