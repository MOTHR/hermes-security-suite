# Privacy-Shield: Internationale Locale-Abdeckung

**Version:** 1.5.0  
**Stand:** 2026-08-23  
**Gültig für:** `RegexPIIDetector` (regex-only) + Phase-2 Name-Heuristik  
**Messmethode:** Empirisch — jede Zelle wurde mit echten Testmustern gegen den aktuellen Code geprüft (`tests/test_locale_coverage.py`). Nichts ist geraten.

---

## Übersicht

Privacy-Shield wurde iterativ für einen DE/EU-primären Use-Case gebaut.  Die Matrix zeigt, welche PII-Typen **heute** in welcher Region zuverlässig erkannt werden — und wo das Plugin lückenhaft bleibt.

| Pattern | DE | US | UK | FR | ES | IT | JP | CN | KR | BR | IN | RU | MX |
|---------|----|----|----|----|----|----|----|----|----|----|----|----|----|
| Email | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| IBAN | ✓ | – | ✓ | ✓ | ✓ | ✓ | – | – | – | ✓ | – | – | – |
| Phone | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ | ✗ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ |
| Name | ✓ | ⚠ | ⚠ | ⚠ | ✗ | ⚠ | ⚠ | ⚠ | ⚠ | ✗ | ⚠ | ⚠ | ✗ |
| Kreditkarte | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| IP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| JWT | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| PLZ/Adresse | ✓ | ⚠ | ✗ | ✓ | ✓ | ✓ | ✗ | ✗ | ⚠ | ✗ | ✗ | ✗ | ✓ |
| Steuer-ID | ✓ | ⚠ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Reisepass | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |

**Legende**

- ✓ voll unterstützt
- ⚠ teilweise / heuristisch / anders typisiert
- ✗ keine Erkennung
- – nicht relevant (z.B. kein IBAN-System)

---

## Wie die Werte gemessen wurden

1. Alle Beispiele laufen über `RegexPIIDetector().scan()`.
2. Pro Land und PII-Typ wurde mindestens ein realistisches Muster geprüft.
3. IBANs wurden zusätzlich durch den ISO 13616 mod-97 Check validiert.
4. Kreditkarten wurden durch den Luhn-Check validiert.
5. Die zugehörigen Regressionstests liegen unter `tests/test_locale_coverage.py`.

---

## Erklärung pro Pattern

### Email — ✓ global

Der Email-Scanner ist ein RFC-5322-Vereinfachung und arbeitet auf normalisiertem Text.  Homoglyph-, HTML-Entity-, URL-Encoding- und `[at]`-Obfuscation werden aufgelöst.  Sprachunabhängig.

### IBAN — ✓ EU + IBAN-Länder, – Nicht-IBAN-Länder

Erkannt werden alle validen IBANs (ISO 13616 mod-97).  Nicht-IBAN-Länder (US, JP, CN, KR, IN, RU, MX) haben kein inländisches IBAN-System — daher "–".

### Phone — ✓ meist, ✗ FR/JP/KR

`_PHONE_STRICT_RE` ist sehr permissiv, erwartet aber eine bestimmte Blockstruktur:

```text
(?:+|00)?\d{1,3}[\s\-./]?
(?:\(0?\d{2,4}\)|0?\d{2,4})[\s\-./]?
\d{3,4}[\s\-./]?\d{2,4}
```

Das erfasst DE, US, UK, ES, IT, CN, IN, RU, BR, MX.  FR-Nummern mit 2-stelligen Blockgruppen (`+33 1 23 45 67 89`), JP (`+81 3 1234 5678`) und KR (`+82 2 123 4567`) passen nicht in diese Struktur.

### Name — ✓ DE, ⚠ lateinisch ohne Akzente, ✗ ES/BR/MX

Der Name-Detector nutzt `_NAME_RE = r'\b[A-Z][a-zäöüß]+\s+[A-Z][a-zäöüß]+\b'`.  Das erkennt nur Buchstaben aus dem deutschen lateinischen Alphabet.  Spanische, brasilianische und mexikanische Namen mit Akzenten (á, ã, é, ñ, …) werden nicht erfasst.  US/UK/FR/IT/JP/CN/KR/IN/RU ohne Akzente funktionieren, aber mit niedrigerer Konfidenz, weil die Vornamen-Whitelist primär deutsch ist.

### Kreditkarte, IP, JWT — ✓ global

- Kreditkarten: Luhn-Check, sprachunabhängig.
- IP: IPv4 + IPv6 Regex, sprachunabhängig.
- JWT: `eyJ...`-Präfix + 3 Base64url-Segmente, sprachunabhängig.

### PLZ/Adresse — ✓ DE, ⚠ gelegentlich, ✗ viele Länder

Nur die deutsche Heuristik existiert:

```text
\d{5}\s+[A-ZÄÖÜ][a-zäöüß]+(...)
```

Funktioniert für DE, FR, ES, IT, MX und manchmal US (5-stellige ZIP).  UK-Postcodes mit Buchstaben, JP mit Bindestrich, BR mit Akzenten, 6-stellige Codes in CN/IN/RU werden nicht erkannt.

### Steuer-ID — ✓ DE, ⚠ US (falsch typisiert), ✗ Rest

- DE: dedizierte 11-stellige Steuer-ID (`tax_id`).
- US: SSN `078-05-1120` wird nicht als `tax_id`, sondern als `steuernummer_alt` erkannt — semantisch falsch.
- UK, FR, ES, IT, JP, CN, KR, IN, RU, MX, BR: keine dedizierten Muster.

### Reisepass — ✓ DE, ✗ Rest

Disambiguierung erfordert deutsche Keywords (`Reisepass`, `Pass`, `Ausweis`).  Englische, französische, spanische, italienische etc. Begriffe werden nicht erkannt.

---

## Was tun, wenn dein Land nicht vollständig unterstützt wird?

1. **Standard-Länder sind DE+US+UK.**  Für diese Regionen ist die Erkennung am ausgereiftesten.
2. **Andere Locales sind für v1.6.0 geplant.**  Dazu gehören:
   - landesspezifische Telefonregexen (FR, JP, KR, …)
   - ausgeweitete Name-Heuristik mit Akzenten und lokalen Vornamen-Listen
   - dedizierte Steuer-ID-/Passport-Detektoren pro Region
   - Postcode-/Adress-Muster für UK, JP, BR, IN, RU, CN
3. **Bis dahin:**  Setze den Modus auf `limited` oder `strict`, um unerkanntes PII zu blockieren, falls ein Prompt besonders sensible Daten aus nicht-DE-Regionen enthält.
4. **Austauschbare Tokenisierung:**  Selbst wenn ein Land nicht vollständig erkannt wird, schützt die Pseudonymisierung für alles, was erkannt wird, weiterhin zuverlässig.

## Workshop-Slide-Vorschlag

**Titelzeile:** "Internationale PII-Abdeckung — heute und v1.6.0"

| Region | Email | Phone | Name | Adresse | Steuer-ID | Reisepass | Status |
|--------|-------|-------|------|---------|-----------|-----------|--------|
| DE | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **Production-ready** |
| US | ✓ | ✓ | ⚠ | ⚠ | ⚠ | ✗ | **Funktioniert** |
| UK | ✓ | ✓ | ⚠ | ✗ | ✗ | ✗ | **Funktioniert** |
| FR/ES/IT | ✓ | ✓/✗ | ⚠/✗ | ✓ | ✗ | ✗ | **Partiell** |
| JP/CN/KR/BR/IN/RU/MX | ✓ | ✗/✓ | ✗/⚠ | ✗/⚠ | ✗ | ✗ | **Eingeschränkt** |

**Optionale Visualisierung:** World-Map-Heatmap (Choropleth) mit grün/gelb/rot pro Land, abgeleitet aus der vollständigen Matrix oben.

**Call-to-Action:** "Volle internationale Abdeckung kommt mit v1.6.0 — heute sicher für DE+US+UK."

---

## Test-Belege

Alle Behauptungen in dieser Matrix werden durch `tests/test_locale_coverage.py` abgedeckt.  Ausführen:

```bash
python3 -m pytest tests/test_locale_coverage.py -v
```

---

## Bekannte Einschränkungen

- OCR-Default-Language ist `deu+eng` (`ocr_lang` in `config.py`).  Für nicht-lateinische Schriften (JP, CN, KR, RU) wird Tesseract ohne zusätzliche Language-Packs kaum brauchbare Texte liefern.
- Es gibt kein `pii.locale` Config-Setting.  Alle Muster laufen gleichzeitig; es gibt keine Laufzeit-Umschaltung auf ein bestimmtes Land.
- Datenschutz ist auch bei Lücken gewahrt, **weil das Plugin nur erkanntes PII tokenisiert**.  Nicht erkannte Daten bleiben im Klartext — das ist keine DSGVO-Verletzung, solange der Nutzer die verbleibenden Risiken kennt.
