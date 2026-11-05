# Privacy-Shield Security Documentation

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Privacy-Shield Security-Dokumentation

**Version:** 1.7.0 (2026-09-09) — Privacy-Shield Security-Eigenschaften + Threat-Model
**Repo-Stand:** entspricht plugin.yaml 1.7.0 (Pre-Intake-Reasoning via post_api_request)
**Letzte Aktualisierung:** 2026-09-09
**Scope:** Threat-Model, bekannte Trade-offs, Security-Design-Entscheidungen

---

## Threat Model

Privacy-Shield ist für **Single-User-Desktop-Umgebungen** ausgelegt (Solo-Operator-Use-Case). Die primären Bedrohungen sind:

1. **Versehentlicher PII-Leak an LLM-APIs** — das Kernproblem, das Privacy-Shield löst
2. **Lokaler Angreifer mit Dateisystem-Zugriff** — ein anderer User auf derselben Maschine oder Malware
3. **LLM-Provider-Logging** — der Provider kann Prompts/Responses loggen

Privacy-Shield ist NICHT ausgelegt für:
- Multi-Tenant-Server-Deployments
- Hochsicherheits-Umgebungen mit HSM-gestützten Keys
- Schutz vor Root-Level-Angreifern

---

## Security-Architektur

### Defense-in-Depth

1. **Hard-Block**: Wenn die Erkennung fehlschlägt oder ein Timeout hat (>80 ms), wird der Prompt komplett blockiert
2. **Auto-Apply**: Erkannte PII wird pseudonymisiert, bevor sie das LLM erreicht
3. **Rollback**: Schlägt der Post-LLM-Hook fehl, wird die Original-Response verworfen

### Verschlüsselung

- **Algorithmus**: AES-256-GCM (authentifizierte Verschlüsselung)
- **Key-Derivation**: PBKDF2-HMAC-SHA256 mit 600.000 Iterationen (OWASP 2023)
- **Salt**: 16 Bytes zufällig pro Verschlüsselung, im Ciphertext gespeichert
- **Nonce**: 12 Bytes zufällig pro Verschlüsselung (kryptografisch sicher)
- **At Rest**: Alle Tokens und Originalwerte sind in der SQLite-Datenbank verschlüsselt
- **Original-Werte**: Niemals im Klartext gespeichert — nur SHA-256-Hashes

### Key-Management

Priorität beim Key-Laden (Design-Vorgabe):
1. `pass show hermes/privacy-shield-key` (bevorzugt)
2. `PRIVACY_SHIELD_KEY` Umgebungsvariable
3. Workshop-Modus (`PRIVACY_SHIELD_WORKSHOP=true`):ephemeraler Key mit Warnung
4. Produktionsmodus: harter Fehler mit Setup-Hinweisen

---

## Bekannte Design-Trade-offs

### Token-Muster-Metadaten-Leak (MED-001)

**Trade-off:** Tokens nutzen das Format `TOKEN_EMAIL_001`, `TOKEN_PHONE_002` usw. Das bedeutet, dass das Token selbst die PII-*Kategorie* offenlegt (E-Mail, Telefon usw.), auch ohne Zugriff auf die Mapping-Tabelle.

**Warum das akzeptabel ist:**
- Tokens sind für **Debugging und Audit** gedacht — die Typ-Kenntnis hilft Operatoren bei der Verifikation
- Tokens werden **niemals im Klartext geloggt** (Logging ist sauber)
- Die Mapping-Tabelle ist at-rest verschlüsselt und durch Dateiberechtigungen (0o600) geschützt
- Ein Angreifer, der Tokens im LLM-Output sieht, hat bereits Zugriff auf den bereinigten Textstrom — die Token-Typ-Metadaten erhöhen den Informations-Leak nicht materiell

**Mitigation:** Falls künftig opake Tokens gebraucht werden, erlauben die Optionen `token_prefix` und `token_style` den Wechsel zu nicht-beschreibenden Formaten (z. B. `TOKEN_001`).

### Key im Speicher (LOW-002)

Der Verschlüsselungs-Key liegt als Python-String-Objekt im Speicher. Python unterstützt kein `mlock`. Ein Angreifer mit Root-Zugriff oder physischem Speicherzugriff kann den Key aus einem Core-Dump oder aus dem Swap extrahieren.

**Mitigation für Phase 1:** Akzeptabel für Single-User-Desktop-Einsatz. Für Phase 2: OS-Level-Swap-Verschlüsselung oder Kernel-Keyring-Integration prüfen.

### `list_all()` ohne Access Control (LOW-004)

Der Befehl `privacy-shield map --list` entschlüsselt und zeigt alle Tokens. Jeder mit Shell-Zugriff und dem Verschlüsselungs-Key kann die gesamte Mapping-Tabelle auslesen.

**Warum das akzeptabel ist:** Der Verschlüsselungs-Key IST die Access Control. Wer den Key hat, kann ohnehin alles entschlüsseln. Der Befehl existiert für Admin-/Debugging-Zwecke.

---

## Dateiberechtigungen

- **Datenbank-Datei** (`mapping.db`): `0o600` (nur Owner lesen/schreiben)
- **Datenbank-Verzeichnis** (`~/.hermes/privacy/`): `0o700` (nur Owner)
- Automatisch bei der Datenbank-Initialisierung gesetzt

---

## Edit-Audit-Log (v1.5.0)

`POST /config` im Desktop-Controls-Backend schreibt bei jeder erfolgreichen
Konfigurationsänderung einen Audit-Event `privacy_shield_config_changed` in das
JSONL-Audit-Log. Der Event enthält:

- Zeitstempel
- Geänderte Keys (keine Werte, um PII zu vermeiden)
- Aktor-Hash (Session-ID-Hash)
- Modus vor und nach der Änderung

Das Audit-Log selbst liegt mit `chmod 600` im Profil-Workspace und wird durch
den bestehenden `AuditLogger` geschrieben. Details zum Format und Export
finden sich in [docs/eu-ai-act-report.md](eu-ai-act-report.md) und
`privacy_shield/audit/__init__.py`.

---

## ReDoS-Schutz

Context-Leak-Detection-Patterns nutzen begrenzte Quantifizierer (`{0,4}` statt `*`), um katastrophales Backtracking zu verhindern. Jedes Pattern läuft mit einem 5-Sekunden-Timeout-Guard — läuft ein Pattern in den Timeout, wird es übersprungen statt die Pipeline zu blockieren.

---

## Wogegen Privacy-Shield NICHT schützt

- **Root-Level-Angreifer** — können Prozessspeicher lesen und Dateiberechtigungen umgehen
- **Physischer Zugriff** — kann die Disk entnehmen, Swap lesen, Memory-Dumps erfassen
- **Kompromittierter LLM-Provider** — ein böswilliger Provider könnte versuchen, PII aus pseudonymisiertem Text zu rekonstruieren
- **Side-Channel-Angriffe** — Timing-Unterschiede in Luhn/IBAN-Validierung (LOW-001, vernachlässigbares Risiko)
- **Multi-Tenant-Umgebungen** — nicht für Shared Hosting ausgelegt

---

## Security-Meldungen

Dies ist ein persönliches Open-Source-Projekt. Für Security-Probleme: GitHub-Issue öffnen oder den Maintainer direkt kontaktieren.

---

## Changelog

| Version | Datum | Änderungen |
|---------|------|---------|
| 1.0.0 | 2026-08-07 | Initial Release. PBKDF2 KDF, Dateiberechtigungen, ReDoS-Schutz, Path-Traversal-Guard |

---

## English

# Privacy-Shield Security Documentation

**Version:** 1.7.0 (2026-09-09) — Privacy-Shield Security-Properties + Threat-Model
**Repo Status:** matches plugin.yaml 1.7.0 (Pre-Intake-Reasoning via post_api_request)
**Last Updated:** 2026-09-09
**Scope:** Threat model, known tradeoffs, security design decisions

---

## Threat Model

Privacy-Shield is designed for **single-user desktop environments** (the solo-operator use case). The primary threats are:

1. **Accidental PII leak to LLM APIs** — the core problem Privacy-Shield solves
2. **Local attacker with filesystem access** — another user on the same machine, or malware
3. **LLM provider logging** — the provider may log prompts/responses

Privacy-Shield is NOT designed for:
- Multi-tenant server deployments
- High-security environments requiring HSM-backed keys
- Protection against root-level attackers

---

## Security Architecture

### Defense-in-Depth

1. **Hard-Block**: If detection fails or times out (>80ms), the prompt is blocked entirely
2. **Auto-Apply**: Detected PII is pseudonymized before reaching the LLM
3. **Rollback**: If the post-LLM hook fails, the original response is discarded

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023)
- **Salt**: 16 bytes random per encryption, stored in ciphertext
- **Nonce**: 12 bytes random per encryption (cryptographically secure)
- **At Rest**: All tokens and original values are encrypted in the SQLite database
- **Original Values**: Never stored in plaintext — only SHA-256 hashes

### Key Management

Key loading priority (design directive):
1. `pass show hermes/privacy-shield-key` (preferred)
2. `PRIVACY_SHIELD_KEY` environment variable
3. Workshop mode (`PRIVACY_SHIELD_WORKSHOP=true`): ephemeral key with warning
4. Production mode: hard error with setup instructions

---

## Known Design Tradeoffs

### Token Pattern Metadata Leak (MED-001)

**Tradeoff:** Tokens use the format `TOKEN_EMAIL_001`, `TOKEN_PHONE_002`, etc. This means the token itself reveals the PII *category* (email, phone, etc.) even without access to the mapping table.

**Why this is acceptable:**
- Tokens are designed for **debugging and audit** — knowing the type helps operators verify correctness
- Tokens are **never logged** in plaintext (logging is clean)
- The mapping table is encrypted at rest and protected by file permissions (0o600)
- An attacker who can see tokens in LLM output already has access to the sanitized text stream — the token type metadata does not materially increase the information leak

**Mitigation:** If opaque tokens are needed in the future, the `token_prefix` and `token_style` configuration options allow switching to non-descriptive formats (e.g., `TOKEN_001`).

### Key in Memory (LOW-002)

The encryption key is held in Python string objects in memory. Python does not support `mlock`. An attacker with root access or physical memory access could extract the key from a core dump or swap.

**Mitigation for Phase 1:** Acceptable for single-user desktop use. For Phase 2, consider OS-level swap encryption or kernel keyring integration.

### `list_all()` Without Access Control (LOW-004)

The `privacy-shield map --list` command decrypts and displays all tokens. Anyone with shell access and the encryption key can dump the entire mapping table.

**Why this is acceptable:** The encryption key IS the access control. Anyone who has the key can decrypt everything anyway. This command exists for admin/debugging purposes.

---

## File Permissions

- **Database file** (`mapping.db`): `0o600` (owner read/write only)
- **Database directory** (`~/.hermes/privacy/`): `0o700` (owner only)
- Set automatically on database initialization

---

## Edit-Audit-Log (v1.5.0)

`POST /config` in the Desktop Controls backend writes an audit event
`privacy_shield_config_changed` to the JSONL audit log on every successful
configuration change. The event contains:

- Timestamp
- Changed keys (no values, to avoid PII)
- Actor hash (session ID hash)
- Mode before and after the change

The audit log itself resides with `chmod 600` in the profile workspace and is
written by the existing `AuditLogger`. Details on format and export can be
found in [docs/eu-ai-act-report.md](eu-ai-act-report.md) and
`privacy_shield/audit/__init__.py`.

---

## ReDoS Protection

Context leak detection patterns use bounded quantifiers (`{0,4}` instead of `*`) to prevent catastrophic backtracking. Each pattern runs with a 5-second timeout guard — if a pattern times out, it is skipped rather than blocking the pipeline.

---

## What Privacy-Shield Does NOT Protect Against

- **Root-level attackers** — can read process memory, bypass file permissions
- **Physical access** — can extract disk, read swap, capture memory dumps
- **Compromised LLM provider** — if the provider is malicious, they could attempt to reconstruct PII from pseudonymized text
- **Side-channel attacks** — timing differences in Luhn/IBAN validation (LOW-001, negligible risk)
- **Multi-tenant environments** — not designed for shared hosting

---

## Reporting Security Issues

This is a personal open-source project. For security issues, open a GitHub issue or contact the maintainer directly.

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-08-07 | Initial release. PBKDF2 KDF, file permissions, ReDoS protection, path traversal guard |
