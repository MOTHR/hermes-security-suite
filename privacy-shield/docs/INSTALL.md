# Privacy-Shield — Installations-Anleitung (INSTALL.md)

🌐 [Deutsch](#deutsch) | [English](#english)

---

## Deutsch

# Privacy-Shield — Installations-Anleitung (INSTALL.md)

**Version:** 1.7.0 (2026-09-09)
**Repository:** https://github.com/MOTHR/hermes-privacy-shield (PRIVAT)
**Zielgruppe:** Entwickler, die Privacy-Shield in Hermes/Hermes integrieren möchten

---

## Inhalt

1. [Voraussetzungen](#1-voraussetzungen)
2. [Installation](#2-installation)
3. [Desktop-Controls](#3-desktop-controls)
4. [Encryption-Key Setup](#4-encryption-key-setup)
5. [Hermes-Loader-Integration](#5-hermes-loader-integration)
6. [Verification](#6-verification)
7. [Profile-Aktivierung](#7-profile-aktivierung)

---

## 1. Voraussetzungen

### System-Anforderungen

| Komponente | Version | Notiz |
|---|---|---|
| **Python** | 3.10+ | Tests laufen mit 3.10, 3.11, 3.12 |
| **Tesseract OCR** | 5.5.2+ | Für Image-OCR (Phase 2) |
| **Hermes Agent** | 0.1+ | Hook-Integration in `pre_llm_call()` und `transform_llm_output()` |
| **pass** (CLI) | latest | Optional — für Key-Storage |
| **OS** | macOS 12+, Ubuntu 22+, Debian 12+ | Andere UNIXe sollten auch funktionieren |

### Tesseract installieren

**macOS:**
```bash
brew install tesseract tesseract-lang
tesseract --version  # Sollte 5.5.2 oder höher zeigen
tesseract --list-langs  # Sollte deu, eng, etc. zeigen
```

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng
tesseract --version
```

**Fedora / RHEL:**
```bash
sudo dnf install -y tesseract tesseract-langpack-deu tesseract-langpack-eng
```

### pass CLI installieren (empfohlen für Key-Storage)

**macOS:**
```bash
brew install pass
# GPG-Key erstellen falls noch nicht vorhanden
gpg --gen-key
# pass initialisieren
pass init "deine-email@example.com"
```

**Ubuntu / Debian:**
```bash
sudo apt-get install -y pass gnupg
```

**Alternativ** kannst du die Env-Variable `PRIVACY_SHIELD_KEY` setzen (siehe unten).

---

## 2. Installation

### Option A: Aus dem Repository installieren (empfohlen für Entwicklung)

```bash
# Repository klonen (SSH, Privatrepo)
git clone git@github.com:MOTHR/hermes-privacy-shield.git
cd hermes-privacy-shield
pip install -e .

# Dependencies automatisch via pyproject.toml:
# - click, cryptography, pyyaml
# - pdfplumber, reportlab (PDF)
# - Pillow, pytesseract, pillow-heif (OCR)
```

**Vorteile:**
- Änderungen am Source-Code wirken sofort (kein Re-Install)
- Perfekt für Development + Testing

### Option B: Production-Install via pip

```bash
# Aus dem Git-Repo (PRIVAT — brauchst du GitHub-Zugang)
pip install git+ssh://git@github.com:MOTHR/hermes-privacy-shield.git@v1.7.0

# Oder via lokaler Wheel-Datei
pip install /pfad/zu/privacy-shield-1.7.0-py3-none-any.whl
```

### Option C: Manuelle Installation (ohne pip)

```bash
cd hermes-privacy-shield
# Dependencies installieren (für CLI + Desktop-Controls + Dev-Tools)
pip install -r requirements.txt
pip install -e ".[desktop]"
# Package zu PYTHONPATH hinzufügen (nicht empfohlen für Production)
export PYTHONPATH="$PWD:$PYTHONPATH"
```

### Verifizieren der Installation

```bash
# 1. CLI verfügbar?
which privacy-shield

# 2. Version prüfen
privacy-shield --version

# 3. Help anzeigen
privacy-shield --help
```

**Erwarteter Output:**
```
Usage: privacy-shield [OPTIONS] COMMAND [ARGS]...

  Privacy-Shield CLI — PII-Pseudonymisierung für Hermes.

Options:
  --version   Show the version and exit.
  --help      Show this message and exit.

Commands:
  doctor      Run system self-test
  map         Manage token mapping table
  pseudonymize  Pseudonymize text
  scan        Scan text for PII (no replacement)
  setup       Setup encryption key
  status      Show plugin status
  test        Run round-trip test
```

## 3. Desktop-Controls

Seit v1.5.0 wird Privacy-Shield zusammen mit einem offiziellen Desktop-Plugin
ausgeliefert. Hermes installiert `desktop/` selbst (`hermes plugins install` /
`hermes plugins enable`) — es wird **kein Kopieren nach
`~/.hermes/desktop-plugins/privacy-shield-controls/` mehr vorgenommen.**

Im Hermes Desktop app erscheint daraufhin ein **Privacy-Shield**-Pane, über das
folgende Einstellungen editiert werden können:

- Plugin an-/ausschalten
- Betriebsmodus (`off`/`audit`/`limited`/`strict`/`paranoid`)
- Confidence-Threshold
- Restore-allowed Channels
- PDF / Image OCR / Cache-Bypass
- Synthetischer Restore-Roundtrip-Test

Änderungen werden mit `POST /config` in `~/.hermes/config.yaml` unter
`plugins.entries.privacy-shield` geschrieben und beim nächsten Plugin-Reload
wirksam. Details zur API und zum UI finden sich in
[docs/desktop-controls.md](desktop-controls.md).

---

## 4. Encryption-Key Setup

Privacy-Shield verschlüsselt die Mapping-Tabelle mit **AES-256-GCM** (PBKDF2 mit 100.000 Iterations). Du brauchst einen 64-Hex-Zeichen Key (32 Bytes).

### Option A: pass-Store (empfohlen für Production)

```bash
# 1. Key generieren (einmalig)
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 2. Verifizieren
pass hermes/privacy-shield-key

# 3. Plugin erkennt den Key automatisch
privacy-shield status
```

**Vorteile:**
- Key ist GPG-verschlüsselt auf Disk
- Multi-Device-Sync möglich (z.B. via git für pass-Store)
- Kein Klartext in Shell-History oder Config-Files

### Option B: Env-Variable (für Container / Server)

```bash
# In deiner Shell / .bashrc / .zshrc
export PRIVACY_SHIELD_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Oder in einem .env-File (mit chmod 600!)
echo "PRIVACY_SHIELD_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > ~/.hermes/privacy-shield.env
chmod 600 ~/.hermes/privacy-shield.env
```

### Option C: Workshop-Modus (nur für Demos, NICHT für Production)

```bash
# Setze die Env-Variable PRIVACY_SHIELD_WORKSHOP=true
# Privacy-Shield generiert einen ephemeralen Key beim Start
export PRIVACY_SHIELD_WORKSHOP=true
privacy-shield scan "test"
```

**⚠️ WARNUNG:** Im Workshop-Modus ist die Mapping-Tabelle nach Neustart **unentschlüsselbar**. Nur für Demos und Tests verwenden!

### Key-Quelle in plugin.yaml konfigurieren

```yaml
privacy_shield:
  key_source: pass  # oder "env" oder "workshop"
  key_pass_path: hermes/privacy-shield-key
  key_env_var: PRIVACY_SHIELD_KEY
```

### Key-Rotation

Alle 90 Tage empfohlen:

```bash
# 1. Neuen Key generieren
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 2. Im pass-Store ersetzen
echo "$NEW_KEY" | pass insert -f hermes/privacy-shield-key

# 3. Alte Sessions beenden (crypto-shredding alter Mappings)
privacy-shield map --close-all

# 4. Plugin reloaden
hermes plugins reload privacy-shield
```

---

## 5. Hermes-Loader-Integration

### 4.1 Plugin zu Hermes hinzufügen

**In `~/.hermes/config.yaml`:**

```yaml
plugins:
  enabled:
    - privacy-shield

  # Optional: Plugin-spezifische Config
  privacy_shield:
    enabled: true
    mode: limited
    # ... (siehe USER-GUIDE.md Sektion 3 für alle Optionen)
```

### 4.2 Plugin-Symlinks setzen

Wenn du das Plugin aus einem anderen Verzeichnis nutzt:

```bash
# Standardmäßig sucht Hermes unter ~/.hermes/plugins/
ls -la ~/.hermes/plugins/privacy-shield
# Sollte Symlink oder Verzeichnis sein
```

Falls du es woanders hast:
```bash
ln -s /pfad/zu/privacy-shield ~/.hermes/plugins/privacy-shield
```

### 4.3 Hermes neu starten oder reloaden

```bash
# Plugin reloaden (empfohlen)
hermes plugins reload privacy-shield

# Oder kompletter Hermes-Restart
hermes restart
```

### 4.4 Verifizieren

```bash
hermes plugins list | grep privacy-shield
# Sollte zeigen: privacy-shield v1.7.0 (enabled)

privacy-shield status
# Sollte zeigen: Privacy-Shield v1.7.0 — ACTIVE
```

### 4.5 Hook-Integration prüfen

```bash
# Sende einen Test-Prompt mit PII
hermes chat "Schreib mir eine Mail an dirk@example.com"

# Im Log solltest du sehen:
# [privacy-shield] pre_llm_call: detected 1 PII match (email)
# [privacy-shield] replaced with TOKEN_EMAIL_xxx
# [privacy-shield] transform_llm_output: restored 1 token
```

Falls das nicht passiert, prüfe:
```bash
# 1. Plugin enabled?
hermes plugins list

# 2. Hook registriert?
grep -r "privacy_shield" ~/.hermes/hooks/ 2>/dev/null

# 3. Config geladen?
python3 -c "import yaml; print(yaml.safe_load(open('~/.hermes/config.yaml'))['plugins'])"
```

---

## 6. Verification

### 5.1 Schneller Smoke-Test (30 Sekunden)

```bash
privacy-shield scan "Test mit dirk@example.com"
# Erwartet: [DETECTED] email pattern
```

### 5.2 Strukturelle Tests (2 Minuten)

```bash
cd ~/.hermes/plugins/privacy-shield
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -q 2>&1 | tail -3
# Erwartet: 369 passed in X.XXs
```

### 5.3 Round-Trip-Test

```bash
privacy-shield test --text "Mail an dirk@example.com mit IBAN DE89370400440532013000"
# Erwartet: Token -> Original Round-Trip OK
```

### 5.4 PDF + OCR-Test

```bash
# Generiere ein Test-Bild
mkdir -p ~/.hermes/privacy/restore/images
python3 ~/.hermes/plugins/privacy-shield/scripts/generate_test_image.py ~/.hermes/privacy/restore/images/test_invoice.png
chmod 700 ~/.hermes/privacy/restore/images

# Sende das Bild an Hermes
hermes chat --image ~/.hermes/privacy/restore/images/test_invoice.png "Was steht auf der Rechnung?"

# Im Log solltest du sehen:
# [privacy-shield] OCR: detected text from image
# [privacy-shield] pre_llm_call: detected N PII matches
```

### 5.5 Vollständiger Doctor-Test

```bash
privacy-shield doctor
# Prüft:
# - Python-Version
# - Tesseract-Installation
# - Key-Verfügbarkeit
# - Hermes-Integration
# - Plugin-Health
# - Test-Suite-Status
```

**Erwarteter Output:**
```
[OK] Python 3.11.5
[OK] Tesseract 5.5.2 (deu+eng installed)
[OK] Encryption key available (pass-store)
[OK] Hermes plugin loaded
[OK] 369/369 tests passing
[OK] Plugin healthy
ALL CHECKS PASSED ✅
```

---

## 7. Profil-Aktivierung

Hermes unterstützt mehrere Profile. Privacy-Shield kann **profil-spezifisch**
aktiviert werden.

### Profil aktivieren

```bash
# Im jeweiligen Profil-Config-File:
plugins:
  enabled: [privacy-shield]

# Oder via CLI:
hermes -p <profile> plugins enable privacy-shield
```

Wiederhole das pro Profil, das du schützen willst. Die Plugin-Installation
(Symlink unter `~/.hermes/plugins/`) ist pro Hermes-Install einmal nötig.

### Verifikation

```bash
hermes -p <profile> plugins list | grep privacy-shield
```

## 🎉 Installation abgeschlossen!

**Nächste Schritte:**

1. Lese [USER-GUIDE.md](USER-GUIDE.md) für die tägliche Nutzung
2. Lese [SECURITY.md](SECURITY.md) für Sicherheits-Details
3. Lese [dsgvo-mapping.md](dsgvo-mapping.md) für Compliance-Aspekte
4. Nutze `privacy-shield doctor` für regelmässige Self-Tests

**Bei Problemen:**

- GitHub Issues: https://github.com/MOTHR/hermes-privacy-shield/issues
- Siehe [USER-GUIDE.md Sektion 10: Troubleshooting](USER-GUIDE.md#10-troubleshooting--häufige-fehler)

---

## English

# Privacy-Shield — Installation Guide (INSTALL.md)

**Version:** 1.7.0 (2026-09-09)
**Repository:** https://github.com/MOTHR/hermes-privacy-shield (PRIVATE)
**Target audience:** Developers who want to integrate Privacy-Shield into Hermes/Hermes

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Desktop-Controls](#3-desktop-controls)
4. [Encryption-Key Setup](#4-encryption-key-setup)
5. [Hermes-Loader-Integration](#5-hermes-loader-integration)
6. [Verification](#6-verification)
7. [Profile Activation](#7-profile-activation)

---

## 1. Prerequisites

### System Requirements

| Component | Version | Note |
|---|---|---|
| **Python** | 3.10+ | Tests run on 3.10, 3.11, 3.12 |
| **Tesseract OCR** | 5.5.2+ | For image OCR (Phase 2) |
| **Hermes Agent** | 0.1+ | Hook integration in `pre_llm_call()` and `transform_llm_output()` |
| **pass** (CLI) | latest | Optional — for key storage |
| **OS** | macOS 12+, Ubuntu 22+, Debian 12+ | Other UNIXes should also work |

### Install Tesseract

**macOS:**
```bash
brew install tesseract tesseract-lang
tesseract --version  # Should show 5.5.2 or higher
tesseract --list-langs  # Should show deu, eng, etc.
```

**Ubuntu / Debian:**
```bash
sudo apt-get update
sudo apt-get install -y tesseract-ocr tesseract-ocr-deu tesseract-ocr-eng
tesseract --version
```

**Fedora / RHEL:**
```bash
sudo dnf install -y tesseract tesseract-langpack-deu tesseract-langpack-eng
```

### Install pass CLI (recommended for key storage)

**macOS:**
```bash
brew install pass
# Create GPG key if not already present
gpg --gen-key
# Initialize pass
pass init "your-email@example.com"
```

**Ubuntu / Debian:**
```bash
sudo apt-get install -y pass gnupg
```

**Alternatively** you can set the `PRIVACY_SHIELD_KEY` environment variable (see below).

---

## 2. Installation

### Option A: Install from repository (recommended for development)

```bash
# Clone repository (SSH, private repo)
git clone git@github.com:MOTHR/hermes-privacy-shield.git
cd hermes-privacy-shield
pip install -e .

# Dependencies automatically via pyproject.toml:
# - click, cryptography, pyyaml
# - pdfplumber, reportlab (PDF)
# - Pillow, pytesseract, pillow-heif (OCR)
```

**Advantages:**
- Source code changes take effect immediately (no re-install)
- Perfect for development + testing

### Option B: Production install via pip

```bash
# From Git repo (PRIVATE — you need GitHub access)
pip install git+ssh://git@github.com:MOTHR/hermes-privacy-shield.git@v1.7.0

# Or via local wheel file
pip install /path/to/privacy-shield-1.7.0-py3-none-any.whl
```

### Option C: Manual installation (without pip)

```bash
cd hermes-privacy-shield
# Install dependencies (for CLI + Desktop-Controls + Dev-Tools)
pip install -r requirements.txt
pip install -e ".[desktop]"
# Add package to PYTHONPATH (not recommended for production)
export PYTHONPATH="$PWD:$PYTHONPATH"
```

### Verify Installation

```bash
# 1. CLI available?
which privacy-shield

# 2. Check version
privacy-shield --version

# 3. Show help
privacy-shield --help
```

**Expected Output:**
```
Usage: privacy-shield [OPTIONS] COMMAND [ARGS]...

  Privacy-Shield CLI — PII Pseudonymization for Hermes.

Options:
  --version   Show the version and exit.
  --help      Show this message and exit.

Commands:
  doctor      Run system self-test
  map         Manage token mapping table
  pseudonymize  Pseudonymize text
  scan        Scan text for PII (no replacement)
  setup       Setup encryption key
  status      Show plugin status
  test        Run round-trip test
```

## 3. Desktop-Controls

Since v1.5.0, Privacy-Shield ships together with an official desktop plugin.
Hermes installs `desktop/` itself (`hermes plugins install` / `hermes plugins
enable`) — **nothing is copied to
`~/.hermes/desktop-plugins/privacy-shield-controls/`.**

The Hermes Desktop app then shows a **Privacy-Shield** pane where
the following settings can be edited:

- Toggle plugin on/off
- Operating mode (`off`/`audit`/`limited`/`strict`/`paranoid`)
- Confidence threshold
- Restore-allowed channels
- PDF / Image OCR / Cache bypass
- Synthetic restore round-trip test

Changes are written via `POST /config` to `~/.hermes/config.yaml` under
`plugins.entries.privacy-shield` and take effect on the next plugin reload.
Details on the API and UI can be found in
[docs/desktop-controls.md](desktop-controls.md).

---

## 4. Encryption-Key Setup

Privacy-Shield encrypts the mapping table with **AES-256-GCM** (PBKDF2 with 100,000 iterations). You need a 64-hex-character key (32 bytes).

### Option A: pass Store (recommended for production)

```bash
# 1. Generate key (once)
python3 -c "import secrets; print(secrets.token_hex(32))" | pass insert hermes/privacy-shield-key

# 2. Verify
pass hermes/privacy-shield-key

# 3. Plugin detects the key automatically
privacy-shield status
```

**Advantages:**
- Key is GPG-encrypted on disk
- Multi-device sync possible (e.g. via git for pass store)
- No plaintext in shell history or config files

### Option B: Environment Variable (for containers / servers)

```bash
# In your shell / .bashrc / .zshrc
export PRIVACY_SHIELD_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Or in a .env file (with chmod 600!)
echo "PRIVACY_SHIELD_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" > ~/.hermes/privacy-shield.env
chmod 600 ~/.hermes/privacy-shield.env
```

### Option C: Workshop Mode (for demos ONLY, NOT for production)

```bash
# Set the environment variable PRIVACY_SHIELD_WORKSHOP=true
# Privacy-Shield generates an ephemeral key on startup
export PRIVACY_SHIELD_WORKSHOP=true
privacy-shield scan "test"
```

**⚠️ WARNING:** In workshop mode, the mapping table is **undecryptable** after restart. Use only for demos and tests!

### Configure key source in plugin.yaml

```yaml
privacy_shield:
  key_source: pass  # or "env" or "workshop"
  key_pass_path: hermes/privacy-shield-key
  key_env_var: PRIVACY_SHIELD_KEY
```

### Key Rotation

Recommended every 90 days:

```bash
# 1. Generate new key
NEW_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 2. Replace in pass store
echo "$NEW_KEY" | pass insert -f hermes/privacy-shield-key

# 3. End old sessions (crypto-shredding old mappings)
privacy-shield map --close-all

# 4. Reload plugin
hermes plugins reload privacy-shield
```

---

## 5. Hermes-Loader-Integration

### 4.1 Add plugin to Hermes

**In `~/.hermes/config.yaml`:**

```yaml
plugins:
  enabled:
    - privacy-shield

  # Optional: Plugin-specific config
  privacy_shield:
    enabled: true
    mode: limited
    # ... (see USER-GUIDE.md section 3 for all options)
```

### 4.2 Set plugin symlinks

If you use the plugin from a different directory:

```bash
# By default, Hermes looks in ~/.hermes/plugins/
ls -la ~/.hermes/plugins/privacy-shield
# Should be a symlink or directory
```

If it is elsewhere:
```bash
ln -s /path/to/privacy-shield ~/.hermes/plugins/privacy-shield
```

### 4.3 Restart or reload Hermes

```bash
# Reload plugin (recommended)
hermes plugins reload privacy-shield

# Or full Hermes restart
hermes restart
```

### 4.4 Verify

```bash
hermes plugins list | grep privacy-shield
# Should show: privacy-shield v1.7.0 (enabled)

privacy-shield status
# Should show: Privacy-Shield v1.7.0 — ACTIVE
```

### 4.5 Check hook integration

```bash
# Send a test prompt with PII
hermes chat "Write me an email to dirk@example.com"

# In the log you should see:
# [privacy-shield] pre_llm_call: detected 1 PII match (email)
# [privacy-shield] replaced with TOKEN_EMAIL_xxx
# [privacy-shield] transform_llm_output: restored 1 token
```

If that doesn't happen, check:
```bash
# 1. Plugin enabled?
hermes plugins list

# 2. Hook registered?
grep -r "privacy_shield" ~/.hermes/hooks/ 2>/dev/null

# 3. Config loaded?
python3 -c "import yaml; print(yaml.safe_load(open('~/.hermes/config.yaml'))['plugins'])"
```

---

## 6. Verification

### 5.1 Quick Smoke Test (30 seconds)

```bash
privacy-shield scan "Test with dirk@example.com"
# Expected: [DETECTED] email pattern
```

### 5.2 Structural Tests (2 minutes)

```bash
cd ~/.hermes/plugins/privacy-shield
~/.hermes/hermes-agent/venv/bin/python -m pytest tests/ -q 2>&1 | tail -3
# Expected: 369 passed in X.XXs
```

### 5.3 Round-Trip Test

```bash
privacy-shield test --text "Mail to dirk@example.com with IBAN DE89370400440532013000"
# Expected: Token -> Original Round-Trip OK
```

### 5.4 PDF + OCR Test

```bash
# Generate a test image
mkdir -p ~/.hermes/privacy/restore/images
python3 ~/.hermes/plugins/privacy-shield/scripts/generate_test_image.py ~/.hermes/privacy/restore/images/test_invoice.png
chmod 700 ~/.hermes/privacy/restore/images

# Send the image to Hermes
hermes chat --image ~/.hermes/privacy/restore/images/test_invoice.png "What does the invoice say?"

# In the log you should see:
# [privacy-shield] OCR: detected text from image
# [privacy-shield] pre_llm_call: detected N PII matches
```

### 5.5 Full Doctor Test

```bash
privacy-shield doctor
# Checks:
# - Python version
# - Tesseract installation
# - Key availability
# - Hermes integration
# - Plugin health
# - Test suite status
```

**Expected Output:**
```
[OK] Python 3.11.5
[OK] Tesseract 5.5.2 (deu+eng installed)
[OK] Encryption key available (pass-store)
[OK] Hermes plugin loaded
[OK] 369/369 tests passing
[OK] Plugin healthy
ALL CHECKS PASSED ✅
```

---

## 7. Profile Activation

Hermes supports multiple profiles. Privacy-Shield can be activated **per profile**.

### Activate profile

```bash
# In the respective profile config file:
plugins:
  enabled: [privacy-shield]

# Or via CLI:
hermes -p <profile> plugins enable privacy-shield
```

Repeat for each profile you want to protect. The plugin installation
(symlink under `~/.hermes/plugins/`) is needed once per Hermes installation.

### Verification

```bash
hermes -p <profile> plugins list | grep privacy-shield
```

## 🎉 Installation complete!

**Next steps:**

1. Read [USER-GUIDE.md](USER-GUIDE.md) for daily usage
2. Read [SECURITY.md](SECURITY.md) for security details
3. Read [dsgvo-mapping.md](dsgvo-mapping.md) for compliance aspects
4. Use `privacy-shield doctor` for regular self-tests

**If you have problems:**

- GitHub Issues: https://github.com/MOTHR/hermes-privacy-shield/issues
- See [USER-GUIDE.md section 10: Troubleshooting](USER-GUIDE.md#10-troubleshooting--häufige-fehler)
