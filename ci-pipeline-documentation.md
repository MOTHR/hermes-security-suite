---
date: "2026-11-09"
type: documentation
memory_class: durable
project: hermes-security-suite
scope: CI/CD
---

# CI-Pipeline-Dokumentation — hermes-security-suite

**Quelle:** Orakel-Arch/CI-Review `20261106-1455-orakel-conformance-review.md` (t_4665065d, Commit df9c1ff4) §3.3  
**Umsetzung:** PR #2 (`ci/real-gate-matrix` → `main`, Commits `2761a11` + `35ccdb0`)  
**Merge:** 2026-11-09, Run [42568917315](https://github.com/MOTHR/hermes-security-suite/actions/runs/42568917315)  
**Status:** ✅ Alle 9 Jobs success auf `main`

---

## 1. Übersicht

Die Root-CI `.github/workflows/ci.yml` wurde von einem always-green No-Op zu einem echten Qualitätsgate umgebaut. Die Pipeline läuft auf jedem `push` zu `main` und jedem `pull_request` gegen `main`.

| Trigger | Zweck |
|---------|-------|
| `push: branches: [main]` | Post-Merge-Validierung |
| `pull_request: branches: [main]` | PR-Qualitätsgate |

---

## 2. Jobs

### 2.1 test (Matrix)
**Scope:** Funktionale Tests je Paket × Python-Version

| Matrix-Dimension | Werte |
|------------------|-------|
| package | `privacy-shield`, `injection-shield` |
| python-version | `"3.11"`, `"3.12"` |
| fail-fast | `false` |

**Schritte:**
1. Checkout
2. Python-Setup (mit pip cache)
3. System-Abhängigkeiten (privacy-shield only: `tesseract-ocr` + Sprachpakete)
4. `python -m compileall -q` (un-masked — Fehl schlägt CI)
5. `pip install -e "${package}[test]"` (Supply-Gate)
6. `pytest tests/ --tb=short -q` (echtes Gate — Fehl schlägt CI)

**Unterschiede zum Vorgänger:**
- Kein `2>/dev/null`, kein `|| true`, kein `continue-on-error`
- `privacy-shield` erhielt ein `[test]`-Extra (`pytest`, `pytest-asyncio`, `fastapi`, `pydantic`, `httpx`, `pypdf`)

---

### 2.2 lint
**Scope:** Statische Code-Analyse mit Ruff

| Paket | Modus | Begründung |
|-------|-------|------------|
| `injection-shield` | `ruff check injection-shield` | Paket bringt `[tool.ruff]`-Config mit |
| `privacy-shield` | Explizite Dateiliste | Kein `[tool.ruff]` im Paket; Glob erzeugt 300+ False-Positives |

**Pinning:** `ruff==0.16.4` (reproduzierbar)

---

### 2.3 type
**Scope:** Typprüfung mit mypy

| Paket | Befehl | Besonderheit |
|-------|--------|--------------|
| `injection-shield` | `scripts/run_mypy_ci.sh` | Paket-eigenes Skript mit Fallback `--ignore-missing-imports` |
| `privacy-shield` | `mypy --strict --ignore-missing-imports -p privacy_shield` | Symlink-Workaround (`mypy_pkg` unter `/tmp`) wegen Hyphen-im-Paketnamen; `MYPYPATH` + `TOKEN_BIC_905570f3cc_000` gesetzt |

---

### 2.4 security
**Scope:** Sicherheitsanalyse mit bandit

| Paket | Level | Excludes |
|-------|-------|----------|
| Beide | `-lll` (high only) | `tests/`, `build/`, `dist/`, `evidence/`, `scripts/`, `venv/`, `tmp_mypy/` |

---

### 2.5 build
**Scope:** Paket-Bau und Artefakt-Speicherung

| Matrix | `privacy-shield`, `injection-shield` |
|--------|-------------------------------------|
| Befehl | `python -m build ${{ matrix.package }}` |
| Artefakt | `dist-${{ matrix.package }}` (wheel + sdist) |
| Retention | Standard (GitHub default) |

---

## 3. Gate-Verhalten

### Vor der Umsetzung (df9c1ff-Baseline)
- Install-Schritt: `pip install -q -e "$pkg"[test] 2>/dev/null || pip install -q -e "$pkg" 2>/dev/null || true`
- pytest-Schritt: `(cd "$pkg" && pytest tests/ --tb=short -q 2>/dev/null) || true`
- Job-Level: `continue-on-error: true`
- **Ergebnis:** CI immer grün, kein Test-Aussagegehalt

### Nach der Umsetzung
- Install-Schritt: `pip install -e "${{ matrix.package }}[test]"`
- pytest-Schritt: `pytest tests/ --tb=short -q`
- Job-Level: kein `continue-on-error`
- **Ergebnis:** Echtes Gate — erster PR-Run (42455186134) war rot (TOKEN_BIC_0b00174be0_000 fehlte), Fix (35ccdb0) → grün (42455295482)

---

## 4. Umgesetzte Orakel-§3.3-Punkte

| §3.3-Punkt | Umsetzung | Status |
|------------|-----------|--------|
| 1. Supply-Gate fixen | `privacy-shield[test]`-Extra ergänzt | ✅ |
| 2. Maskierung raus | Kein `2>/dev/null`, `|| true`, `continue-on-error` | ✅ |
| 3. Matrix | `{package × python 3.11/3.12}`, `fail-fast: false` | ✅ |
| 4. Statische Jobs | ruff, mypy, bandit je Paket-Vorbild | ✅ |
| 5. Build/Artifacts | `python -m build` + `upload-artifact` | ✅ |
| 6. Suite-Bugs | orphan `test_audit_pdf.py` → 10 passed; Detector-Failures → Fixture-Drift (3f640549-Splits) | ✅ |
| 7. Eigene CI-Karte | t_0258e675, assignee operator | ✅ |

---

## 5. Nicht-blockierende Review-Checks

Die Pipeline ist so gestaltet, dass statische Analysen (lint, type, security) parallel zu den Tests laufen und jeweils eigene Checks erzeugen. Sie blockieren nicht gegenseitig, sind aber als separate Checks im PR sichtbar.

| Check | Blockierend | Sichtbarkeit |
|-------|-------------|--------------|
| test | Ja | Required |
| lint | Ja | Required |
| type | Ja | Required |
| security | Ja (Advisory-Level -lll) | Required |
| build | Nein (Artefakt-Job) | Sichtbar |

---

## 6. Keine Duplikate

- Paket-Level `.github/workflows/ci.yml` wurden entfernt (df9c1ff-Präzedenz + Orakel-Klarstellung); GitHub führt nur Root-Workflows aus.
- `release.yml.disabled` wurde ebenfalls entfernt.
- Keine doppelten Test-Läufe: Matrix-Kombinationen sind disjunkt.

---

## 7. Verifizierter Main-Run

| Run | Commit | Status | Jobs |
|-----|--------|--------|------|
| [42568917315](https://github.com/MOTHR/hermes-security-suite/actions/runs/42568917315) | `1fa1a63` (merge commit) | ✅ success | 9/9 success |

Einzelne Job-Ergebnisse (alle `success`):
- `test (privacy-shield, 3.11)`
- `test (privacy-shield, 3.12)`
- `test (injection-shield, 3.11)`
- `test (injection-shield, 3.12)`
- `lint`
- `type`
- `security`
- `build (privacy-shield)`
- `build (injection-shield)`

---

## 8. Dateien

| Datei | Zweck |
|-------|-------|
| `.github/workflows/ci.yml` | Root-CI (dieses Dokument) |
| `privacy-shield/pyproject.toml` | `[test]`-Extra ergänzt |
| `injection-shield/tests/test_credential_leak.py` | 3× ISC004-Klammerung (ruff 0.16.4) |

---

*Dokument erstellt: 2026-11-09 von link-devops (Task t_bc30358a)*
*Referenz: Orakel-Review §3.3, Cycle-Close-Report §8, t_0258e675*
