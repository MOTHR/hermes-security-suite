#!/usr/bin/env python3
"""Review-Report-Scaffold für Frontmatter-Familie frontierbreach-p0.

Härtung nach Vault-Maintenance-20261119 Priority 2 (Regel 12 — Generator-Hebel,
nicht Output-Heal): der Review-Worker schreibt den Report-Body, aber die
Frontmatter-Erzeugung geht NUR über dieses Script.

Kontrakt:
- Pflicht-FM wird immer gesetzt: date, title, type, tags, memory_class
- `repo` ist IMMER ein Plain-Scalar aus dem erlaubten Set (keine Klammern,
  kein eingebetteter Doppelpunkt); Checkout-Pfad gehört ins separate,
  quoted Feld `workspace_checkout`
- Report-Datei wird mit generiertem FM angelegt; ein bestehender Body ohne
  FM wird validiert und ggf. mit dem generierten FM versehen (idempotent,
  Review-Report bleibt unveränderlich — der Script überschreibt nie einen
  bestehenden Body)
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:  # Suite läuft mit dem hermes venv; PyYAML ist dort vorhanden
    yaml = None

REQUIRED_KEYS = ("date", "title", "type", "tags", "memory_class",
                 "repo", "workspace_checkout")
ALLOWED_REPO = "MOTHR/hermes-security-suite"
TYPE_VOCAB = ("report",)

# Plain-Scalar-Falle: "(...)" mit eingebettetem Doppelt-Leerzeichen ("checkout: ")
PAREN_COLON = re.compile(r"^\S.*\s \(.*:\ .*\)\s*$")
FM_DELIM = "---"


class FMError(ValueError):
    """Invalid or missing Review-Frontmatter."""


def build_fm(
    *,
    date_val: str,
    title: str,
    tags: list[str],
    memory_class: str = "expiring",
    reviewer: str,
    task: str,
    commit: str,
    repo: str,
    workspace_checkout: str,
    review_lens: str,
    verdict: str,
    finding_count: int,
) -> dict:
    """FM-Dict im Harten-Kontrakt bauen; Feld-Split wird hier erzwungen."""
    if PAREN_COLON.match(repo.strip()) or ": " in repo:
        raise FMError(
            "repo darf keinen eingebetteten ' (...: ...)'-Suffix tragen — "
            "Checkout-Pfad gehört in workspace_checkout (Feld-Split)"
        )
    if repo != ALLOWED_REPO:
        raise FMError(f"repo außerhalb des erlaubten Sets ({ALLOWED_REPO!r}): {repo!r}")
    if date_val.lower() == "today":
        date_val = date.today().isoformat()
    return {
        "title": title,
        "date": date_val,
        "type": "report",
        "tags": list(tags),
        "reviewer": reviewer,
        "task": task,
        "commit": commit,
        "repo": repo,
        "workspace_checkout": workspace_checkout,
        "review_lens": review_lens,
        "verdict": verdict,
        "memory_class": memory_class,
        "finding_count": int(finding_count),
    }


def parse_fm(path: Path) -> dict | None:
    """FM-Block einer .md-Datei parsen; None, wenn kein FM vorhanden."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith(FM_DELIM + "\n"):
        return None
    try:
        end = text.index("\n" + FM_DELIM, len(FM_DELIM) + 1)
    except ValueError as exc:
        raise FMError(f"{path.name}: FM-Block nicht geschlossen") from exc
    if yaml is None:
        raise FMError("PyYAML nicht verfügbar — validate verweigert (kein Silent-Skip)")
    return yaml.safe_load(text[len(FM_DELIM) + 1 : end])


def validate(fm: dict, *, name: str = "<fm>") -> list[str]:
    errors: list[str] = []
    for key in REQUIRED_KEYS:
        if key not in fm or fm[key] in (None, "", []):
            errors.append(f"{name}: Pflicht-FM fehlt/leer: {key}")
    if errors:
        return errors
    repo = str(fm.get("repo", "")).strip()
    if PAREN_COLON.match(repo) or ": " in repo:
        errors.append(
            f"{name}: repo ist Plain-Scalar mit Klammer-Doppelpunkt "
            f"({repo!r}) — Feld-Split: repo + workspace_checkout (quoted)"
        )
    if fm.get("type") not in TYPE_VOCAB:
        errors.append(f"{name}: type außerhalb des Vokabulars: {fm.get('type')!r}")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(fm["date"])):
        errors.append(f"{name}: date nicht im ISO-Format: {fm.get('date')!r}")
    if fm.get("memory_class") not in ("durable", "expiring", "ephemeral", "reference"):
        errors.append(f"{name}: memory_class ungültig: {fm.get('memory_class')!r}")
    return errors


def selftest() -> None:
    """Gegenbeispiele aus dem Vault-Fund (8 FM-Befunde vom 19.11.) absichern."""
    broken = {
        "repo": "MOTHR/hermes-security-suite (workspace checkout: ~/.hermes/wave1)",
        "date": "2026-11-18",
        "type": "report",
        "tags": ["operations", "security"],
        "memory_class": "expiring",
    }
    assert validate(broken), "Klammer-Doppel-Scalar muss FAILEN"
    good = {
        "title": "Review: injection-shield fix (a7c3c64)",
        "repo": ALLOWED_REPO,
        "workspace_checkout": "~/.hermes/profiles/operator/workspace/hermes-security-suite",
        "date": "2026-11-18",
        "type": "report",
        "tags": ["operations", "security"],
        "memory_class": "expiring",
    }
    assert validate(good) == [], f"valides FM muss PARSEN LEER: {validate(good)}"
    for key in REQUIRED_KEYS:
        gutted = {**good}
        gutted.pop(key)
        assert validate(gutted), f"fehlendes Pflicht-FM {key} muss FAILEN"
    try:
        build_fm(
            date_val="2026-11-19",
            title="x",
            tags=["operations"],
            reviewer="orakel",
            task="t_x",
            commit="a7c3c64",
            repo=ALLOWED_REPO + " (workspace checkout: /tmp)",
            workspace_checkout="/tmp",
            review_lens="x",
            verdict="APPROVE",
            finding_count=0,
        )
    except FMError:
        pass
    else:
        raise AssertionError("build_fm muss Klammer-Doppel-Scalar verweigern")
    print("selftest OK: Klammern-Doppelt-Scalar wird verweigert; Pflicht-FM wird erzwungen")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_validate = sub.add_parser("validate")
    p_validate.add_argument("paths", nargs="+", help=".md-Review-Dateien")

    p_self = sub.add_parser("selftest")

    args = ap.parse_args()
    if args.cmd == "selftest":
        selftest()
        return 0
    failures: list[str] = []
    for raw in args.paths:
        path = Path(raw).expanduser()
        try:
            fm = parse_fm(path)
        except FMError as exc:
            failures.append(str(exc))
            continue
        if fm is None:
            failures.append(f"{path}: kein Frontmatter (FM ohne Fences)")
            continue
        failures.extend(validate(fm, name=path.name))
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"OK: {len(args.paths)} Datei(en) validieren sauber")
    return 0


if __name__ == "__main__":
    sys.exit(main())
