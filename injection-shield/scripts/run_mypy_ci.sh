#!/usr/bin/env bash
set -euo pipefail

# CI type-check helper: mypy refuses to treat a directory named
# 'hermes-injection-shield' as a package because of the hyphen. We create
# a temporary copy under a valid Python package name, run mypy on it,
# then clean up.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/injection_shield"
rsync -a \
  --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='.pytest_cache' --exclude='.mypy_cache' --exclude='.ruff_cache' \
  --exclude='dist' --exclude='build' --exclude='*.egg-info' \
  --exclude='.coverage' --exclude='coverage.xml' --exclude='.venv' \
  --exclude='tests' --exclude='evidence' --exclude='scripts' \
  --exclude='docs' --exclude='.github' --exclude='tmp_mypy' \
  "$REPO_ROOT/" "$TMP_DIR/injection_shield/"

cd "$TMP_DIR"
mypy --install-types --non-interactive injection_shield/ 2>/dev/null || true
mypy injection_shield/ "$@"
