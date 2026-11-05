#!/usr/bin/env bash
# Local release helper for privacy-shield.
#
# This script builds the package, sanity-checks the distribution, creates a git
# tag, and prints the manual push/upload steps. It does NOT push or upload
# because release credentials must not live in repository scripts.
#
# Usage:
#   ./scripts/release.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# Verify sync_version.py helper exists so version bumps are consistent.
if [[ ! -f "scripts/sync_version.py" ]]; then
    echo "ERROR: scripts/sync_version.py not found. Version sync helper is required." && exit 1
fi

# Extract version from pyproject.toml (first "version = \"...\"" line).
VERSION="$(grep -E '^version\s*=' pyproject.toml | head -1 | awk -F'"' '{print $2}')"
if [[ -z "${VERSION}" ]]; then
    echo "ERROR: could not extract version from pyproject.toml" && exit 1
fi

echo "Releasing privacy-shield v${VERSION}"
echo "=================================="

# Clean previous dist artifacts.
rm -rf dist/ build/ *.egg-info/

# Build source and wheel distributions.
python -m build

# Validate distributions if twine is available.
if command -v twine >/dev/null 2>&1; then
    twine check dist/*
else
    echo "WARN: twine not installed; skipping dist validation. Run: pip install twine"
fi

# Create an annotated git tag (idempotent: fails if tag already exists).
git tag -a "v${VERSION}" -m "Release privacy-shield v${VERSION}"

echo ""
echo "Release artifacts built in dist/"
echo ""
echo "Manual next steps (credentials required):"
echo "  git push origin v${VERSION}"
echo "  twine upload dist/*"
