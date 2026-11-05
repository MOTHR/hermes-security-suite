#!/bin/bash
# scripts/setup-profiles.sh
# Aktiviert privacy-shield fuer ALLE Hermes-Profile
# Idempotent: bereits aktivierte Profile werden uebersprungen.
#
# Ported from injection-shield FIX-3C (R3 CRIT-3) for privacy-shield
# (BUTLER-PS-5).

set -e

PROFILES_DIR="$HOME/.hermes/profiles"
PLUGIN_NAME="privacy-shield"

echo "=== Privacy-Shield Multi-Profile Setup ==="
echo

# Validate plugin exists
if [ ! -d "$HOME/.hermes/plugins/$PLUGIN_NAME" ] && [ ! -d "$HOME/.hermes/plugins/privacy_shield" ]; then
    echo "ERROR: Plugin $PLUGIN_NAME not found in ~/.hermes/plugins/"
    exit 1
fi

# Find all profiles
if ! PROFILES=$(ls -d "$PROFILES_DIR"/*/ 2>/dev/null | xargs -n1 basename); then
    echo "ERROR: cannot list $PROFILES_DIR"
    exit 1
fi

if [ -z "$PROFILES" ]; then
    echo "No profiles found in $PROFILES_DIR"
    exit 1
fi

echo "Found $(echo "$PROFILES" | wc -l | tr -d ' ') profiles: $PROFILES"
echo

enabled_count=0
skipped_count=0
error_count=0

for profile in $PROFILES; do
    config="$PROFILES_DIR/$profile/config.yaml"
    if [ ! -f "$config" ]; then
        echo "WARN $profile: no config.yaml, skipping"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    # Check if already enabled (idempotency)
    if grep -E "^\s*-\s*${PLUGIN_NAME}\s*$" "$config" > /dev/null 2>&1; then
        echo "OK   $profile: already enabled"
        skipped_count=$((skipped_count + 1))
        continue
    fi

    # Add plugin to enabled list — append to plugins.enabled block if present,
    # else create the block. Uses Python for cross-platform YAML safety.
    if python3 -c "
import sys
from pathlib import Path

cfg_path = Path('$config')
text = cfg_path.read_text()
lines = text.splitlines()

plugins_idx = None
enabled_idx = None
for i, line in enumerate(lines):
    if line.strip() == 'plugins:' or line.startswith('plugins:'):
        plugins_idx = i
        for j in range(i + 1, min(i + 20, len(lines))):
            stripped = lines[j].strip()
            if stripped == 'enabled:':
                enabled_idx = j
                break
        break

if plugins_idx is None:
    # Append new plugins section
    new_lines = lines + ['', 'plugins:', '  enabled:', '    - $PLUGIN_NAME']
elif enabled_idx is None:
    # plugins: present but no enabled: — insert under it
    insert_at = plugins_idx + 1
    # skip any existing comments under plugins:
    while insert_at < len(lines) and lines[insert_at].strip().startswith('#'):
        insert_at += 1
    new_lines = lines[:insert_at] + ['  enabled:', '    - $PLUGIN_NAME'] + lines[insert_at:]
else:
    # Insert under enabled: (preserve any list items already there)
    insert_at = enabled_idx + 1
    while insert_at < len(lines):
        s = lines[insert_at].lstrip()
        if s.startswith('- ') or s == '' or s.startswith('#'):
            insert_at += 1
            continue
        break
    new_lines = lines[:insert_at] + ['    - $PLUGIN_NAME'] + lines[insert_at:]

cfg_path.write_text('\n'.join(new_lines) + ('\n' if text.endswith('\n') else ''))
" 2>/dev/null; then
        echo "OK   $profile: enabled"
        enabled_count=$((enabled_count + 1))
    else
        echo "FAIL $profile: could not update config.yaml"
        error_count=$((error_count + 1))
    fi
done

echo
echo "=== Setup complete ==="
echo "Enabled: $enabled_count, Skipped: $skipped_count, Errors: $error_count"
echo
echo "Verify:"
hermes plugins list 2>/dev/null | grep "$PLUGIN_NAME" || echo "(hermes CLI not on PATH — check profiles/$profile/config.yaml manually)"
