#!/usr/bin/env bash
set -euo pipefail

JOURNALD_CONF="/etc/systemd/journald.conf"
MAX_RETENTION="3day"

echo "Configuring journald retention to ${MAX_RETENTION}..."

# Backup config if not already backed up
if [ ! -f "${JOURNALD_CONF}.bak" ]; then
  cp "${JOURNALD_CONF}" "${JOURNALD_CONF}.bak"
  echo "Backup created: ${JOURNALD_CONF}.bak"
fi

# Set MaxRetentionSec (uncomment or replace if exists)
if grep -q "^#\?MaxRetentionSec=" "$JOURNALD_CONF"; then
  sed -i "s/^#\?MaxRetentionSec=.*/MaxRetentionSec=${MAX_RETENTION}/" "$JOURNALD_CONF"
else
  echo "MaxRetentionSec=${MAX_RETENTION}" >> "$JOURNALD_CONF"
fi

echo "Restarting systemd-journald..."
systemctl restart systemd-journald

echo "Deleting journal logs older than ${MAX_RETENTION}..."
journalctl --vacuum-time=${MAX_RETENTION}

echo "Done."
