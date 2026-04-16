#!/bin/bash
# Diagnostic script for CIFS + Grafana Alloy log collection issues
# Run as root on the monitoring host: sudo bash diagnose_cifs_logs.sh

set -euo pipefail

OUTFILE="/tmp/cifs_diag_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"

log() { echo -e "\n===== $1 =====" | tee -a "$OUTFILE"; }

echo "CIFS/Alloy diagnostics — $(date)" | tee "$OUTFILE"
echo "Hostname: $(hostname)" | tee -a "$OUTFILE"
uname -r | tee -a "$OUTFILE"

# 1. Verify mount options actually applied
log "CIFS mounts from /proc/mounts"
grep cifs /proc/mounts 2>/dev/null | tee -a "$OUTFILE" || echo "No CIFS mounts found" | tee -a "$OUTFILE"

log "Mount options from findmnt"
findmnt -t cifs -o TARGET,SOURCE,OPTIONS 2>/dev/null | tee -a "$OUTFILE" || true

# 2. CIFS kernel module parameters
log "CIFS module parameters"
if [[ -d /sys/module/cifs/parameters ]]; then
  for p in /sys/module/cifs/parameters/*; do
    echo "$(basename "$p") = $(cat "$p" 2>/dev/null)" | tee -a "$OUTFILE"
  done
else
  echo "CIFS module not loaded or /sys/module/cifs/parameters missing" | tee -a "$OUTFILE"
fi

# 3. /proc/fs/cifs stats
log "/proc/fs/cifs contents"
if [[ -d /proc/fs/cifs ]]; then
  for f in /proc/fs/cifs/*; do
    echo "--- $(basename "$f") ---" | tee -a "$OUTFILE"
    cat "$f" 2>/dev/null | tee -a "$OUTFILE" || true
  done
else
  echo "/proc/fs/cifs not present" | tee -a "$OUTFILE"
fi

# 4. modprobe config
log "modprobe.d CIFS config"
cat /etc/modprobe.d/cifs-nooplocks.conf 2>/dev/null | tee -a "$OUTFILE" || echo "File not found" | tee -a "$OUTFILE"

# 5. fstab CIFS entries
log "/etc/fstab CIFS entries"
grep -i cifs /etc/fstab 2>/dev/null | tee -a "$OUTFILE" || echo "None" | tee -a "$OUTFILE"

# 6. Metadata freshness test — the core diagnostic
log "Metadata freshness test (stat mtime over 30s on first .log file per mount)"
for mnt in /mnt/*/; do
  [[ -d "$mnt" ]] || continue
  logfile=$(find "$mnt" -maxdepth 3 -name '*.log' -type f 2>/dev/null | head -1)
  if [[ -z "$logfile" ]]; then
    echo "SKIP $mnt — no .log files found" | tee -a "$OUTFILE"
    continue
  fi

  echo "Testing: $logfile" | tee -a "$OUTFILE"

  stat1=$(stat -c '%Y %s' "$logfile" 2>/dev/null)
  md5_1=$(md5sum "$logfile" 2>/dev/null | awk '{print $1}')
  echo "  T=0s  mtime+size=[$stat1]  md5=$md5_1" | tee -a "$OUTFILE"

  sleep 10

  stat2=$(stat -c '%Y %s' "$logfile" 2>/dev/null)
  md5_2=$(md5sum "$logfile" 2>/dev/null | awk '{print $1}')
  echo "  T=10s mtime+size=[$stat2]  md5=$md5_2" | tee -a "$OUTFILE"

  sleep 20

  stat3=$(stat -c '%Y %s' "$logfile" 2>/dev/null)
  md5_3=$(md5sum "$logfile" 2>/dev/null | awk '{print $1}')
  echo "  T=30s mtime+size=[$stat3]  md5=$md5_3" | tee -a "$OUTFILE"

  if [[ "$md5_1" != "$md5_3" && "$stat1" == "$stat3" ]]; then
    echo "  *** STALE METADATA: content changed but mtime/size did NOT update ***" | tee -a "$OUTFILE"
  elif [[ "$md5_1" == "$md5_3" ]]; then
    echo "  File unchanged during test (try a busier log file or longer wait)" | tee -a "$OUTFILE"
  else
    echo "  OK: metadata updated with content" | tee -a "$OUTFILE"
  fi
  echo "" | tee -a "$OUTFILE"
done

# 7. Alloy service status
log "Alloy service status"
systemctl status alloy --no-pager 2>&1 | tee -a "$OUTFILE" || true

# 8. Recent Alloy logs (last 50 lines)
log "Alloy journal logs (last 50 lines)"
journalctl -u alloy --no-pager -n 50 2>&1 | tee -a "$OUTFILE" || true

# 9. Alloy config — file_watch and file_match sections
log "Alloy config — file_match and file_watch"
grep -A5 'local.file_match\|file_watch\|sync_period\|poll_frequency' /etc/alloy/config.alloy 2>/dev/null | tee -a "$OUTFILE" || echo "Config not found" | tee -a "$OUTFILE"

# 10. Alloy positions file — check if it's tracking files
log "Alloy positions file"
POSITIONS=$(find /var/lib/alloy /tmp -name 'positions*.yml' -o -name 'positions*.yaml' 2>/dev/null | head -3)
if [[ -n "$POSITIONS" ]]; then
  for pf in $POSITIONS; do
    echo "--- $pf (last 20 lines) ---" | tee -a "$OUTFILE"
    tail -20 "$pf" 2>/dev/null | tee -a "$OUTFILE"
  done
else
  echo "Positions file not found in standard paths" | tee -a "$OUTFILE"
fi

# 11. CIFS version negotiated
log "CIFS connection details (cifscreds / DebugData)"
cat /proc/fs/cifs/DebugData 2>/dev/null | head -60 | tee -a "$OUTFILE" || echo "Not available" | tee -a "$OUTFILE"

# 12. Kernel CIFS-related dmesg
log "Kernel CIFS messages (dmesg)"
dmesg | grep -i cifs | tail -20 | tee -a "$OUTFILE" || echo "None" | tee -a "$OUTFILE"

echo ""
echo "===== Done. Output saved to: $OUTFILE ====="
