#!/usr/bin/env bash
set -euo pipefail

# Tail OTPWeb logs from a single directory (default: /var/log/otpweb).
LOG_DIR="${OTPWEB_LOG_DIR:-/var/log/otpweb}"

if [[ ! -d "$LOG_DIR" ]]; then
  echo "[ERROR] Log directory not found: $LOG_DIR"
  echo "Hint: set OTPWEB_LOG_DIR env or check permissions."
  exit 1
fi

echo "[INFO] Tailing logs under: $LOG_DIR"
echo " - audit.log (structured JSONL)"
echo " - admin.log, qr.log (application logs)"
echo
# tail multiple files if present
FILES=()
for f in "$LOG_DIR/audit.log" "$LOG_DIR/admin.log" "$LOG_DIR/qr.log"; do
  [[ -f "$f" ]] && FILES+=("$f")
done

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "[WARN] No log files found in $LOG_DIR yet."
  ls -lah "$LOG_DIR" || true
  exit 0
fi

exec tail -n 200 -F "${FILES[@]}"
