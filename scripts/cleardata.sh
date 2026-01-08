#!/usr/bin/env bash
set -euo pipefail

# Uses qr.db located next to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PATH="${SCRIPT_DIR}/qr.db"

# Pre-checks
command -v python3 >/dev/null 2>&1 || { echo "[ERROR] python3 not found."; exit 1; }
[ -f "$DB_PATH" ] || { echo "[ERROR] DB file not found: ${DB_PATH}"; exit 1; }

echo "This will clean up old data."
read -rp "Enter the number of days (e.g., 30 = delete QR link data older than 30 days): " DAYS

# Validate numeric input
if ! [[ "${DAYS}" =~ ^[0-9]+$ ]]; then
  echo "[ERROR] Please enter an integer."
  exit 1
fi
if [ "${DAYS}" -le 0 ]; then
  echo "[ERROR] Please enter a value >= 1."
  exit 1
fi

NOW_TS=$(date +%s)
CUTOFF_TS=$(( NOW_TS - DAYS*86400 ))

echo "Cutoff: ${DAYS} days ago (epoch ${CUTOFF_TS})"
echo "Target DB: ${DB_PATH}"

# Safety backup
BK="${DB_PATH}.bak.$(date +%F_%H%M%S)"
cp -a -- "$DB_PATH" "$BK"
echo "Backup created: ${BK}"

# Preview and delete using Python (confirmation via /dev/tty)
python3 - "$DB_PATH" "$CUTOFF_TS" <<'PYEOF'
import sqlite3, sys, time, datetime, os

def ts_to_local(ts):
    if ts is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

if len(sys.argv) != 3:
    print("[ERROR] Internal argument error")
    sys.exit(2)

db_path = sys.argv[1]
cutoff  = int(sys.argv[2])

if not os.path.exists(db_path):
    print(f"[ERROR] DB file not found: {db_path}")
    sys.exit(1)

conn = sqlite3.connect(db_path, timeout=5.0)
conn.execute("PRAGMA busy_timeout=3000;")
conn.execute("PRAGMA journal_mode=WAL;")
cur = conn.cursor()

# Preview items to delete
rows = cur.execute(
    """
    SELECT token, user, created_at, clicked_at
      FROM tokens
     WHERE created_at < ?
        OR (clicked_at IS NOT NULL AND clicked_at < ?)
     ORDER BY created_at ASC
    """,
    (cutoff, cutoff)
).fetchall()

if not rows:
    print("Nothing to delete. Exiting.")
    conn.close()
    sys.exit(0)

print(f"Items to delete: {len(rows)}")
for tkn, usr, c_at, cl_at in rows:
    print(f"  token={tkn}  user={usr}  created={ts_to_local(c_at)}  clicked={ts_to_local(cl_at)}")

# ---- Read confirmation from /dev/tty (stdin is a heredoc) ----
def prompt_yesno(msg="Proceed with deletion? [y/N]: "):
    try:
        with open('/dev/tty', 'r') as tty:
            sys.stdout.write(msg)
            sys.stdout.flush()
            ans = tty.readline()
            if not ans:
                return False
            return ans.strip().lower() in ('y','yes')
    except Exception:
        return False

if not prompt_yesno():
    print("Cancelled.")
    conn.close()
    sys.exit(0)

# Perform deletion
cur.execute(
    """
    DELETE FROM tokens
     WHERE created_at < ?
        OR (clicked_at IS NOT NULL AND clicked_at < ?)
    """,
    (cutoff, cutoff)
)
deleted = cur.rowcount
conn.commit()

# WAL checkpoint + VACUUM to shrink the DB file
try:
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    conn.commit()
except Exception:
    pass
conn.close()

conn2 = sqlite3.connect(db_path, timeout=5.0)
try:
    conn2.execute("VACUUM;")
    conn2.commit()
finally:
    conn2.close()

print(f"Done: {deleted}records removed.")
PYEOF

echo "Cleanup completed."

