#!/usr/bin/env bash
set -euo pipefail

# clearaccount.sh
# Lists orphan home directories under /home/<NETBIOS>/<user> where the user no longer exists in AD.
# Optionally deletes those orphan directories (root only).

HOME_ROOT="/home"

die() { echo "[ERROR] $*" >&2; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

[[ $EUID -eq 0 ]] || die "Run as root."
need_cmd wbinfo || die "wbinfo not found. Winbind integration is required."

get_netbios() {
  local wg=""
  wg="$(wbinfo --own-domain 2>/dev/null || true)"
  wg="$(echo "$wg" | tr -d '[:space:]')"
  if [[ -n "$wg" ]]; then
    echo "$wg"
    return 0
  fi

  # Fallback: read smb.conf
  if [[ -f /etc/samba/smb.conf ]]; then
    wg="$(awk -F= 'tolower($1) ~ /^[[:space:]]*workgroup[[:space:]]*$/ {gsub(/[[:space:]]+/, "", $2); print $2; exit}' /etc/samba/smb.conf 2>/dev/null || true)"
    wg="$(echo "$wg" | tr -d '[:space:]')"
    [[ -n "$wg" ]] && { echo "$wg"; return 0; }
  fi

  return 1
}

NETBIOS="$(get_netbios || true)"
[[ -n "$NETBIOS" ]] || die "Failed to detect NETBIOS (workgroup)."

DOMAIN_HOME="${HOME_ROOT}/${NETBIOS}"
[[ -d "$DOMAIN_HOME" ]] || die "Domain home root not found: ${DOMAIN_HOME}"

TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

AD_USERS_FILE="$TMPDIR/ad_users.txt"
HOME_USERS_FILE="$TMPDIR/home_users.txt"
ORPHANS_FILE="$TMPDIR/orphans.txt"

echo "[INFO] NETBIOS detected: ${NETBIOS}"
echo "[INFO] Domain home root:  ${DOMAIN_HOME}"
echo

# AD users (normalize to username part)
wbinfo -u 2>/dev/null   | sed 's/\r$//'   | awk -F'\\' '{print $NF}'   | awk 'NF'   | sort -u > "$AD_USERS_FILE"

# Home directories under /home/<NETBIOS>/
find "$DOMAIN_HOME" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'   | awk 'NF'   | sort -u > "$HOME_USERS_FILE"

# Orphans = home exists but not in AD
comm -13 "$AD_USERS_FILE" "$HOME_USERS_FILE" > "$ORPHANS_FILE" || true

echo "=== Orphan home directories (home exists, but no matching AD account) ==="
if [[ -s "$ORPHANS_FILE" ]]; then
  cat "$ORPHANS_FILE" | sed 's/^/ - /'
else
  echo " (none)"
  echo
  echo "[INFO] Nothing to do."
  exit 0
fi
echo

echo -n "Do you want to delete ALL orphan home directories listed above? (y/n): "
read -r ans
if [[ "$ans" != "y" && "$ans" != "Y" ]]; then
  echo "Cancelled."
  exit 0
fi

echo
echo "[INFO] Deleting orphan home directories..."
while IFS= read -r u; do
  [[ -n "$u" ]] || continue
  target="${DOMAIN_HOME}/${u}"
  if [[ -d "$target" ]]; then
    echo " - Removing: ${target}"
    rm -rf --one-file-system "$target"
  else
    echo " - Skipped (not found): ${target}"
  fi
done < "$ORPHANS_FILE"

echo
echo "[INFO] Done."
