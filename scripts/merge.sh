#!/bin/bash
set -euo pipefail

# OTP helper (AD/Winbind friendly)
# - Does NOT create/delete AD accounts
# - Stores OTP secret in <home>/.google_authenticator (Google Authenticator PAM default)

usage="Usage : merge.sh [-h] [-l] [-a <ID>] [-c <ID>] [-d <ID>] [-f]
  -l            List OTP accounts (id + secret)
  -a <ID>       Add (create) OTP key for ID
  -c <ID>       Change OTP key for ID
  -d <ID>       Delete OTP key for ID (does NOT delete AD user)
  -f            Force (no confirmation)
"

force=false
list=false
add=false
change=false
delete=false
id=""

get_workgroup() {
  if command -v wbinfo >/dev/null 2>&1; then
    local d
    d="$(wbinfo --own-domain 2>/dev/null || true)"
    d="$(echo "$d" | tr -d '[:space:]')"
    [[ -n "$d" ]] && { echo "$d"; return 0; }
  fi
  if [[ -f /etc/samba/smb.conf ]]; then
    local wg
    wg="$(awk -F= 'tolower($1) ~ /^[[:space:]]*workgroup[[:space:]]*$/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/samba/smb.conf 2>/dev/null || true)"
    [[ -n "$wg" ]] && { echo "$wg"; return 0; }
  fi
  echo ""
}

getent_line() {
  local name="$1"
  getent passwd "$name" 2>/dev/null || true
}

resolve_user() {
  local id="$1"
  local line uid gid home
  line="$(getent_line "$id")"
  if [[ -z "$line" ]]; then
    local wg
    wg="$(get_workgroup)"
    if [[ -n "$wg" ]]; then
      line="$(getent_line "${wg}\\${id}")"
    fi
  fi
  [[ -z "$line" ]] && return 1
  uid="$(echo "$line" | cut -d: -f3)"
  gid="$(echo "$line" | cut -d: -f4)"
  home="$(echo "$line" | cut -d: -f6)"
  [[ -z "$home" ]] && return 1
  echo "${uid}:${gid}:${home}"
}

ensure_home() {
  local id="$1"
  local info uid gid home
  info="$(resolve_user "$id")" || return 1
  IFS=: read -r uid gid home <<<"$info"

  if [[ ! -d "$home" ]]; then
    mkdir -p "$home"
  fi
  chown "$uid:$gid" "$home" 2>/dev/null || true
  chmod 700 "$home" 2>/dev/null || true
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -RF "$home" >/dev/null 2>&1 || true
  fi
  echo "$home"
}

ga_path() { echo "$1/.google_authenticator"; }

read_secret() {
  local ga="$1"
  [[ -f "$ga" ]] || return 1
  head -1 "$ga" 2>/dev/null | tr -d '\r\n'
}

run_google_authenticator() {
  local id="$1" home="$2" ga="$3"
  rm -f "$ga" 2>/dev/null || true
  command -v google-authenticator >/dev/null 2>&1 || { echo "[err] google-authenticator not installed"; return 2; }

  if id "$id" >/dev/null 2>&1; then
    HOME="$home" sudo -u "$id" -H google-authenticator -tdf -C -e 0 -r 5 -R 30 -w 17 -Q UTF8 -i Horizon-VDI -l "$id" -s "$ga" >/dev/null
  else
    HOME="$home" google-authenticator -tdf -C -e 0 -r 5 -R 30 -w 17 -Q UTF8 -i Horizon-VDI -l "$id" -s "$ga" >/dev/null
  fi

  local info uid gid
  if info="$(resolve_user "$id" 2>/dev/null || true)"; then
    IFS=: read -r uid gid _ <<<"$info"
    chown "$uid:$gid" "$ga" 2>/dev/null || true
  fi
  chmod 400 "$ga" 2>/dev/null || true
  if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$ga" >/dev/null 2>&1 || true
  fi
}

do_list() {
  echo "List of generated IDs"
  echo
  find /home -maxdepth 4 -type f -name ".google_authenticator" 2>/dev/null     | while read -r f; do
        dir="$(dirname "$f")"
        uid="$(basename "$dir")"
        secret="$(head -1 "$f" 2>/dev/null || true)"
        [[ -n "$uid" && -n "$secret" ]] || continue
        echo -e "${uid}\t${secret}"
      done     | (command -v column >/dev/null 2>&1 && column -t || cat)
}

do_add() {
  local uid="$1"
  local home ga
  home="$(ensure_home "$uid")" || { echo "The user ID does not exist (getent failed)."; exit 1; }
  ga="$(ga_path "$home")"
  if [[ -f "$ga" ]]; then
    echo "The account already exists!"
    exit 1
  fi
  run_google_authenticator "$uid" "$home" "$ga"
  echo "${uid} - Key : $(read_secret "$ga" || true)"
}

do_change() {
  local uid="$1"
  local home ga
  home="$(ensure_home "$uid")" || { echo "The user ID does not exist (getent failed)."; exit 1; }
  ga="$(ga_path "$home")"
  if [[ ! -f "$ga" ]]; then
    echo "The user ID does not exist."
    exit 1
  fi

  local confirm="N"
  if [[ "$force" == true ]]; then
    confirm="Y"
  else
    read -r -p "Are you sure you want to change the OTP key for this account? - ${uid} [y/N] : " confirm
  fi

  if [[ "$confirm" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    run_google_authenticator "$uid" "$home" "$ga"
    echo "${uid} - Key : $(read_secret "$ga" || true)"
  fi
}

do_delete() {
  local uid="$1"
  local home ga
  home="$(ensure_home "$uid")" || { echo "The user ID does not exist (getent failed)."; exit 1; }
  ga="$(ga_path "$home")"
  if [[ ! -f "$ga" ]]; then
    echo "The user ID does not exist (no OTP key)."
    exit 1
  fi

  local confirm="N"
  if [[ "$force" == true ]]; then
    confirm="Y"
  else
    read -r -p "Are you sure you want to delete the OTP key? - ${uid} [y/N] : " confirm
  fi
  [[ "$confirm" =~ ^([yY][eE][sS]|[yY])$ ]] || exit 0

  rm -f "$ga"
  echo "${uid} - OTP key deleted."
}

if [[ $# -eq 0 ]]; then
  echo "$usage"; exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) echo "$usage"; exit 0 ;;
    -l|--list) list=true ;;
    -a|--add) add=true; id="${2:-}"; shift ;;
    -c|--change) change=true; id="${2:-}"; shift ;;
    -d|--delete) delete=true; id="${2:-}"; shift ;;
    -f|--force) force=true ;;
    *) ;;
  esac
  shift
done

if [[ "$add" == true || "$change" == true || "$delete" == true ]]; then
  [[ -z "${id}" ]] && { echo "No ID provided"; exit 1; }
  [[ "${id}" =~ ^[0-9a-zA-Z_.-]+$ ]] || { echo "Invalid ID Format"; exit 1; }
fi

if [[ "$list" == true ]]; then
  do_list
elif [[ "$add" == true ]]; then
  do_add "$id"
elif [[ "$change" == true ]]; then
  do_change "$id"
elif [[ "$delete" == true ]]; then
  do_delete "$id"
else
  echo "$usage"; exit 1
fi
