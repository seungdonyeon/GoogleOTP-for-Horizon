#!/usr/bin/env bash
set -euo pipefail

# -------------------------------------------------------------------
# offline_packages.sh (v4)
#
# Purpose:
#   Prepare an "offline install bundle" under ./packages/ by downloading:
#     - RPMs (+dependencies) into: packages/rpms/base/
#     - Python wheels        into: packages/wheels/
#   and generating RPM repo metadata (repodata/) via createrepo_c.
#
# Key design goals:
#   - SAFE: use `dnf download --resolve` so offline installs won't miss dependencies.
#   - FAST: resolve/download ONCE (not per-package), to avoid huge "Already downloaded" SKIPs.
#   - Self-contained: auto install helpers (python3-pip / dnf-plugins-core / createrepo_c).
#   - EPEL-aware: auto install epel-release (needed for google-authenticator on Rocky/RHEL),
#     and best-effort enable CRB (often required for EPEL dependencies).
#
# Usage (on an ONLINE Rocky/RHEL build host):
#   cd /opt/otpweb
#   sudo bash offline_packages.sh
#
# Then copy the entire project directory (including ./packages/) to the
# offline server and run:
#   sudo bash install.sh
# -------------------------------------------------------------------

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="${PROJECT_ROOT}/packages"
RPM_DIR="${PKG_DIR}/rpms/base"
WHEELS_DIR="${PKG_DIR}/wheels"
RPM_LIST_FILE_DEFAULT="${PROJECT_ROOT}/pkglist.rpms.txt"
RPM_LIST_FILE_LEGACY="${PKG_DIR}/pkglist.rpms.txt"
REQ_FILE="${PROJECT_ROOT}/requirements.txt"

log()  { echo -e "[INFO] $*"; }
warn() { echo -e "[WARN] $*"; }
err()  { echo -e "[ERROR] $*" >&2; }

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "This script needs root (dnf install / repo enable)."
    err "Run: sudo bash offline_packages.sh"
    exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

EPEL_INSTALLED_BY_SCRIPT=0

rpm_list_file() {
  if [[ -f "$RPM_LIST_FILE_DEFAULT" ]]; then
    echo "$RPM_LIST_FILE_DEFAULT"
    return 0
  fi
  if [[ -f "$RPM_LIST_FILE_LEGACY" ]]; then
    echo "$RPM_LIST_FILE_LEGACY"
    return 0
  fi
  echo "$RPM_LIST_FILE_DEFAULT"
  return 0
}

install_build_helpers() {
  have_cmd dnf || { err "dnf not found."; exit 1; }

  local need=()
  rpm -q python3 >/dev/null 2>&1           || need+=("python3")
  rpm -q python3-pip >/dev/null 2>&1       || need+=("python3-pip")
  rpm -q dnf-plugins-core >/dev/null 2>&1  || need+=("dnf-plugins-core")
  rpm -q createrepo_c >/dev/null 2>&1      || need+=("createrepo_c")

  if [[ "${#need[@]}" -gt 0 ]]; then
    log "Installing build helpers: ${need[*]}"
    dnf -y install "${need[@]}"
  fi

  if ! dnf download --help >/dev/null 2>&1; then
    err "'dnf download' not available. Ensure dnf-plugins-core is installed."
    exit 1
  fi
  if ! have_cmd createrepo_c; then
    err "createrepo_c still not available after installation."
    exit 1
  fi
}

enable_epel_and_crb_best_effort() {
  if ! rpm -q epel-release >/dev/null 2>&1; then
    log "Installing epel-release (required for google-authenticator on Rocky/RHEL)..."
    if dnf -y install epel-release; then
      EPEL_INSTALLED_BY_SCRIPT=1
      log "epel-release installed by this script."
    else
      warn "Failed to install epel-release. EPEL packages (e.g., google-authenticator) may not be downloadable."
      return 0
    fi
  else
    log "epel-release already installed."
  fi

  # CRB is often required for EPEL dependencies on RHEL/Rocky 9 (best-effort).
  if dnf config-manager --help >/dev/null 2>&1; then
    if dnf repolist all 2>/dev/null | awk '{print $1}' | grep -qx 'crb'; then
      log "Enabling CRB repo (best-effort)..."
      dnf config-manager --set-enabled crb >/dev/null 2>&1 || warn "Could not enable CRB repo automatically."
    fi
  fi

  dnf -y makecache >/dev/null 2>&1 || true
}

read_rpm_list() {
  local f
  f="$(rpm_list_file)"
  if [[ ! -f "$f" ]]; then
    err "RPM list file not found: $f"
    exit 1
  fi
  grep -vE '^\s*#' "$f" | grep -vE '^\s*$' || true
}

download_rpms_once() {
  mkdir -p "$RPM_DIR"
  log "Downloading RPMs (+dependencies) to: $RPM_DIR"
  log "Resolving/downloading in ONE call for speed..."

  # Use xargs to avoid command-line length limits.
  local list_tmp
  list_tmp="$(mktemp)"
  read_rpm_list > "$list_tmp"

  if [[ ! -s "$list_tmp" ]]; then
    err "RPM list is empty."
    rm -f "$list_tmp"
    exit 1
  fi

  # If any package cannot be resolved, dnf exits non-zero. This is usually what we want (safe).
  # To troubleshoot, temporarily run with `set +e` and inspect which repo is missing.
  if ! xargs -r -a "$list_tmp" dnf download --resolve --alldeps --destdir "$RPM_DIR"; then
    rm -f "$list_tmp"
    err "dnf download failed. Most common causes:"
    err " - EPEL/CRB not enabled (google-authenticator, etc.)"
    err " - BaseOS/AppStream/Extras repos disabled"
    exit 1
  fi

  rm -f "$list_tmp"

  log "Generating repo metadata (repodata/)..."
  createrepo_c "$RPM_DIR" >/dev/null
}

download_wheels() {
  mkdir -p "$WHEELS_DIR"
  if [[ ! -f "$REQ_FILE" ]]; then
    err "requirements.txt not found: $REQ_FILE"
    exit 1
  fi
  log "Downloading Python wheels to: $WHEELS_DIR"
  python3 -m pip download -r "$REQ_FILE" -d "$WHEELS_DIR"
}

cleanup_best_effort() {
  if [[ "$EPEL_INSTALLED_BY_SCRIPT" == "1" ]]; then
    log "Removing epel-release (best-effort revert)..."
    dnf -y remove epel-release >/dev/null 2>&1 || warn "Failed to remove epel-release (safe to ignore)."
  fi
}

main() {
  need_root
  install_build_helpers
  enable_epel_and_crb_best_effort
  download_rpms_once
  download_wheels
  cleanup_best_effort

  log "Offline bundle ready."
  log " - RPM repo:   $RPM_DIR (repodata present)"
  log " - Wheelhouse: $WHEELS_DIR"
  log "Copy the whole project directory (including ./packages/) to the offline server, then run:"
  log "  sudo bash install.sh"
}

main "$@"
