#!/usr/bin/env bash
set -euo pipefail


# -------------------------------------------------------------------
# Sections:
#   1) Load env + prompt for secrets
#   2) Install OS packages (offline repo if ./packages exists)
#   3) Configure FreeRADIUS + PAM Google Authenticator
#   4) Optional AD Join (Winbind) + permissions
#   5) Generate self-signed TLS cert (5 years) + systemd units
#   6) Start/enable services + post-install hints
# -------------------------------------------------------------------

# OTPWeb Offline/Online Installer (Rocky Linux 9.x)
# - Offline install using local RPM repo + pip wheels in ./packages
# - Optional AD Join using Samba/Winbind (SSSD removed to avoid conflicts)
# - Configures FreeRADIUS client for Horizon Connection Server (clients.conf)
# - Configures FreeRADIUS PAM + pam_google_authenticator (Google Authenticator OTP)
# - OTP secrets are synced to a central store (/var/lib/otp) in a PAM-writable, SELinux-safe way:
#     /var/lib/otp/<user>/.google_authenticator
#   so pam_google_authenticator can create temp files and update state safely.
# - Opens firewall ports for:
#     Admin UI (TCP 8000 by default), QR (TCP 5000 by default)
#     RADIUS Auth (UDP 1812) + Accounting (UDP 1813)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/install.env"

# Safety check: config file must exist
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERROR] install.env not found in: $SCRIPT_DIR" >&2
  echo "→ Copy and edit install.env before running install.sh" >&2
  exit 1
fi


# shellcheck disable=SC1090
source "$ENV_FILE"

INSTALL_DIR="${INSTALL_DIR:-$SCRIPT_DIR}"
ADMIN_PORT="${ADMIN_PORT:-8000}"
QR_PORT="${QR_PORT:-5000}"
OFFLINE_MODE="${OFFLINE_MODE:-auto}"

ADMIN_BIND="${ADMIN_BIND:-0.0.0.0}"
QR_BIND="${QR_BIND:-0.0.0.0}"
ENABLE_HTTPS="${ENABLE_HTTPS:-0}"
ALLOW_SELF_SIGNED_TLS="${ALLOW_SELF_SIGNED_TLS:-0}"
QR_ADMIN_KEY="${QR_ADMIN_KEY:-}"
QR_ALLOWED_CIDRS="${QR_ALLOWED_CIDRS:-}"
OTP_DISPLAY_NAME="${OTP_DISPLAY_NAME:-VDI}"
# Back-compat (deprecated): if caller still sets OTP_ISSUER/OTP_LABEL_PREFIX, prefer OTP_DISPLAY_NAME
OTP_ISSUER="${OTP_ISSUER:-$OTP_DISPLAY_NAME}"
OTP_LABEL_PREFIX="${OTP_LABEL_PREFIX:-$OTP_DISPLAY_NAME}"
CERT_DIR="${CERT_DIR:-/etc/otpweb/certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/otpweb.crt}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/otpweb.key}"

CERT_MODE="${CERT_MODE:-selfsigned}"

AD_JOIN="${AD_JOIN:-0}"
AD_REALM="${AD_REALM:-}"
AD_WORKGROUP="${AD_WORKGROUP:-}"
AD_JOIN_USER="${AD_JOIN_USER:-Administrator}"
AD_JOIN_PASS="${AD_JOIN_PASS:-}"

RADIUS_CLIENT_IP="${RADIUS_CLIENT_IP:-}"
RADIUS_SECRET="${RADIUS_SECRET:-}"   # prompt if empty; blank => default VMware1!

RPM_REPO_DIR="${RPM_REPO_DIR:-$INSTALL_DIR/packages/rpms/base}"
WHEELS_DIR="${WHEELS_DIR:-$INSTALL_DIR/packages/wheels}"
VENV_DIR="${VENV_DIR:-}"
HAS_MKHOMEDIR="${HAS_MKHOMEDIR:-0}"

log()  { echo -e "[INFO] $*"; }
warn() { echo -e "[WARN] $*"; }
err()  { echo -e "[ERROR] $*" >&2; }

ensure_qr_admin_key() {
  # Generate QR_ADMIN_KEY if not present, and persist it into install.env.
  local key="${QR_ADMIN_KEY:-}"
  if [[ -n "$key" ]]; then
    return 0
  fi
  log "QR_ADMIN_KEY is empty; generating a random admin key for QR service endpoints..."
  # Prefer openssl; fall back to /dev/urandom.
  if command -v openssl >/dev/null 2>&1; then
    key="$(openssl rand -hex 32)"
  else
    key="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  fi
  QR_ADMIN_KEY="$key"

  # Persist into the env file so services and future runs use the same key.
  if grep -q '^QR_ADMIN_KEY=' "$ENV_FILE"; then
    sed -i "s/^QR_ADMIN_KEY=.*/QR_ADMIN_KEY=\"$key\"/" "$ENV_FILE"
  else
    printf '\nQR_ADMIN_KEY="%s"\n' "$key" >> "$ENV_FILE"
  fi
  log "Generated QR_ADMIN_KEY and saved to install.env."
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Root privileges are required. Run: sudo bash install.sh"
    exit 1
  fi
}

detect_offline() {
  local want="$OFFLINE_MODE"
  if [[ "$want" == "1" || "$want" == "true" || "$want" == "TRUE" ]]; then echo "1"; return; fi
  if [[ "$want" == "0" || "$want" == "false" || "$want" == "FALSE" ]]; then echo "0"; return; fi
  [[ -d "$RPM_REPO_DIR/repodata" ]] && echo "1" || echo "0"
}

ensure_requirements_txt() {
  [[ -f "$INSTALL_DIR/requirements.txt" ]] && return
  log "requirements.txt not found; creating a minimal one."
  cat > "$INSTALL_DIR/requirements.txt" <<'EOF'
Flask
gunicorn
qrcode[pil]
EOF
}

choose_venv_dir() {
  [[ -n "$VENV_DIR" ]] && return
  local selinux
  selinux="$(getenforce 2>/dev/null || echo Disabled)"
  if [[ "$selinux" == "Enforcing" ]]; then
    VENV_DIR="/opt/otpweb-venv"
  else
    VENV_DIR="$INSTALL_DIR/.venv"
  fi
}

setup_local_repo() {
  if [[ ! -d "$RPM_REPO_DIR/repodata" ]]; then
    err "Offline RPM repo metadata not found: $RPM_REPO_DIR/repodata"
    err "Make sure you ran createrepo_c on the build server."
    exit 1
  fi
  log "Creating local repo file: /etc/yum.repos.d/otpweb-local.repo"
  cat > /etc/yum.repos.d/otpweb-local.repo <<EOF
[otpweb-local]
name=OTPWeb Local Repo
baseurl=file://$RPM_REPO_DIR
enabled=1
gpgcheck=0
EOF
}

dnf_install() {
  local offline="$1"; shift
  if [[ "$offline" == "1" ]]; then
    dnf -y --disablerepo="*" --enablerepo="otpweb-local" --allowerasing install "$@"
  else
    dnf -y install "$@"
  fi
}

remove_sssd_if_present() {
  if rpm -q sssd >/dev/null 2>&1 || rpm -q sssd-common >/dev/null 2>&1; then
    warn "Detected 'sssd' packages. They are not needed for the Winbind approach and may cause dependency conflicts; removing them."
    dnf -y remove 'sssd*' || true
  fi
}

enable_epel_and_crb_best_effort() {
  # Online-only helper:
  # - EPEL provides google-authenticator packages on Rocky/RHEL 9 in many environments.
  # - CRB is often required for EPEL dependencies (best-effort).
  local offline="$1"
  [[ "$offline" == "1" ]] && return 0

  if ! rpm -q epel-release >/dev/null 2>&1; then
    log "Installing epel-release (required for google-authenticator on Rocky/RHEL)..."
    if ! dnf -y install epel-release; then
      warn "Failed to install epel-release. google-authenticator may not be installable from enabled repos."
      return 0
    fi
  fi

  # Ensure config-manager exists (dnf-plugins-core), then best-effort enable CRB if present.
  if ! dnf config-manager --help >/dev/null 2>&1; then
    dnf -y install dnf-plugins-core >/dev/null 2>&1 || true
  fi

  if dnf config-manager --help >/dev/null 2>&1; then
    if dnf repolist all 2>/dev/null | awk '{print $1}' | grep -qx 'crb'; then
      log "Enabling CRB repo (best-effort)..."
      dnf config-manager --set-enabled crb >/dev/null 2>&1 || warn "Could not enable CRB repo automatically."
    fi
  fi

  dnf -y makecache >/dev/null 2>&1 || true
}


install_packages() {
  local offline="$1"
  [[ "$offline" == "1" ]] && setup_local_repo

  log "Installing required packages (dnf)... (offline=$offline)"
  dnf_install "$offline" python3 python3-pip krb5-workstation authselect curl bind-utils firewalld
  # mkhomedir (auto-create home directories on first login) - optional because it may be missing in offline repo
  if dnf_install "$offline" oddjob oddjob-mkhomedir >/dev/null 2>&1; then
    systemctl enable --now oddjobd >/dev/null 2>&1 || true
    HAS_MKHOMEDIR=1
  else
    HAS_MKHOMEDIR=0
    warn "oddjob/oddjob-mkhomedir not available in the repo; skipping mkhomedir. (OTPWeb will create home directories itself when needed.)"
  fi

  dnf_install "$offline" openssl make

  dnf_install "$offline" freeradius freeradius-utils

  # google-authenticator (CLI + PAM module) is typically provided by EPEL on Rocky/RHEL 9.
  # NOTE: 'google-authenticator-libpam' is a Debian/Ubuntu package name and does NOT exist on Rocky/RHEL.
  # If we try to install a non-existent package alongside a real one, dnf fails the whole transaction.
  enable_epel_and_crb_best_effort "$offline"

  if dnf_install "$offline" google-authenticator; then
    :
  else
    warn "Failed to install google-authenticator from current repositories."
    warn "If you're on a restricted/offline network, make sure EPEL + CRB RPMs are present in your offline repo bundle."
  fi

  # Final sanity check: the UI requires /usr/bin/google-authenticator (or equivalent) to exist.
  if ! command -v google-authenticator >/dev/null 2>&1; then
    warn "google-authenticator command not found after installation attempt. OTP features that depend on it will not work."
  fi

  remove_sssd_if_present
  dnf_install "$offline" samba samba-winbind samba-winbind-clients

  systemctl enable --now firewalld >/dev/null 2>&1 || true
}

configure_firewall() {
  log "Opening firewall ports..."
  firewall-cmd --permanent --add-port="${ADMIN_PORT}/tcp" >/dev/null 2>&1 || true

  # QR service is usually exposed to end-users (to fetch /q/<token> images).
  # Optionally restrict by source CIDR(s) via QR_ALLOWED_CIDRS.
  if [[ -z "${QR_ALLOWED_CIDRS// }" ]]; then
    firewall-cmd --permanent --add-port="${QR_PORT}/tcp" >/dev/null 2>&1 || true
  else
    # Remove any prior broad port-open rule (best-effort)
    firewall-cmd --permanent --remove-port="${QR_PORT}/tcp" >/dev/null 2>&1 || true
    IFS=',' read -r -a _cidrs <<< "$QR_ALLOWED_CIDRS"
    for c in "${_cidrs[@]}"; do
      c="$(echo "$c" | xargs)"
      [[ -z "$c" ]] && continue
      firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$c\" port port=\"${QR_PORT}\" protocol=\"tcp\" accept" >/dev/null 2>&1 || true
    done
  fi
  firewall-cmd --permanent --add-port="1812/udp" >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port="1813/udp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
}

prompt_admin_password() {
  log "Set OTPWeb admin UI password"
  echo "Tip: Press Enter twice to use the default password (VMware1!)."
  local p1 p2
  read -r -s -p "Admin password: " p1; echo
  read -r -s -p "Confirm admin password: " p2; echo
  if [[ -z "$p1" && -z "$p2" ]]; then
    ADMIN_PASSWORD="VMware1!"
    log "Default password set to VMware1!."
  elif [[ "$p1" != "$p2" ]]; then
    err "Passwords do not match."
    exit 1
  else
    ADMIN_PASSWORD="$p1"
  fi
}

setup_admin_password_hash() {
  mkdir -p "$INSTALL_DIR/account"
  chmod 700 "$INSTALL_DIR/account" || true  # Store PBKDF2 (Werkzeug) hash in: $INSTALL_DIR/account/admin.pass
  ( umask 077
    INSTALL_DIR="$INSTALL_DIR" ADMIN_PASSWORD="$ADMIN_PASSWORD" "$VENV_DIR/bin/python" - <<'PY'
import os, sys
from werkzeug.security import generate_password_hash

install_dir = os.environ.get("INSTALL_DIR", ".")
pw = os.environ.get("ADMIN_PASSWORD", "")
if not pw:
    print("[ERROR] ADMIN_PASSWORD is empty", file=sys.stderr)
    sys.exit(1)

out_path = os.path.join(install_dir, "account", "admin.pass")
hashed = generate_password_hash(pw, method="pbkdf2:sha256", salt_length=16)

os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w", encoding="utf-8") as f:
    f.write(hashed)
os.chmod(out_path, 0o600)
PY
  )
}

setup_python_env() {
  local offline="$1"
  ensure_requirements_txt
  choose_venv_dir
  log "Creating Python virtual environment: $VENV_DIR"
  rm -rf "$VENV_DIR" || true
  python3 -m venv "$VENV_DIR"
  if [[ "$offline" == "0" ]]; then
    "$VENV_DIR/bin/python" -m pip install -U pip >/dev/null 2>&1 || true
  fi
  if [[ "$offline" == "1" ]]; then
    [[ -d "$WHEELS_DIR" ]] || { err "Offline wheels directory not found: $WHEELS_DIR"; exit 1; }
    log "Installing Python dependencies offline (local wheels)..."
    "$VENV_DIR/bin/python" -m pip install --no-index --find-links="$WHEELS_DIR" -r "$INSTALL_DIR/requirements.txt"
  else
    log "Installing Python dependencies online (PyPI)..."
    "$VENV_DIR/bin/python" -m pip install -r "$INSTALL_DIR/requirements.txt"
  fi
}

ensure_self_signed_cert() {
  # Generates a self-signed certificate (5 years) for HTTPS.
  # Files:
  #   $CERT_FILE (public cert)
  #   $KEY_FILE  (private key)
  if [[ "${ENABLE_HTTPS}" != "1" ]]; then
    return 0
  fi

  # Manual mode: require engineer-provided cert/key.
  if [[ "${CERT_MODE}" == "manual" ]]; then
    if [[ -f "${CERT_FILE}" && -f "${KEY_FILE}" ]]; then
      chmod 600 "$KEY_FILE" || true
      chmod 644 "$CERT_FILE" || true
      return 0
    fi
    err "CERT_MODE=manual but certificate files not found: CERT_FILE=$CERT_FILE , KEY_FILE=$KEY_FILE"
    err "Provide existing files (e.g., ./certs/otpweb.crt and ./certs/otpweb.key) and set CERT_DIR/CERT_FILE/KEY_FILE accordingly."
    exit 1
  fi

  mkdir -p "$CERT_DIR"
  chmod 700 "$CERT_DIR" || true

  if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
    return 0
  fi

  log "Generating self-signed TLS certificate (5 years)..."
  local cn
  cn="$(hostname -f 2>/dev/null || hostname)"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 1825 -nodes \
    -keyout "$KEY_FILE" -out "$CERT_FILE" \
    -subj "/CN=${cn}" >/dev/null 2>&1

  chmod 600 "$KEY_FILE" || true
  chmod 644 "$CERT_FILE" || true
}


write_systemd_units() {
  choose_venv_dir
  log "Creating systemd service unit files..."

  ensure_self_signed_cert
  local ADMIN_TLS_ARGS=""
  local QR_TLS_ARGS=""
  if [[ "${ENABLE_HTTPS}" == "1" ]]; then
    ADMIN_TLS_ARGS="--certfile $CERT_FILE --keyfile $KEY_FILE"
    QR_TLS_ARGS="--certfile $CERT_FILE --keyfile $KEY_FILE"
  fi
  cat > /etc/systemd/system/otpweb-admin.service <<EOF
[Unit]
Description=OTPWeb Admin UI (Flask/Gunicorn)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=-$INSTALL_DIR/install.env
ExecStart=$VENV_DIR/bin/python -m gunicorn -b ${ADMIN_BIND}:$ADMIN_PORT -w 2 $ADMIN_TLS_ARGS app:app
Restart=always
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/otpweb-qr.service <<EOF
[Unit]
Description=OTPWeb QR Service (Flask/Gunicorn)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=-$INSTALL_DIR/install.env
ExecStart=$VENV_DIR/bin/python -m gunicorn -b ${QR_BIND}:$QR_PORT -w 2 $QR_TLS_ARGS qrsvc:app
Restart=always
RestartSec=2
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now otpweb-admin otpweb-qr
}

configure_authselect_winbind() {
  log "Configuring authselect (winbind) (best-effort)..."
  if command -v authselect >/dev/null 2>&1; then
    if [[ "${HAS_MKHOMEDIR:-0}" == "1" ]]; then
      authselect select winbind with-mkhomedir --force >/dev/null 2>&1 || true
    else
      authselect select winbind --force >/dev/null 2>&1 || true
    fi
  fi
}

configure_samba_conf() {
  [[ "$AD_JOIN" == "1" || "$AD_JOIN" == "true" || "$AD_JOIN" == "TRUE" ]] || return 0
  [[ -n "$AD_REALM" && -n "$AD_WORKGROUP" ]] || { err "AD_JOIN=1 but AD_REALM or AD_WORKGROUP is empty."; exit 1; }

  log "Configuring smb.conf (/etc/samba/smb.conf)..."
  cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = $AD_WORKGROUP
   realm = $AD_REALM
   security = ads
   server role = member server

   winbind use default domain = yes
   winbind enum users = yes
   winbind enum groups = yes
   template shell = /bin/bash
   template homedir = /home/%D/%U

   idmap config * : backend = tdb
   idmap config * : range = 3000-7999
   idmap config $AD_WORKGROUP : backend = rid
   idmap config $AD_WORKGROUP : range = 10000-999999
EOF

  systemctl enable --now smb winbind >/dev/null 2>&1 || true
  systemctl restart smb winbind >/dev/null 2>&1 || true
}

ad_join_winbind() {
  [[ "$AD_JOIN" == "1" || "$AD_JOIN" == "true" || "$AD_JOIN" == "TRUE" ]] || return 0
  configure_samba_conf
  configure_authselect_winbind

  log "Joining the domain (net ads join)..."
  local pass="$AD_JOIN_PASS"
  if [[ -z "$pass" ]]; then read -r -s -p "AD join password (${AD_JOIN_USER}): " pass; echo; fi

  echo "$pass" | kinit "${AD_JOIN_USER}@${AD_REALM}" >/dev/null 2>&1 || true
  if echo "$pass" | net ads join -U "$AD_JOIN_USER" >/dev/null 2>&1; then
    log "AD join succeeded"
  else
    err "AD join failed: restart smb/winbind and verify with: net ads testjoin, wbinfo -u"
    exit 1
  fi
  systemctl restart smb winbind >/dev/null 2>&1 || true
}

prompt_radius_client_ip() {
  [[ -n "$RADIUS_CLIENT_IP" ]] && return
  log "Set Horizon Connection Server IP (FreeRADIUS client)"
  echo "Example: 192.168.10.151"
  read -r -p "Connection Server IP: " RADIUS_CLIENT_IP
  [[ -n "$RADIUS_CLIENT_IP" ]] || { err "Connection Server IP is empty."; exit 1; }
}

prompt_radius_secret() {
  [[ -n "$RADIUS_SECRET" ]] && return
  log "Set FreeRADIUS shared secret"
  echo "Tip: Press Enter twice to use the default shared secret (VMware1!)."
  local s1 s2
  read -r -s -p "Shared secret: " s1; echo
  read -r -s -p "Confirm shared secret: " s2; echo
  if [[ -z "$s1" && -z "$s2" ]]; then
    RADIUS_SECRET="VMware1!"
    log "Default shared secret set to VMware1!."
  elif [[ "$s1" != "$s2" ]]; then
    err "Shared secrets do not match."
    exit 1
  else
    RADIUS_SECRET="$s1"
  fi
}

ensure_radius_can_start() {
  if [[ -f /etc/raddb/certs/server.pem && -f /etc/raddb/certs/server.key ]]; then
    return 0
  fi

  if [[ -d /etc/raddb/certs ]]; then
    if [[ -f /etc/raddb/certs/Makefile ]]; then
      log "FreeRADIUS EAP certificates not found; generating self-signed certs in /etc/raddb/certs (make)"
      (cd /etc/raddb/certs && make >/dev/null 2>&1) || true
    elif [[ -f /etc/raddb/certs/bootstrap ]]; then
      log "FreeRADIUS EAP certificates not found; generating self-signed certs in /etc/raddb/certs (bootstrap)"
      (cd /etc/raddb/certs && ./bootstrap >/dev/null 2>&1) || true
    fi
  fi

  if [[ -f /etc/raddb/certs/server.pem && -f /etc/raddb/certs/server.key ]]; then
    restorecon -Rv /etc/raddb/certs >/dev/null 2>&1 || true
    return 0
  fi

  warn "Could not generate EAP certs (server.pem/server.key). If you only use PAP, EAP will be disabled."
  rm -f /etc/raddb/mods-enabled/eap >/dev/null 2>&1 || true
  sed -i 's/^[[:space:]]*eap[[:space:]]*$/# eap (disabled by otpweb installer)/' \
    /etc/raddb/sites-enabled/default /etc/raddb/sites-enabled/inner-tunnel 2>/dev/null || true
}

### OTPWEB OTPSTORE SYNC ###
install_otpstore_sync() {
  local sync_script="/usr/local/sbin/otpweb-sync-otpstore.sh"
  local svc="/etc/systemd/system/otpweb-otpstore-sync.service"
  local timer="/etc/systemd/system/otpweb-otpstore-sync.timer"

  log "Configuring OTP secret store sync (/var/lib/otp/<user>/.google_authenticator)"

  # Base directory: root managed, readable by radiusd
  mkdir -p /var/lib/otp
  chown root:radiusd /var/lib/otp 2>/dev/null || true
  chmod 0750 /var/lib/otp 2>/dev/null || true

  # Install sync script (idempotent)
  cat > "$sync_script" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail

SRC_ROOT="/home"
DST_ROOT="/var/lib/otp"
DST_FILE=".google_authenticator"

have_restorecon() { command -v restorecon >/dev/null 2>&1; }
have_semanage()   { command -v semanage   >/dev/null 2>&1; }

ensure_selinux_context() {
  if command -v getenforce >/dev/null 2>&1; then
    local mode
    mode="$(getenforce 2>/dev/null || true)"
    if [[ "$mode" == "Enforcing" ]]; then
      if have_semanage; then
        semanage fcontext -a -t radiusd_var_lib_t "${DST_ROOT}(/.*)?" 2>/dev/null || true
      fi
      if have_restorecon; then
        restorecon -Rv "$DST_ROOT" >/dev/null 2>&1 || true
      fi
    fi
  fi
}

# Ensure destination base exists (root managed)
mkdir -p "$DST_ROOT"
chown root:radiusd "$DST_ROOT" 2>/dev/null || true
chmod 0750 "$DST_ROOT" 2>/dev/null || true
ensure_selinux_context

declare -A seen=()

# Find /home/<DOMAIN>/<user>/.google_authenticator
while IFS= read -r -d '' src; do
  user="$(basename "$(dirname "$src")")"
  seen["$user"]=1

  user_dir="$DST_ROOT/$user"
  dst="$user_dir/$DST_FILE"

  # Create per-user directory so pam_google_authenticator can create tempfiles inside it
  # (root owned, group radiusd, group-writable)
  install -d -o root -g radiusd -m 0770 "$user_dir"

  # Copy only if missing or changed
  if [[ ! -f "$dst" ]] || ! cmp -s "$src" "$dst"; then
    tmp="${dst}.tmp.$$"
    install -o root -g radiusd -m 0660 "$src" "$tmp"
    if have_restorecon; then
      restorecon -F "$tmp" >/dev/null 2>&1 || true
    fi
    mv -f "$tmp" "$dst"
  fi

  # Enforce metadata even if unchanged
  chown root:radiusd "$dst" 2>/dev/null || true
  chmod 0660 "$dst" 2>/dev/null || true
  if have_restorecon; then
    restorecon -F "$dst" >/dev/null 2>&1 || true
  fi
done < <(find "$SRC_ROOT" -maxdepth 3 -type f -name ".google_authenticator" -print0 2>/dev/null)

# Remove stale users (directories) in DST_ROOT
shopt -s nullglob
for user_dir in "$DST_ROOT"/*; do
  [[ -d "$user_dir" ]] || continue
  user="$(basename "$user_dir")"
  if [[ -z "${seen[$user]+x}" ]]; then
    rm -rf "$user_dir"
  fi
done

# Ensure SELinux labeling after changes (best effort)
ensure_selinux_context
EOS

  chmod 0755 "$sync_script" || true
  chown root:root "$sync_script" || true
  restorecon -v "$sync_script" >/dev/null 2>&1 || true

  cat > "$svc" <<EOF
[Unit]
Description=OTPWeb - Sync OTP secrets into /var/lib/otp for FreeRADIUS PAM
After=network.target

[Service]
Type=oneshot
ExecStart=$sync_script
EOF

  cat > "$timer" <<'EOF'
[Unit]
Description=OTPWeb - Periodic OTP secret sync timer

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=5s
Unit=otpweb-otpstore-sync.service

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now otpweb-otpstore-sync.timer >/dev/null 2>&1 || true

  # Run once immediately
  bash "$sync_script" || true
}

configure_freeradius_pam_otp() {
  local mods_dir="/etc/raddb/mods-enabled"
  local default_site="/etc/raddb/sites-enabled/default"
  local pam_avail="/etc/raddb/mods-available/pam"
  local pam_link="${mods_dir}/pam"
  local pam_service="/etc/pam.d/radiusd"

  log "Applying FreeRADIUS PAM (OTP) configuration"

  # Enable rlm_pam
  mkdir -p "$mods_dir"
  if [[ -f "$pam_avail" && ! -e "$pam_link" ]]; then
    ln -s "$pam_avail" "$pam_link"
  fi

  # PAM service config (idempotent)
  cat > "$pam_service" <<'EOF'
# OTPWEB_PAM_SERVICE
# OTPWeb PAM service for FreeRADIUS (Google Authenticator OTP)
# Central secret store:
#   /var/lib/otp/<user>/.google_authenticator
# We run pam_google_authenticator as user=radiusd.
# Secret files are root:radiusd and mode 0660 so pam can update state (tempfiles) safely.
auth required pam_google_authenticator.so secret=/var/lib/otp/${USER}/.google_authenticator user=radiusd no_strict_owner allowed_perm=0660 debug
account required pam_permit.so
EOF
  chmod 0644 "$pam_service" || true
  restorecon -v "$pam_service" >/dev/null 2>&1 || true

  # Patch FreeRADIUS default virtual server safely (IDEMPOTENT)
  if [[ ! -f "$default_site" ]]; then
    warn "$default_site not found; skipping PAM integration patch."
    return 0
  fi

  # Reset default site baseline to prevent cumulative corruption
  if [[ -f "/etc/raddb/sites-available/default" ]]; then
    cp -f "/etc/raddb/sites-available/default" "$default_site" || true
  fi

  # Remove any previous OTPWeb blocks
  sed -i '/^[[:space:]]*# OTPWEB_BEGIN_AUTHZ$/,/^[[:space:]]*# OTPWEB_END_AUTHZ$/d' "$default_site" 2>/dev/null || true
  sed -i '/^[[:space:]]*# OTPWEB_BEGIN_AUTHN$/,/^[[:space:]]*# OTPWEB_END_AUTHN$/d' "$default_site" 2>/dev/null || true

  # authorize: Route PAP(User-Password) to PAM
  awk '
    function count_char(s, c,   i,n) { n=0; for(i=1;i<=length(s);i++){ if(substr(s,i,1)==c) n++ } return n }
    BEGIN{ in_authz=0; depth=0 }
    /^[[:space:]]*authorize[[:space:]]*\{/ {
      in_authz=1
      depth=1
      print $0
      next
    }
    {
      if (in_authz) {
        depth += count_char($0, "{")
        depth -= count_char($0, "}")
        if (depth == 0) {
          print "    # OTPWEB_BEGIN_AUTHZ"
          print "    # OTPWeb: Route PAP to PAM for Google Authenticator OTP"
          print "    if (&User-Password && !&EAP-Message) {"
          print "        update control {"
          print "            Auth-Type := PAM"
          print "        }"
          print "    }"
          print "    # OTPWEB_END_AUTHZ"
          print $0
          in_authz=0
          next
        }
      }
      print $0
    }
  ' "$default_site" > "${default_site}.otpweb.tmp" && mv -f "${default_site}.otpweb.tmp" "$default_site"

  # authenticate: Ensure Auth-Type PAM exists
  awk '
    function count_char(s, c,   i,n) { n=0; for(i=1;i<=length(s);i++){ if(substr(s,i,1)==c) n++ } return n }
    BEGIN{ in_authn=0; depth=0; inserted=0 }
    /^[[:space:]]*authenticate[[:space:]]*\{/ {
      in_authn=1
      depth=1
      print $0
      next
    }
    {
      if (in_authn) {
        if (!inserted && depth==1 && $0 ~ /^[[:space:]]*Auth-Type[[:space:]]+CHAP[[:space:]]*\{/) {
          print "    # OTPWEB_BEGIN_AUTHN"
          print "    # OTPWeb: PAM authentication for Google Authenticator"
          print "    Auth-Type PAM {"
          print "        pam"
          print "    }"
          print "    # OTPWEB_END_AUTHN"
          inserted=1
        }

        depth += count_char($0, "{")
        depth -= count_char($0, "}")

        if (depth == 0) {
          if (!inserted) {
            print "    # OTPWEB_BEGIN_AUTHN"
            print "    # OTPWeb: PAM authentication for Google Authenticator"
            print "    Auth-Type PAM {"
            print "        pam"
            print "    }"
            print "    # OTPWEB_END_AUTHN"
            inserted=1
          }
          print $0
          in_authn=0
          next
        }
      }
      print $0
    }
  ' "$default_site" > "${default_site}.otpweb.tmp" && mv -f "${default_site}.otpweb.tmp" "$default_site"

  restorecon -v "$default_site" >/dev/null 2>&1 || true
}

configure_freeradius_client() {
  prompt_radius_client_ip
  prompt_radius_secret

  local conf="/etc/raddb/clients.conf"
  local begin="# BEGIN OTPWEB HORIZON CS"
  local end="# END OTPWEB HORIZON CS"

  log "Registering Connection Server in clients.conf: $RADIUS_CLIENT_IP"
  [[ -f "$conf" ]] || { err "$conf not found. Check that FreeRADIUS is installed."; exit 1; }

  # Remove existing block (idempotent)
  if grep -qF "$begin" "$conf"; then
    awk -v b="$begin" -v e="$end" '
      $0==b {skip=1; next}
      $0==e {skip=0; next}
      skip!=1 {print}
    ' "$conf" > "${conf}.tmp"
    mv -f "${conf}.tmp" "$conf"
  fi

  cat >> "$conf" <<EOF

$begin
client horizon_cs {
    ipaddr = $RADIUS_CLIENT_IP
    secret = $RADIUS_SECRET
    require_message_authenticator = yes
}
$end
EOF

  chgrp radiusd "$conf" 2>/dev/null || true
  chmod 0640 "$conf" 2>/dev/null || true
  restorecon -v "$conf" >/dev/null 2>&1 || true

  configure_freeradius_pam_otp
  install_otpstore_sync
  ensure_radius_can_start

  if ! radiusd -XC >/dev/null 2>&1; then
    err "FreeRADIUS config check failed (radiusd -XC). Review the output below:"
    radiusd -XC || true
    exit 1
  fi

  systemctl enable --now radiusd >/dev/null 2>&1 || true
  systemctl restart radiusd
}

sanity_checks() {
  mkdir -p "$INSTALL_DIR/account"
  chmod 0700 "$INSTALL_DIR/account" || true
  [[ -f "$INSTALL_DIR/app.py" && -f "$INSTALL_DIR/qrsvc.py" ]] || { err "Project files not found (app.py / qrsvc.py). INSTALL_DIR=$INSTALL_DIR"; exit 1; }
}

main() {
  need_root
  sanity_checks

  ensure_qr_admin_key

  local offline
  offline="$(detect_offline)"
  log "Install mode: $([[ "$offline" == "1" ]] && echo OFFLINE || echo ONLINE)"

  install_packages "$offline"

  if [[ "$AD_JOIN" == "1" || "$AD_JOIN" == "true" || "$AD_JOIN" == "TRUE" ]]; then
    ad_join_winbind
  else
    log "AD_JOIN disabled: skipping domain join step."
  fi

  configure_freeradius_client

  prompt_admin_password

  setup_python_env "$offline"
  setup_admin_password_hash
  write_systemd_units
  configure_firewall

  echo
  log "Installation completed"

  local SCHEME="http"
  if [[ "${ENABLE_HTTPS}" == "1" ]]; then SCHEME="https"; fi
  local ADMIN_URL="${SCHEME}://<server-ip>:${ADMIN_PORT}"
  local QR_URL="${SCHEME}://<server-ip>:${QR_PORT}"

  echo " - Admin UI: http://<server-ip>:${ADMIN_PORT}"
  echo " - User QR:   ${QR_URL}"
  echo " - RADIUS Auth: UDP/1812 (PAP recommended for Horizon)"
  echo
  systemctl --no-pager status otpweb-admin otpweb-qr radiusd || true
}

main "$@"
