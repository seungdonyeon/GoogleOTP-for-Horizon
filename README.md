# Google OTP for Horizon

Google Authenticator–based OTP account & QR link management web app, designed for **Horizon VDI 2FA** deployments on **Rocky Linux / RHEL**.

OTPWeb is built for environments where **offline/closed networks are common**:
- Online: run `install.sh` and it installs what it needs
- Offline: run `offline_packages.sh` **once on an internet-connected build machine** to generate `packages/`, then copy the whole project to the offline server and run `install.sh`

---

## Architecture

OTPWeb runs as two services:

- **Admin UI** (`app.py`)
  - Create/delete OTP accounts
  - Create QR links
  - Configure QR TTL / click TTL
  - Export AD user list (Winbind)
  - login account: admin

- **QR Service** (`qrsvc.py`)
  - Displays QR via link
  - Enforces:
    - *created-at TTL* (expires after creation)
    - *click TTL* (expires after first click or after N seconds)

- **Access**: HTTPS (self-signed certificate)

---

## Requirements

- Rocky Linux / RHEL 9.x
- systemd
- Python 3
- OpenSSL
- EPEL (required for `google-authenticator` on Rocky/RHEL)

---

## Quick start (online install)

1) Install OS & set IP/network

2) Copy config template and edit it:

```bash
cp install.env.example install.env
vi install.env
```

3) make excutable and Install:

```bash
chmod +x install.sh
sudo bash install.sh
```

4) Check services:

```bash
systemctl status otpweb-admin
systemctl status otpweb-qr
```

Open Admin UI:

- `https://<server-ip>:<OTPWEB_ADMIN_PORT>`

You will see a browser warning because the certificate is self-signed.

---

## Offline install (closed networks)

### Step A — Prepare `packages/` on an internet-connected build machine

From the project root:

```bash
chmod +x offline_packages.sh
sudo bash offline_packages.sh
```

This creates:

- `packages/rpms/base/` (RPMs + dependencies + `repodata/`)
- `packages/wheels/` (pip wheelhouse)

### Step B — Copy to the offline server

Copy the entire project directory **including `packages/`** to the offline server.

### Step C — Install on the offline server (same as Online Install)

```bash
cp install.env.example install.env
vi install.env
chmod +x install.sh
sudo bash install.sh
```

## Repository layout

- `src/` — application modules
- `templates/`, `static/` — UI assets
- `scripts/` — helper scripts (wrappers are kept at repo root for convenience)
- `systemd/` — example unit files
- `packages/` — offline bundle (not committed to Git)
