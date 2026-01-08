# OTPWeb

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
  - Configure TTL / click-TTL
  - Export AD user list (Winbind)

- **QR Service** (`qrsvc.py`)
  - Displays QR via link
  - Enforces:
    - *created-at TTL* (expires after creation)
    - *click TTL* (expires after first click or after N seconds)

### Security model (important)

- **External access**: HTTPS (self-signed certificate)
- **Admin ↔ QR internal calls**: allowed only on `127.0.0.1/localhost`, where certificate verification is relaxed **only for this internal loopback path**.

This keeps “TLS exceptions” narrowly scoped to local-only traffic.

---

## Requirements

- Rocky Linux / RHEL 9.x
- systemd
- Python 3
- OpenSSL
- EPEL (required for `google-authenticator` on Rocky/RHEL)

> Note: `install.sh` installs required packages automatically (online),
> or from `packages/` if you prepared an offline bundle.

---

## Quick start (online install)

1) Install OS & set IP/network

2) Copy config template and edit it:

```bash
cp install.env.example install.env
vi install.env
```

3) Install:

```bash
sudo bash install.sh
```

4) Check services:

```bash
systemctl status otpweb-admin
systemctl status otpweb-qr
```

Open Admin UI:

- `https://<server-ip>:<OTPWEB_ADMIN_PORT>` (default: 8443)

You will see a browser warning because the certificate is self-signed.

---

## Offline install (closed networks)

### Step A — Prepare `packages/` on an internet-connected build machine

From the project root:

```bash
rm -rf packages
sudo bash offline_packages.sh
```

This creates:

- `packages/rpms/base/` (RPMs + dependencies + `repodata/`)
- `packages/wheels/` (pip wheelhouse)

### Step B — Copy to the offline server

Copy the entire project directory **including `packages/`** to the offline server.

### Step C — Install on the offline server

```bash
sudo bash install.sh
```

---

## Operations

### Restart services

```bash
sudo systemctl restart otpweb-admin
sudo systemctl restart otpweb-qr
```

### Logs

```bash
journalctl -u otpweb-admin -f
journalctl -u otpweb-qr -f
```

---

## Troubleshooting

### `google-authenticator not installed`
- On Rocky/RHEL, `google-authenticator` is typically provided by **EPEL**.
- If you're online, ensure EPEL is reachable.
- If you're offline, re-generate the bundle via `offline_packages.sh` (it installs EPEL on the build machine to download EPEL packages).

### `CERTIFICATE_VERIFY_FAILED`
- Expected with self-signed certs.
- OTPWeb restricts TLS verification exceptions to **loopback internal calls** only.

### `Connection refused (127.0.0.1:5000)`
- QR service may be down:

```bash
systemctl status otpweb-qr
journalctl -u otpweb-qr -n 200 --no-pager
```

---

## Repository layout

- `src/` — application modules
- `templates/`, `static/` — UI assets
- `scripts/` — helper scripts (wrappers are kept at repo root for convenience)
- `systemd/` — example unit files
- `packages/` — offline bundle (not committed to Git)

---

## Publishing to GitHub (first time)

1) Initialize git and commit:

```bash
git init
git add .
git commit -m "Initial release"
```

2) Create a new repository on GitHub, then push:

```bash
git remote add origin <your-repo-url>
git branch -M main
git push -u origin main
```

Before pushing, confirm `.gitignore` excludes `install.env`, `packages/`, certs, DB, and logs.
