import os
import secrets
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

import shlex

def _load_env_file(path: str) -> None:
    """Best-effort parser for install.env-style KEY=VALUE files.

    This makes OTPWeb resilient if systemd EnvironmentFile injection is unavailable.
    Existing os.environ keys are NOT overridden.
    """
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#'):
                    continue
                # allow "export KEY=VALUE"
                if line.startswith('export '):
                    line = line[len('export '):].lstrip()
                if '=' not in line:
                    continue
                key, val = line.split('=', 1)
                key = key.strip()
                val = val.strip()
                if not key or key in os.environ:
                    continue
                # Strip surrounding quotes if present
                if (len(val) >= 2) and ((val[0] == val[-1]) and val[0] in ('"', "'")):
                    val = val[1:-1]
                # Unescape common backslash sequences (space, quotes, etc.)
                val = val.replace('\\ ', ' ')
                val = val.replace('\\"', '"').replace("\\'", "'")
                os.environ[key] = val
    except FileNotFoundError:
        return
    except Exception:
        # Never fail import due to env file parsing
        return

# Try to load env file if present (without overriding existing environment variables)
_DEFAULT_ENV_CANDIDATES = [
    os.environ.get('OTPWEB_ENV_FILE', '').strip(),
    os.path.join(os.environ.get('INSTALL_DIR', '').strip() or '', 'install.env'),
    '/otpweb/install.env',
    os.path.join(PROJECT_ROOT, 'install.env'),
]
for _p in _DEFAULT_ENV_CANDIDATES:
    if _p:
        _load_env_file(_p)

def _env(key: str, default=None):
    val = os.environ.get(key)
    return default if val is None else val

def env_str(key: str, default: str = "") -> str:
    return str(_env(key, default))

def env_int(key: str, default: int) -> int:
    val = _env(key, None)
    if val is None or str(val).strip() == "":
        return int(default)
    try:
        return int(str(val).strip())
    except Exception:
        return int(default)

def env_bool(key: str, default: bool = False) -> bool:
    val = _env(key, None)
    if val is None:
        return bool(default)
    s = str(val).strip().lower()
    if s in ("1","true","yes","y","on","enable","enabled"):
        return True
    if s in ("0","false","no","n","off","disable","disabled"):
        return False
    return bool(default)

# ---- Paths ----
ACCOUNT_DIR = env_str('OTPWEB_ACCOUNT_DIR', os.path.join(PROJECT_ROOT, 'account'))
FLASK_SECRET_FILE = os.path.join(ACCOUNT_DIR, 'flask.secret')
PASSWORD_FILE = os.path.join(ACCOUNT_DIR, 'admin.pass')
MERGE_SCRIPT  = os.path.join(PROJECT_ROOT, 'merge.sh')

# ---- Network / Ports ----
ADMIN_BIND = env_str('ADMIN_BIND', '0.0.0.0')
QR_BIND    = env_str('QR_BIND', '0.0.0.0')
ADMIN_PORT = env_int('ADMIN_PORT', 8000)
QR_PORT    = env_int('QR_PORT', 5000)

QR_ADMIN_KEY = env_str('QR_ADMIN_KEY', '').strip()  # Admin UI -> QR service auth key


def _load_or_create_secret(path: str, *, length_bytes: int = 32) -> str:
    """Load a shared secret from disk, or create it once (atomically).

    This is used for QR_ADMIN_KEY so both services share the same key even when
    the operator does not set the environment variable.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    if p.exists():
        return p.read_text(encoding='utf-8').strip()

    # Atomic create: either we create, or another process beats us and we read.
    secret = secrets.token_hex(length_bytes)
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(secret + "\n")
        return secret
    except FileExistsError:
        return p.read_text(encoding='utf-8').strip()


# If QR_ADMIN_KEY is not provided, persist a shared default.
_QR_ADMIN_KEY_PATH = '/etc/otpweb/qr_admin.key'


def get_qr_admin_key() -> str:
    """Return the shared Admin UI -> QR service auth key.

    Why a function (not just a module constant)?
    - Allows runtime reload if the operator regenerates /etc/otpweb/qr_admin.key
      but only restarts one of the two services.
    - Keeps behavior deterministic: env QR_ADMIN_KEY overrides disk.
    """
    env_val = env_str('QR_ADMIN_KEY', '').strip()
    if env_val:
        return env_val
    # Disk-backed shared default
    return _load_or_create_secret(_QR_ADMIN_KEY_PATH, length_bytes=32).strip()


if not QR_ADMIN_KEY:
    QR_ADMIN_KEY = get_qr_admin_key()

# ---- TLS ----
CERT_FILE = env_str('OTPWEB_CERT_FILE', os.path.join(PROJECT_ROOT, 'cert', 'otpweb.crt'))
KEY_FILE  = env_str('OTPWEB_KEY_FILE',  os.path.join(PROJECT_ROOT, 'cert', 'otpweb.key'))
ENABLE_HTTPS = env_bool('ENABLE_HTTPS', True)

# Admin -> QR internal base URL (defaults to loopback)
_scheme = 'https' if ENABLE_HTTPS else 'http'
QR_SERVICE_BASE = env_str('QR_SERVICE_BASE', f"{_scheme}://127.0.0.1:{QR_PORT}").strip().rstrip('/')
if QR_SERVICE_BASE.endswith('/q'):
    QR_SERVICE_BASE = QR_SERVICE_BASE[:-2]

# ---- Display name (Google Authenticator issuer/label prefix) ----
# New: OTP_DISPLAY_NAME (single source of truth)
# Back-compat: OTP_LABEL_PREFIX / OTP_ISSUER (deprecated)
OTP_DISPLAY_NAME = env_str('OTP_DISPLAY_NAME', '').strip()
if not OTP_DISPLAY_NAME:
    OTP_DISPLAY_NAME = env_str('OTP_LABEL_PREFIX', '').strip() or 'VDI'

# ---- QR public base (optional) ----
QR_PUBLIC_BASE = env_str('QR_PUBLIC_BASE', '').strip().rstrip('/')

def is_loopback_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return host in ("127.0.0.1", "localhost")
    except Exception:
        return False
