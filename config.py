import os
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
