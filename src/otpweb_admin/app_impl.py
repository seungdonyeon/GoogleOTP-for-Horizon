import hashlib
import json
import os
import re
import secrets
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

import config as cfg

from . import qr_client, auth as auth_mod, domain as domain_mod, ttl as ttl_mod
PROJECT_ROOT = cfg.PROJECT_ROOT

# Small in-process caches for displaying current TTL values after updates.
# These are best-effort only; the source of truth remains the QR service.
_QR_TTL_CACHE = {"val": None, "ts": 0.0}
_QR_CLICK_TTL_CACHE = {"val": None, "ts": 0.0}


# ---- Paths (must be defined before load_flask_secret/app.secret_key) ----
ACCOUNT_DIR = cfg.ACCOUNT_DIR
FLASK_SECRET_FILE = cfg.FLASK_SECRET_FILE
PASSWORD_FILE = cfg.PASSWORD_FILE
MERGE_SCRIPT  = cfg.MERGE_SCRIPT
BASE_DIR      = PROJECT_ROOT


app = Flask(
    __name__,
    static_folder=os.path.join(PROJECT_ROOT, 'static'),
    template_folder=os.path.join(PROJECT_ROOT, 'templates'),
    static_url_path='/static'
)
def load_flask_secret():
    os.makedirs(ACCOUNT_DIR, exist_ok=True)
    if not os.path.exists(FLASK_SECRET_FILE):
        with open(FLASK_SECRET_FILE, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(FLASK_SECRET_FILE, 'r') as f:
        return f.read().strip()

app.secret_key = load_flask_secret()  # file-backed (persists across reboots)

SESSION_TIMEOUT = 1800

ADMIN_USERNAME = auth_mod.ADMIN_USERNAME
DEFAULT_PASSWORD_HASH = None  # Initialized in load_admin_password_hash()

# QR service base URL (used by the Admin UI to query TTL settings and to build QR links)
CERT_FILE = os.environ.get("OTPWEB_CERT_FILE", "/etc/otpweb/certs/otpweb.crt")
KEY_FILE  = os.environ.get("OTPWEB_KEY_FILE",  "/etc/otpweb/certs/otpweb.key")

def _https_enabled() -> bool:
    v = os.environ.get("ENABLE_HTTPS", "").strip().lower()
    if v in ("1","true","yes","on"):
        return True
    if v in ("0","false","no","off"):
        return False
    # Auto-detect: if cert/key exist, assume HTTPS (works for offline installs too)
    try:
        return os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)
    except Exception:
        return False

ENABLE_HTTPS = cfg.ENABLE_HTTPS

QR_BASE = cfg.QR_SERVICE_BASE

# If HTTPS is enabled with a self-signed cert, the Admin UI often needs to call
# the local QR service over HTTPS. Allow opting out of cert verification for
# internal calls (loopback) via ALLOW_SELF_SIGNED_TLS = cfg.env_bool('ALLOW_SELF_SIGNED_TLS', False)  # deprecated: loopback is always allowed
ALLOW_SELF_SIGNED_TLS = os.environ.get('ALLOW_SELF_SIGNED_TLS', '0').strip().lower() in ('1','true','yes','y')

def _ssl_context_for_url(url: str):
    """Return SSLContext override for urllib calls.

    Security policy:
    - Only loopback (127.0.0.1/localhost) may bypass certificate verification.
    - Non-loopback targets MUST use normal certificate verification.
    """
    try:
        if not str(url).lower().startswith("https://"):
            return None
        if cfg.is_loopback_url(str(url)):
            return ssl._create_unverified_context()
    except Exception:
        return None
    return None


QR_BASE = QR_BASE.strip().rstrip('/')
if QR_BASE.endswith('/q'):
    QR_BASE = QR_BASE[:-2]

TTL_OPTIONS = ttl_mod.TTL_OPTIONS
CLICK_TTL_OPTIONS = ttl_mod.CLICK_TTL_OPTIONS
def http_post_form(url: str, data: dict, timeout: int = 5) -> bytes:
    """POST form data. If URL is loopback HTTP but service is HTTPS, retry via HTTPS."""
    body = urllib.parse.urlencode(data).encode('utf-8')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # Protect admin-only QR service endpoints.
    if getattr(cfg, 'QR_ADMIN_KEY', '').strip():
        headers['X-OTPWEB-ADMIN-KEY'] = cfg.QR_ADMIN_KEY.strip()
    req = urllib.request.Request(url, data=body, headers=headers, method='POST')
    def _do(u: str) -> bytes:
        r = urllib.request.Request(u, data=body, headers=headers, method='POST')
        ctx = _ssl_context_for_url(u)
        with urllib.request.urlopen(r, timeout=timeout, context=ctx) as resp:
            return resp.read()
    try:
        return _do(url)
    except Exception as e:
        # Typical symptom when we POST http://127.0.0.1 to a HTTPS gunicorn: reset/HTTP_REQUEST
        if url.startswith('http://') and ('127.0.0.1' in url or 'localhost' in url):
            https_url = 'https://' + url[len('http://'): ]
            return _do(https_url)
        raise

def http_get_json(url: str, timeout: int = 5) -> dict:
    ctx = _ssl_context_for_url(url)
    headers = {}
    if getattr(cfg, 'QR_ADMIN_KEY', '').strip():
        headers['X-OTPWEB-ADMIN-KEY'] = cfg.QR_ADMIN_KEY.strip()
    req = urllib.request.Request(url, headers=headers, method='GET')
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode('utf-8'))

@app.before_request
def check_session_timeout():
    session.permanent = True
    now = time.time()
    if 'last_activity' in session and now - session['last_activity'] > SESSION_TIMEOUT:
        session.clear()
    session['last_activity'] = now

def _is_legacy_sha256_hash(s: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", (s or "").strip()))

def _hash_password(plain: str) -> str:
    # PBKDF2 (salted + iterated). No extra dependency required.
    return generate_password_hash(plain, method='pbkdf2:sha256', salt_length=16)

def _verify_password(stored_hash: str, plain: str) -> bool:
    stored_hash = (stored_hash or '').strip()
    if not stored_hash:
        return False
    # Legacy support: old installs stored SHA256 hexdigest
    if _is_legacy_sha256_hash(stored_hash):
        return hashlib.sha256(plain.encode('utf-8')).hexdigest() == stored_hash
    try:
        return check_password_hash(stored_hash, plain)
    except Exception:
        return False

def load_admin_password_hash():
    """Load or initialize the admin UI password hash.

    Priority:
    1) If account/admin.pass exists, use it.
    2) Else initialize with default password 'admin' (PBKDF2).
    """
    os.makedirs(ACCOUNT_DIR, exist_ok=True)
    if not os.path.exists(PASSWORD_FILE):
        default_hash = _hash_password('admin')
        with open(PASSWORD_FILE, 'w', encoding='utf-8') as f:
            f.write(default_hash)
        os.chmod(PASSWORD_FILE, 0o600)
    with open(PASSWORD_FILE, 'r', encoding='utf-8') as f:
        return f.read().strip()

ADMIN_PASSWORD_HASH = load_admin_password_hash()

def get_joined_domain() -> str:
    return domain_mod.get_joined_domain()

def ttl_label(sec: int) -> str:
    return ttl_mod.ttl_label(int(sec))

def click_ttl_label(sec: int) -> str:
    return ttl_mod.click_ttl_label(int(sec))

def qr_get_ttl_safe() -> int:
    try:
        return int(qr_client.qr_get_ttl())
    except Exception:
        return 3600

def qr_get_click_ttl_safe() -> int:
    try:
        return int(qr_client.qr_get_click_ttl())
    except Exception:
        return 0

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user' not in session:
        return redirect('/login')

    domain = get_joined_domain()
    result = ""

    current_ttl_val = qr_get_ttl_safe()
    current_ttl_label = ttl_label(current_ttl_val)

    current_click_ttl_val = qr_get_click_ttl_safe()
    current_click_ttl_label = click_ttl_label(current_click_ttl_val)

    if request.method == 'POST':
        action = request.form.get('action')
        uid    = request.form.get('uid', '').strip()

        if action in ['add', 'delete', 'change', 'qr_link'] and not uid:
            result = "The ID input is empty. Please enter a valid ID."
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        if action == 'extract_users':
            if domain in ["No domain", "Failed to read domain"]:
                result = f"[ERROR] Unable to load domain information: {domain}"
            else:
                domain_dir = os.path.join(BASE_DIR, domain)
                os.makedirs(domain_dir, exist_ok=True)
                target_file = os.path.join(domain_dir, 'user_list.txt')
                try:
                    output = subprocess.check_output(['wbinfo', '-u'], text=True)
                    filtered = [u for u in output.strip().splitlines()
                                if u and not u.endswith('$') and u.lower() not in ['krbtgt','guest','administrator']]
                    with open(target_file, 'w') as f:
                        f.write('\n'.join(filtered))
                    result = '\n'.join(filtered)
                except subprocess.CalledProcessError as e:
                    result = f"[ERROR] Failed to export user list:\n{e}"
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        if action == 'check_missing_otp':
            domain_dir = os.path.join(BASE_DIR, domain)
            user_list_path = os.path.join(domain_dir, 'user_list.txt')
            no_otp_list_path = os.path.join(domain_dir, 'no_otp_user_list.txt')
            if not os.path.exists(user_list_path):
                result = f"[ERROR] '{user_list_path}' file not found. Please run 'Export AD user list' first."
                return render_template('index.html', result=result, user=session['user'], domain=domain,
                                       ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                       click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)
            with open(user_list_path, 'r') as f:
                ad_users = set(line.strip() for line in f if line.strip())
            proc = subprocess.run([MERGE_SCRIPT, '-l'], capture_output=True, text=True)
            otp_users = set(line.split()[0] for line in proc.stdout.strip().splitlines()
                            if line.strip() and len(line.split()) >= 1 and not line.startswith("List of generated IDs"))
            missing = sorted(ad_users - otp_users)

            os.makedirs(domain_dir, exist_ok=True)
            with open(no_otp_list_path, 'w') as f:
                f.write("\n".join(missing))

            formatted = ""
            for user_id in sorted(ad_users):
                formatted += f">>{user_id}<<\n" if user_id in missing else f"{user_id}\n"
            return render_template('index.html', result=formatted, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        if action == 'generate_missing_otp':
            domain_dir = os.path.join(BASE_DIR, domain)
            no_otp_list_path = os.path.join(domain_dir, 'no_otp_user_list.txt')
            if not os.path.exists(no_otp_list_path):
                result = f"[ERROR] '{no_otp_list_path}' file not found. Please run 'Find accounts without OTP' first."
                return render_template('index.html', result=result, user=session['user'], domain=domain,
                                       ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                       click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)
            with open(no_otp_list_path, 'r') as f:
                missing_users = [line.strip() for line in f if line.strip()]
            output_log = ""
            for u in missing_users:
                try:
                    proc = subprocess.run([MERGE_SCRIPT, '-a', u], capture_output=True, text=True)
                    output_log += proc.stdout
                    if proc.stderr:
                        output_log += f"\n[stderr for {u}]\n{proc.stderr}"
                except Exception as e:
                    output_log += f"\n[ERROR] {u} failed to create account: {e}\n"
            result = output_log or "[OK] No accounts without OTP."
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        if action == 'set_ttl':
            sel = request.form.get('ttl', '')
            try:
                body = http_post_form(f"{QR_BASE}/set-ttl", {'ttl_sec': sel}, timeout=1)
                current_ttl_val = int(json.loads(body)['ttl_sec'])
                current_ttl_label = ttl_label(current_ttl_val)
                global _QR_TTL_CACHE
                _QR_TTL_CACHE.update({"val": current_ttl_val, "ts": time.time()})
                result = f"QR link TTL updated to {current_ttl_label} ."
            except Exception as e:
                result = f"[ERROR] Failed to update TTL: {e}"
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        if action == 'set_click_ttl':
            sel = request.form.get('click_ttl', '')
            try:
                body = http_post_form(f"{QR_BASE}/set-click-ttl", {'click_ttl_sec': sel}, timeout=1)
                current_click_ttl_val = int(json.loads(body)['click_ttl_sec'])
                current_click_ttl_label = click_ttl_label(current_click_ttl_val)
                global _QR_CLICK_TTL_CACHE
                _QR_CLICK_TTL_CACHE.update({"val": current_click_ttl_val, "ts": time.time()})
                result = f"Click-TTL updated to {current_click_ttl_label} ."
            except Exception as e:
                result = f"[ERROR] Failed to update click-TTL: {e}"
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        if action == 'qr_link':
            try:
                body = http_post_form(f"{QR_BASE}/token", {'user': uid}, timeout=1)
                j = json.loads(body)
                link = j.get('absolute_url') or j.get('url')
                result = (
                    f"[{uid}] Secret key generated.\n"
                    f"One-time QR link: {link}\n"
                    f"(Note: valid for {current_click_ttl_label} after clicking, depending on policy)"
                )
            except Exception as e:
                result = f"[ERROR] Failed to create QR link: {e}"
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        cmd = [MERGE_SCRIPT]
        if action == 'list':
            cmd.append('-l')
        elif action == 'add':
            cmd += ['-a', uid]
        elif action == 'delete':
            cmd += ['-d', uid, '-f']
        elif action == 'change':
            cmd += ['-c', uid, '-f']
        else:
            result = "Unknown action."
            return render_template('index.html', result=result, user=session['user'], domain=domain,
                                   ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                                   click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

        proc = subprocess.run(cmd, capture_output=True, text=True)
        result = proc.stdout + proc.stderr

    return render_template('index.html', result=result, user=session['user'], domain=domain,
                           ttl_options=TTL_OPTIONS, current_ttl_val=current_ttl_val, current_ttl_label=current_ttl_label,
                           click_ttl_options=CLICK_TTL_OPTIONS, current_click_ttl_val=current_click_ttl_val, current_click_ttl_label=current_click_ttl_label)

@app.route('/login', methods=['GET', 'POST'])
def login():
    global ADMIN_PASSWORD_HASH
    if request.method == 'POST':
        user = request.form['username']
        pw   = request.form['password']
        if user == ADMIN_USERNAME and _verify_password(ADMIN_PASSWORD_HASH, pw):
            # Upgrade legacy SHA256 hash to PBKDF2 after successful login
            if _is_legacy_sha256_hash(ADMIN_PASSWORD_HASH):
                new_hash = _hash_password(pw)
                with open(PASSWORD_FILE, 'w', encoding='utf-8') as f:
                    f.write(new_hash)
                ADMIN_PASSWORD_HASH = new_hash
            session['user'] = user
            return redirect('/')
        else:
            return "Login Failed", 401
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    global ADMIN_PASSWORD_HASH
    if 'user' not in session:
        return redirect('/login')
    message = ''
    if request.method == 'POST':
        current = request.form['current']
        new     = request.form['new']
        confirm = request.form['confirm']
        if not _verify_password(ADMIN_PASSWORD_HASH, current):
            message = 'Current password is incorrect.'
        elif new != confirm:
            message = 'New passwords do not match.'
        else:
            new_hash = _hash_password(new)
            os.makedirs(ACCOUNT_DIR, exist_ok=True)
            with open(PASSWORD_FILE, 'w') as f:
                f.write(new_hash)
            ADMIN_PASSWORD_HASH = new_hash
            message = 'Password updated.'
    return render_template('change_password.html', message=message)

if __name__ == '__main__':
    app.run(host=os.environ.get('ADMIN_BIND','0.0.0.0'), port=int(os.environ.get('ADMIN_PORT','8000')), threaded=True)