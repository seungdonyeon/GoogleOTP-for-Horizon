import os, time, uuid, socket
from typing import Optional, Dict, Any
import urllib.parse

from . import db_layer, settings, otp as otp_mod
import config as cfg

def get_user_home(user: str) -> Optional[str]:
    # Existing behavior: search /home/*/<user> then /home/<user>
    base = "/home"
    try:
        for d in os.listdir(base):
            p = os.path.join(base, d, user)
            if os.path.isfile(os.path.join(p, ".google_authenticator")):
                return p
    except Exception:
        pass
    p2 = os.path.join(base, user)
    if os.path.isfile(os.path.join(p2, ".google_authenticator")):
        return p2
    return None

def get_secret_for_user(user: str) -> Optional[str]:
    home = get_user_home(user)
    if not home:
        return None
    path = os.path.join(home, ".google_authenticator")
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                return line.split()[0]
    except Exception:
        return None
    return None

def guess_primary_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        try: s.close()
        except Exception: pass

def absolute_q_url(token: str) -> str:
    base = cfg.QR_PUBLIC_BASE or ""
    if not base:
        scheme = "https" if cfg.env_bool("ENABLE_HTTPS", True) else "http"
        host = guess_primary_ip()
        base = f"{scheme}://{host}:{cfg.QR_PORT}"
    return base.rstrip("/") + "/q/" + urllib.parse.quote(token)

def create_token(user: str, ttl_sec: Optional[int] = None, click_ttl_sec: Optional[int] = None) -> Dict[str, Any]:
    user = (user or "").strip()
    if not user:
        raise ValueError("user required")
    secret = get_secret_for_user(user)
    if not secret:
        raise FileNotFoundError("secret not found for user")
    t = str(uuid.uuid4())
    now = int(time.time())
    with db_layer.connect() as conn:
        conn.execute("UPDATE tokens SET used=1 WHERE user=? AND used=0", (user,))
        conn.execute("INSERT INTO tokens(token,user,secret,created_at,used,clicked_at) VALUES(?,?,?,?,0,NULL)", (t, user, secret, now))
    ttl = int(ttl_sec) if ttl_sec is not None else settings.get_ttl_sec()
    return {"token": t, "url": f"/q/{t}", "absolute_url": absolute_q_url(t), "expires_in_sec": None if ttl == 0 else ttl}

def get_row(token: str):
    with db_layer.connect() as conn:
        return conn.execute("SELECT * FROM tokens WHERE token=?", (token,)).fetchone()

def is_creation_expired(row) -> bool:
    ttl = settings.get_ttl_sec()
    if ttl == 0:
        return False
    return (int(time.time()) - int(row["created_at"]) > ttl)

def is_click_window_expired(row) -> bool:
    """Return True if the click-window has expired.

    Semantics:
    - click_ttl == 0 means "expire immediately AFTER the QR is shown once".
      We implement this by marking `used=1` after serving the QR image once.
      Therefore, for click_ttl==0 we do NOT treat clicked_at as immediate expiry here.
    """
    click_ttl = settings.get_click_ttl_sec()
    ca = row["clicked_at"]
    if ca is None:
        return False
    if click_ttl == 0:
        return False
    return (int(time.time()) - int(ca) > click_ttl)

def record_click(token: str) -> None:
    """Record the first click timestamp.

    NOTE: Do NOT mark used here. For click_ttl==0 (one-time view),
    we mark used AFTER successfully serving the QR image.
    """
    now = int(time.time())
    row = get_row(token)
    if not row:
        return
    if row["clicked_at"] is None:
        with db_layer.connect() as conn:
            conn.execute("UPDATE tokens SET clicked_at=? WHERE token=?", (now, token))

def mark_used(token: str) -> None:
    with db_layer.connect() as conn:
        conn.execute("UPDATE tokens SET used=1 WHERE token=?", (token,))

def purge() -> None:
    now = int(time.time())
    ttl = settings.get_ttl_sec()
    click_ttl = settings.get_click_ttl_sec()
    with db_layer.connect() as conn:
        conn.execute("DELETE FROM tokens WHERE used=1")
        if ttl > 0:
            conn.execute("DELETE FROM tokens WHERE (? - created_at) > ?", (now, ttl))
        if click_ttl >= 0:
            conn.execute("DELETE FROM tokens WHERE clicked_at IS NOT NULL AND (? - clicked_at) > ?", (now, max(0, click_ttl)))
