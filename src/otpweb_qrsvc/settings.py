from . import db_layer

DEFAULT_TTL_SEC = 3600
DEFAULT_CLICK_TTL_SEC = 0

def get_ttl_sec() -> int:
    with db_layer.connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='ttl_sec'").fetchone()
    return int(row["value"]) if row else DEFAULT_TTL_SEC

def _set_key(key: str, value: str) -> None:
    # Works even if older DB schema lacks UNIQUE constraints (best-effort UPDATE then INSERT).
    with db_layer.connect() as conn:
        cur = conn.execute("UPDATE settings SET value=? WHERE key=?", (value, key))
        if getattr(cur, "rowcount", 0) == 0:
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?)", (key, value))

def set_ttl_sec(ttl_sec: int) -> None:
    _set_key("ttl_sec", str(int(ttl_sec)))

def get_click_ttl_sec() -> int:
    with db_layer.connect() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key='click_ttl_sec'").fetchone()
    return int(row["value"]) if row else DEFAULT_CLICK_TTL_SEC

def set_click_ttl_sec(click_ttl_sec: int) -> None:
    _set_key("click_ttl_sec", str(int(click_ttl_sec)))
