import sqlite3
import os
import config as cfg

DB_PATH = os.path.join(cfg.PROJECT_ROOT, 'qr.db')

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
    except Exception:
        pass
    return conn

def init_db(default_ttl_sec: int, default_click_ttl_sec: int) -> None:
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tokens(
                token TEXT PRIMARY KEY,
                user  TEXT NOT NULL,
                secret TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                used  INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        # Add clicked_at column (if missing)
        try:
            conn.execute("ALTER TABLE tokens ADD COLUMN clicked_at INTEGER;")
        except Exception:
            pass

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_user_used ON tokens(user, used);")

        row = conn.execute("SELECT value FROM settings WHERE key='ttl_sec'").fetchone()
        if not row:
            conn.execute("INSERT INTO settings(key,value) VALUES('ttl_sec', ?)", (str(default_ttl_sec),))

        row2 = conn.execute("SELECT value FROM settings WHERE key='click_ttl_sec'").fetchone()
        if not row2:
            conn.execute("INSERT INTO settings(key,value) VALUES('click_ttl_sec', ?)", (str(default_click_ttl_sec),))
