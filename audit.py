import sqlite3, os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "vault", "audit.db")

def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action    TEXT NOT NULL,
                filename  TEXT,
                algorithm TEXT,
                status    TEXT NOT NULL,
                details   TEXT
            )
        """)
        conn.commit()

def log(action, filename=None, algorithm=None, status="success", details=None):
    with _connect() as conn:
        conn.execute(
            "INSERT INTO audit_log (timestamp,action,filename,algorithm,status,details) VALUES (?,?,?,?,?,?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), action, filename, algorithm, status, details)
        )
        conn.commit()

def get_logs(limit=300):
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]

def clear_logs():
    with _connect() as conn:
        conn.execute("DELETE FROM audit_log")
        conn.commit()
