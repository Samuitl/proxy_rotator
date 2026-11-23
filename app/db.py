"""SQLite-Zugriff (stdlib, thread-sicher über ein Lock)."""
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS proxies(
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,              -- http | socks4 | socks5
    source TEXT,
    first_seen REAL,
    last_seen REAL,
    status TEXT NOT NULL DEFAULT 'new',  -- new | alive | dead
    anonymity TEXT,                      -- transparent | anonymous | elite
    exit_ip TEXT,
    country_code TEXT,
    country TEXT,
    latency_ms REAL,
    https INTEGER DEFAULT 0,
    last_checked REAL DEFAULT 0,
    last_ok REAL,
    check_fails INTEGER DEFAULT 0,
    checks_ok INTEGER DEFAULT 0,
    checks_total INTEGER DEFAULT 0,
    req_ok INTEGER DEFAULT 0,
    req_fail INTEGER DEFAULT 0,
    UNIQUE(host, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status, last_checked);
CREATE INDEX IF NOT EXISTS idx_proxies_exit ON proxies(exit_ip);

CREATE TABLE IF NOT EXISTS sources(
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,
    protocol TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    last_fetch REAL,
    last_count INTEGER,
    last_error TEXT
);

CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS geo(
    ip TEXT PRIMARY KEY,
    country_code TEXT,
    country TEXT,
    ts REAL
);
"""


class DB:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.executescript(SCHEMA)
            cols = {r[1] for r in self.conn.execute("PRAGMA table_info(sources)")}
            if "decode" not in cols:
                self.conn.execute("ALTER TABLE sources ADD COLUMN decode INTEGER DEFAULT 0")
            if "max_pages" not in cols:
                self.conn.execute("ALTER TABLE sources ADD COLUMN max_pages INTEGER DEFAULT 1")

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        with self.lock:
            r = self.conn.execute(sql, args).fetchone()
            return dict(r) if r else None

    def scalar(self, sql, args=()):
        with self.lock:
            r = self.conn.execute(sql, args).fetchone()
            return r[0] if r else None

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            return cur.rowcount, cur.lastrowid

    def many(self, sql, seq):
        seq = list(seq)
        if not seq:
            return
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.executemany(sql, seq)
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
