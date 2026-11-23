"""Umgebungsvariablen und im Dashboard änderbare Einstellungen."""
import json
import logging
import os
import secrets

log = logging.getLogger("config")

DATA_DIR = os.environ.get("DATA_DIR", "/data")
PROXY_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "8080"))
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8000"))
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", "")


def _persisted_secret(env_name: str, filename: str, nbytes: int) -> str:
    val = os.environ.get(env_name)
    if val:
        return val
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    val = secrets.token_urlsafe(nbytes)
    with open(path, "w") as f:
        f.write(val)
    os.chmod(path, 0o600)
    return val


def load_secrets():
    os.makedirs(DATA_DIR, exist_ok=True)
    secret_key = _persisted_secret("SECRET_KEY", "secret.key", 32)
    generated = not os.environ.get("DASHBOARD_PASSWORD") and not os.path.exists(
        os.path.join(DATA_DIR, "dashboard_password.txt"))
    dash_pw = _persisted_secret("DASHBOARD_PASSWORD", "dashboard_password.txt", 12)
    if generated:
        log.warning("Kein DASHBOARD_PASSWORD gesetzt. Generiertes Passwort: %s "
                    "(gespeichert in %s/dashboard_password.txt)", dash_pw, DATA_DIR)
    return secret_key, dash_pw


ROTATION_MODES = ("request", "time", "sticky")
ANONYMITY_LEVELS = ("transparent", "anonymous", "elite")
PROTOCOLS = ("http", "socks4", "socks5")

DEFAULTS = {
    # Rotation
    "rotation_mode": "request",        # request | time | sticky
    "rotation_interval_s": 60,         # für "time"
    "sticky_ttl_s": 600,               # für "sticky"
    "max_retries": 3,                  # weitere Proxys bei Fehlern
    "connect_timeout_s": 10,
    "response_timeout_s": 25,
    # Filter für die Rotation (Standard, pro Anfrage überschreibbar)
    "default_countries": [],           # leer = alle
    "exclude_countries": [],
    "min_anonymity": "anonymous",
    "max_latency_ms": 0,               # 0 = egal
    "allowed_protocols": ["http", "socks4", "socks5"],
    # Hintergrundjobs
    "scrape_interval_min": 30,
    "recheck_interval_min": 15,
    "check_concurrency": 150,
    "check_timeout_s": 10,
    "dead_after_fails": 3,
    "purge_dead_after_h": 12,
    # IP-Checker
    "judges": [
        {"url": "http://httpbin.org/get", "type": "httpbin"},
        {"url": "http://azenv.net/", "type": "azenv"},
    ],
    "https_test_url": "https://httpbin.org/get",
}


def _countries(v):
    if isinstance(v, str):
        v = [x for x in v.replace(";", ",").replace(" ", ",").split(",")]
    out = []
    for c in v or []:
        c = str(c).strip().upper()
        if len(c) == 2 and c.isalpha() and c not in out:
            out.append(c)
    return out


class Settings:
    def __init__(self, db):
        self.db = db
        self._v = dict(DEFAULTS)
        for row in db.q("SELECT key, value FROM settings"):
            if row["key"] in DEFAULTS:
                try:
                    self._v[row["key"]] = json.loads(row["value"])
                except ValueError:
                    pass

    def __getattr__(self, name):
        v = self.__dict__.get("_v")
        if v is not None and name in v:
            return v[name]
        raise AttributeError(name)

    def all(self):
        return dict(self._v)

    def update(self, data: dict):
        errors = {}
        new = {}
        for k, v in data.items():
            if k not in DEFAULTS:
                continue
            d = DEFAULTS[k]
            try:
                if k == "rotation_mode":
                    if v not in ROTATION_MODES:
                        raise ValueError("ungültig")
                elif k == "min_anonymity":
                    if v not in ANONYMITY_LEVELS:
                        raise ValueError("ungültig")
                elif k in ("default_countries", "exclude_countries"):
                    v = _countries(v)
                elif k == "allowed_protocols":
                    v = [p for p in v if p in PROTOCOLS]
                    if not v:
                        raise ValueError("mindestens ein Protokoll")
                elif k == "judges":
                    js = []
                    for j in v:
                        if j.get("type") not in ("httpbin", "azenv", "ip"):
                            raise ValueError(f"Typ unbekannt: {j.get('type')}")
                        if not str(j.get("url", "")).startswith("http://"):
                            raise ValueError("Judge-URLs müssen http:// sein (sonst sind Header nicht sichtbar)")
                        js.append({"url": j["url"], "type": j["type"]})
                    if not js:
                        raise ValueError("mindestens ein Judge")
                    v = js
                elif isinstance(d, bool):
                    v = bool(v)
                elif isinstance(d, int):
                    v = int(v)
                    if v < 0:
                        raise ValueError("muss >= 0 sein")
                elif isinstance(d, float):
                    v = float(v)
                elif isinstance(d, str):
                    v = str(v)
                new[k] = v
            except (ValueError, TypeError, AttributeError) as e:
                errors[k] = str(e)
        if errors:
            return errors
        for k, v in new.items():
            self._v[k] = v
            self.db.x("INSERT INTO settings(key,value) VALUES(?,?) "
                      "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, json.dumps(v)))
        return {}
