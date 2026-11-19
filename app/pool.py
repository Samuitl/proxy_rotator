"""Pool der geprüften Proxys und Rotationslogik."""
import random
import time
from dataclasses import dataclass, field

ANON_RANK = {"transparent": 0, "anonymous": 1, "elite": 2}


@dataclass
class Proxy:
    id: int
    host: str
    port: int
    protocol: str
    anonymity: str
    country_code: str
    latency_ms: float
    https: int
    exit_ip: str
    fails: int = 0          # aufeinanderfolgende Fehler im echten Traffic

    @property
    def label(self):
        return f"{self.protocol}://{self.host}:{self.port}"


@dataclass
class Opts:
    """Pro-Anfrage-Optionen (aus Proxy-Benutzername oder X-Proxy-* Headern)."""
    countries: list | None = None    # None = Standard aus Einstellungen, [] = alle
    min_anon: str | None = None
    rotate: str | None = None
    session: str | None = None
    protocols: list | None = None


@dataclass
class _Pin:
    pid: int
    ts: float
    last: float = field(default=0.0)


def parse_opts(username: str | None, headers: dict) -> Opts:
    o = Opts()

    def apply(k, v):
        k, v = k.lower(), v.strip()
        if not v:
            return
        if k == "country":
            if v.lower() in ("any", "all", "alle"):
                o.countries = []
            else:
                o.countries = [c.upper() for c in v.replace(",", "_").replace("+", "_").split("_")
                               if len(c) == 2 and c.isalpha()]
        elif k in ("anon", "anonymity"):
            if v.lower() in ANON_RANK:
                o.min_anon = v.lower()
        elif k in ("rotate", "rotation"):
            v = {"req": "request", "zeit": "time"}.get(v.lower(), v.lower())
            if v in ("request", "time", "sticky"):
                o.rotate = v
        elif k == "session":
            o.session = v[:64]
            if o.rotate is None:
                o.rotate = "sticky"
        elif k in ("proto", "protocol"):
            ps = [x for x in v.lower().replace(",", "_").split("_") if x in ("http", "socks4", "socks5")]
            if ps:
                o.protocols = ps

    keys = {"country", "anon", "anonymity", "rotate", "rotation", "session", "proto", "protocol"}
    tokens = (username or "").split("-")
    i = 0
    while i < len(tokens):
        if tokens[i].lower() in keys and i + 1 < len(tokens):
            apply(tokens[i], tokens[i + 1])
            i += 2
        else:
            i += 1
    for hk, ok in (("x-proxy-country", "country"), ("x-proxy-anon", "anon"),
                   ("x-proxy-rotate", "rotate"), ("x-proxy-session", "session"),
                   ("x-proxy-protocol", "proto")):
        if hk in headers:
            apply(ok, headers[hk])
    return o


class Pool:
    def __init__(self, db, settings):
        self.db = db
        self.s = settings
        self.items: dict[int, Proxy] = {}
        self._time_pins: dict = {}
        self._sticky: dict = {}
        self._last: dict = {}

    def reload(self):
        rows = self.db.q("SELECT id,host,port,protocol,anonymity,country_code,latency_ms,https,exit_ip "
                         "FROM proxies WHERE status='alive'")
        old = self.items
        new = {}
        for r in rows:
            p = Proxy(**{k: r[k] for k in ("id", "host", "port", "protocol", "anonymity",
                                            "country_code", "latency_ms", "https", "exit_ip")})
            p.latency_ms = p.latency_ms or 3000
            p.anonymity = p.anonymity or "transparent"
            p.country_code = p.country_code or "ZZ"
            if r["id"] in old:
                p.fails = old[r["id"]].fails
            new[p.id] = p
        self.items = new
        now = time.time()
        ttl = max(self.s.sticky_ttl_s, 60)
        self._sticky = {k: v for k, v in self._sticky.items() if now - v.last < ttl}

    def _filter(self, o: Opts, tunnel: bool):
        s = self.s
        min_rank = ANON_RANK[o.min_anon or s.min_anonymity]
        countries = set(o.countries if o.countries is not None else s.default_countries)
        excl = set(s.exclude_countries) if o.countries is None else set()
        protos = set(o.protocols or s.allowed_protocols)
        maxlat = s.max_latency_ms

        def ok(p: Proxy):
            if ANON_RANK.get(p.anonymity, 0) < min_rank:
                return False
            if countries and p.country_code not in countries:
                return False
            if p.country_code in excl:
                return False
            if p.protocol not in protos:
                return False
            if tunnel and not p.https:
                return False
            if maxlat and p.latency_ms > maxlat:
                return False
            return True

        key = (tuple(sorted(countries)), tuple(sorted(excl)), min_rank, tuple(sorted(protos)), tunnel)
        return ok, key

    @staticmethod
    def _weighted(cands, avoid=None):
        if avoid is not None and len(cands) > 1:
            cands = [p for p in cands if p.id != avoid] or cands
        weights = [1.0 / ((p.latency_ms or 3000) + 300) / (1 + p.fails) for p in cands]
        return random.choices(cands, weights=weights, k=1)[0]

    def count(self, o: Opts, tunnel: bool):
        ok, _ = self._filter(o, tunnel)
        return sum(1 for p in self.items.values() if ok(p))

    def select(self, o: Opts, client_ip: str, tunnel: bool, exclude: set):
        ok, fkey = self._filter(o, tunnel)

        def valid(pid):
            p = self.items.get(pid)
            return p if p and pid not in exclude and ok(p) else None

        mode = o.rotate or self.s.rotation_mode
        now = time.time()
        if mode == "time":
            pin = self._time_pins.get(fkey)
            if pin and now - pin.ts < self.s.rotation_interval_s and (p := valid(pin.pid)):
                return p
        elif mode == "sticky":
            skey = (o.session or client_ip, fkey)
            pin = self._sticky.get(skey)
            if pin and now - pin.last < self.s.sticky_ttl_s and (p := valid(pin.pid)):
                pin.last = now
                return p

        cands = [p for p in self.items.values() if p.id not in exclude and ok(p)]
        if not cands:
            return None
        p = self._weighted(cands, avoid=self._last.get(fkey))
        self._last[fkey] = p.id
        if mode == "time":
            self._time_pins[fkey] = _Pin(p.id, now)
        elif mode == "sticky":
            self._sticky[(o.session or client_ip, fkey)] = _Pin(p.id, now, now)
        return p

    def report(self, p: Proxy, ok: bool):
        if ok:
            p.fails = 0
            self.db.x("UPDATE proxies SET req_ok=req_ok+1 WHERE id=?", (p.id,))
            return
        p.fails += 1
        self.db.x("UPDATE proxies SET req_fail=req_fail+1 WHERE id=?", (p.id,))
        if p.fails >= max(1, self.s.dead_after_fails):
            self.db.x("UPDATE proxies SET status='dead', check_fails=check_fails+1 WHERE id=?", (p.id,))
            self.items.pop(p.id, None)

    def stats(self):
        return {"active": len(self.items), "sticky_sessions": len(self._sticky)}
