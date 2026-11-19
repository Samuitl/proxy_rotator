"""Prüft Proxys auf Erreichbarkeit, Anonymität, HTTPS-Fähigkeit und Latenz."""
import asyncio
import ipaddress
import json
import logging
import random
import time
import urllib.request

from .pool import Proxy
from .upstream import http_get_via

log = logging.getLogger("checker")

REVEALING = {"x-forwarded-for", "via", "forwarded", "x-real-ip", "proxy-connection", "x-proxy-id",
             "client-ip", "x-client-ip", "x-forwarded-host", "x-originating-ip", "x-proxy-connection",
             "x-forwarded-proto", "x-forwarded-server", "x-bluecoat-via", "proxy-agent"}
REAL_IP_URLS = ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip",
                "https://checkip.amazonaws.com"]


def _valid_ip(s):
    try:
        return str(ipaddress.ip_address(s.strip()))
    except ValueError:
        return None


def classify(jtype: str, body: bytes, real_ip: str | None):
    """Gibt (anonymity, exit_ip) zurück oder (None, None) wenn die Antwort unbrauchbar ist."""
    text = body.decode("utf-8", "replace")
    origin, hdrs = [], set()
    if jtype == "httpbin":
        try:
            d = json.loads(text)
        except ValueError:
            return None, None
        origin = [x.strip() for x in str(d.get("origin", "")).split(",") if x.strip()]
        hdrs = {k.lower() for k in (d.get("headers") or {})}
    elif jtype == "azenv":
        env = {}
        for ln in text.splitlines():
            if " = " in ln:
                k, v = ln.split(" = ", 1)
                env[k.strip().upper()] = v.strip()
        if "REMOTE_ADDR" not in env:
            return None, None
        origin = [x.strip() for x in env.get("HTTP_X_FORWARDED_FOR", "").split(",") if x.strip()]
        origin.append(env["REMOTE_ADDR"])
        hdrs = {k[5:].lower().replace("_", "-") for k in env if k.startswith("HTTP_")}
    elif jtype == "ip":
        origin = [text.strip()]
    origin = [ip for ip in (_valid_ip(o) for o in origin) if ip]
    if not origin:
        return None, None
    exit_ip = origin[-1]
    if real_ip and real_ip in text:
        return "transparent", exit_ip
    if hdrs & REVEALING or len(set(origin)) > 1:
        return "anonymous", exit_ip
    return "elite", exit_ip


class Checker:
    def __init__(self, db, settings, pool, geo):
        self.db = db
        self.s = settings
        self.pool = pool
        self.geo = geo
        self.real_ip = None
        self.real_ip_ts = 0
        self.wake = asyncio.Event()
        self.status = {"running": False, "batch": 0, "done": 0, "alive_found": 0,
                       "last_batch_end": None, "checked_total": 0}

    def _fetch_real_ip(self):
        for url in REAL_IP_URLS:
            try:
                with urllib.request.urlopen(url, timeout=10) as r:
                    ip = _valid_ip(r.read().decode())
                    if ip:
                        return ip
            except Exception:  # noqa: BLE001
                continue
        return None

    async def refresh_real_ip(self, force=False):
        max_age = 3600 if self.real_ip else 300
        if force or time.time() - self.real_ip_ts > max_age:
            self.real_ip_ts = time.time()
            ip = await asyncio.to_thread(self._fetch_real_ip)
            if ip:
                if ip != self.real_ip:
                    log.info("Eigene öffentliche IP: %s", ip)
                self.real_ip = ip
            elif not self.real_ip:
                log.warning("Eigene IP nicht ermittelbar – transparente Proxys werden nur über Header erkannt")

    async def check(self, row: dict) -> dict:
        p = Proxy(row["id"], row["host"], row["port"], row["protocol"], "", "", 0, 0, "")
        timeout = self.s.check_timeout_s
        judge = random.choice(self.s.judges)
        t0 = time.monotonic()
        res = {"id": row["id"], "ok": False}
        try:
            status, _, body = await http_get_via(p, judge["url"], timeout)
        except (Exception, asyncio.TimeoutError) as e:  # noqa: BLE001
            res["error"] = type(e).__name__
            return res
        latency = (time.monotonic() - t0) * 1000
        if status != 200:
            res["error"] = f"HTTP {status}"
            return res
        anon, exit_ip = classify(judge["type"], body, self.real_ip)
        if not anon:
            res["error"] = "Antwort unbrauchbar"
            return res
        https = 0
        try:
            st, _, _ = await http_get_via(p, self.s.https_test_url, timeout)
            https = 1 if st == 200 else 0
        except (Exception, asyncio.TimeoutError):  # noqa: BLE001
            pass
        res.update(ok=True, anonymity=anon, exit_ip=exit_ip, latency_ms=round(latency, 1), https=https)
        return res

    def store(self, results, rows_by_id):
        now = time.time()
        ok_rows, fail_rows = [], []
        for r in results:
            if r["ok"]:
                old = rows_by_id[r["id"]]
                keep_geo = old.get("exit_ip") == r["exit_ip"]
                kg = 1 if keep_geo else 0
                ok_rows.append((r["anonymity"], r["exit_ip"], r["latency_ms"], r["https"], now, now,
                                kg, kg, r["id"]))
            else:
                fail_rows.append((now, max(1, self.s.dead_after_fails), r["id"]))
        self.db.many(
            "UPDATE proxies SET status='alive', anonymity=?, exit_ip=?, latency_ms=?, https=?, "
            "last_checked=?, last_ok=?, check_fails=0, checks_ok=checks_ok+1, checks_total=checks_total+1, "
            "country_code=CASE WHEN ? THEN country_code ELSE NULL END, "
            "country=CASE WHEN ? THEN country ELSE NULL END WHERE id=?", ok_rows)
        self.db.many(
            "UPDATE proxies SET last_checked=?1, check_fails=check_fails+1, checks_total=checks_total+1, "
            "status=CASE WHEN status='new' OR check_fails+1 >= ?2 THEN 'dead' ELSE status END WHERE id=?3",
            fail_rows)

    def _due(self, n):
        cutoff = time.time() - self.s.recheck_interval_min * 60
        rows = self.db.q("SELECT * FROM proxies WHERE status='alive' AND last_checked < ? "
                         "ORDER BY last_checked LIMIT ?", (cutoff, n))
        if len(rows) < n:
            rows += self.db.q("SELECT * FROM proxies WHERE status='new' ORDER BY first_seen DESC LIMIT ?",
                              (n - len(rows),))
        return rows

    async def check_one_and_store(self, pid: int):
        row = self.db.one("SELECT * FROM proxies WHERE id=?", (pid,))
        if not row:
            return None
        await self.refresh_real_ip()
        res = await self.check(row)
        self.store([res], {row["id"]: row})
        if res["ok"]:
            await self.geo.resolve_pending()
        self.pool.reload()
        return res

    def _kick_geo(self):
        if self.geo.busy:
            return

        async def job():
            await self.geo.resolve_pending()
            self.pool.reload()
        self._geo_task = asyncio.create_task(job())

    async def run(self):
        await self.refresh_real_ip(force=True)
        while True:
            try:
                await self.refresh_real_ip()
                batch = self._due(max(100, self.s.check_concurrency * 5))
                if not batch:
                    self.status["running"] = False
                    try:
                        await asyncio.wait_for(self.wake.wait(), 20)
                    except asyncio.TimeoutError:
                        pass
                    self.wake.clear()
                    continue
                self.status.update(running=True, batch=len(batch), done=0, alive_found=0)
                sem = asyncio.Semaphore(max(1, self.s.check_concurrency))

                async def one(row):
                    async with sem:
                        r = await self.check(row)
                        self.status["done"] += 1
                        if r["ok"]:
                            self.status["alive_found"] += 1
                        return r

                results = await asyncio.gather(*(one(r) for r in batch))
                self.store(results, {r["id"]: r for r in batch})
                self.status["checked_total"] += len(results)
                self.status["last_batch_end"] = time.time()
                self.pool.reload()
                self._kick_geo()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Checker-Fehler")
                await asyncio.sleep(10)
