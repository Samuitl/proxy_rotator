"""Länderbestimmung der Exit-IPs über ip-api.com (Batch, kostenlos, 15 Anfragen/Minute)."""
import asyncio
import json
import logging
import time
import urllib.request

log = logging.getLogger("geo")
BATCH_URL = "http://ip-api.com/batch?fields=status,query,countryCode,country"
CACHE_DAYS = 14


class Geo:
    def __init__(self, db):
        self.db = db
        self.last_error = None
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    @property
    def busy(self):
        return self._lock.locked()

    def _batch(self, ips):
        req = urllib.request.Request(BATCH_URL, data=json.dumps(ips).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            remaining = r.headers.get("X-Rl")
            ttl = r.headers.get("X-Ttl")
            data = json.loads(r.read())
        if remaining is not None and int(remaining) <= 0 and ttl:
            self._next_allowed = time.time() + int(ttl) + 1
        return data

    async def resolve_pending(self):
        """Fehlende Länder für alle Proxys mit Exit-IP ermitteln."""
        async with self._lock:
            self._apply_cache()
            ips = [r["exit_ip"] for r in self.db.q(
                "SELECT DISTINCT exit_ip FROM proxies WHERE exit_ip IS NOT NULL AND country_code IS NULL "
                "AND status='alive' LIMIT 2000")]
            for i in range(0, len(ips), 100):
                wait = self._next_allowed - time.time()
                if wait > 0:
                    await asyncio.sleep(min(wait, 65))
                chunk = ips[i:i + 100]
                try:
                    res = await asyncio.to_thread(self._batch, chunk)
                    self.last_error = None
                except Exception as e:  # noqa: BLE001
                    self.last_error = str(e)
                    log.warning("Geo-Lookup fehlgeschlagen: %s", e)
                    return
                now = time.time()
                rows = []
                for item in res:
                    if item.get("status") == "success":
                        rows.append((item["query"], item.get("countryCode") or "ZZ",
                                     item.get("country") or "Unbekannt", now))
                    else:
                        rows.append((item.get("query"), "ZZ", "Unbekannt", now))
                self.db.many("INSERT INTO geo(ip,country_code,country,ts) VALUES(?,?,?,?) "
                             "ON CONFLICT(ip) DO UPDATE SET country_code=excluded.country_code, "
                             "country=excluded.country, ts=excluded.ts", [r for r in rows if r[0]])
                self._apply_cache()
                await asyncio.sleep(4.2)  # unter 15/min bleiben

    def _apply_cache(self):
        self.db.x("DELETE FROM geo WHERE ts < ?", (time.time() - CACHE_DAYS * 86400,))
        self.db.x("UPDATE proxies SET country_code=(SELECT country_code FROM geo WHERE geo.ip=proxies.exit_ip), "
                  "country=(SELECT country FROM geo WHERE geo.ip=proxies.exit_ip) "
                  "WHERE country_code IS NULL AND exit_ip IN (SELECT ip FROM geo)")
