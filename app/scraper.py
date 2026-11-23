"""Sammelt Proxys von kostenlosen Listen im Hintergrund."""
import asyncio
import base64
import binascii
import ipaddress
import logging
import re
import time
import urllib.request

from .upstream import UA

log = logging.getLogger("scraper")

GH = "https://raw.githubusercontent.com"
DEFAULT_SOURCES = [
    (f"{GH}/TheSpeedX/PROXY-List/master/http.txt", "http"),
    (f"{GH}/TheSpeedX/PROXY-List/master/socks4.txt", "socks4"),
    (f"{GH}/TheSpeedX/PROXY-List/master/socks5.txt", "socks5"),
    (f"{GH}/monosans/proxy-list/main/proxies/http.txt", "http"),
    (f"{GH}/monosans/proxy-list/main/proxies/socks4.txt", "socks4"),
    (f"{GH}/monosans/proxy-list/main/proxies/socks5.txt", "socks5"),
    (f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt", "http"),
    (f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt", "socks4"),
    (f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt", "socks5"),
    (f"{GH}/roosterkid/openproxylist/main/HTTPS_RAW.txt", "http"),
    (f"{GH}/roosterkid/openproxylist/main/SOCKS4_RAW.txt", "socks4"),
    (f"{GH}/roosterkid/openproxylist/main/SOCKS5_RAW.txt", "socks5"),
    (f"{GH}/hookzof/socks5_list/master/proxy.txt", "socks5"),
    ("https://vakhov.github.io/fresh-proxy-list/http.txt", "http"),
    ("https://vakhov.github.io/fresh-proxy-list/socks5.txt", "socks5"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http"
     "&proxy_format=ipport&format=text", "http"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks4"
     "&proxy_format=ipport&format=text", "socks4"),
    ("https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5"
     "&proxy_format=ipport&format=text", "socks5"),
    ("https://free-proxy-list.net/", "http"),
    ("https://www.sslproxies.org/", "http"),
    ("https://www.us-proxy.org/", "http"),
]

# Erkennt "ip:port", "proto://ip:port" und HTML-Tabellen "<td>ip</td><td>port</td>"
PATTERN = re.compile(
    r"(?:(https?|socks4a?|socks5h?)://)?"
    r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"
    r"(?::|\s*</td>\s*<td[^>]*>\s*|[ \t]+)"
    r"(\d{2,5})\b", re.I)
PROTO_MAP = {"http": "http", "https": "http", "socks4": "socks4", "socks4a": "socks4",
             "socks5": "socks5", "socks5h": "socks5"}
MAX_BYTES = 20 * 1024 * 1024

# Veraltete Standard-URLs in bestehenden Datenbanken automatisch ersetzen
RENAMED_SOURCES = {
    f"{GH}/vakhov/fresh-proxy-lists/master/http.txt": "https://vakhov.github.io/fresh-proxy-list/http.txt",
    f"{GH}/vakhov/fresh-proxy-lists/master/socks5.txt": "https://vakhov.github.io/fresh-proxy-list/socks5.txt",
}


def parse(text: str, default_proto: str):
    out = set()
    for scheme, ip, port in PATTERN.findall(text):
        try:
            port = int(port)
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not (0 < port < 65536) or not addr.is_global:
            continue
        out.add((ip, port, PROTO_MAP.get(scheme.lower(), default_proto) if scheme else default_proto))
    return out


# Base64-kodierte (ggf. umgedrehte) Einträge, wie sie manche Seiten zur Verschleierung nutzen
B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
MAX_PAGES = 100


def _b64(token: str):
    t = token.strip("=").replace("-", "+").replace("_", "/")
    t += "=" * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
        return raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def decode_obfuscated(text: str) -> str:
    """Probiert jeden Base64-artigen Block: dekodieren, umgedreht dekodieren, Ergebnis umdrehen."""
    text = text.replace("\\/", "/")
    out = []
    for tok in set(B64_TOKEN.findall(text)):
        for t in (tok, tok[::-1]):
            d = _b64(t)
            if d and d.isprintable():
                out.append(d)
                out.append(d[::-1])
    return "\n".join(out)


ROW_PROTO = re.compile(r">\s*(socks5|socks4|https|http)\s*<", re.I)


def _parse_chunk(text: str, default_proto: str, decode: bool):
    found = parse(text, default_proto)
    if decode or not found:
        found |= parse(decode_obfuscated(text), default_proto)
    return found


def parse_text(text: str, default_proto: str, decode: bool):
    """Normales Parsen; mit decode=True (oder wenn nichts gefunden wurde) zusätzlich Base64/umgedreht.
    In HTML-Tabellen wird ein Typ wie "SOCKS5" aus derselben Zeile als Protokoll übernommen."""
    if "<tr" not in text:
        return _parse_chunk(text, default_proto, decode)
    found = set()
    for row in re.split(r"<tr[\s>]", text):
        m = ROW_PROTO.search(row)
        proto = PROTO_MAP[m.group(1).lower()] if m else default_proto
        found |= _parse_chunk(row, proto, decode)
    return found


def page_urls(url: str, pages: int):
    if "{page}" not in url and "{page0}" not in url:
        return [url]
    pages = max(1, min(int(pages or 1), MAX_PAGES))
    return [url.replace("{page}", str(i + 1)).replace("{page0}", str(i)) for i in range(pages)]


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(MAX_BYTES).decode("utf-8", "replace")


class Scraper:
    def __init__(self, db, settings, checker):
        self.db = db
        self.s = settings
        self.checker = checker
        self.wake = asyncio.Event()
        self.status = {"running": False, "last_run": None, "next_run": None, "last_new": 0, "last_found": 0}

    def seed(self):
        if self.db.scalar("SELECT COUNT(*) FROM sources") == 0:
            self.db.many("INSERT OR IGNORE INTO sources(url, protocol) VALUES(?,?)", DEFAULT_SOURCES)
        for old, new in RENAMED_SOURCES.items():
            if self.db.scalar("SELECT COUNT(*) FROM sources WHERE url=?", (new,)):
                self.db.x("DELETE FROM sources WHERE url=?", (old,))
            else:
                self.db.x("UPDATE sources SET url=?, last_error=NULL WHERE url=?", (new, old))

    async def fetch_source(self, src):
        """Holt alle Seiten einer Quelle und gibt (gefundene Proxys, Anzahl Seiten) zurück."""
        found = set()
        urls = page_urls(src["url"], src.get("max_pages") or 1)
        pages = 0
        for i, url in enumerate(urls):
            try:
                text = await asyncio.to_thread(fetch, url)
            except Exception:  # noqa: BLE001
                if i == 0:
                    raise
                break  # Ende der Seiten erreicht (z. B. 404)
            new = parse_text(text, src["protocol"], bool(src.get("decode"))) - found
            pages += 1
            if not new:
                break
            found |= new
            if i + 1 < len(urls):
                await asyncio.sleep(1)  # Seite nicht überlasten
        return found, pages

    async def scrape_source(self, src):
        try:
            found, _ = await self.fetch_source(src)
            self.db.x("UPDATE sources SET last_fetch=?, last_count=?, last_error=NULL WHERE id=?",
                      (time.time(), len(found), src["id"]))
            return found
        except Exception as e:  # noqa: BLE001
            self.db.x("UPDATE sources SET last_fetch=?, last_error=? WHERE id=?",
                      (time.time(), str(e)[:300], src["id"]))
            log.warning("Quelle fehlgeschlagen %s: %s", src["url"], e)
            return set()

    async def scrape_all(self):
        self.status["running"] = True
        try:
            sources = self.db.q("SELECT * FROM sources WHERE enabled=1")
            sem = asyncio.Semaphore(6)

            async def one(src):
                async with sem:
                    return src["url"], await self.scrape_source(src)

            results = await asyncio.gather(*(one(s) for s in sources))
            now = time.time()
            before = self.db.scalar("SELECT COUNT(*) FROM proxies")
            rows = []
            seen = set()
            for url, found in results:
                for ip, port, proto in found:
                    if (ip, port, proto) not in seen:
                        seen.add((ip, port, proto))
                        rows.append((ip, port, proto, url[:200], now, now))
            self.db.many("INSERT INTO proxies(host,port,protocol,source,first_seen,last_seen) "
                         "VALUES(?,?,?,?,?,?) ON CONFLICT(host,port,protocol) "
                         "DO UPDATE SET last_seen=excluded.last_seen", rows)
            new = self.db.scalar("SELECT COUNT(*) FROM proxies") - before
            self.status.update(last_run=now, last_found=len(rows), last_new=new)
            log.info("Scrape: %d Proxys gefunden, %d neu aus %d Quellen", len(rows), new, len(sources))
            self.checker.wake.set()
        finally:
            self.status["running"] = False

    async def run(self):
        self.seed()
        while True:
            try:
                await self.scrape_all()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("Scraper-Fehler")
            interval = max(1, self.s.scrape_interval_min) * 60
            self.status["next_run"] = time.time() + interval
            try:
                await asyncio.wait_for(self.wake.wait(), interval)
            except asyncio.TimeoutError:
                pass
            self.wake.clear()
