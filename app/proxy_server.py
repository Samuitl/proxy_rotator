"""Eingehender HTTP/HTTPS-Proxy, der jede Anfrage über einen Upstream-Proxy aus dem Pool leitet."""
import asyncio
import base64
import hmac
import logging
import time
from collections import deque
from urllib.parse import urlsplit

from . import config
from .pool import parse_opts
from .upstream import fmt_host, open_forward, open_tunnel

log = logging.getLogger("proxy")

DROP_HEADERS = {"proxy-authorization", "proxy-connection", "connection", "keep-alive",
                "x-proxy-country", "x-proxy-anon", "x-proxy-rotate", "x-proxy-session",
                "x-proxy-protocol", "upgrade", "te", "trailer"}
MAX_BUFFERED_BODY = 1024 * 1024
IDLE_TIMEOUT = 300


class Stats:
    def __init__(self):
        self.started = time.time()
        self.total = self.ok = self.fail = self.no_proxy = 0
        self.bytes_up = self.bytes_down = 0
        self.active = 0
        self.log = deque(maxlen=500)
        self.minutes = deque(maxlen=60)  # [minute, ok, fail]

    def _bucket(self):
        m = int(time.time() // 60)
        if not self.minutes or self.minutes[-1][0] != m:
            self.minutes.append([m, 0, 0])
        return self.minutes[-1]

    def record(self, **e):
        self.total += 1
        b = self._bucket()
        if e["result"] == "ok":
            self.ok += 1
            b[1] += 1
        else:
            self.fail += 1
            b[2] += 1
            if e["result"] == "no_proxy":
                self.no_proxy += 1
        self.bytes_up += e.get("up", 0)
        self.bytes_down += e.get("down", 0)
        e["ts"] = time.time()
        self.log.append(e)

    def series(self):
        self._bucket()
        now = int(time.time() // 60)
        d = {m: (o, f) for m, o, f in self.minutes}
        return [{"m": m, "ok": d.get(m, (0, 0))[0], "fail": d.get(m, (0, 0))[1]}
                for m in range(now - 59, now + 1)]


async def _copy(src, dst, counter, idx):
    try:
        while True:
            data = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
            if not data:
                break
            dst.write(data)
            await dst.drain()
            counter[idx] += len(data)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        try:
            if dst.can_write_eof():
                dst.write_eof()
        except (OSError, RuntimeError, AttributeError):
            pass


async def pipe(cr, cw, ur, uw, counter):
    up = asyncio.create_task(_copy(cr, uw, counter, 0))
    down = asyncio.create_task(_copy(ur, cw, counter, 1))
    try:
        done, _ = await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
        if down in done:
            up.cancel()
        else:
            await down
    finally:
        for t in (up, down):
            t.cancel()
        uw.close()


class ProxyServer:
    def __init__(self, pool, settings, stats):
        self.pool = pool
        self.s = settings
        self.stats = stats
        self.server = None

    async def start(self, host, port):
        self.server = await asyncio.start_server(self.handle, host, port, limit=2 ** 16)
        log.info("Proxy lauscht auf %s:%s (Auth: %s)", host, port,
                 "an" if config.PROXY_PASSWORD else "aus")

    @staticmethod
    async def _respond(w, code, reason, body="", extra=""):
        b = body.encode()
        w.write((f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 f"Content-Length: {len(b)}\r\nConnection: close\r\n{extra}\r\n").encode() + b)
        try:
            await w.drain()
        except OSError:
            pass

    def _auth(self, headers):
        """Gibt (ok, username) zurück."""
        raw = headers.get("proxy-authorization", "")
        user = pw = None
        if raw.lower().startswith("basic "):
            try:
                user, _, pw = base64.b64decode(raw[6:].strip()).decode("utf-8", "replace").partition(":")
            except ValueError:
                pass
        if config.PROXY_PASSWORD:
            if pw is None or not hmac.compare_digest(pw.encode(), config.PROXY_PASSWORD.encode()):
                return False, user
        return True, user

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername") or ("?", 0)
        client_ip = peer[0]
        self.stats.active += 1
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError):
                return
            lines = head.decode("latin-1").split("\r\n")
            try:
                method, target, _ = lines[0].split(" ", 2)
            except ValueError:
                return await self._respond(writer, 400, "Bad Request", "Ungültige Anfrage\n")
            hlist = []
            hdict = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hlist.append((k.strip(), v.strip()))
                    hdict[k.strip().lower()] = v.strip()

            ok, user = self._auth(hdict)
            if not ok:
                return await self._respond(writer, 407, "Proxy Authentication Required",
                                           "Proxy-Login erforderlich\n",
                                           'Proxy-Authenticate: Basic realm="proxy-rotator"\r\n')
            opts = parse_opts(user, hdict)
            if method.upper() == "CONNECT":
                await self.do_connect(reader, writer, target, opts, client_ip)
            else:
                await self.do_http(reader, writer, method, target, hlist, hdict, opts, client_ip)
        except Exception:  # noqa: BLE001
            log.exception("Fehler bei Anfrage von %s", client_ip)
        finally:
            self.stats.active -= 1
            try:
                writer.close()
            except OSError:
                pass

    async def _no_proxy(self, writer, tried, entry):
        if not tried:
            entry["result"] = "no_proxy"
            self.stats.record(**entry)
            await self._respond(writer, 503, "No Proxy Available",
                                "Kein passender Proxy im Pool (Filter prüfen oder warten, bis der Checker "
                                "Proxys gefunden hat).\n")
        else:
            entry["result"] = "fail"
            self.stats.record(**entry)
            await self._respond(writer, 502, "Bad Gateway",
                                f"Alle {len(tried)} versuchten Proxys sind fehlgeschlagen.\n")

    async def do_connect(self, reader, writer, target, opts, client_ip):
        host, _, port = target.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port)
        except ValueError:
            return await self._respond(writer, 400, "Bad Request", "CONNECT host:port erwartet\n")
        t0 = time.monotonic()
        tried = set()
        entry = {"client": client_ip, "method": "CONNECT", "target": f"{host}:{port}",
                 "proxy": None, "country": None, "attempts": 0}
        for _ in range(self.s.max_retries + 1):
            p = self.pool.select(opts, client_ip, tunnel=True, exclude=tried)
            if not p:
                break
            tried.add(p.id)
            entry["attempts"] += 1
            try:
                ur, uw = await asyncio.wait_for(open_tunnel(p, host, port), self.s.connect_timeout_s)
            except (Exception, asyncio.TimeoutError):  # noqa: BLE001
                self.pool.report(p, False)
                continue
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: proxy-rotator\r\n\r\n")
            await writer.drain()
            counter = [0, 0]
            await pipe(reader, writer, ur, uw, counter)
            good = counter[1] > 0 or counter[0] == 0
            self.pool.report(p, good)
            entry.update(proxy=p.label, country=p.country_code, up=counter[0], down=counter[1],
                         ms=int((time.monotonic() - t0) * 1000), result="ok" if good else "fail")
            self.stats.record(**entry)
            return
        entry["ms"] = int((time.monotonic() - t0) * 1000)
        await self._no_proxy(writer, tried, entry)

    async def do_http(self, reader, writer, method, target, hlist, hdict, opts, client_ip):
        u = urlsplit(target)
        if u.scheme != "http" or not u.hostname:
            return await self._respond(
                writer, 400, "Bad Request",
                "Dies ist ein Proxy-Server. Konfiguriere ihn als HTTP/HTTPS-Proxy in deinem Client.\n")
        host, port = u.hostname, u.port or 80
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        netloc = fmt_host(host) + ("" if port == 80 else f":{port}")
        absolute = f"http://{netloc}{path}"

        headers = [(k, v) for k, v in hlist if k.lower() not in DROP_HEADERS]
        if "host" not in hdict:
            headers.insert(0, ("Host", netloc))
        headers.append(("Connection", "close"))
        hdr_bytes = "".join(f"{k}: {v}\r\n" for k, v in headers).encode("latin-1", "replace")

        body = b""
        streaming = False
        if "chunked" in hdict.get("transfer-encoding", "").lower():
            streaming = True
        elif hdict.get("content-length"):
            try:
                n = int(hdict["content-length"])
            except ValueError:
                return await self._respond(writer, 400, "Bad Request", "Content-Length ungültig\n")
            if n <= MAX_BUFFERED_BODY:
                body = await reader.readexactly(n)
            else:
                streaming = True

        t0 = time.monotonic()
        tried = set()
        entry = {"client": client_ip, "method": method, "target": absolute[:200],
                 "proxy": None, "country": None, "attempts": 0}
        for _ in range(self.s.max_retries + 1):
            p = self.pool.select(opts, client_ip, tunnel=False, exclude=tried)
            if not p:
                break
            tried.add(p.id)
            entry["attempts"] += 1
            try:
                if p.protocol == "http":
                    ur, uw = await asyncio.wait_for(open_forward(p), self.s.connect_timeout_s)
                    reqline = f"{method} {absolute} HTTP/1.1\r\n"
                else:
                    ur, uw = await asyncio.wait_for(open_tunnel(p, host, port), self.s.connect_timeout_s)
                    reqline = f"{method} {path} HTTP/1.1\r\n"
                uw.write(reqline.encode("latin-1", "replace") + hdr_bytes + b"\r\n" + body)
                await uw.drain()
            except (Exception, asyncio.TimeoutError):  # noqa: BLE001
                self.pool.report(p, False)
                continue

            counter = [len(body), 0]
            if not streaming:
                # Auf den Anfang der Antwort warten, damit bei Fehlern der nächste Proxy probiert werden kann
                try:
                    first = await asyncio.wait_for(ur.read(65536), self.s.response_timeout_s)
                except (Exception, asyncio.TimeoutError):  # noqa: BLE001
                    first = b""
                if not first.startswith(b"HTTP/") or first[9:12] == b"407":
                    uw.close()
                    self.pool.report(p, False)
                    continue
                writer.write(first)
                await writer.drain()
                counter[1] += len(first)
            await pipe(reader, writer, ur, uw, counter)
            self.pool.report(p, True)
            entry.update(proxy=p.label, country=p.country_code, up=counter[0], down=counter[1],
                         ms=int((time.monotonic() - t0) * 1000), result="ok")
            self.stats.record(**entry)
            return
        entry["ms"] = int((time.monotonic() - t0) * 1000)
        await self._no_proxy(writer, tried, entry)
