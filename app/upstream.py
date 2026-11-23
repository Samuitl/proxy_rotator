"""Verbindungen über Upstream-Proxys (HTTP CONNECT, SOCKS4/4a, SOCKS5)."""
import asyncio
import ipaddress
import json
import ssl
from urllib.parse import urlsplit

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
STREAM_LIMIT = 2 ** 16


class UpstreamError(Exception):
    pass


def fmt_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


async def _open(host, port):
    return await asyncio.open_connection(host, port, limit=STREAM_LIMIT)


async def _http_connect(r, w, host, port):
    hp = f"{fmt_host(host)}:{port}"
    w.write(f"CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nUser-Agent: {UA}\r\n\r\n".encode())
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    parts = head.split(None, 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise UpstreamError("ungültige CONNECT-Antwort")
    if parts[1] != b"200":
        raise UpstreamError(f"CONNECT abgelehnt ({parts[1].decode(errors='replace')})")


async def _socks5(r, w, host, port):
    w.write(b"\x05\x01\x00")
    await w.drain()
    if await r.readexactly(2) != b"\x05\x00":
        raise UpstreamError("SOCKS5: Auth nötig/abgelehnt")
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        hb = host.encode("idna")
        addr = b"\x03" + bytes([len(hb)]) + hb
    w.write(b"\x05\x01\x00" + addr + port.to_bytes(2, "big"))
    await w.drain()
    rep = await r.readexactly(4)
    if rep[0] != 5 or rep[1] != 0:
        raise UpstreamError(f"SOCKS5: Fehlercode {rep[1]}")
    atyp = rep[3]
    if atyp == 1:
        await r.readexactly(6)
    elif atyp == 4:
        await r.readexactly(18)
    elif atyp == 3:
        n = (await r.readexactly(1))[0]
        await r.readexactly(n + 2)
    else:
        raise UpstreamError("SOCKS5: unbekannter Adresstyp")


async def _socks4(r, w, host, port):
    try:
        ip = ipaddress.ip_address(host)
        if ip.version != 4:
            raise UpstreamError("SOCKS4 unterstützt kein IPv6")
        pkt = b"\x04\x01" + port.to_bytes(2, "big") + ip.packed + b"\x00"
    except ValueError:  # SOCKS4a mit Hostname
        pkt = b"\x04\x01" + port.to_bytes(2, "big") + b"\x00\x00\x00\x01\x00" + host.encode("idna") + b"\x00"
    w.write(pkt)
    await w.drain()
    rep = await r.readexactly(8)
    if rep[1] != 0x5A:
        raise UpstreamError(f"SOCKS4: abgelehnt ({rep[1]})")


async def open_tunnel(p, host: str, port: int):
    """Öffnet einen TCP-Tunnel host:port über den Proxy p. Gibt (reader, writer) zurück."""
    r, w = await _open(p.host, p.port)
    try:
        if p.protocol == "http":
            await _http_connect(r, w, host, port)
        elif p.protocol == "socks5":
            await _socks5(r, w, host, port)
        elif p.protocol == "socks4":
            await _socks4(r, w, host, port)
        else:
            raise UpstreamError(f"Protokoll {p.protocol}?")
        return r, w
    except BaseException:
        w.close()
        raise


async def open_forward(p):
    """Direkte Verbindung zu einem HTTP-Proxy für Anfragen in Absolute-Form."""
    return await _open(p.host, p.port)


async def read_response(r, max_body=512 * 1024):
    head = await r.readuntil(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise UpstreamError("keine HTTP-Antwort")
    status = int(parts[1])
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = b""
    if "chunked" in headers.get("transfer-encoding", "").lower():
        while len(body) <= max_body:
            size_line = await r.readuntil(b"\r\n")
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                break
            body += await r.readexactly(size)
            await r.readexactly(2)
    elif "content-length" in headers:
        n = int(headers["content-length"])
        if n > max_body:
            raise UpstreamError("Antwort zu groß")
        body = await r.readexactly(n)
    else:
        while len(body) <= max_body:
            chunk = await r.read(65536)
            if not chunk:
                break
            body += chunk
    return status, headers, body


_SSL_CTX = ssl.create_default_context()


async def http_get_via(p, url: str, timeout: float):
    """GET url über Proxy p. Gibt (status, headers, body) zurück."""
    async def run():
        u = urlsplit(url)
        https = u.scheme == "https"
        host = u.hostname
        port = u.port or (443 if https else 80)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if p.protocol == "http" and not https:
            r, w = await open_forward(p)
            target = url
        else:
            r, w = await open_tunnel(p, host, port)
            if https:
                await w.start_tls(_SSL_CTX, server_hostname=host)
            target = path
        try:
            w.write((f"GET {target} HTTP/1.1\r\nHost: {fmt_host(host)}"
                     f"{'' if port in (80, 443) else ':' + str(port)}\r\n"
                     f"User-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n").encode())
            await w.drain()
            return await read_response(r)
        finally:
            w.close()

    return await asyncio.wait_for(run(), timeout)


def parse_json(body: bytes):
    return json.loads(body.decode("utf-8", "replace"))
