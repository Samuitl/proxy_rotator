"""Internes Dashboard (Starlette) mit Login und JSON-API."""
import asyncio
import hmac
import os
import time

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from . import config

STATIC = os.path.join(os.path.dirname(__file__), "static")
SORTS = {"latency": "latency_ms ASC", "checked": "last_checked DESC", "country": "country_code ASC",
         "seen": "first_seen DESC", "success": "req_ok DESC", "anonymity": "anonymity DESC"}


def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


def create_app(ctx):
    db, settings, stats, pool = ctx["db"], ctx["settings"], ctx["stats"], ctx["pool"]
    checker, scraper = ctx["checker"], ctx["scraper"]
    dash_pw = ctx["dashboard_password"]
    pages = {"index": _read("index.html"), "login": _read("login.html")}
    failed_logins = {}

    def authed(fn):
        async def wrapper(request: Request):
            if not request.session.get("auth"):
                return JSONResponse({"error": "nicht angemeldet"}, status_code=401)
            if request.method != "GET" and request.headers.get("x-requested-with") != "dashboard":
                return JSONResponse({"error": "CSRF-Schutz"}, status_code=403)
            return await fn(request)
        return wrapper

    async def index(request):
        if not request.session.get("auth"):
            return RedirectResponse("/login", 303)
        return HTMLResponse(pages["index"])

    async def login_page(request):
        return HTMLResponse(pages["login"])

    async def login(request):
        ip = request.client.host if request.client else "?"
        n, ts = failed_logins.get(ip, (0, 0))
        if n >= 5 and time.time() - ts < 300:
            return JSONResponse({"error": "Zu viele Versuche, bitte 5 Minuten warten"}, status_code=429)
        try:
            data = await request.json()
        except ValueError:
            data = {}
        if hmac.compare_digest(str(data.get("password", "")).encode(), dash_pw.encode()):
            failed_logins.pop(ip, None)
            request.session["auth"] = True
            return JSONResponse({"ok": True})
        failed_logins[ip] = (n + 1, time.time())
        await asyncio.sleep(1)
        return JSONResponse({"error": "Falsches Passwort"}, status_code=401)

    async def logout(request):
        request.session.clear()
        return RedirectResponse("/login", 303)

    @authed
    async def api_stats(request):
        by = lambda col: db.q(f"SELECT {col} AS k, COUNT(*) AS n FROM proxies WHERE status='alive' "  # noqa: E731
                              f"GROUP BY {col} ORDER BY n DESC")
        counts = {r["status"]: r["n"] for r in db.q("SELECT status, COUNT(*) n FROM proxies GROUP BY status")}
        countries = db.q("SELECT COALESCE(country_code,'ZZ') AS code, COALESCE(MAX(country),'Unbekannt') AS name, "
                         "COUNT(*) AS n, SUM(anonymity='elite') AS elite, SUM(https) AS https, "
                         "ROUND(AVG(latency_ms)) AS latency FROM proxies WHERE status='alive' "
                         "GROUP BY COALESCE(country_code,'ZZ') ORDER BY n DESC")
        return JSONResponse({
            "counts": {"alive": counts.get("alive", 0), "new": counts.get("new", 0),
                       "dead": counts.get("dead", 0), "total": sum(counts.values())},
            "pool": pool.stats(),
            "usable": {"http": pool.count(_opts(), False), "https": pool.count(_opts(), True)},
            "anonymity": by("anonymity"), "protocols": by("protocol"), "countries": countries,
            "traffic": {"total": stats.total, "ok": stats.ok, "fail": stats.fail, "no_proxy": stats.no_proxy,
                        "bytes_up": stats.bytes_up, "bytes_down": stats.bytes_down, "active": stats.active,
                        "series": stats.series()},
            "checker": {**checker.status, "real_ip": checker.real_ip, "geo_error": checker.geo.last_error,
                        "geo_busy": checker.geo.busy},
            "scraper": scraper.status,
            "uptime": time.time() - stats.started,
            "proxy_port": config.PROXY_PORT, "proxy_auth": bool(config.PROXY_PASSWORD),
            "rotation_mode": settings.rotation_mode,
            "sources": {"enabled": db.scalar("SELECT COUNT(*) FROM sources WHERE enabled=1"),
                        "errors": db.scalar("SELECT COUNT(*) FROM sources WHERE enabled=1 AND last_error IS NOT NULL")},
        })

    def _opts():
        from .pool import Opts
        return Opts()

    def _proxy_filter(qp):
        where, args = [], []
        if qp.get("status"):
            where.append("status=?")
            args.append(qp["status"])
        if qp.get("country"):
            cs = [c.strip().upper() for c in qp["country"].split(",") if c.strip()]
            where.append(f"COALESCE(country_code,'ZZ') IN ({','.join('?' * len(cs))})")
            args += cs
        if qp.get("protocol"):
            where.append("protocol=?")
            args.append(qp["protocol"])
        if qp.get("anonymity"):
            where.append("anonymity=?")
            args.append(qp["anonymity"])
        if qp.get("https") == "1":
            where.append("https=1")
        if qp.get("q"):
            where.append("(host LIKE ? OR exit_ip LIKE ?)")
            args += [f"%{qp['q']}%"] * 2
        return (" WHERE " + " AND ".join(where)) if where else "", args

    @authed
    async def api_proxies(request):
        qp = request.query_params
        w, args = _proxy_filter(qp)
        order = SORTS.get(qp.get("sort", "latency"), SORTS["latency"])
        limit = min(int(qp.get("limit", 100)), 1000)
        offset = int(qp.get("offset", 0))
        total = db.scalar(f"SELECT COUNT(*) FROM proxies{w}", args)
        rows = db.q(f"SELECT * FROM proxies{w} ORDER BY {order} NULLS LAST, id LIMIT ? OFFSET ?",
                    args + [limit, offset])
        return JSONResponse({"total": total, "items": rows})

    @authed
    async def api_export(request):
        w, args = _proxy_filter(request.query_params)
        rows = db.q(f"SELECT protocol, host, port FROM proxies{w} ORDER BY latency_ms NULLS LAST", args)
        text = "\n".join(f"{r['protocol']}://{r['host']}:{r['port']}" for r in rows) + "\n"
        return PlainTextResponse(text, headers={"Content-Disposition": "attachment; filename=proxies.txt"})

    @authed
    async def api_proxy_item(request):
        pid = int(request.path_params["pid"])
        if request.method == "DELETE":
            db.x("DELETE FROM proxies WHERE id=?", (pid,))
            pool.reload()
            return JSONResponse({"ok": True})
        res = await checker.check_one_and_store(pid)
        if res is None:
            return JSONResponse({"error": "nicht gefunden"}, status_code=404)
        return JSONResponse({"result": res, "proxy": db.one("SELECT * FROM proxies WHERE id=?", (pid,))})

    @authed
    async def api_settings(request):
        if request.method == "POST":
            errors = settings.update(await request.json())
            if errors:
                return JSONResponse({"errors": errors}, status_code=400)
            pool.reload()
        return JSONResponse(settings.all())

    @authed
    async def api_sources(request):
        if request.method == "POST":
            data = await request.json()
            url = str(data.get("url", "")).strip()
            proto = data.get("protocol")
            if not url.startswith(("http://", "https://")) or proto not in config.PROTOCOLS:
                return JSONResponse({"error": "URL (http/https) und Protokoll nötig"}, status_code=400)
            db.x("INSERT OR IGNORE INTO sources(url, protocol, decode, max_pages) VALUES(?,?,?,?)",
                 (url, proto, 1 if data.get("decode") else 0, _pages(data.get("max_pages"))))
        return JSONResponse(db.q("SELECT * FROM sources ORDER BY protocol, url"))

    @authed
    async def api_source_item(request):
        sid = int(request.path_params["sid"])
        if request.method == "DELETE":
            db.x("DELETE FROM sources WHERE id=?", (sid,))
        else:
            data = await request.json()
            if "enabled" in data:
                db.x("UPDATE sources SET enabled=? WHERE id=?", (1 if data["enabled"] else 0, sid))
            if data.get("protocol") in config.PROTOCOLS:
                db.x("UPDATE sources SET protocol=? WHERE id=?", (data["protocol"], sid))
            if "decode" in data:
                db.x("UPDATE sources SET decode=? WHERE id=?", (1 if data["decode"] else 0, sid))
            if "max_pages" in data:
                db.x("UPDATE sources SET max_pages=? WHERE id=?", (_pages(data["max_pages"]), sid))
        return JSONResponse({"ok": True})

    def _pages(v):
        try:
            return max(1, min(int(v or 1), 100))
        except (TypeError, ValueError):
            return 1

    @authed
    async def api_source_preview(request):
        """Quelle testen, ohne etwas zu speichern."""
        data = await request.json()
        url = str(data.get("url", "")).strip()
        if not url.startswith(("http://", "https://")):
            return JSONResponse({"error": "URL (http/https) nötig"}, status_code=400)
        src = {"url": url, "protocol": data.get("protocol") if data.get("protocol") in config.PROTOCOLS else "http",
               "decode": bool(data.get("decode")), "max_pages": _pages(data.get("max_pages"))}
        try:
            found, pages = await scraper.fetch_source(src)
        except Exception as e:  # noqa: BLE001
            return JSONResponse({"error": f"Abruf fehlgeschlagen: {e}"}, status_code=502)
        sample = sorted(found)[:15]
        return JSONResponse({"count": len(found), "pages": pages,
                             "sample": [f"{p}://{h}:{port}" for h, port, p in sample]})

    @authed
    async def api_action(request):
        action = request.path_params["action"]
        if action == "scrape":
            scraper.wake.set()
        elif action == "recheck":
            db.x("UPDATE proxies SET last_checked=0 WHERE status='alive'")
            checker.wake.set()
        elif action == "retry-dead":
            n, _ = db.x("UPDATE proxies SET status='new', check_fails=0 WHERE status='dead'")
            checker.wake.set()
            return JSONResponse({"ok": True, "count": n})
        elif action == "purge-dead":
            n, _ = db.x("DELETE FROM proxies WHERE status='dead'")
            return JSONResponse({"ok": True, "count": n})
        elif action == "reset-sessions":
            pool._sticky.clear()
            pool._time_pins.clear()
        else:
            return JSONResponse({"error": "unbekannte Aktion"}, status_code=404)
        return JSONResponse({"ok": True})

    @authed
    async def api_log(request):
        return JSONResponse(list(reversed(stats.log))[:200])

    async def health(request):
        return JSONResponse({"ok": True, "alive": len(pool.items)})

    async def favicon(request):
        return Response(status_code=204)

    routes = [
        Route("/", index), Route("/login", login_page), Route("/login", login, methods=["POST"]),
        Route("/logout", logout), Route("/health", health), Route("/favicon.ico", favicon),
        Route("/api/stats", api_stats), Route("/api/proxies", api_proxies), Route("/api/export", api_export),
        Route("/api/proxies/{pid:int}", api_proxy_item, methods=["DELETE", "POST"]),
        Route("/api/settings", api_settings, methods=["GET", "POST"]),
        Route("/api/sources", api_sources, methods=["GET", "POST"]),
        Route("/api/sources/preview", api_source_preview, methods=["POST"]),
        Route("/api/sources/{sid:int}", api_source_item, methods=["DELETE", "PATCH"]),
        Route("/api/actions/{action}", api_action, methods=["POST"]),
        Route("/api/log", api_log),
    ]
    middleware = [Middleware(SessionMiddleware, secret_key=ctx["secret_key"], same_site="strict",
                             session_cookie="prdash", max_age=7 * 86400, https_only=False)]
    return Starlette(routes=routes, middleware=middleware)
