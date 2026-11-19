"""Startpunkt: Proxy-Server, Hintergrundjobs und Dashboard in einem Prozess."""
import asyncio
import logging
import os
import time

import uvicorn

from . import config
from .checker import Checker
from .dashboard import create_app
from .db import DB
from .geo import Geo
from .pool import Pool
from .proxy_server import ProxyServer, Stats
from .scraper import Scraper

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
log = logging.getLogger("main")


async def maintenance(db, settings, pool):
    while True:
        await asyncio.sleep(60)
        try:
            cutoff = time.time() - settings.purge_dead_after_h * 3600
            n, _ = db.x("DELETE FROM proxies WHERE status='dead' AND last_checked < ?", (cutoff,))
            if n:
                log.info("%d tote Proxys entfernt", n)
            pool.reload()
        except Exception:  # noqa: BLE001
            log.exception("Wartungsfehler")


async def main():
    secret_key, dash_pw = config.load_secrets()
    db = DB(os.path.join(config.DATA_DIR, "proxies.db"))
    settings = config.Settings(db)
    stats = Stats()
    pool = Pool(db, settings)
    pool.reload()
    geo = Geo(db)
    checker = Checker(db, settings, pool, geo)
    scraper = Scraper(db, settings, checker)

    proxy = ProxyServer(pool, settings, stats)
    await proxy.start(config.PROXY_HOST, config.PROXY_PORT)

    tasks = [asyncio.create_task(scraper.run(), name="scraper"),
             asyncio.create_task(checker.run(), name="checker"),
             asyncio.create_task(maintenance(db, settings, pool), name="maintenance")]

    app = create_app({"db": db, "settings": settings, "stats": stats, "pool": pool, "checker": checker,
                      "scraper": scraper, "secret_key": secret_key, "dashboard_password": dash_pw})
    server = uvicorn.Server(uvicorn.Config(app, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT,
                                           log_level="warning", access_log=False))
    log.info("Dashboard auf http://%s:%s", config.DASHBOARD_HOST, config.DASHBOARD_PORT)
    try:
        await server.serve()
    finally:
        for t in tasks:
            t.cancel()
        proxy.server.close()


if __name__ == "__main__":
    asyncio.run(main())
