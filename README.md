# Proxy-Rotator

Ein Docker-Container, der selbst als HTTP/HTTPS-Proxy arbeitet und jede eingehende Anfrage über einen rotierenden Pool kostenloser Proxys weiterleitet. Der Pool wird im Hintergrund gescraped, auf Anonymität, HTTPS-Fähigkeit und Latenz geprüft und nach Land sortiert. Ein internes Dashboard zeigt alles an und steuert es.

## Start

```bash
# Passwort in docker-compose.yml anpassen, dann:
docker compose up -d --build
docker compose logs -f
```

- Proxy: `http://localhost:8080` (HTTP und HTTPS über CONNECT)
- Dashboard: `http://localhost:8000`

Ohne `DASHBOARD_PASSWORD` wird ein Passwort generiert, ins Log geschrieben und unter `/data/dashboard_password.txt` gespeichert.

Nach dem Start dauert es ein paar Minuten, bis die ersten Proxys geprüft sind. Bis dahin antwortet der Proxy mit `503`.

## Verwendung

```bash
curl -x http://localhost:8080 https://api.ipify.org
```

Optionen pro Anfrage stehen im **Benutzernamen** des Proxy-Logins (Paare `schlüssel-wert`, verbunden mit `-`). Das Passwort ist `PROXY_PASSWORD`, oder beliebig, wenn keins gesetzt ist:

| Option | Beispiel | Wirkung |
|---|---|---|
| `country` | `country-de`, `country-de_at_ch`, `country-any` | Nur Proxys aus diesen Ländern (Exit-IP) |
| `rotate` | `rotate-request`, `rotate-time`, `rotate-sticky` | Rotationsmodus für diese Anfrage |
| `session` | `session-job42` | Sticky: gleiche Session = gleicher Proxy (setzt `rotate-sticky`) |
| `anon` | `anon-elite` | Mindest-Anonymität |
| `proto` | `proto-socks5`, `proto-http_socks5` | Nur diese Upstream-Typen |

```bash
curl -x http://country-de-session-abc:PASSWORT@localhost:8080 https://example.com
```

Alternativ gehen die Header `X-Proxy-Country`, `X-Proxy-Rotate`, `X-Proxy-Session`, `X-Proxy-Anon` und `X-Proxy-Protocol` (bei curl mit `--proxy-header`). Sie werden vor dem Weiterleiten entfernt. Ohne Optionen gelten die Standardwerte aus dem Dashboard.

## Rotationsmodi

- **Pro Anfrage**: Jede Verbindung geht über einen anderen Proxy. Schnelle Proxys werden bevorzugt.
- **Zeitbasiert**: Derselbe Proxy bleibt `rotation_interval_s` Sekunden aktiv (getrennt pro Filterkombination).
- **Sticky**: Pro Session-ID oder sonst pro Client-IP bleibt derselbe Proxy für `sticky_ttl_s` Sekunden.

Fällt ein Proxy aus, wird automatisch der nächste genommen (`max_retries`). Nach `dead_after_fails` Fehlern in Folge fliegt er aus dem Pool.

## So wird geprüft

1. **Scraper**: Holt ca. 20 öffentliche Listen (GitHub-Listen, ProxyScrape, free-proxy-list.net …). Die Quellen kannst du im Dashboard ändern.
2. **Checker**: Ruft über jeden Proxy einen IP-Judge auf (`httpbin.org/get`, `azenv.net`) und vergleicht das Ergebnis mit der eigenen öffentlichen IP:
   - *transparent*: Deine echte IP ist sichtbar. Diese Proxys werden standardmäßig nie benutzt.
   - *anonymous*: Proxy-Header wie `Via` oder `X-Forwarded-For` sind sichtbar.
   - *elite*: Kein Hinweis auf einen Proxy.
   Danach folgt ein HTTPS-Test über CONNECT oder SOCKS. Nur bestandene Proxys werden für HTTPS-Ziele benutzt.
3. **Land**: Die Exit-IP wird über die ip-api.com-Batch-API aufgelöst (kostenlos, wird 14 Tage gecacht).

Aktive Proxys werden alle `recheck_interval_min` Minuten erneut geprüft. Tote werden nach `purge_dead_after_h` Stunden gelöscht und tauchen beim nächsten Scrape wieder als „neu“ auf.

## Umgebungsvariablen

| Variable | Standard | |
|---|---|---|
| `DASHBOARD_PASSWORD` | generiert | Login fürs Dashboard |
| `PROXY_PASSWORD` | leer | Wenn gesetzt, verlangt der Proxy einen Login (`407` ohne) |
| `PROXY_PORT` / `DASHBOARD_PORT` | 8080 / 8000 | |
| `SECRET_KEY` | generiert | Signiert das Session-Cookie |
| `DATA_DIR` | `/data` | SQLite-Datenbank und Secrets (Volume) |
| `LOG_LEVEL` | INFO | |

Alle anderen Einstellungen werden im Dashboard geändert und in der Datenbank gespeichert.

## Sicherheit

- **Kostenlose Proxys sind nicht vertrauenswürdig.** Der Betreiber kann unverschlüsselten `http://`-Traffic mitlesen und verändern. Schick Logins und Cookies nur über `https://`. Dort ist die Verbindung bis zum Ziel verschlüsselt (CONNECT-Tunnel).
- In der Compose-Datei sind die Ports standardmäßig nur an `127.0.0.1` gebunden. Wenn du sie fürs LAN öffnest, setze `PROXY_PASSWORD`. Ein offener Proxy im Internet wird sehr schnell missbraucht.
- Halte dich an die Nutzungsbedingungen der Quell- und Zielseiten.

## Aufbau

```
app/
  main.py          Startet alles in einem asyncio-Prozess
  proxy_server.py  Eingehender HTTP/HTTPS-Proxy, Retry, Statistik
  pool.py          Proxy-Pool, Filter, Rotationsmodi, Optionen aus Benutzername/Header
  upstream.py      HTTP CONNECT, SOCKS4/4a, SOCKS5, Mini-HTTP-Client
  scraper.py       Quellen holen und ip:port parsen
  checker.py       Anonymität, HTTPS, Latenz
  geo.py           Länder per ip-api.com
  dashboard.py     Starlette-App, Login, JSON-API
  static/          Dashboard-Oberfläche (Vanilla JS, keine externen Ressourcen)
```
