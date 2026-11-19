FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    PROXY_PORT=8080 \
    DASHBOARD_PORT=8000

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd -r -u 1000 -d /srv proxy \
 && mkdir -p /data && chown proxy /data

COPY app ./app
USER proxy
VOLUME ["/data"]
EXPOSE 8080 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"DASHBOARD_PORT\"]}/health', timeout=4)" || exit 1

CMD ["python", "-m", "app.main"]
