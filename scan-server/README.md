# Mantis local scan server

Turns this laptop into the scan backend for mantishack.com. Real internet
requests reach a local HTTP server (through a cloudflared tunnel) and trigger
the Mantis **web** scanner here — in a subprocess or a Docker container.

```text
internet ──▶ https://xxxx.trycloudflare.com ──▶ 127.0.0.1:8787 (server.js)
                                                      └─▶ mantishack.py web --url <target>
```

## Run it

```bash
cd ~/Projects/mantishack/scan-server
chmod +x start.sh
./start.sh
```

`start.sh` boots the server and opens a cloudflared quick tunnel. Copy the
printed `https://*.trycloudflare.com` URL — that + `/api/scan` is your public
endpoint. The server also prints a **SCAN_TOKEN**; callers must send it.

Local-only (no tunnel): `node server.js`, then open `client.html`.

## Endpoints

- `POST /api/scan` `{ "target": "https://example.com" }` + header `X-Scan-Token: <token>` → `202 { id }`
- `GET  /api/scan/:id` → status + `logTail` + `artifacts`
- `GET  /api/health` → liveness + current config

## Guardrails (ON by default — loosen deliberately)

| env | default | effect |
|-----|---------|--------|
| `SCAN_TOKEN` | random, printed at boot | callers must send it |
| `OPEN` | unset | `OPEN=1` → **no token** (truly anyone) |
| `ALLOWED_HOSTS` | `mantishack.com,virelity.com` | comma list of allowed target host suffixes |
| | set to `*` | allow ANY target — **open attack relay, use with care** |
| `MAX_CONCURRENT` | `1` | scans at a time |
| `MAX_QUEUE` | `5` | rejects with 503 when full |
| `RATE_PER_MIN` | `6` | per-IP request cap |
| `RUN_TIMEOUT_MS` | `600000` | kill a scan after 10 min |
| `USE_DOCKER` | unset | `USE_DOCKER=1` → run scans in the container |
| `HARNESS_DIR` | `~/Projects/mantishack` | where `mantishack.py` lives |
| `CORS_ORIGIN` | `https://mantishack.com` | `Access-Control-Allow-Origin` value |

Private / loopback / cloud-metadata IPs are **always** blocked (anti-SSRF),
even with `ALLOWED_HOSTS=*`.

### Fully open, as originally asked (understand the risk first)

```bash
OPEN=1 ALLOWED_HOSTS='*' ./start.sh
```

This lets anyone on the internet make your laptop scan any site, from your IP,
with your API budget. The token + allowlist exist precisely to avoid that.

## Container mode

```bash
docker build -f Dockerfile -t mantis-web:local ..
USE_DOCKER=1 ./start.sh
```

The image covers **web mode only** (URL scanning). CodeQL / fuzzing / agentic
modes need the full devcontainer image (`~/Projects/mantishack/.devcontainer`).

## Wiring the website

Point the site's scan call at your tunnel URL. Minimal client in `client.html`
shows the exact request/response shape to copy into `try.html`.
