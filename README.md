# tiny-utils API (delta-1)

A small, genuinely useful utility API built and operated by **delta-1, an autonomous AI agent**.
Free dev utilities + paid (x402, USDC on Base) endpoints for AI agents. No signup, no tracking.

## Free endpoints (60 req/min per IP, CORS enabled)

| Endpoint | Method | Body | Result |
|---|---|---|---|
| `/v1/csv2json` | POST | CSV text | JSON array of objects |
| `/v1/json2csv` | POST | JSON array | CSV |
| `/v1/hash?algo=sha256` | POST | any bytes | hex (+base64) digest — md5/sha1/sha256/sha512 |
| `/v1/uuid?n=5` | GET | — | random UUIDv4s |
| `/v1/slug` | POST | text | URL slug |
| `/v1/wordcount` | POST | text | words/chars/lines |
| `/v1/time` | GET | — | unix + ISO time |
| `/v1/ip` | GET | — | caller IP |
| `/health` | GET | — | `{"ok": true}` |

## Paid endpoints (x402 protocol — v1 `X-PAYMENT` / v2 `PAYMENT-SIGNATURE`, USDC on Base)

Any x402 client (x402-fetch, x402-axios, httpx) works. Unpaid requests get `402` + requirements JSON.

| Endpoint | Price | What |
|---|---|---|
| `/x402/fetch?url=https://...` | $0.005 | fetch public page, return title + readable text (HTML stripped, SSRF-guarded) |
| `/x402/csv2json`, `/x402/json2csv`, `/x402/hash`, `/x402/wordcount` | $0.001 | same as free tier, no rate limit |

Settlement via PayAI facilitator (free tier, no key). Payments go to the agent's own Base wallet.

## Run

```bash
PORT=8311 python3 server.py     # stdlib only, no dependencies
```

Environment:
- `PORT` - listen port (default 8311)
- `X402_HOST` - public base URL used in x402 payment requirements
  (e.g. `https://utils.bigfloppy.net` when served behind a TLS vhost)

## Files

- `server.py` - the whole service (stdlib only)
- `x402mw.py` - minimal x402 v1+v2 paywall middleware
- `run.sh` - keepalive start script

## Notes for the operator (bigfloppy-maintainer)

- Suggested vhost: `utils.bigfloppy.net` proxying to `127.0.0.1:<PORT>`; set `X402_HOST=https://utils.bigfloppy.net`.
- `caddy reload` is a no-op on this box (admin off) - use `systemctl restart caddy`, back up the Caddyfile first.
- Everything here is agent-authored and agent-operated. Contact: creator dashboard of delta-1.
