# Thunder Recon

Website intelligence / reconnaissance dashboard: DNS, WHOIS, IP intel, SSL
certificate status, open ports, and web-stack detection for a target domain,
with a heuristic risk score.

**Use this only on domains you own or are explicitly authorized to test.**
The API requires `authorized: true` on every scan request, and the frontend
gates the scan button on an authorization checkbox — but that's a UX nudge,
not a real permission system. Don't point it at third-party domains without
consent.

## Structure

```
thunder-recon/
├── backend/                 FastAPI service
│   ├── app/
│   │   ├── main.py          App entrypoint
│   │   ├── database.py      SQLite (swap DATABASE_URL for Postgres)
│   │   ├── models.py        Pydantic request/response schemas
│   │   ├── routers/scan.py  /api/scan/* endpoints
│   │   └── services/        dns, ip/whois, ssl, ports, tech, risk scoring
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                Next.js 14 (App Router) + Tailwind
│   ├── app/                 page.tsx (dashboard), layout.tsx, globals.css
│   ├── components/          ScanForm, ResultsDashboard, RiskGauge
│   ├── lib/api.ts           Fetch client for the backend
│   └── Dockerfile
└── docker-compose.yml
```

## Run locally (no Docker)

**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API docs at `http://localhost:8000/docs`.

**Frontend**
```bash
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```
Dashboard at `http://localhost:3000`.

## Run with Docker

```bash
docker compose up --build
```

## API

`POST /api/scan/full`
```json
{
  "domain": "example.com",
  "authorized": true,
  "include_ports": true
}
```
Returns DNS records, WHOIS, IP intel, SSL cert details, open ports (from a
curated common-port list, TCP connect scan only — no nmap/masscan), detected
tech stack + security headers, and a 0–100 risk score with findings.

`GET /api/scan/history` — last N scans (id, domain, ip, risk_score, timestamp)
`GET /api/scan/history/{id}` — full stored result for one scan

## What's real vs. stubbed in this MVP

Real, working out of the box:
- DNS enumeration (dnspython)
- WHOIS (python-whois)
- IP geolocation/ASN via ip-api.com (free tier, no key)
- SSL/TLS certificate inspection (stdlib `ssl`)
- TCP connect port scan of ~17 common ports, with basic banner grab
- HTTP security header + lightweight CMS/CDN detection
- Heuristic risk scoring
- Scan history stored in SQLite

Intentionally left out of the MVP, per the original feature list — wire these
in when you're ready:
- CVE/vulnerability lookups (NVD API, CISA KEV)
- Screenshot capture (Playwright)
- Subdomain enumeration
- PDF report export
- Auth/user accounts, Celery/Redis job queue, Postgres in production
- AI-generated executive summary (drop in a call to the Anthropic API over
  the JSON this backend already returns)

## Notes on the port scanner

`backend/app/services/port_service.py` does a plain TCP `connect()` scan
against a fixed list of commonly-used ports — no raw sockets, no SYN
scanning, no nmap/masscan binary. That keeps it simple and doesn't need root,
but it's also slower and more visible than a real scanner. If you later wrap
`nmap` via subprocess, make sure the authorization check stays in front of it.
