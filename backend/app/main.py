from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routers import scan, breach, auth, analyze, sandbox, ip, ssl_router, dns, cve, headers, whois_router, tech, tools

app = FastAPI(
    title="Thunder Recon API",
    description="Advanced Cybersecurity Reconnaissance & Threat Intelligence API.",
    version="4.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(breach.router)
app.include_router(auth.router)
app.include_router(analyze.router)
app.include_router(sandbox.router)
app.include_router(ip.router)
app.include_router(ssl_router.router)
app.include_router(dns.router)
app.include_router(cve.router)
app.include_router(headers.router)
app.include_router(whois_router.router)
app.include_router(tech.router)
app.include_router(tools.router)


try:
    init_db()
except Exception:
    pass

