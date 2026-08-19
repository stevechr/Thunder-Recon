from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routers import scan, breach

app = FastAPI(
    title="Thunder Recon API",
    description="Website intelligence & reconnaissance API — DNS, WHOIS, IP intel, "
                 "SSL, open ports, web technology detection, and Am I Pwned breach engine.",
    version="0.2.0",
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


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {"status": "ok", "service": "Thunder Recon API"}
