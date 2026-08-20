from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    domain: str = Field(..., description="Target domain, e.g. example.com")
    authorized: bool = Field(
        ..., description="Must be true: confirms the requester owns or is authorized to scan this target."
    )
    email: str | None = Field(default=None, description="Requester Gmail / email address")
    session_token: str | None = Field(default=None, description="Cryptographic verified authentication session token")
    include_ports: bool = Field(default=True)
    include_breaches: bool = Field(default=True)


class ScanResponse(BaseModel):
    domain: str
    email: str | None = None
    ip: str | None
    dns_records: dict
    whois: dict
    ip_intel: dict
    ssl: dict
    ports: list
    technology: dict
    breaches: dict
    risk: dict
    audit_modules: dict | None = None
    threat_intel: dict | None = None
    virustotal: dict | None = None


class EmailCheckRequest(BaseModel):
    email: str = Field(..., description="Email address to check against data breaches.")


class PasswordCheckRequest(BaseModel):
    password: str = Field(..., description="Password string to check against Pwned Passwords via k-Anonymity.")
