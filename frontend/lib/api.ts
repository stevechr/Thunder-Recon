const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export interface BreachDetail {
  name: string;
  title: string;
  domain?: string;
  breach_date: string;
  pwn_count?: number;
  data_classes: string[];
  description: string;
  industry?: string;
  is_verified?: boolean;
}

export interface BreachSummary {
  domain: string;
  breach_count: number;
  total_pwned_accounts: number;
  breaches: BreachDetail[];
  risk_level: string;
  exposed_data_types: string[];
  has_sensitive_leaks?: boolean;
  threat_summary?: string;
}

export interface ScanResult {
  domain: string;
  ip: string | null;
  dns_records: Record<string, string[]>;
  whois: Record<string, any>;
  ip_intel: Record<string, any>;
  ssl: Record<string, any>;
  ports: { port: number; service: string; state: string; banner: string | null }[];
  technology: Record<string, any>;
  breaches: BreachSummary;
  risk: { score: number; rating: string; findings: string[] };
}

export interface EmailBreachResult {
  email: string;
  is_pwned: boolean;
  breach_count: number;
  breaches: BreachDetail[];
  exposed_data_types: string[];
  risk_level: string;
  analytics?: {
    risk_score?: number;
    risk_label?: string;
    password_strength?: Record<string, any>;
  };
  error?: string;
}

export interface PasswordPwnedResult {
  pwned: boolean;
  count: number;
  sha1_prefix?: string;
  risk_level: string;
  recommendation: string;
  error?: string;
}

export async function runScan(
  domain: string,
  authorized: boolean,
  includePorts: boolean = true,
  includeBreaches: boolean = true
): Promise<ScanResult> {
  const res = await fetch(`${API_BASE}/api/scan/full`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      domain,
      authorized,
      include_ports: includePorts,
      include_breaches: includeBreaches,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Scan failed" }));
    throw new Error(err.detail || `Scan failed with status ${res.status}`);
  }

  return res.json();
}

export async function checkEmailBreach(email: string): Promise<EmailBreachResult> {
  const res = await fetch(`${API_BASE}/api/breach/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Breach check failed" }));
    throw new Error(err.detail || `Breach check failed with status ${res.status}`);
  }

  return res.json();
}

export async function checkPasswordPwned(password: string): Promise<PasswordPwnedResult> {
  const res = await fetch(`${API_BASE}/api/breach/password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Password check failed" }));
    throw new Error(err.detail || `Password check failed with status ${res.status}`);
  }

  return res.json();
}

export async function getHistory(limit = 20) {
  const res = await fetch(`${API_BASE}/api/scan/history?limit=${limit}`);
  if (!res.ok) throw new Error("Could not load scan history");
  return res.json();
}
