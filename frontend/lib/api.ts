const API_BASE = process.env.NEXT_PUBLIC_API_BASE !== undefined
  ? process.env.NEXT_PUBLIC_API_BASE
  : (typeof window !== "undefined" && window.location.hostname !== "localhost" ? "" : "http://localhost:8000");


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
  email?: string | null;
  ip: string | null;
  dns_records: Record<string, string[]>;
  whois: Record<string, any>;
  ip_intel: Record<string, any>;
  ssl: Record<string, any>;
  ports: { port: number; service: string; state: string; banner: string | null }[];
  technology: Record<string, any>;
  breaches: BreachSummary;
  risk: { score: number; rating: string; findings: string[] };
  audit_modules?: Record<string, any>;
  threat_intel?: {
    integrity_score: number;
    integrity_rating: string;
    defacement: { is_defaced: boolean; status: string; findings: string[]; summary: string };
    malware_planted: { is_infected: boolean; status: string; findings: string[]; summary: string };
    seo_spam: { is_spammed: boolean; status: string; findings: string[]; summary: string };
    dns_spoofing: { is_spoofed: boolean; is_consistent: boolean; status: string; details: string };
    blacklists: { name: string; listed: boolean }[];
    target_online?: boolean;
  };
  virustotal?: {
    source: string;
    reputation: number;
    harmless_count: number;
    malicious_count: number;
    suspicious_count: number;
    undetected_count: number;
    total_engines: number;
    categories: string[];
    engine_results: { engine_name: string; category: string; result: string; method: string }[];
    urlhaus?: any;
    alienvault_otx?: any;
    vt_link: string;
  };
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

export interface UrlAnalysisResult {
  raw_url: string;
  final_url: string;
  scheme: string;
  domain: string;
  path: string;
  query_params: Record<string, string[]>;
  ip: string | null;
  status_code: number | null;
  content_type: string;
  server: string;
  is_accessible: boolean;
  redirect_hops_count: number;
  redirect_chain: { hop: number; url: string; status_code: number; location: string }[];
  heuristics: { type: string; details: string; severity: string }[];
  risk_score: number;
  risk_rating: string;
  virustotal: {
    source: string;
    reputation: number;
    harmless_count: number;
    malicious_count: number;
    suspicious_count: number;
    total_engines: number;
    engine_results: { engine_name: string; category: string; result: string; method: string }[];
    vt_url_link: string;
  };
}

export interface MailHeaderResult {
  envelope: {
    from: string;
    from_domain: string;
    to: string;
    subject: string;
    date: string;
    message_id: string;
    return_path: string;
    reply_to: string;
    originating_ip: string | null;
  };
  authentication: {
    spf: string;
    dkim: string;
    dmarc: string;
    auth_summary: string;
    raw_auth_results: string;
  };
  delivery_hops: {
    hop_number: number;
    from_host: string;
    by_host: string;
    protocol: string;
    ip: string | null;
    timestamp_raw: string;
    raw: string;
  }[];
  total_hops: number;
  security_flags: { severity: string; type: string; description: string }[];
  is_spoofed_or_phishing: boolean;
  trust_score: number;
  trust_rating: string;
  spam_telemetry: {
    spam_status: string;
    spam_score: string;
    virus_scanned: string;
  };
  error?: string;
}

export async function runScan(
  domain: string,
  authorized: boolean,
  includePorts: boolean = true,
  includeBreaches: boolean = true,
  email?: string,
  sessionToken?: string
): Promise<ScanResult> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (sessionToken) {
    headers["Authorization"] = `Bearer ${sessionToken}`;
  }

  const res = await fetch(`${API_BASE}/api/scan/full`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      domain,
      authorized,
      email: email?.trim() || undefined,
      session_token: sessionToken || undefined,
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

export async function analyzeUrl(url: string): Promise<UrlAnalysisResult> {
  const res = await fetch(`${API_BASE}/api/analyze/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url.trim() }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "URL analysis failed" }));
    throw new Error(err.detail || `URL analysis failed with status ${res.status}`);
  }

  return res.json();
}

export async function analyzeMailHeaders(rawHeaders: string): Promise<MailHeaderResult> {
  const res = await fetch(`${API_BASE}/api/analyze/mail-header`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_headers: rawHeaders.trim() }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Mail header analysis failed" }));
    throw new Error(err.detail || `Mail header analysis failed with status ${res.status}`);
  }

  return res.json();
}

export async function verifyGoogleToken(idToken?: string, accessToken?: string): Promise<{
  verified: boolean;
  email: string;
  name: string;
  picture?: string;
  provider: string;
  session_token: string;
}> {
  const res = await fetch(`${API_BASE}/api/auth/google-verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id_token: idToken || undefined,
      access_token: accessToken || undefined,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Google sign-in verification failed" }));
    throw new Error(err.detail || "Google authentication failed.");
  }

  return res.json();
}

export async function sendVerificationCode(email: string): Promise<{
  status: string;
  email: string;
  email_delivered: boolean;
  verification_code?: string;
  message: string;
}> {
  const res = await fetch(`${API_BASE}/api/auth/send-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: email.trim().toLowerCase() }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to send verification code" }));
    throw new Error(err.detail || "Could not send verification code.");
  }

  return res.json();
}

export async function verifyCode(email: string, code: string): Promise<{
  verified: boolean;
  email: string;
  name: string;
  session_token: string;
  message: string;
}> {
  const res = await fetch(`${API_BASE}/api/auth/verify-code`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email.trim().toLowerCase(),
      code: code.trim(),
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Verification failed" }));
    throw new Error(err.detail || "Invalid verification code.");
  }

  return res.json();
}

export async function quickVerify(email?: string, targetDomain?: string): Promise<{
  verified: boolean;
  email: string;
  name: string;
  provider: string;
  session_token: string;
  message: string;
}> {
  const res = await fetch(`${API_BASE}/api/auth/quick-verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: email?.trim() || undefined,
      target_domain: targetDomain?.trim() || undefined,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Quick authorization failed" }));
    throw new Error(err.detail || "Instant verification failed.");
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

export async function getHistory(limit = 20, email?: string) {
  const query = email ? `limit=${limit}&email=${encodeURIComponent(email)}` : `limit=${limit}`;
  const res = await fetch(`${API_BASE}/api/scan/history?${query}`);
  if (!res.ok) throw new Error("Could not load scan history");
  return res.json();
}

// ──────────────────────────────────────────────────────────────────
// Sandbox — File & URL Detonation Intelligence
// ──────────────────────────────────────────────────────────────────

export interface SandboxEngineResult {
  engine_name: string;
  category: string;
  result: string;
  method: string;
}

export interface SandboxBehavioralIndicator {
  type: string;
  severity: string;
  detail: string;
}

export interface SandboxVerdict {
  overall: string;           // "CLEAN" | "SUSPICIOUS" | "MALICIOUS" | "POTENTIALLY UNWANTED"
  color: string;             // "clean" | "suspicious" | "critical" | "warn"
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  undetected_count?: number;
  total_engines: number;
  reputation: number;
  risk_score?: number;
  risk_rating?: string;
}

export interface SandboxFileResult {
  submission: {
    filename: string;
    size_bytes: number;
    size_display: string;
    first_seen: string | null;
    last_seen: string | null;
    times_submitted: number;
  };
  file_identity: {
    md5: string;
    sha1: string;
    sha256: string;
    extension: string;
    magic_description: string;
    category: string;
    is_executable: boolean;
    is_suspicious_extension: boolean;
    entropy: number;
    entropy_level: string;
    entropy_risk: string;
  };
  verdict: SandboxVerdict;
  community: { votes_harmless: number; votes_malicious: number };
  engine_results: SandboxEngineResult[];
  behavioral_indicators: SandboxBehavioralIndicator[];
  embedded_iocs: {
    urls: string[];
    ips: string[];
    domains: string[];
    total_iocs: number;
  };
  malwarebazaar: Record<string, any> | null;
  source: string;
  vt_link: string;
}

export interface SandboxUrlResult {
  type: "url";
  submission: {
    raw_url: string;
    final_url: string;
    domain: string;
    ip: string | null;
    redirect_hops: number;
    redirect_chain: { hop: number; url: string; status_code: number; location: string }[];
    status_code: number | null;
    content_type: string;
    server: string;
    is_accessible: boolean;
    scheme: string;
    path: string;
  };
  verdict: SandboxVerdict;
  heuristics: { type: string; details: string; severity: string }[];
  engine_results: SandboxEngineResult[];
  source: string;
  vt_link: string;
}

export async function submitFileToSandbox(file: File): Promise<SandboxFileResult> {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/sandbox/file`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Sandbox analysis failed" }));
    throw new Error(err.detail || `Sandbox error: ${res.status}`);
  }

  return res.json();
}

export async function submitUrlToSandbox(url: string): Promise<SandboxUrlResult> {
  const res = await fetch(`${API_BASE}/api/sandbox/url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url.trim() }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Sandbox URL analysis failed" }));
    throw new Error(err.detail || `Sandbox URL error: ${res.status}`);
  }

  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// IP Intelligence Types & API
// ─────────────────────────────────────────────────────────────────
export interface IpIntelResult {
  target: string;
  resolved_ip: string;
  is_domain: boolean;
  reverse_dns: string;
  country: string;
  country_code: string;
  region: string;
  city: string;
  zip: string;
  latitude: number;
  longitude: number;
  timezone: string;
  isp: string;
  organization: string;
  asn: string;
  is_proxy: boolean;
  is_hosting: boolean;
  is_mobile: boolean;
  risk_score: number;
  threat_rating: string;
  color: string;
  threat_factors: { type: string; severity: string; detail: string }[];
}

export async function lookupIpIntel(target: string): Promise<IpIntelResult> {
  const res = await fetch(`${API_BASE}/api/ip/lookup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: target.trim() }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "IP lookup failed" }));
    throw new Error(err.detail || `IP lookup error: ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// SSL Inspector Types & API
// ─────────────────────────────────────────────────────────────────
export interface SslInspectResult {
  hostname: string;
  port: number;
  subject_cn: string;
  issuer_cn: string;
  serial_number: string;
  valid_from: string;
  valid_to: string;
  days_until_expiry: number;
  is_expired: boolean;
  sans: string[];
  total_sans: number;
  signature_algorithm: string;
  key_size: string;
  protocol_version: string;
  cipher_suite: string;
  cipher_bits: number;
  grade: string;
  risk_score: number;
  security_checks: { issue: string; severity: string; details: string }[];
}

export async function inspectSslCert(target: string, port = 443): Promise<SslInspectResult> {
  const res = await fetch(`${API_BASE}/api/ssl/inspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target: target.trim(), port }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "SSL inspection failed" }));
    throw new Error(err.detail || `SSL error: ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// DNS Intelligence Types & API
// ─────────────────────────────────────────────────────────────────
export interface DnsInspectResult {
  domain: string;
  total_records: number;
  dnssec_enabled: boolean;
  records: Record<string, any[]>;
  mail_security: {
    spf_record: string | null;
    dmarc_record: string | null;
    findings: { level: string; title: string; detail: string }[];
  };
}

export async function inspectDnsRecords(domain: string): Promise<DnsInspectResult> {
  const res = await fetch(`${API_BASE}/api/dns/inspect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: domain.trim() }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "DNS inspection failed" }));
    throw new Error(err.detail || `DNS error: ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// CVE Search Types & API
// ─────────────────────────────────────────────────────────────────
export interface CveItem {
  cve_id: string;
  published: string;
  last_modified: string;
  description: string;
  cvss_score: number;
  severity: string;
  attack_vector: string;
  vector_string: string;
  references: string[];
  nvd_url: string;
}

export interface CveSearchResult {
  query: string;
  total_results: number;
  cves: CveItem[];
  error?: string;
}

export async function searchCveVulnerabilities(query: string): Promise<CveSearchResult> {
  const res = await fetch(`${API_BASE}/api/cve/search`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: query.trim() }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "CVE search failed" }));
    throw new Error(err.detail || `CVE search error: ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// HTTP Security Headers Audit Types & API
// ─────────────────────────────────────────────────────────────────
export interface SecurityHeaderItem {
  header: string;
  key: string;
  present: boolean;
  value: string;
  description: string;
  recommendation: string;
  weight: number;
}

export interface HeaderAuditResult {
  raw_target: string;
  final_url: string;
  status_code: number;
  score_percentage: number;
  grade: string;
  headers_audited: SecurityHeaderItem[];
  info_leaks: { header: string; value: string; risk: string }[];
  raw_headers: Record<string, string>;
}

export async function auditSecurityHeaders(url: string): Promise<HeaderAuditResult> {
  const res = await fetch(`${API_BASE}/api/headers/audit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url.trim() }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Header audit failed" }));
    throw new Error(err.detail || `Header audit error: ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// WHOIS Intelligence Types & API
// ─────────────────────────────────────────────────────────────────
export interface WhoisResult {
  domain: string;
  registrar: string;
  whois_server: string;
  creation_date: string;
  expiration_date: string;
  updated_date: string;
  domain_age_days: number | null;
  days_to_expiry: number | null;
  is_recently_registered: boolean;
  name_servers: string[];
  abuse_emails: string[];
  domain_status: string[];
  raw_text: string;
}

export async function lookupWhois(domain: string): Promise<WhoisResult> {
  const res = await fetch(`${API_BASE}/api/whois/lookup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain: domain.trim() }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "WHOIS lookup failed" }));
    throw new Error(err.detail || `WHOIS error: ${res.status}`);
  }
  return res.json();
}

// ─────────────────────────────────────────────────────────────────
// Web Tech Stack Fingerprint Types & API
// ─────────────────────────────────────────────────────────────────
export interface TechItem {
  name: string;
  category: string;
  icon: string;
}

export interface TechDetectResult {
  url: string;
  final_url: string;
  status_code: number;
  total_detected: number;
  technologies: TechItem[];
}

export async function detectTechStack(url: string): Promise<TechDetectResult> {
  const res = await fetch(`${API_BASE}/api/tech/detect`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url.trim() }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Tech detection failed" }));
    throw new Error(err.detail || `Tech detection error: ${res.status}`);
  }
  return res.json();
}



