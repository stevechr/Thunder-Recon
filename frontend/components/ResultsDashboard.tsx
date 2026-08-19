"use client";

import { ScanResult } from "@/lib/api";
import RiskGauge from "./RiskGauge";

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-panel border border-panelBorder rounded-lg p-5">
      <h3 className="font-display text-xs tracking-widest uppercase text-cyan-signal mb-3">
        {title}
      </h3>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 border-b border-panelBorder/50 last:border-0 text-sm">
      <span className="text-mist">{label}</span>
      <span className="text-right" style={{ color: "#E8EDF2" }}>
        {value ?? "—"}
      </span>
    </div>
  );
}

export default function ResultsDashboard({ result }: { result: ScanResult }) {
  const { dns_records, whois, ip_intel, ssl, ports, technology, breaches, risk } = result;

  return (
    <div className="w-full max-w-5xl space-y-6">
      {/* Header + risk */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-6 bg-panel border border-panelBorder rounded-lg p-6">
        <div>
          <div className="text-xs text-mist uppercase tracking-widest">Target</div>
          <div className="font-display text-2xl md:text-3xl" style={{ color: "#E8EDF2" }}>
            {result.domain}
          </div>
          <div className="text-sm text-mist mt-1">{result.ip}</div>
        </div>
        <RiskGauge score={risk.score} rating={risk.rating} />
      </div>

      {/* Findings */}
      {risk.findings.length > 0 && (
        <Card title="Findings">
          <ul className="space-y-2">
            {risk.findings.map((f, i) => (
              <li key={i} className="flex gap-2 text-sm">
                <span className="text-amber-warn">▲</span>
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {/* Breach Intelligence Section */}
      <Card title={`Data Breach & Leak Intelligence (${breaches?.breach_count || 0} breaches)`}>
        {(!breaches || breaches.breach_count === 0) ? (
          <div className="flex items-center gap-3 p-3 bg-cyan-signal/10 border border-cyan-signal/30 rounded-md text-sm text-cyan-signal">
            <span>✅</span>
            <span>No historical data breaches or domain credential dumps detected for {result.domain}.</span>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 p-3 bg-crimson-risk/10 border border-crimson-risk/30 rounded-md">
              <div className="text-sm text-crimson-risk font-semibold">
                ⚠️ Domain exposed in {breaches.breach_count} known data breaches ({breaches.total_pwned_accounts ? breaches.total_pwned_accounts.toLocaleString() : "Multiple"} compromised accounts).
              </div>
              <span className="text-xs font-mono font-bold px-2.5 py-1 bg-crimson-risk text-white rounded">
                {breaches.risk_level}
              </span>
            </div>

            {breaches.exposed_data_types && breaches.exposed_data_types.length > 0 && (
              <div className="text-xs">
                <span className="text-mist font-mono">EXPOSED ATTRIBUTES: </span>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {breaches.exposed_data_types.map((dt, i) => (
                    <span key={i} className="px-2 py-0.5 bg-panelBorder text-amber-warn rounded font-mono text-[11px]">
                      {dt}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-2">
              <div className="text-xs font-mono text-mist uppercase tracking-widest">Breach Event Records:</div>
              {breaches.breaches.map((b, idx) => (
                <div key={idx} className="bg-void/80 border border-panelBorder/70 p-3 rounded text-xs space-y-1">
                  <div className="flex justify-between font-bold text-amber-warn text-sm">
                    <span>{b.title || b.name}</span>
                    <span className="text-mist font-mono text-xs">{b.breach_date}</span>
                  </div>
                  {b.description && (
                    <p className="text-mist leading-relaxed" dangerouslySetInnerHTML={{ __html: b.description }} />
                  )}
                  {b.data_classes && b.data_classes.length > 0 && (
                    <div className="flex flex-wrap gap-1 pt-1">
                      {b.data_classes.map((dc, k) => (
                        <span key={k} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-crimson-risk/20 text-crimson-risk">
                          {dc}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* DNS */}
        <Card title="DNS records">
          {Object.keys(dns_records).length === 0 && <div className="text-sm text-mist">No records found</div>}
          {Object.entries(dns_records).map(([type, values]) => (
            <div key={type} className="mb-2">
              <div className="text-xs text-amber-warn mb-1">{type}</div>
              {values.map((v, i) => (
                <div key={i} className="text-sm break-all text-mist">{v}</div>
              ))}
            </div>
          ))}
        </Card>

        {/* SSL */}
        <Card title="SSL / TLS">
          {ssl.valid === false ? (
            <div className="text-sm text-crimson-risk">{ssl.error}</div>
          ) : (
            <>
              <Row label="Issuer" value={ssl.issuer} />
              <Row label="Valid to" value={ssl.valid_to?.slice(0, 10)} />
              <Row
                label="Days remaining"
                value={
                  <span className={ssl.expiring_soon ? "text-amber-warn" : ssl.expired ? "text-crimson-risk" : ""}>
                    {ssl.days_remaining}
                  </span>
                }
              />
              <Row label="TLS version" value={ssl.tls_version} />
              <Row label="Cipher" value={ssl.cipher} />
            </>
          )}
        </Card>

        {/* IP Intel */}
        <Card title="IP intelligence">
          <Row label="IP" value={ip_intel.ip} />
          <Row label="ISP" value={ip_intel.isp} />
          <Row label="Org" value={ip_intel.org} />
          <Row label="ASN" value={ip_intel.asn} />
          <Row label="Country" value={ip_intel.country} />
          <Row label="City" value={ip_intel.city} />
        </Card>

        {/* WHOIS */}
        <Card title="WHOIS">
          <Row label="Registrar" value={whois.registrar} />
          <Row label="Created" value={String(whois.creation_date ?? "—").slice(0, 10)} />
          <Row label="Expires" value={String(whois.expiration_date ?? "—").slice(0, 10)} />
          <Row label="Org" value={whois.org} />
        </Card>

        {/* Technology */}
        <Card title="Technology">
          <Row label="Server" value={technology.server} />
          <Row label="Powered by" value={technology.powered_by} />
          <Row label="CDN" value={technology.cdn} />
          <Row label="CMS" value={technology.cms?.join(", ") || "—"} />
          <div className="mt-3">
            <div className="text-xs text-mist uppercase tracking-widest mb-2">Security headers</div>
            {Object.entries(technology.security_headers || {}).map(([h, present]) => (
              <div key={h} className="flex justify-between text-sm py-0.5">
                <span className="text-mist">{h}</span>
                <span className={present ? "text-cyan-signal" : "text-crimson-risk"}>
                  {present ? "✓" : "✗"}
                </span>
              </div>
            ))}
          </div>
        </Card>

        {/* Ports */}
        <Card title={`Open ports (${ports.length})`}>
          {ports.length === 0 ? (
            <div className="text-sm text-mist">No open ports detected</div>
          ) : (
            <div className="space-y-1">
              {ports.map((p) => (
                <div key={p.port} className="flex justify-between text-sm">
                  <span>
                    <span className="text-cyan-signal">{p.port}</span>
                    <span className="text-mist">/{p.service}</span>
                  </span>
                  <span className="text-mist truncate max-w-[140px]">{p.banner || ""}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
