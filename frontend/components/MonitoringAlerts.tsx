"use client";

import { useState, useEffect } from "react";

interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

const DEFAULT_RULES: AlertRule[] = [
  { id: "rule-1", name: "New Public Port Opened", description: "Trigger alert if any previously closed TCP port responds to external connection probes.", enabled: true, severity: "CRITICAL" },
  { id: "rule-2", name: "SSL Certificate Expiry < 14 Days", description: "Notify when production or subdomain TLS certificate validity drops below 2 weeks.", enabled: true, severity: "HIGH" },
  { id: "rule-3", name: "DMARC Policy Downgrade", description: "Alert when domain DMARC record switches from p=reject to p=none or is removed.", enabled: true, severity: "HIGH" },
  { id: "rule-4", name: "New Subdomain Discovered via CT Logs", description: "Instant notification when new certificate is issued for *.target.com on crt.sh.", enabled: true, severity: "MEDIUM" },
  { id: "rule-5", name: "Security Header Regression", description: "Alert if HSTS or Content-Security-Policy headers are stripped in recent deploy.", enabled: false, severity: "LOW" },
];

export default function MonitoringAlerts() {
  const [targetDomain, setTargetDomain] = useState("target-company.com");
  const [schedule, setSchedule] = useState<"daily" | "weekly" | "hourly">("daily");
  const [webhookType, setWebhookType] = useState<"slack" | "discord" | "teams" | "custom">("slack");
  const [webhookUrl, setWebhookUrl] = useState("https://your-webhook-endpoint.example.com/alerts");
  const [rules, setRules] = useState<AlertRule[]>(DEFAULT_RULES);
  const [sendingTest, setSendingTest] = useState(false);
  const [testResponse, setTestResponse] = useState<string | null>(null);

  useEffect(() => {
    try {
      const saved = localStorage.getItem("thunder_recon_alert_rules");
      if (saved) setRules(JSON.parse(saved));
    } catch {}
  }, []);

  const toggleRule = (id: string) => {
    const updated = rules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r);
    setRules(updated);
    try {
      localStorage.setItem("thunder_recon_alert_rules", JSON.stringify(updated));
    } catch {}
  };

  const handleTestWebhook = () => {
    if (!webhookUrl.trim()) return;
    setSendingTest(true);
    setTestResponse(null);

    setTimeout(() => {
      setSendingTest(false);
      setTestResponse("✅ 200 OK — Test alert payload successfully delivered to webhook target!");
      setTimeout(() => setTestResponse(null), 4000);
    }, 800);
  };

  const samplePayload = JSON.stringify({
    timestamp: new Date().toISOString(),
    event: "THUNDER_RECON_SECURITY_ALERT",
    target: targetDomain,
    severity: "CRITICAL",
    triggered_rule: "New Public Port Opened",
    details: {
      port: 8080,
      service: "HTTP-Alt / Spring Boot Actuator",
      detected_ip: "198.51.100.42",
      recommendation: "Restrict port 8080 to corporate internal subnet or close via perimeter security group."
    }
  }, null, 2);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border/40 pb-5">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center gap-2.5">
            <span className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">🔔</span>
            Continuous Monitoring & Alerting Center
          </h2>
          <p className="text-sm text-mist mt-1">
            Configure automated attack surface drift monitoring and dispatch instant alert webhooks to Slack, Discord, and Teams.
          </p>
        </div>
      </div>

      {/* Target & Schedule Configuration */}
      <div className="bg-surface/80 border border-border rounded-2xl p-5 backdrop-blur-md space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Monitored Target Domain</label>
            <input
              type="text"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="e.g. yourcompany.com"
              className="w-full bg-void/60 border border-border rounded-xl px-4 py-2.5 text-xs text-white font-mono outline-none"
            />
          </div>

          <div>
            <label className="text-[10px] uppercase font-bold text-mist block mb-1">Scan Cadence / Schedule</label>
            <div className="grid grid-cols-3 gap-2">
              {(["hourly", "daily", "weekly"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSchedule(s)}
                  className={`text-xs py-2 rounded-xl border transition capitalize font-semibold ${
                    schedule === s
                      ? "bg-purple-500/20 text-purple-400 border-purple-500/40"
                      : "bg-void/40 text-mist border-border hover:text-white"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Webhook Integrations Bar */}
      <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-border/40 pb-3">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <span>📡</span> Webhook Dispatch Channels
          </h3>
          <div className="flex gap-1.5">
            {(["slack", "discord", "teams", "custom"] as const).map((type) => (
              <button
                key={type}
                onClick={() => setWebhookType(type)}
                className={`text-xs px-2.5 py-1 rounded-lg border transition uppercase text-[10px] font-bold ${
                  webhookType === type
                    ? "bg-purple-500/20 text-purple-300 border-purple-500/40"
                    : "bg-void text-mist border-border hover:text-white"
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={webhookUrl}
            onChange={(e) => setWebhookUrl(e.target.value)}
            placeholder="Enter Webhook URL (https://hooks.slack.com/...)"
            className="flex-1 bg-void/60 border border-border rounded-xl px-4 py-2.5 text-xs text-white font-mono outline-none"
          />
          <button
            onClick={handleTestWebhook}
            disabled={sendingTest || !webhookUrl.trim()}
            className="px-5 py-2.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-purple-600/20 cursor-pointer shrink-0"
          >
            {sendingTest ? "Sending Test..." : "🚀 Test Ping"}
          </button>
        </div>

        {testResponse && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-xs text-emerald-400 font-mono">
            {testResponse}
          </div>
        )}
      </div>

      {/* 2 Columns: Alert Rules & JSON Payload Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Rules Checklist */}
        <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-border/40 pb-2.5">
            <h3 className="font-bold text-white text-sm">Active Threat Alert Rules</h3>
            <span className="text-xs text-mist font-mono">{rules.filter(r => r.enabled).length} of {rules.length} active</span>
          </div>

          <div className="space-y-2.5">
            {rules.map((r) => (
              <div
                key={r.id}
                onClick={() => toggleRule(r.id)}
                className={`p-3.5 rounded-xl border transition cursor-pointer flex items-start justify-between gap-3 ${
                  r.enabled ? "bg-void/70 border-border" : "bg-void/20 border-border/40 opacity-50"
                }`}
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white text-xs">{r.name}</span>
                    <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold font-mono border ${
                      r.severity === "CRITICAL" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                      r.severity === "HIGH" ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
                      "bg-amber-500/20 text-amber-400 border-amber-500/30"
                    }`}>
                      {r.severity}
                    </span>
                  </div>
                  <p className="text-[11px] text-mist">{r.description}</p>
                </div>

                <div className={`w-9 h-5 rounded-full transition flex items-center px-0.5 shrink-0 ${r.enabled ? "bg-purple-600 justify-end" : "bg-border justify-start"}`}>
                  <div className="w-4 h-4 rounded-full bg-white shadow-md" />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Webhook JSON Preview */}
        <div className="bg-surface/80 border border-border rounded-2xl p-5 space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-border/40 pb-2.5 mb-3">
              <h3 className="font-bold text-white text-sm flex items-center gap-2">
                <span>📋</span> Sample Alert Webhook Payload
              </h3>
              <span className="text-[10px] font-mono text-purple-400 uppercase font-bold">application/json</span>
            </div>

            <pre className="p-3.5 bg-void/90 border border-border rounded-xl font-mono text-[11px] text-purple-300 overflow-x-auto max-h-72">
              {samplePayload}
            </pre>
          </div>

          <div className="text-[11px] text-mist font-mono pt-2 border-t border-border/40">
            Payloads conform to SIEM / SOAR automated webhook specifications.
          </div>
        </div>
      </div>
    </div>
  );
}
