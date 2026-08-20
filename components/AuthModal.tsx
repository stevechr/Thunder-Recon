"use client";

import React, { useState, useEffect } from "react";
import {
  AuthUser,
  GoogleIcon,
  YahooIcon,
  MicrosoftIcon,
  ProviderType,
} from "./AuthProviders";
import { sendVerificationCode, verifyCode, verifyGoogleToken } from "@/lib/api";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  targetDomain: string;
  initialProvider?: ProviderType;
  onAuthenticated: (user: AuthUser) => void;
}

export default function AuthModal({
  isOpen,
  onClose,
  targetDomain,
  initialProvider = "google",
  onAuthenticated,
}: Props) {
  const [selectedProvider, setSelectedProvider] = useState<ProviderType>(initialProvider);
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [step, setStep] = useState<"enter_email" | "enter_code">("enter_email");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [smtpNotice, setSmtpNotice] = useState<string | null>(null);
  const [fallbackCode, setFallbackCode] = useState<string | null>(null);

  // Initialize Google Identity Services OAuth button inside modal
  useEffect(() => {
    if (!isOpen) return;

    const googleClientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
    if (!googleClientId) return;

    const handleCredentialResponse = async (response: any) => {
      if (response && response.credential) {
        setLoading(true);
        setError(null);
        try {
          const verifiedUser = await verifyGoogleToken(response.credential);
          const authUser: AuthUser = {
            email: verifiedUser.email,
            name: verifiedUser.name,
            provider: "google",
            picture: verifiedUser.picture,
            verified: true,
            session_token: verifiedUser.session_token,
          };
          try {
            localStorage.setItem("thunder_recon_auth_user", JSON.stringify(authUser));
          } catch (e) {}
          onAuthenticated(authUser);
          onClose();
        } catch (err: any) {
          setError(err.message || "Google sign-in verification failed.");
        } finally {
          setLoading(false);
        }
      }
    };

    if (typeof window !== "undefined") {
      const initGsi = () => {
        if ((window as any).google?.accounts?.id) {
          try {
            (window as any).google.accounts.id.initialize({
              client_id: googleClientId,
              callback: handleCredentialResponse,
              auto_select: false,
            });
            const btnContainer = document.getElementById("modal-google-signin-btn");
            if (btnContainer) {
              (window as any).google.accounts.id.renderButton(btnContainer, {
                theme: "filled_dark",
                size: "large",
                type: "standard",
                shape: "pill",
                text: "continue_with",
                logo_alignment: "left",
                width: 280,
              });
            }
          } catch (e) {}
        }
      };

      if (!(window as any).google) {
        const script = document.createElement("script");
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.defer = true;
        script.onload = initGsi;
        document.body.appendChild(script);
      } else {
        setTimeout(initGsi, 100);
      }
    }
  }, [isOpen, selectedProvider]);

  if (!isOpen) return null;

  const getProviderDomain = (p: ProviderType) => {
    if (p === "google") return "gmail.com";
    if (p === "yahoo") return "yahoo.com";
    return "outlook.com";
  };

  const handleSendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) {
      setError("Please enter a valid email address.");
      return;
    }
    setLoading(true);
    setError(null);
    setSmtpNotice(null);
    setFallbackCode(null);
    try {
      const res = await sendVerificationCode(email);
      setStep("enter_code");
      setCode("");
      if (!res.email_delivered) {
        setSmtpNotice("Outbound email server is not configured in Vercel. Use the generated verification code below to verify your session.");
        if (res.verification_code) {
          setFallbackCode(res.verification_code);
          setCode(res.verification_code);
        }
      }
    } catch (err: any) {
      setError(err.message || "Failed to send verification code.");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!code || code.trim().length < 6) {
      setError("Please enter the 6-digit verification code.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await verifyCode(email, code);
      if (res.verified) {
        const authUser: AuthUser = {
          email: res.email,
          name: res.name,
          provider: selectedProvider,
          picture: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(res.email)}`,
          verified: true,
          session_token: res.session_token,
        };
        try {
          localStorage.setItem("thunder_recon_auth_user", JSON.stringify(authUser));
        } catch (e) {}
        onAuthenticated(authUser);
        onClose();
      }
    } catch (err: any) {
      setError(err.message || "Invalid or expired verification code.");
    } finally {
      setLoading(false);
    }
  };

  const handleSwitchProvider = (p: ProviderType) => {
    setSelectedProvider(p);
    setError(null);
    if (!email || email.endsWith("@gmail.com") || email.endsWith("@yahoo.com") || email.endsWith("@outlook.com")) {
      const prefix = email.split("@")[0] || "";
      setEmail(prefix ? `${prefix}@${getProviderDomain(p)}` : "");
    }
  };

  const hasGoogleClientId = !!process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      <div className="relative w-full max-w-md bg-panel border border-panelBorder rounded-2xl p-6 sm:p-7 shadow-2xl flex flex-col items-center text-center space-y-5">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-mist hover:text-white text-lg transition"
        >
          ✕
        </button>

        {/* Shield Icon */}
        <div className="w-14 h-14 rounded-2xl bg-cyan-signal/15 border border-cyan-signal/40 flex items-center justify-center text-2xl shadow-lg">
          🛡️
        </div>

        {/* Title */}
        <div>
          <h3 className="font-display text-xl font-bold text-white">
            Authenticate Account to Scan
          </h3>
          <p className="text-mist text-xs sm:text-sm mt-1.5 leading-relaxed">
            Target: <span className="text-cyan-signal font-mono font-semibold">{targetDomain || "domain"}</span>. To prevent unauthorized scans, please sign in with your verified email account.
          </p>
        </div>

        {/* Provider Selector Tabs */}
        <div className="flex bg-void/80 border border-panelBorder p-1 rounded-xl w-full justify-between gap-1">
          <button
            type="button"
            onClick={() => handleSwitchProvider("google")}
            className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-mono transition ${
              selectedProvider === "google"
                ? "bg-panel border border-cyan-signal/50 text-white font-bold"
                : "text-mist hover:text-white"
            }`}
          >
            <GoogleIcon className="w-3.5 h-3.5" />
            <span>Gmail</span>
          </button>
          <button
            type="button"
            onClick={() => handleSwitchProvider("yahoo")}
            className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-mono transition ${
              selectedProvider === "yahoo"
                ? "bg-panel border border-purple-400/50 text-white font-bold"
                : "text-mist hover:text-white"
            }`}
          >
            <YahooIcon className="w-3.5 h-3.5" />
            <span>Yahoo</span>
          </button>
          <button
            type="button"
            onClick={() => handleSwitchProvider("microsoft")}
            className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-lg text-xs font-mono transition ${
              selectedProvider === "microsoft"
                ? "bg-panel border border-blue-400/50 text-white font-bold"
                : "text-mist hover:text-white"
            }`}
          >
            <MicrosoftIcon className="w-3.5 h-3.5" />
            <span>Microsoft</span>
          </button>
        </div>

        {/* Google Native OAuth Option if configured */}
        {selectedProvider === "google" && hasGoogleClientId && (
          <div className="w-full flex flex-col items-center gap-3 py-1">
            <div id="modal-google-signin-btn" className="min-h-[44px]" />
            <div className="flex items-center gap-2 w-full text-xs text-mist/60 font-mono">
              <div className="flex-1 h-[1px] bg-panelBorder" />
              <span>OR USE EMAIL CODE</span>
              <div className="flex-1 h-[1px] bg-panelBorder" />
            </div>
          </div>
        )}

        {/* Email Passcode Verification Form */}
        {step === "enter_email" ? (
          <form onSubmit={handleSendCode} className="w-full space-y-4">
            <div className="space-y-1.5 text-left">
              <label className="text-[11px] font-mono uppercase tracking-wider text-mist">
                Enter your {selectedProvider === "google" ? "Gmail" : selectedProvider === "yahoo" ? "Yahoo" : "Microsoft"} Address:
              </label>
              <div className="flex items-center gap-2 bg-void border border-panelBorder rounded-xl px-3.5 py-2.5 focus-within:border-cyan-signal transition">
                {selectedProvider === "google" && <GoogleIcon className="w-4 h-4" />}
                {selectedProvider === "yahoo" && <YahooIcon className="w-4 h-4" />}
                {selectedProvider === "microsoft" && <MicrosoftIcon className="w-4 h-4" />}
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={`name@${getProviderDomain(selectedProvider)}`}
                  className="flex-1 bg-transparent outline-none text-white placeholder-mist/40 font-mono text-sm"
                />
              </div>
            </div>

            {error && (
              <div className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg p-2 font-mono">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !email.trim()}
              className="w-full py-2.5 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:brightness-110 disabled:opacity-30 disabled:cursor-not-allowed transition shadow-md"
            >
              {loading ? "Sending Passcode…" : "Send Verification Code →"}
            </button>
          </form>
        ) : (
          <form onSubmit={handleVerifyCode} className="w-full space-y-4">
            <div className="space-y-1.5 text-left">
              <div className="flex justify-between items-center text-[11px] font-mono text-mist">
                <span>Verification code for:</span>
                <button
                  type="button"
                  onClick={() => {
                    setStep("enter_email");
                    setError(null);
                    setSmtpNotice(null);
                    setFallbackCode(null);
                  }}
                  className="text-cyan-signal hover:underline"
                >
                  Change
                </button>
              </div>
              <div className="text-xs font-mono font-semibold text-white bg-void/70 border border-panelBorder px-3 py-1.5 rounded-lg">
                {email}
              </div>
            </div>

            {smtpNotice && (
              <div className="text-left bg-amber-500/10 border border-amber-500/30 rounded-xl p-3 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs text-amber-400 font-semibold font-mono">
                  <span>ℹ️ Outbound Mail Note:</span>
                </div>
                <p className="text-[11px] text-amber-300/90 font-mono leading-relaxed">
                  {smtpNotice}
                </p>
                {fallbackCode && (
                  <div className="mt-2 bg-void/80 border border-amber-500/40 rounded-lg px-3 py-2 text-center">
                    <span className="text-xs font-mono text-mist mr-2">Passcode:</span>
                    <span className="font-mono text-base font-bold text-amber-300 tracking-widest">{fallbackCode}</span>
                  </div>
                )}
              </div>
            )}

            <div className="space-y-1.5 text-left">
              <label className="text-[11px] font-mono uppercase tracking-wider text-mist">
                Enter 6-Digit Passcode:
              </label>
              <input
                type="text"
                required
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
                className="w-full bg-void border border-panelBorder rounded-xl px-4 py-2.5 text-center text-xl font-mono tracking-widest text-cyan-signal font-bold outline-none focus:border-cyan-signal transition"
              />
            </div>

            {error && (
              <div className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg p-2 font-mono">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || code.length < 6}
              className="w-full py-2.5 rounded-xl bg-cyan-signal text-void font-display font-bold text-sm hover:brightness-110 disabled:opacity-30 disabled:cursor-not-allowed transition shadow-md"
            >
              {loading ? "Verifying…" : "Verify & Start Scan ⚡"}
            </button>
          </form>
        )}

        <div className="flex items-center gap-1.5 text-[11px] text-mist/60 font-mono">
          <span>🔒 Cryptographic token verification protects against unvalidated scan requests.</span>
        </div>
      </div>
    </div>
  );
}
