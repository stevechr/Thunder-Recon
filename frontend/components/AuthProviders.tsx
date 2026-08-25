"use client";

import React from "react";

export type ProviderType = "google" | "yahoo" | "microsoft" | "instant_pass" | "email" | "guest";

export interface AuthUser {
  email: string;
  name: string;
  provider: ProviderType;
  picture?: string;
  verified?: boolean;
  session_token?: string;
}

export function GoogleIcon({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24">
      <path
        fill="#4285F4"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
      />
      <path
        fill="#EA4335"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
      />
    </svg>
  );
}

export function YahooIcon({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none">
      <rect width="24" height="24" rx="4" fill="#6001D2" />
      <path
        d="M6 6L10.5 13.5V18.5H13.5V13.5L18 6H14.8L12 11.2L9.2 6H6Z"
        fill="white"
      />
      <circle cx="18" cy="17" r="1.5" fill="white" />
    </svg>
  );
}

export function MicrosoftIcon({ className = "w-4 h-4" }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24">
      <rect x="2" y="2" width="9.5" height="9.5" fill="#F25022" />
      <rect x="12.5" y="2" width="9.5" height="9.5" fill="#7FBA00" />
      <rect x="2" y="12.5" width="9.5" height="9.5" fill="#00A4EF" />
      <rect x="12.5" y="12.5" width="9.5" height="9.5" fill="#FFB900" />
    </svg>
  );
}

export function UserHeaderBadge({
  user,
  onSignOut,
}: {
  user: AuthUser;
  onSignOut: () => void;
}) {
  const getProviderIcon = () => {
    if (user.provider === "google") return <GoogleIcon className="w-3.5 h-3.5" />;
    if (user.provider === "yahoo") return <YahooIcon className="w-3.5 h-3.5" />;
    return <MicrosoftIcon className="w-3.5 h-3.5" />;
  };

  return (
    <div className="flex items-center gap-3 bg-panel border border-emerald-500/40 rounded-full px-3.5 py-1.5 shadow-md">
      <div className="relative">
        <img
          src={user.picture || `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(user.email)}`}
          alt={user.name}
          className="w-7 h-7 rounded-full border border-emerald-400/60 object-cover"
        />
        <div className="absolute -bottom-1 -right-1 bg-void rounded-full p-0.5 border border-panelBorder">
          {getProviderIcon()}
        </div>
      </div>
      <div className="flex flex-col text-left">
        <div className="flex items-center gap-1.5">
          <span className="text-xs font-semibold text-white leading-tight capitalize">{user.name}</span>
          <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
            Verified ✓
          </span>
        </div>
        <span className="text-[10px] font-mono text-cyan-signal">{user.email}</span>
      </div>
      <button
        onClick={onSignOut}
        className="ml-2 text-[11px] font-mono text-mist hover:text-rose-400 transition"
        title="Sign out"
      >
        Sign Out
      </button>
    </div>
  );
}

export function ProviderButtonsBar({
  user,
  onSelectProvider,
  onSignOut,
}: {
  user: AuthUser | null;
  onSelectProvider: (provider: ProviderType) => void;
  onSignOut: () => void;
}) {
  if (user) {
    const getProviderIcon = () => {
      if (user.provider === "google") return <GoogleIcon className="w-4 h-4" />;
      if (user.provider === "yahoo") return <YahooIcon className="w-4 h-4" />;
      if (user.provider === "microsoft") return <MicrosoftIcon className="w-4 h-4" />;
      return <span className="text-sm">⚡</span>;
    };

    return (
      <div className="flex items-center justify-between gap-3 bg-panel/70 border border-emerald-500/30 rounded-xl px-4 py-2.5 shadow-sm">
        <div className="flex items-center gap-2.5 text-xs font-mono">
          <span className="text-mist">Verified Account:</span>
          <div className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 rounded-lg text-emerald-400 font-semibold">
            {getProviderIcon()}
            <span>{user.email}</span>
            <span className="text-[10px] bg-emerald-500/20 px-1 py-0.2 rounded">✓</span>
          </div>
        </div>
        <button
          type="button"
          onClick={onSignOut}
          className="text-xs font-mono text-mist hover:text-rose-400 transition underline"
        >
          Switch Account
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-2.5 bg-panel/60 border border-panelBorder/80 rounded-xl p-3">
      <span className="text-xs font-mono text-mist">Sign in to scan with:</span>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onSelectProvider("google")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-panel border border-panelBorder hover:border-cyan-signal/60 text-xs font-mono text-mist hover:text-white transition shadow-sm hover:scale-[1.02] active:scale-95"
          title="Sign in with Gmail / Google"
        >
          <GoogleIcon className="w-4 h-4" />
          <span>Gmail</span>
        </button>

        <button
          type="button"
          onClick={() => onSelectProvider("yahoo")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-panel border border-panelBorder hover:border-purple-400 text-xs font-mono text-mist hover:text-white transition shadow-sm hover:scale-[1.02] active:scale-95"
          title="Sign in with Yahoo"
        >
          <YahooIcon className="w-4 h-4" />
          <span>Yahoo</span>
        </button>

        <button
          type="button"
          onClick={() => onSelectProvider("microsoft")}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-panel border border-panelBorder hover:border-blue-400 text-xs font-mono text-mist hover:text-white transition shadow-sm hover:scale-[1.02] active:scale-95"
          title="Sign in with Microsoft / Outlook"
        >
          <MicrosoftIcon className="w-4 h-4" />
          <span>Microsoft</span>
        </button>
      </div>
    </div>
  );
}
