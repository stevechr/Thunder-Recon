"use client";

import { useEffect, useState } from "react";

export interface GoogleUser {
  email: string;
  name: string;
  picture?: string;
  sub?: string;
}

interface Props {
  onUserChange?: (user: GoogleUser | null) => void;
}

export function parseJwt(token: string): any {
  try {
    const base64Url = token.split(".")[1];
    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join("")
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return null;
  }
}

export default function GoogleAuth({ onUserChange }: Props) {
  const [user, setUser] = useState<GoogleUser | null>(null);

  // Restore user from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem("thunder_recon_google_user");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && parsed.email) {
          setUser(parsed);
          onUserChange?.(parsed);
        }
      }
    } catch (e) {
      console.warn("Could not parse saved Google user", e);
    }
  }, []);

  // Initialize Google Identity Services SDK if Client ID is configured
  useEffect(() => {
    const googleClientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
    if (!googleClientId) return;

    const handleCredentialResponse = (response: any) => {
      if (response && response.credential) {
        const payload = parseJwt(response.credential);
        if (payload && payload.email) {
          const userObj: GoogleUser = {
            email: payload.email,
            name: payload.name || payload.email.split("@")[0],
            picture: payload.picture,
            sub: payload.sub,
          };
          setUser(userObj);
          try {
            localStorage.setItem("thunder_recon_google_user", JSON.stringify(userObj));
          } catch (e) {}
          onUserChange?.(userObj);
        }
      }
    };

    if (typeof window !== "undefined" && !(window as any).google) {
      const script = document.createElement("script");
      script.src = "https://accounts.google.com/gsi/client";
      script.async = true;
      script.defer = true;
      script.onload = () => {
        try {
          (window as any).google.accounts.id.initialize({
            client_id: googleClientId,
            callback: handleCredentialResponse,
            auto_select: false,
          });
          const buttonDiv = document.getElementById("google-signin-btn");
          if (buttonDiv) {
            (window as any).google.accounts.id.renderButton(buttonDiv, {
              theme: "filled_dark",
              size: "medium",
              type: "standard",
              shape: "pill",
              text: "continue_with",
              logo_alignment: "left",
            });
          }
        } catch (err) {}
      };
      document.body.appendChild(script);
    } else if ((window as any).google) {
      try {
        (window as any).google.accounts.id.initialize({
          client_id: googleClientId,
          callback: handleCredentialResponse,
        });
        setTimeout(() => {
          const buttonDiv = document.getElementById("google-signin-btn");
          if (buttonDiv) {
            (window as any).google.accounts.id.renderButton(buttonDiv, {
              theme: "filled_dark",
              size: "medium",
              type: "standard",
              shape: "pill",
              text: "continue_with",
              logo_alignment: "left",
            });
          }
        }, 100);
      } catch (err) {}
    }
  }, [user]);

  const handleSignOut = () => {
    setUser(null);
    try {
      localStorage.removeItem("thunder_recon_google_user");
    } catch (e) {}
    onUserChange?.(null);
  };

  const handleGmailSignIn = () => {
    const inputEmail = prompt("Enter your Gmail address to sign in:", "stevechristopher96@gmail.com");
    if (inputEmail && inputEmail.trim().includes("@")) {
      const gmailUser: GoogleUser = {
        email: inputEmail.trim(),
        name: inputEmail.split("@")[0],
        picture: `https://api.dicebear.com/7.x/initials/svg?seed=${encodeURIComponent(inputEmail)}`,
      };
      setUser(gmailUser);
      try {
        localStorage.setItem("thunder_recon_google_user", JSON.stringify(gmailUser));
      } catch (e) {}
      onUserChange?.(gmailUser);
    }
  };

  if (user) {
    return (
      <div className="flex items-center gap-3 bg-panel border border-panelBorder rounded-full px-4 py-1.5 shadow-md">
        {user.picture ? (
          <img
            src={user.picture}
            alt={user.name}
            className="w-7 h-7 rounded-full border border-cyan-signal/50 object-cover"
          />
        ) : (
          <div className="w-7 h-7 rounded-full bg-cyan-signal/20 text-cyan-signal border border-cyan-signal/40 flex items-center justify-center font-display text-xs font-bold">
            {user.name.charAt(0).toUpperCase()}
          </div>
        )}
        <div className="flex flex-col text-left">
          <span className="text-xs font-medium text-white leading-tight">{user.name}</span>
          <span className="text-[10px] font-mono text-cyan-signal">{user.email}</span>
        </div>
        <button
          onClick={handleSignOut}
          className="ml-2 text-[11px] font-mono text-mist hover:text-rose-400 transition"
          title="Sign out of Google"
        >
          Sign Out
        </button>
      </div>
    );
  }

  const hasGoogleClientId = !!process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;

  return (
    <div className="flex items-center gap-2">
      {hasGoogleClientId ? (
        <div id="google-signin-btn" className="min-h-[40px] min-w-[180px]" />
      ) : (
        <button
          onClick={handleGmailSignIn}
          className="px-4 py-2 rounded-full bg-panel border border-panelBorder hover:border-cyan-signal/50 text-xs font-mono text-mist hover:text-white transition flex items-center gap-2 shadow-sm"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24">
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
          Continue with Gmail
        </button>
      )}
    </div>
  );
}
