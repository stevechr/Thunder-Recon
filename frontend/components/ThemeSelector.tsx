"use client";

import React, { useState, useEffect } from "react";

export type ThemeType = "aurora" | "obsidian" | "cyberpunk" | "matrix" | "crimson" | "deepblue";

export const THEMES: { id: ThemeType; name: string; icon: string; primary: string; bg: string }[] = [
  { id: "aurora", name: "Quantum Aurora", icon: "✨", primary: "#00F5D4", bg: "#03060A" },
  { id: "obsidian", name: "Cyber Obsidian", icon: "🛡️", primary: "#00F0FF", bg: "#07090E" },
  { id: "cyberpunk", name: "Synth Wave", icon: "🟣", primary: "#D946EF", bg: "#08060F" },
  { id: "matrix", name: "Matrix Terminal", icon: "🟢", primary: "#22C55E", bg: "#030805" },
  { id: "crimson", name: "Red Team", icon: "🔴", primary: "#EF4444", bg: "#0B0406" },
  { id: "deepblue", name: "Blue Command", icon: "🔵", primary: "#3B82F6", bg: "#040814" },
];

export default function ThemeSelector() {
  const [currentTheme, setCurrentTheme] = useState<ThemeType>("obsidian");
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => {
    try {
      const saved = (localStorage.getItem("thunder_recon_theme") as ThemeType) || "obsidian";
      setCurrentTheme(saved);
      document.documentElement.setAttribute("data-theme", saved);
    } catch {}
  }, []);

  const handleSelect = (theme: ThemeType) => {
    setCurrentTheme(theme);
    setIsOpen(false);
    try {
      localStorage.setItem("thunder_recon_theme", theme);
      document.documentElement.setAttribute("data-theme", theme);
    } catch {}
  };

  const activeThemeObj = THEMES.find((t) => t.id === currentTheme) || THEMES[0];

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-mono border border-white/10 bg-white/5 hover:bg-white/10 hover:border-white/20 transition-all text-slate-300 shadow-sm"
        title="Change UI Theme"
      >
        <span>{activeThemeObj.icon}</span>
        <span className="hidden sm:inline-block text-[11px] font-medium">{activeThemeObj.name}</span>
        <span
          className="w-2 h-2 rounded-full shadow-[0_0_8px]"
          style={{ backgroundColor: activeThemeObj.primary, boxShadow: `0 0 8px ${activeThemeObj.primary}` }}
        />
        <svg
          className={`w-3 h-3 transition-transform ${isOpen ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />
          <div className="absolute right-0 mt-2 w-48 py-1.5 rounded-xl bg-[#0d121c] border border-white/15 shadow-2xl backdrop-blur-2xl z-50 animate-fadeIn">
            <div className="px-3 py-1 text-[10px] uppercase font-mono tracking-wider text-slate-400 border-b border-white/5 mb-1">
              Select Cyber Theme
            </div>
            {THEMES.map((theme) => {
              const isSelected = currentTheme === theme.id;
              return (
                <button
                  key={theme.id}
                  onClick={() => handleSelect(theme.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 text-xs font-sans transition-all text-left ${
                    isSelected
                      ? "bg-white/10 text-white font-semibold"
                      : "text-slate-300 hover:bg-white/5 hover:text-white"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span>{theme.icon}</span>
                    <span>{theme.name}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-2.5 h-2.5 rounded-full border border-white/20"
                      style={{ backgroundColor: theme.primary }}
                    />
                    {isSelected && (
                      <span className="text-[10px]" style={{ color: theme.primary }}>
                        ✓
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
