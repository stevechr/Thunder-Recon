import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Thunder Recon — Website Intelligence",
  description: "DNS, SSL, port, and technology reconnaissance for your own domains.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-mono min-h-screen">{children}</body>
    </html>
  );
}
