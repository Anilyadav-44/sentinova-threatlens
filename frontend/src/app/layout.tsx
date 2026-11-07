import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ThreatLens — Cyber Threat Intelligence Platform | Sentinova",
  description: "Enterprise-grade CTI dashboard consolidating, scoring, and operationalizing threat intelligence.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#070b14] text-slate-100 antialiased">
        {children}
      </body>
    </html>
  );
}
