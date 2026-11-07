"use client";

import React, { useEffect, useState } from "react";
import { ShieldAlert, Activity, Database, Radio, ArrowRight, ExternalLink, Lock } from "lucide-react";

export default function ThreatLensPortal() {
  const [apiHealth, setApiHealth] = useState<{ status: string; service: string; version: string } | null>(null);
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
  const backendBase = apiUrl.replace("/api/v1", "");

  useEffect(() => {
    fetch(`${backendBase}/health`)
      .then((res) => res.json())
      .then((data) => setApiHealth(data))
      .catch(() => setApiHealth(null));
  }, [backendBase]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8 bg-[#070b14] text-slate-100">
      <div className="max-w-4xl w-full bg-[#0d1527] border border-[#1f305b] rounded-2xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow backdrop */}
        <div className="absolute top-0 right-0 w-96 h-96 bg-sky-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex items-center space-x-4 mb-6">
          <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-sky-400 via-blue-600 to-indigo-800 flex items-center justify-center shadow-lg shadow-sky-500/20">
            <ShieldAlert className="w-8 h-8 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-2xl font-bold tracking-wider text-white">
                THREAT<span className="text-sky-400">LENS</span>
              </h1>
              <span className="text-xs px-2.5 py-0.5 rounded bg-[#172342] text-sky-300 font-mono border border-[#1f305b]">
                v1.0 PRD
              </span>
            </div>
            <p className="text-xs text-slate-400 font-medium">SENTINOVA SECURITY SYSTEMS · CYBER THREAT INTELLIGENCE</p>
          </div>
        </div>

        <p className="text-slate-300 mb-8 leading-relaxed">
          ThreatLens consolidates, normalizes, deduplicates, enriches, scores (0–100), and operationalizes threat intelligence across modern Security Operations Centres (SOC).
        </p>

        {/* Status Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <div className="bg-[#111b33] border border-[#1f305b] rounded-xl p-4 flex items-center space-x-3">
            <Activity className="w-5 h-5 text-emerald-400" />
            <div>
              <div className="text-xs text-slate-400">API Status</div>
              <div className="text-sm font-semibold text-emerald-400">
                {apiHealth ? "Online & Healthy" : "FastAPI Backend"}
              </div>
            </div>
          </div>
          <div className="bg-[#111b33] border border-[#1f305b] rounded-xl p-4 flex items-center space-x-3">
            <Database className="w-5 h-5 text-sky-400" />
            <div>
              <div className="text-xs text-slate-400">Feed Engine</div>
              <div className="text-sm font-semibold text-sky-400">6 Multi-Source Collectors</div>
            </div>
          </div>
          <div className="bg-[#111b33] border border-[#1f305b] rounded-xl p-4 flex items-center space-x-3">
            <Radio className="w-5 h-5 text-purple-400" />
            <div>
              <div className="text-xs text-slate-400">Real-Time Gateway</div>
              <div className="text-sm font-semibold text-purple-400">WebSocket &lt; 5s Latency</div>
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-4 items-center pt-4 border-t border-[#172342]">
          <a
            href={`${backendBase}/dashboard`}
            className="inline-flex items-center space-x-2 px-6 py-3 rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold transition shadow-lg shadow-sky-500/20"
          >
            <span>Launch SOC Analyst Dashboard</span>
            <ArrowRight className="w-4 h-4" />
          </a>

          <a
            href={`${backendBase}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center space-x-2 px-5 py-3 rounded-lg bg-[#172342] hover:bg-[#1f305b] text-slate-200 text-sm font-medium border border-[#1f305b] transition"
          >
            <span>Interactive OpenAPI Swagger</span>
            <ExternalLink className="w-4 h-4" />
          </a>
        </div>

        <div className="mt-6 text-xs text-slate-500 flex items-center space-x-2">
          <Lock className="w-3.5 h-3.5 text-slate-400" />
          <span>Demo Credentials: <code>analyst</code> / <code>ciso</code> / <code>ir_lead</code> / <code>hunter</code> / <code>admin</code> (Password: <code>ThreatLens@2026!</code>)</span>
        </div>
      </div>
    </main>
  );
}
