"use client";

import { useCallback, useEffect, useState } from "react";
import { fetchEvents, fetchStats } from "@/lib/api";
import type { AuditEvent, Stats } from "@/lib/types";
import KpiCard from "@/components/KpiCard";
import { ActionChart, AttackChart, RiskHistogram } from "@/components/Charts";
import EventFeed from "@/components/EventFeed";
import RedTeamPanel from "@/components/RedTeamPanel";
import { riskColor } from "@/lib/colors";

const POLL_MS = 5000;

function ThreatLevelBar({ score }: { score: number }) {
  const color = riskColor(score);
  const label =
    score >= 0.9 ? "CRITICAL" :
    score >= 0.75 ? "HIGH" :
    score >= 0.5 ? "ELEVATED" :
    score >= 0.25 ? "GUARDED" : "NOMINAL";

  return (
    <div className="flex items-center gap-2">
      <span className="text-[9px] font-bold tracking-[0.2em] mono" style={{ color: "var(--muted2)" }}>
        THREAT
      </span>
      <div className="flex gap-[3px]">
        {["NOMINAL","GUARDED","ELEVATED","HIGH","CRITICAL"].map((lvl, i) => {
          const levels = ["NOMINAL","GUARDED","ELEVATED","HIGH","CRITICAL"];
          const active = levels.indexOf(label) >= i;
          const lvlColors = ["#00ffa3","#00b0ff","#ffc107","#ff6d00","#ff1744"];
          return (
            <div
              key={lvl}
              className="h-3 w-5 rounded-sm transition-all duration-500"
              style={{
                background: active ? lvlColors[i] : "var(--border2)",
                boxShadow: active ? `0 0 6px ${lvlColors[i]}90` : "none",
                opacity: active ? 1 : 0.3,
              }}
            />
          );
        })}
      </div>
      <span className="text-[9px] font-bold tracking-[0.15em] mono" style={{ color }}>
        {label}
      </span>
    </div>
  );
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const [live, setLive] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const [s, e] = await Promise.all([fetchStats(), fetchEvents(200)]);
      setStats(s);
      setEvents(e);
      setError(null);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reach API");
    }
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [live, refresh]);

  const avgRisk = stats?.avg_risk_score ?? 0;
  const detectionColor = riskColor(stats?.detection_rate ?? 0);

  return (
    <div className="min-h-screen flex flex-col" style={{ background: "var(--bg)" }}>

      {/* ── Header ── */}
      <header
        className="flex items-center justify-between px-6 sticky top-0 z-50 h-14 overflow-hidden"
        style={{
          background: "rgba(2,4,10,0.92)",
          backdropFilter: "blur(16px)",
          borderBottom: "1px solid var(--border)",
          boxShadow: "0 1px 0 rgba(0,255,163,0.06)",
        }}
      >
        {/* Scan sweep line */}
        <div className="scan-sweep" />

        {/* Logo */}
        <div className="flex items-center gap-4">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center text-base font-bold mono"
            style={{
              background: "linear-gradient(135deg, #00ffa312, #00ffa306)",
              border: "1px solid #00ffa335",
              color: "#00ffa3",
              boxShadow: "0 0 16px #00ffa320",
            }}
          >
            ⬡
          </div>
          <div>
            <div
              className="text-sm font-bold tracking-[0.12em] mono glitch leading-none"
              style={{ color: "#00ffa3" }}
            >
              PROMPTSENTRY
            </div>
            <div className="text-[9px] tracking-[0.18em] mono leading-none mt-0.5" style={{ color: "var(--muted)" }}>
              THREAT MONITOR v0.1
            </div>
          </div>

          {/* Threat level */}
          <div
            className="ml-4 px-3 py-1 rounded"
            style={{ background: "var(--surface)", border: "1px solid var(--border2)" }}
          >
            <ThreatLevelBar score={avgRisk} />
          </div>
        </div>

        {/* Right controls */}
        <div className="flex items-center gap-2">
          {error && (
            <span className="text-[10px] px-2 py-1 rounded mono" style={{ background: "var(--red-dim)", color: "var(--red)", border: "1px solid var(--red-border)" }}>
              ⚠ API OFFLINE
            </span>
          )}

          {lastRefresh && !error && (
            <span className="text-[10px] tabular-nums mono" style={{ color: "var(--muted)" }}>
              {lastRefresh.toLocaleTimeString()}
            </span>
          )}

          <button
            onClick={() => setLive((l) => !l)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] font-bold mono transition-all"
            style={{
              background: live ? "#00ffa310" : "transparent",
              color: live ? "#00ffa3" : "var(--muted2)",
              border: `1px solid ${live ? "#00ffa330" : "var(--border2)"}`,
              letterSpacing: "0.12em",
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full pulse-dot"
              style={{
                background: live ? "#00ffa3" : "var(--muted)",
                boxShadow: live ? "0 0 6px #00ffa3" : "none",
              }}
            />
            {live ? "LIVE" : "PAUSED"}
          </button>

          <button
            onClick={refresh}
            className="px-3 py-1.5 rounded text-[10px] font-bold mono transition-all hover:bg-white/5"
            style={{ color: "var(--muted2)", border: "1px solid var(--border2)", letterSpacing: "0.1em" }}
          >
            ↺ SYNC
          </button>

          <a
            href={process.env.NEXT_PUBLIC_API_DOCS_URL ?? "http://localhost:8100/docs"}
            target="_blank"
            rel="noopener noreferrer"
            className="px-3 py-1.5 rounded text-[10px] font-bold mono transition-all hover:bg-white/5"
            style={{ color: "var(--muted2)", border: "1px solid var(--border2)", letterSpacing: "0.1em" }}
          >
            API ↗
          </a>
        </div>
      </header>

      {/* ── Content ── */}
      <main className="flex-1 px-6 py-5 flex flex-col gap-5 max-w-[1600px] mx-auto w-full">

        {/* Error bar */}
        {error && (
          <div
            className="rounded-lg px-5 py-3 text-[11px] mono flex items-center gap-3 animate-fade-in"
            style={{ background: "var(--red-dim)", color: "var(--red)", border: "1px solid var(--red-border)" }}
          >
            <span>⚠</span>
            <span>
              CANNOT REACH API
            </span>
          </div>
        )}

        {/* ── KPI row ── */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <KpiCard label="Total Events"   value={stats?.total ?? 0}                                  accent="#00ffa3" icon="◎" />
          <KpiCard label="Blocked"        value={stats?.blocked ?? 0}                                accent="#ff1744" icon="✕" sub="action = block" />
          <KpiCard label="Alerted"        value={stats?.alerted ?? 0}                                accent="#ff6d00" icon="⚑" sub="action = alert" />
          <KpiCard label="Detection Rate" value={stats ? `${Math.round(stats.detection_rate * 100)}%` : "0%"} accent={detectionColor} icon="◈" />
          <KpiCard label="Avg Risk"       value={stats ? `${Math.round(stats.avg_risk_score * 100)}%` : "0%"} accent={riskColor(avgRisk)} icon="◉" />
        </div>

        {/* ── Charts row ── */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <ActionChart   data={stats?.action_counts ?? {}} />
          <AttackChart   data={stats?.attack_counts ?? {}} />
          <RiskHistogram data={stats?.risk_buckets  ?? {}} />
        </div>

        {/* ── Event feed ── */}
        <section className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h2 className="text-[9px] font-bold tracking-[0.2em] uppercase mono" style={{ color: "var(--muted2)" }}>
                {"// Event Feed"}
              </h2>
              {events.length > 0 && (
                <span className="text-[9px] mono px-2 py-0.5 rounded" style={{ background: "#00ffa310", color: "#00ffa3", border: "1px solid #00ffa325" }}>
                  {events.length} loaded
                </span>
              )}
            </div>
            {events.length > 0 && (
              <span className="text-[9px] mono" style={{ color: "var(--muted)" }}>
                showing last {Math.min(events.length, 50)}
              </span>
            )}
          </div>
          <EventFeed events={events} limit={50} />
        </section>

        {/* ── Red team ── */}
        <section className="flex flex-col gap-2">
          <h2 className="text-[9px] font-bold tracking-[0.2em] uppercase mono" style={{ color: "var(--muted2)" }}>
            {"// Red Team"}
          </h2>
          <RedTeamPanel />
        </section>
      </main>

      {/* ── Footer ── */}
      <footer
        className="flex items-center justify-between px-6 py-2.5 mono text-[9px]"
        style={{ color: "var(--muted)", borderTop: "1px solid var(--border)", letterSpacing: "0.1em" }}
      >
        <span>PROMPTSENTRY <span className="blink">_</span></span>
        <span style={{ color: "var(--border2)" }}>{"// polling every "}{POLL_MS / 1000}s</span>
        <span>⬡</span>
      </footer>
    </div>
  );
}
