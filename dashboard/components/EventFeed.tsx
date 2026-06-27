"use client";

import type { AuditEvent } from "@/lib/types";
import { ActionBadge, SeverityBadge } from "./ActionBadge";
import RiskScore from "./RiskScore";

interface Props {
  events: AuditEvent[];
  limit?: number;
}

export default function EventFeed({ events, limit = 50 }: Props) {
  const rows = [...events]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit);

  return (
    <div
      className="rounded-xl overflow-hidden hex-bg"
      style={{
        background: "linear-gradient(145deg, var(--surface) 0%, var(--surface2) 100%)",
        border: "1px solid #00ffa318",
        boxShadow: "0 0 30px rgba(0,255,163,0.04)",
      }}
    >
      {/* Header */}
      <div
        className="grid text-[9px] font-bold tracking-[0.18em] uppercase px-4 py-2.5 mono"
        style={{
          gridTemplateColumns: "90px 110px 90px 75px 130px 1fr 100px",
          color: "var(--muted2)",
          background: "var(--surface2)",
          borderBottom: "1px solid var(--border)",
        }}
      >
        {["// time", "source", "action", "severity", "risk", "attack types", "req id"].map((h) => (
          <span key={h}>{h}</span>
        ))}
      </div>

      {rows.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 gap-3">
          <div
            className="w-10 h-10 rounded-full flex items-center justify-center mono"
            style={{ border: "1px solid #00ffa330", color: "#00ffa3", fontSize: 20, opacity: 0.4 }}
          >
            ⬡
          </div>
          <p className="text-[11px] mono" style={{ color: "var(--muted)" }}>
            // no events — send a request to the API
          </p>
        </div>
      ) : (
        <div>
          {rows.map((e, i) => {
            const isHighRisk = e.action === "block" || e.action === "alert";
            return (
              <div
                key={e.event_id}
                className="grid items-center px-4 py-2 text-xs transition-colors hover:bg-white/[0.015] animate-slide-in"
                style={{
                  gridTemplateColumns: "90px 110px 90px 75px 130px 1fr 100px",
                  animationDelay: `${i * 15}ms`,
                  borderBottom: "1px solid var(--border)",
                  borderLeft: isHighRisk ? "2px solid var(--red)" : "2px solid transparent",
                }}
              >
                <span className="tabular-nums mono text-[10px]" style={{ color: "var(--muted2)" }}>
                  {new Date(e.timestamp).toLocaleTimeString()}
                </span>
                <span className="mono text-[10px] truncate" style={{ color: "var(--text)" }}>
                  {e.source ?? "—"}
                </span>
                <span>
                  {e.action ? <ActionBadge value={e.action} /> : <span style={{ color: "var(--muted)" }}>—</span>}
                </span>
                <span>
                  {e.severity ? <SeverityBadge value={e.severity} /> : <span style={{ color: "var(--muted)" }}>—</span>}
                </span>
                <span>
                  {e.risk_score != null ? <RiskScore value={e.risk_score} /> : <span style={{ color: "var(--muted)" }}>—</span>}
                </span>
                <span
                  className="truncate text-[10px] mono"
                  style={{ color: "#d050ff" }}
                  title={e.attack_types?.join(", ")}
                >
                  {e.attack_types?.join(", ") || <span style={{ color: "var(--muted)" }}>—</span>}
                </span>
                <span className="mono text-[9px]" style={{ color: "var(--muted)" }}>
                  {e.request_id?.slice(0, 10) ?? "—"}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
