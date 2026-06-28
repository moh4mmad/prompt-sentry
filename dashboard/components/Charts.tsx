"use client";

import {
  Bar, BarChart, CartesianGrid, Cell,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { ACTION_COLORS, ATTACK_PALETTE } from "@/lib/colors";

const TOOLTIP_STYLE = {
  background: "#070d1a",
  border: "1px solid #162845",
  borderRadius: 6,
  color: "#b8cce4",
  fontSize: 11,
  fontFamily: "'Space Mono', monospace",
  boxShadow: "0 8px 40px rgba(0,0,0,0.7), 0 0 16px rgba(0,255,163,0.06)",
  padding: "8px 12px",
};

const TICK = { fill: "#2a4060", fontSize: 10, fontFamily: "'Space Mono', monospace" };

interface BarEntry { name: string; value: number; }

function Panel({
  title, children, accent = "#00ffa3", tag,
}: {
  title: string;
  children: React.ReactNode;
  accent?: string;
  tag?: string;
}) {
  return (
    <div
      className="rounded-xl p-5 flex flex-col gap-4 relative overflow-hidden hex-bg"
      style={{
        background: "linear-gradient(145deg, var(--surface) 0%, var(--surface2) 100%)",
        border: `1px solid ${accent}20`,
        boxShadow: `0 0 30px ${accent}06, inset 0 1px 0 ${accent}12`,
      }}
    >
      {/* Top edge glow */}
      <div
        className="absolute top-0 left-[15%] right-[15%] h-[1px]"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}, transparent)`, opacity: 0.5 }}
      />
      {/* Corner ticks */}
      <div className="absolute top-2 left-2 w-2 h-2 opacity-30" style={{ borderTop: `1px solid ${accent}`, borderLeft: `1px solid ${accent}` }} />
      <div className="absolute top-2 right-2 w-2 h-2 opacity-30" style={{ borderTop: `1px solid ${accent}`, borderRight: `1px solid ${accent}` }} />

      <div className="flex items-center justify-between">
        <h2 className="text-[9px] font-bold tracking-[0.2em] uppercase mono" style={{ color: "var(--muted2)" }}>
          {title}
        </h2>
        {tag && (
          <span className="text-[9px] mono px-1.5 py-0.5 rounded" style={{ color: accent, background: `${accent}12`, border: `1px solid ${accent}25` }}>
            {tag}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

function Empty({ accent = "#00ffa3" }: { accent?: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-40 gap-3">
      <div
        className="w-9 h-9 rounded-full flex items-center justify-center mono text-lg"
        style={{ border: `1px solid ${accent}30`, color: accent, opacity: 0.4 }}
      >
        ◌
      </div>
      <p className="text-[11px] mono" style={{ color: "var(--muted)" }}>
        {"// awaiting data"}
      </p>
    </div>
  );
}

export function ActionChart({ data }: { data: Record<string, number> }) {
  const entries: BarEntry[] = Object.entries(data).map(([name, value]) => ({ name, value }));
  if (!entries.length) return <Panel title="Action Breakdown" accent="#00ffa3"><Empty /></Panel>;

  return (
    <Panel title="Action Breakdown" accent="#00ffa3" tag="live">
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={entries} margin={{ top: 4, right: 4, left: -24, bottom: 0 }} barCategoryGap="35%">
          <CartesianGrid strokeDasharray="2 6" stroke="#0f1e35" vertical={false} />
          <XAxis dataKey="name" tick={TICK} axisLine={false} tickLine={false} />
          <YAxis tick={TICK} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(0,255,163,0.04)" }} />
          <Bar dataKey="value" radius={[3, 3, 0, 0]} isAnimationActive={true} animationDuration={600} animationEasing="ease-out">
            {entries.map((e) => {
              const c = ACTION_COLORS[e.name] ?? "#2a4060";
              return (
                <Cell key={e.name} fill={c} style={{ filter: `drop-shadow(0 0 5px ${c}70)` }} />
              );
            })}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

export function AttackChart({ data }: { data: Record<string, number> }) {
  const entries: BarEntry[] = Object.entries(data)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name: name.replace(/_/g, " "), value }));

  if (!entries.length) return <Panel title="Attack Types" accent="#d050ff"><Empty accent="#d050ff" /></Panel>;

  return (
    <Panel title="Attack Types" accent="#d050ff" tag={`top ${entries.length}`}>
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={entries} layout="vertical" margin={{ top: 4, right: 12, left: 0, bottom: 0 }} barCategoryGap="30%">
          <CartesianGrid strokeDasharray="2 6" stroke="#0f1e35" horizontal={false} />
          <XAxis type="number" tick={TICK} axisLine={false} tickLine={false} />
          <YAxis
            type="category"
            dataKey="name"
            tick={{ ...TICK, fill: "#b8cce4", fontSize: 9 }}
            width={108}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(208,80,255,0.04)" }} />
          <Bar dataKey="value" radius={[0, 3, 3, 0]} isAnimationActive={true} animationDuration={600} animationEasing="ease-out">
            {entries.map((_, i) => {
              const c = ATTACK_PALETTE[i % ATTACK_PALETTE.length];
              return <Cell key={i} fill={c} style={{ filter: `drop-shadow(0 0 4px ${c}55)` }} />;
            })}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

export function RiskHistogram({ data }: { data: Record<string, number> }) {
  const entries = Object.entries(data).map(([bucket, count]) => ({
    bucket,
    count,
    color: riskBucketColor(parseFloat(bucket)),
  }));

  if (!entries.length) return <Panel title="Risk Distribution" accent="#ffc107"><Empty accent="#ffc107" /></Panel>;

  return (
    <Panel title="Risk Distribution" accent="#ffc107" tag="histogram">
      <ResponsiveContainer width="100%" height={180}>
        <BarChart data={entries} margin={{ top: 4, right: 4, left: -24, bottom: 0 }} barCategoryGap="15%">
          <CartesianGrid strokeDasharray="2 6" stroke="#0f1e35" vertical={false} />
          <XAxis dataKey="bucket" tick={{ ...TICK, fontSize: 9 }} axisLine={false} tickLine={false} />
          <YAxis tick={TICK} axisLine={false} tickLine={false} />
          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "rgba(255,193,7,0.04)" }} />
          <Bar dataKey="count" radius={[3, 3, 0, 0]} isAnimationActive={true} animationDuration={600} animationEasing="ease-out">
            {entries.map((e, i) => (
              <Cell key={i} fill={e.color} style={{ filter: `drop-shadow(0 0 5px ${e.color}55)` }} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </Panel>
  );
}

function riskBucketColor(v: number): string {
  if (v >= 0.9) return "#ff1744";
  if (v >= 0.7) return "#ff6d00";
  if (v >= 0.5) return "#ffc107";
  if (v >= 0.3) return "#00b0ff";
  return "#00ffa3";
}
