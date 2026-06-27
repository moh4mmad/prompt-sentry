"use client";

import { ACTION_COLORS, SEVERITY_COLORS } from "@/lib/colors";

const ACTION_ICONS: Record<string, string> = {
  allow:    "✓",
  monitor:  "◎",
  sanitize: "⚙",
  block:    "✕",
  alert:    "⚑",
};

export function ActionBadge({ value }: { value: string }) {
  const color = ACTION_COLORS[value] ?? "#2a4060";
  const icon  = ACTION_ICONS[value] ?? "·";
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.15em] mono"
      style={{
        background: `${color}14`,
        color,
        border: `1px solid ${color}35`,
        boxShadow: `0 0 6px ${color}20`,
      }}
    >
      <span style={{ fontSize: 8, opacity: 0.9 }}>{icon}</span>
      {value}
    </span>
  );
}

const SEVERITY_ICONS: Record<string, string> = {
  low:      "▽",
  medium:   "◇",
  high:     "△",
  critical: "◆",
};

export function SeverityBadge({ value }: { value: string }) {
  const color = SEVERITY_COLORS[value] ?? "#2a4060";
  const icon  = SEVERITY_ICONS[value] ?? "·";
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.12em] mono"
      style={{
        background: `${color}12`,
        color,
        border: `1px solid ${color}30`,
      }}
    >
      <span style={{ fontSize: 8 }}>{icon}</span>
      {value}
    </span>
  );
}
