"use client";

import { riskColor } from "@/lib/colors";

export default function RiskScore({ value }: { value: number }) {
  const color = riskColor(value);
  const pct   = Math.round(value * 100);
  const bars  = 10;
  const filled = Math.round(value * bars);

  return (
    <div className="flex items-center gap-2">
      <div className="flex gap-[2px] items-end">
        {Array.from({ length: bars }).map((_, i) => (
          <div
            key={i}
            className="w-[3px] rounded-sm transition-all duration-300"
            style={{
              height: `${7 + i * 1.6}px`,
              background: i < filled ? color : "var(--border2)",
              boxShadow: i < filled ? `0 0 5px ${color}90` : "none",
              opacity: i < filled ? 1 : 0.4,
            }}
          />
        ))}
      </div>
      <span
        className="text-[11px] font-bold tabular-nums mono"
        style={{ color, textShadow: `0 0 8px ${color}70` }}
      >
        {pct}%
      </span>
    </div>
  );
}
