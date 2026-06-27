"use client";

import { useEffect, useRef, useState } from "react";

interface Props {
  label: string;
  value: string | number;
  accent?: string;
  sub?: string;
  icon?: string;
}

function useCountUp(target: number, duration = 800) {
  const [display, setDisplay] = useState(0);
  const raf = useRef<number | null>(null);
  const start = useRef<number | null>(null);
  const from = useRef(0);

  useEffect(() => {
    from.current = display;
    start.current = null;
    if (raf.current) cancelAnimationFrame(raf.current);

    function step(ts: number) {
      if (!start.current) start.current = ts;
      const progress = Math.min((ts - start.current) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(from.current + (target - from.current) * ease));
      if (progress < 1) raf.current = requestAnimationFrame(step);
    }

    raf.current = requestAnimationFrame(step);
    return () => { if (raf.current) cancelAnimationFrame(raf.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  return display;
}

export default function KpiCard({ label, value, accent = "#00ffa3", sub, icon }: Props) {
  const isNumber = typeof value === "number";
  const isPercent = typeof value === "string" && value.endsWith("%");
  const numericTarget = isNumber ? value : isPercent ? parseFloat(value) : null;
  const animated = useCountUp(numericTarget ?? 0);

  const displayValue = isNumber
    ? animated
    : isPercent
    ? `${animated}%`
    : value;

  return (
    <div
      className="relative rounded-xl p-5 flex flex-col gap-3 overflow-hidden group transition-all duration-300 hover:-translate-y-0.5 hex-bg count-up"
      style={{
        background: `linear-gradient(145deg, var(--surface) 0%, var(--surface2) 100%)`,
        border: `1px solid ${accent}25`,
        boxShadow: `0 0 24px ${accent}08, inset 0 1px 0 ${accent}15`,
      }}
    >
      {/* Top neon line */}
      <div
        className="absolute top-0 left-[10%] right-[10%] h-[1px]"
        style={{ background: `linear-gradient(90deg, transparent, ${accent}, transparent)`, opacity: 0.7 }}
      />

      {/* Corner tick marks */}
      <div className="absolute top-2 left-2 w-2 h-2 opacity-40" style={{ borderTop: `1px solid ${accent}`, borderLeft: `1px solid ${accent}` }} />
      <div className="absolute top-2 right-2 w-2 h-2 opacity-40" style={{ borderTop: `1px solid ${accent}`, borderRight: `1px solid ${accent}` }} />
      <div className="absolute bottom-2 left-2 w-2 h-2 opacity-40" style={{ borderBottom: `1px solid ${accent}`, borderLeft: `1px solid ${accent}` }} />
      <div className="absolute bottom-2 right-2 w-2 h-2 opacity-40" style={{ borderBottom: `1px solid ${accent}`, borderRight: `1px solid ${accent}` }} />

      {/* Hover glow */}
      <div
        className="absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ background: `radial-gradient(ellipse at 50% 0%, ${accent}0c 0%, transparent 65%)` }}
      />

      <div className="flex items-center justify-between relative z-10">
        <span className="text-[9px] font-bold tracking-[0.2em] uppercase mono" style={{ color: "var(--muted2)" }}>
          {label}
        </span>
        {icon && (
          <span className="text-sm" style={{ color: accent, opacity: 0.7, textShadow: `0 0 8px ${accent}` }}>
            {icon}
          </span>
        )}
      </div>

      <div className="relative z-10">
        <span
          className="text-4xl font-bold tabular-nums leading-none mono"
          style={{
            color: accent,
            textShadow: `0 0 12px ${accent}80, 0 0 30px ${accent}30`,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {displayValue}
        </span>
        {/* blinking cursor */}
        <span className="blink ml-0.5 text-2xl leading-none" style={{ color: accent, opacity: 0.6 }}>_</span>
      </div>

      {sub && (
        <span className="text-[10px] mono relative z-10" style={{ color: "var(--muted)" }}>
          // {sub}
        </span>
      )}
    </div>
  );
}
