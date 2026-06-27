"use client";

import { useState } from "react";
import { runRedTeam } from "@/lib/api";
import type { RedTeamResult } from "@/lib/types";
import { ActionBadge } from "./ActionBadge";

export default function RedTeamPanel() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RedTeamResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleRun() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await runRedTeam("library"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  const passRate = result ? Math.round(result.pass_rate * 100) : null;
  const passColor =
    passRate === null ? "#3d5070"
    : passRate >= 100 ? "#00ff9d"
    : passRate >= 80 ? "#ffb700"
    : "#ff2d55";

  return (
    <div
      className="rounded-xl p-5 flex flex-col gap-5 relative overflow-hidden"
      style={{
        background: "linear-gradient(135deg, var(--surface) 0%, var(--surface2) 100%)",
        border: "1px solid var(--border2)",
      }}
    >
      <div
        className="absolute top-0 left-0 right-0 h-[1px]"
        style={{ background: "linear-gradient(90deg, transparent, #0090ff60, transparent)" }}
      />

      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-[10px] font-semibold tracking-[0.15em] uppercase" style={{ color: "var(--muted2)" }}>
            Red Team Suite
          </h2>
          <p className="text-xs mt-1" style={{ color: "var(--muted)" }}>
            Run 100 labeled attack scenarios against the detector
          </p>
        </div>
        <button
          onClick={handleRun}
          disabled={loading}
          className="relative flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-semibold transition-all duration-200 disabled:opacity-50 overflow-hidden"
          style={{
            background: loading ? "var(--surface2)" : "linear-gradient(135deg, #0090ff18, #0090ff08)",
            color: "#0090ff",
            border: "1px solid #0090ff40",
            boxShadow: loading ? "none" : "0 0 16px #0090ff20",
          }}
        >
          {loading ? (
            <>
              <span className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin" />
              Running…
            </>
          ) : (
            <>
              <span>▶</span>
              Run Full Library
            </>
          )}
        </button>
      </div>

      {error && (
        <div
          className="rounded-lg px-4 py-3 text-xs"
          style={{
            background: "var(--red-dim)",
            color: "var(--red)",
            border: "1px solid var(--red-border)",
          }}
        >
          ⚠ {error}
        </div>
      )}

      {result && (
        <div className="flex flex-col gap-4 animate-slide-in">
          {/* Score row */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: "Total Tests", value: result.total_tests, color: "var(--text)" },
              { label: "Passed", value: result.passed, color: "#00ff9d" },
              { label: "Failed", value: result.failed, color: result.failed > 0 ? "#ff2d55" : "#00ff9d" },
              { label: "Pass Rate", value: `${passRate}%`, color: passColor },
            ].map((item) => (
              <div
                key={item.label}
                className="rounded-lg p-4 text-center"
                style={{
                  background: "var(--bg2)",
                  border: "1px solid var(--border)",
                }}
              >
                <div className="text-[10px] uppercase tracking-wider mb-2" style={{ color: "var(--muted2)" }}>
                  {item.label}
                </div>
                <div
                  className="text-3xl font-bold tabular-nums"
                  style={{ color: item.color, textShadow: `0 0 16px ${item.color}50` }}
                >
                  {item.value}
                </div>
              </div>
            ))}
          </div>

          {/* Pass rate bar */}
          <div>
            <div className="flex justify-between text-[10px] mb-1.5" style={{ color: "var(--muted2)" }}>
              <span>Coverage</span>
              <span style={{ color: passColor }}>{passRate}%</span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "var(--border)" }}>
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${passRate}%`,
                  background: `linear-gradient(90deg, ${passColor}80, ${passColor})`,
                  boxShadow: `0 0 8px ${passColor}60`,
                }}
              />
            </div>
          </div>

          {result.failures.length > 0 && (
            <div>
              <p className="text-[10px] uppercase tracking-wider mb-3" style={{ color: "#ffb700" }}>
                ⚠ {result.failures.length} Failure{result.failures.length !== 1 ? "s" : ""}
              </p>
              <div
                className="rounded-lg overflow-hidden"
                style={{ border: "1px solid var(--border)" }}
              >
                <div
                  className="grid text-[10px] uppercase tracking-wider px-4 py-2"
                  style={{
                    gridTemplateColumns: "1fr 1.5fr 90px 90px 70px",
                    color: "var(--muted2)",
                    background: "var(--surface2)",
                    borderBottom: "1px solid var(--border)",
                  }}
                >
                  {["Test ID", "Category", "Expected", "Got", "Risk"].map((h) => (
                    <span key={h}>{h}</span>
                  ))}
                </div>
                <div className="divide-y" style={{ borderColor: "var(--border)" }}>
                  {result.failures.map((f) => (
                    <div
                      key={f.test_id}
                      className="grid items-center px-4 py-2.5 text-xs"
                      style={{ gridTemplateColumns: "1fr 1.5fr 90px 90px 70px" }}
                    >
                      <span className="font-mono text-[10px]" style={{ color: "var(--muted2)" }}>
                        {f.test_id}
                      </span>
                      <span style={{ color: "#b060ff" }}>
                        {f.category.replace(/_/g, " ")}
                      </span>
                      <span><ActionBadge value={f.expected_action} /></span>
                      <span><ActionBadge value={f.actual_action} /></span>
                      <span className="font-mono" style={{ color: "#ff2d55" }}>
                        {Math.round(f.risk_score * 100)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {result.failures.length === 0 && (
            <div
              className="rounded-lg px-4 py-3 flex items-center gap-2 text-sm"
              style={{ background: "#00ff9d0a", color: "#00ff9d", border: "1px solid #00ff9d25" }}
            >
              <span>✓</span>
              All {result.total_tests} tests passed
            </div>
          )}
        </div>
      )}
    </div>
  );
}
