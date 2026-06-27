import type { AuditEvent, RedTeamResult, Stats } from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export async function fetchEvents(limit = 200): Promise<AuditEvent[]> {
  const data = await get<{ events: AuditEvent[] }>(`/dashboard/events?limit=${limit}`);
  return data.events;
}

export async function fetchStats(limit = 1000): Promise<Stats> {
  return get<Stats>(`/dashboard/stats?limit=${limit}`);
}

export async function runRedTeam(suite = "default"): Promise<RedTeamResult> {
  const res = await fetch(`${BASE}/v1/red-team/run`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ suite, categories: [], mode: "offline" }),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<RedTeamResult>;
}
