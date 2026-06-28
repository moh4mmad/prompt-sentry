import type { AuditEvent, RedTeamResult, Stats } from "./types";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export async function fetchEvents(limit = 200): Promise<AuditEvent[]> {
  const data = await get<{ events: AuditEvent[] }>(`/api/events?limit=${limit}`);
  return data.events;
}

export async function fetchStats(limit = 1000): Promise<Stats> {
  return get<Stats>(`/api/stats?limit=${limit}`);
}

export async function runRedTeam(suite = "default"): Promise<RedTeamResult> {
  const res = await fetch("/api/red-team", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ suite, categories: [], mode: "offline" }),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<RedTeamResult>;
}
