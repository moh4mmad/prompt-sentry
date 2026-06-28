import "server-only";

const API_URL = process.env.PROMPT_SENTRY_API_URL ?? "http://localhost:8100";

export async function proxyApi(path: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  const apiKey = process.env.PROMPT_SENTRY_API_KEY;
  const dashboardKey = process.env.DASHBOARD_API_KEY;
  if (apiKey) headers.set("X-API-Key", apiKey);
  if (dashboardKey) headers.set("X-Dashboard-Key", dashboardKey);

  try {
    const upstream = await fetch(`${API_URL}${path}`, {
      ...init,
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(30_000),
    });
    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: { "Content-Type": upstream.headers.get("Content-Type") ?? "application/json" },
    });
  } catch {
    return Response.json({ detail: "PromptSentry API is unavailable" }, { status: 503 });
  }
}
