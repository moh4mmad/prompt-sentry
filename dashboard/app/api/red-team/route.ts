import { proxyApi } from "@/lib/server-api";

export async function POST(request: Request): Promise<Response> {
  return proxyApi("/v1/red-team/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: await request.text(),
  });
}
