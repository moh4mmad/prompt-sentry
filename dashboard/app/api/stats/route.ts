import { NextRequest } from "next/server";
import { proxyApi } from "@/lib/server-api";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest): Promise<Response> {
  const limit = request.nextUrl.searchParams.get("limit") ?? "1000";
  return proxyApi(`/dashboard/stats?limit=${encodeURIComponent(limit)}`);
}
