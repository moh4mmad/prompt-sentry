import { NextRequest, NextResponse } from "next/server";

function equal(left: string, right: string): boolean {
  const size = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < size; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

export function proxy(request: NextRequest): NextResponse {
  if (request.nextUrl.pathname === "/api/health") return NextResponse.next();

  const username = process.env.DASHBOARD_USERNAME;
  const password = process.env.DASHBOARD_PASSWORD;
  if (!username || !password) return NextResponse.next();

  const header = request.headers.get("authorization");
  if (header?.startsWith("Basic ")) {
    try {
      const decoded = atob(header.slice(6));
      const separator = decoded.indexOf(":");
      if (
        separator >= 0 &&
        equal(decoded.slice(0, separator), username) &&
        equal(decoded.slice(separator + 1), password)
      ) {
        return NextResponse.next();
      }
    } catch {
      // Malformed credentials are handled by the challenge below.
    }
  }

  return new NextResponse("Authentication required", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="PromptSentry", charset="UTF-8"' },
  });
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
