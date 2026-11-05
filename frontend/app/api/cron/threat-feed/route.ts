import { timingSafeEqual } from "node:crypto";
export const maxDuration = 60;
export async function GET(request: Request) {
  const secret = process.env.CRON_SECRET;
  const auth = request.headers.get("authorization") || "";
  const expected = `Bearer ${secret}`;
  if (
    !secret ||
    Buffer.byteLength(auth) !== Buffer.byteLength(expected) ||
    !timingSafeEqual(Buffer.from(auth), Buffer.from(expected))
  ) {
    return Response.json(
      { detail: "Authorized scheduler required." },
      { status: 401 },
    );
  }
  const backend = process.env.BACKEND_URL;
  if (!backend)
    return Response.json(
      { detail: "Feed service is not configured." },
      { status: 503 },
    );
  try {
    const response = await fetch(new URL("/internal/feed-sync", backend), {
      method: "POST",
      headers: { Authorization: expected },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(55000),
    });
    return Response.json(await response.json(), {
      status: response.status,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json(
      { detail: "Feed synchronization could not be reached." },
      { status: 503 },
    );
  }
}
