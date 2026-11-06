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
    const outcome = await response.json();
    const status =
      typeof outcome.status === "string" ? outcome.status : "unavailable";
    console.info(JSON.stringify({ event: "feed_scheduler", status }));
    return Response.json(outcome, {
      status: !response.ok
        ? response.status
        : status === "rate_limited"
          ? 429
          : ["unavailable", "not_configured"].includes(status)
            ? 503
            : 200,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    console.warn(
      JSON.stringify({ event: "feed_scheduler", status: "unavailable" }),
    );
    return Response.json(
      { detail: "Feed synchronization could not be reached." },
      { status: 503 },
    );
  }
}
