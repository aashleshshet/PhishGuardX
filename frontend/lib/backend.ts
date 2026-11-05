import { NextRequest, NextResponse } from "next/server";
const allowed = new Set([
  "analyze",
  "health",
  "models",
  "history",
  "threat-intelligence",
]);
export async function proxy(request: NextRequest, path: string) {
  if (!allowed.has(path))
    return NextResponse.json({ detail: "Not found" }, { status: 404 });
  const base =
    process.env.BACKEND_URL ||
    (process.env.NODE_ENV === "development" ? "http://127.0.0.1:8000" : "");
  if (!base)
    return NextResponse.json(
      { detail: "Analysis service is not configured." },
      { status: 503 },
    );
  try {
    let body: string | undefined;
    if (request.method === "POST") {
      const reader = request.body?.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.length;
          if (size > 131072) {
            await reader.cancel();
            return NextResponse.json(
              { detail: "Input exceeds 128 KB." },
              { status: 413 },
            );
          }
          chunks.push(value);
        }
      }
      body = Buffer.concat(chunks).toString("utf8");
    }
    const response = await fetch(new URL("/" + path, base), {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
        "X-History-Token": request.headers.get("x-history-token") || "",
      },
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(55000),
    });
    const data = await response.json();
    return NextResponse.json(data, {
      status: response.status,
      headers: { "Cache-Control": "no-store" },
    });
  } catch {
    return NextResponse.json(
      {
        detail:
          "The analysis service could not be reached. Please try again shortly.",
      },
      { status: 503 },
    );
  }
}
