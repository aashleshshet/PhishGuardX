import { NextRequest } from "next/server";
import { proxy } from "@/lib/backend";
export const maxDuration = 60;
export function POST(request: NextRequest) {
  return proxy(request, "analyze");
}
