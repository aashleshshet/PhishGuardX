import { NextRequest } from "next/server";
import { proxy } from "@/lib/backend";
export const maxDuration = 60;
export function GET(request: NextRequest) {
  return proxy(request, "threat-intelligence");
}
