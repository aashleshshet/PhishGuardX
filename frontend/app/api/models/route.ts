import { NextRequest } from "next/server";
import { proxy } from "@/lib/backend";
export function GET(request: NextRequest) {
  return proxy(request, "models");
}
