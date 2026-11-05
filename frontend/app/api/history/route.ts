import { NextRequest } from "next/server";
import { proxy } from "@/lib/backend";
export function GET(request: NextRequest) {
  return proxy(request, "history");
}
export function POST(request: NextRequest) {
  return proxy(request, "history");
}
export function DELETE(request: NextRequest) {
  return proxy(request, "history");
}
