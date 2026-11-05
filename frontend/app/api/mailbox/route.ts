import { auth, clerkClient } from "@clerk/nextjs/server";
import { NextRequest, NextResponse } from "next/server";
import {
  MailboxError,
  validateProvider,
  listMessages,
  importMessage,
  mailScopes,
} from "@/lib/mailbox";
export const maxDuration = 30;
export async function GET(request: NextRequest) {
  try {
    if (
      !process.env.CLERK_SECRET_KEY ||
      !process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
    )
      throw new MailboxError("Sign-in is not configured yet.", 503);
    const { userId } = await auth();
    if (!userId)
      throw new MailboxError("Sign in before connecting your mailbox.", 401);
    const provider = validateProvider(
      request.nextUrl.searchParams.get("provider"),
    );
    const client = await clerkClient();
    const tokens = await client.users.getUserOauthAccessToken(userId, provider);
    const credential = tokens.data.find((t) =>
      t.scopes?.some(
        (scope) =>
          scope === mailScopes[provider] ||
          (provider === "microsoft" && scope.endsWith("/Mail.Read")),
      ),
    );
    if (!credential?.token)
      throw new MailboxError(
        "Connect your account and grant read-only email access first.",
        403,
      );
    const id = request.nextUrl.searchParams.get("id");
    const data = id
      ? await importMessage(provider, credential.token, id)
      : { messages: await listMessages(provider, credential.token) };
    return NextResponse.json(data, {
      headers: { "Cache-Control": "private, no-store" },
    });
  } catch (error) {
    const known = error instanceof MailboxError;
    return NextResponse.json(
      {
        detail: known
          ? error.message
          : "Mailbox connection could not be completed. Check that your provider is configured in Clerk and reconnect.",
      },
      {
        status: known ? error.status : 502,
        headers: { "Cache-Control": "no-store" },
      },
    );
  }
}
