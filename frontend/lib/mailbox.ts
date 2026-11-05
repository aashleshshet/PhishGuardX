import "server-only";
export type Provider = "google" | "microsoft";
export const mailScopes = {
  google: "https://www.googleapis.com/auth/gmail.readonly",
  microsoft: "Mail.Read",
};
export class MailboxError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export function validateProvider(value: string | null): Provider {
  if (value !== "google" && value !== "microsoft")
    throw new MailboxError("Choose Google or Microsoft.", 400);
  return value;
}
export function validateMessageId(id: string) {
  if (!/^[a-zA-Z0-9_+=-]{1,512}$/.test(id))
    throw new MailboxError("Invalid message identifier.", 400);
  return id;
}
async function providerFetch(url: string, token: string) {
  const parsed = new URL(url);
  if (
    !["gmail.googleapis.com", "graph.microsoft.com"].includes(
      parsed.hostname,
    ) ||
    parsed.protocol !== "https:"
  )
    throw new MailboxError("Unsupported mailbox destination.", 400);
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Prefer: 'outlook.body-content-type="text"',
    },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403)
      throw new MailboxError(
        "Mailbox permission is missing or expired. Reconnect your account with read-only mail access.",
        403,
      );
    throw new MailboxError(
      "Your email provider could not complete the request. Please try again.",
      502,
    );
  }
  // Limit provider responses; never log tokens or mailbox bodies.
  const reader = response.body?.getReader();
  if (!reader)
    throw new MailboxError(
      "The email provider returned an empty response.",
      502,
    );
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > 4 * 1024 * 1024) {
      await reader.cancel();
      throw new MailboxError(
        "This email is too large to import. Paste the relevant text instead.",
        413,
      );
    }
    chunks.push(value);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}
export async function listMessages(provider: Provider, token: string) {
  if (provider === "google") {
    const list = await providerFetch(
      "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10&labelIds=INBOX",
      token,
    );
    const ids = (list.messages || []).slice(0, 10) as { id: string }[];
    return Promise.all(
      ids.map(async ({ id }) => {
        validateMessageId(id);
        const data = await providerFetch(
          `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date`,
          token,
        );
        const headers = data.payload?.headers || [];
        const header = (key: string) =>
          headers.find(
            (h: { name: string; value: string }) =>
              h.name.toLowerCase() === key,
          )?.value || "";
        return {
          id,
          subject: header("subject") || "(No subject)",
          from: header("from"),
          date: header("date"),
        };
      }),
    );
  }
  const data = await providerFetch(
    "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$top=10&$select=id,subject,from,receivedDateTime&$orderby=receivedDateTime%20desc",
    token,
  );
  return (data.value || []).map(
    (m: {
      id: string;
      subject: string;
      from?: { emailAddress?: { name?: string; address?: string } };
      receivedDateTime: string;
    }) => ({
      id: m.id,
      subject: m.subject || "(No subject)",
      from:
        m.from?.emailAddress?.name ||
        m.from?.emailAddress?.address ||
        "Unknown sender",
      date: m.receivedDateTime,
    }),
  );
}
export async function importMessage(
  provider: Provider,
  token: string,
  id: string,
) {
  validateMessageId(id);
  if (provider === "google") {
    const data = await providerFetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(id)}?format=raw`,
      token,
    );
    if (typeof data.raw !== "string")
      throw new MailboxError("The message could not be decoded.", 502);
    const content = Buffer.from(data.raw, "base64url").toString("utf8");
    if (content.length > 30000)
      throw new MailboxError(
        "This message is over 30,000 characters. Download it and paste the relevant section instead.",
        413,
      );
    return { content, headers: "" };
  }
  const data = await providerFetch(
    `https://graph.microsoft.com/v1.0/me/messages/${encodeURIComponent(id)}?$select=subject,body,from,replyTo,internetMessageHeaders`,
    token,
  );
  const selected = new Set([
    "from",
    "reply-to",
    "subject",
    "authentication-results",
    "return-path",
  ]);
  const headers = (data.internetMessageHeaders || [])
    .filter((h: { name: string }) => selected.has(h.name.toLowerCase()))
    .map(
      (h: { name: string; value: string }) =>
        `${h.name}: ${h.value.replace(/[\r\n]+/g, " ")}`,
    )
    .join("\n");
  const content = String(data.body?.content || "");
  if (content.length > 30000 || headers.length > 20000)
    throw new MailboxError(
      "This message is too large. Paste the relevant section instead.",
      413,
    );
  return {
    content,
    headers:
      headers ||
      `Subject: ${String(data.subject || "").replace(/[\r\n]+/g, " ")}`,
  };
}
