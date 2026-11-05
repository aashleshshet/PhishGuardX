"use client";
import { useEffect, useState } from "react";
import { useReverification } from "@clerk/nextjs";
import type {
  CreateExternalAccountParams,
  ExternalAccountResource,
} from "@clerk/nextjs/types";
import {
  ArrowDownToLine,
  ChevronRight,
  Inbox,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  X,
} from "lucide-react";
import { useIdentity } from "./auth-provider";
import { Button } from "./ui/button";
type Provider = "google" | "microsoft";
interface Message {
  id: string;
  subject: string;
  from: string;
  date: string;
}
export function ProviderLogo({ provider }: { provider: Provider }) {
  return provider === "google" ? (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M21.6 12.2c0-.7-.1-1.4-.2-2.1H12v4h5.4a4.6 4.6 0 0 1-2 3v2.5h3.2c1.9-1.8 3-4.3 3-7.4Z"
      />
      <path
        fill="#34A853"
        d="M12 22c2.7 0 4.9-.9 6.6-2.4l-3.2-2.5c-.9.6-2 .9-3.4.9a6 6 0 0 1-5.7-4.2H3v2.6A10 10 0 0 0 12 22Z"
      />
      <path
        fill="#FBBC05"
        d="M6.3 13.8a6 6 0 0 1 0-3.6V7.6H3a10 10 0 0 0 0 8.8l3.3-2.6Z"
      />
      <path
        fill="#EA4335"
        d="M12 6c1.5 0 2.8.5 3.8 1.5l2.8-2.8A9.6 9.6 0 0 0 12 2a10 10 0 0 0-9 5.6l3.3 2.6A6 6 0 0 1 12 6Z"
      />
    </svg>
  ) : (
    <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
      <path fill="#f25022" d="M2 2h9v9H2z" />
      <path fill="#7fba00" d="M13 2h9v9h-9z" />
      <path fill="#00a4ef" d="M2 13h9v9H2z" />
      <path fill="#ffb900" d="M13 13h9v9h-9z" />
    </svg>
  );
}
export function MailboxConnect({
  onImport,
}: {
  onImport: (content: string, headers: string) => void;
}) {
  const identity = useIdentity();
  if (!identity.configured)
    return (
      <section className="mailbox-panel">
        <div className="mailbox-heading">
          <Inbox size={19} />
          <div>
            <h3>Bring an email from your inbox.</h3>
            <p>Connect Google or Microsoft with read-only access.</p>
          </div>
        </div>
        <div className="provider-buttons">
          <Button variant="secondary" disabled>
            <ProviderLogo provider="google" /> Connect Google
          </Button>
          <Button variant="secondary" disabled>
            <ProviderLogo provider="microsoft" /> Connect Microsoft
          </Button>
        </div>
        <p className="fine-print">
          Account connection will be available once Clerk is linked to this
          deployment. You can paste or upload an email below.
        </p>
      </section>
    );
  return <ConnectedMailbox onImport={onImport} />;
}
function ConnectedMailbox({
  onImport,
}: {
  onImport: (content: string, headers: string) => void;
}) {
  const { user, loaded, openSignIn, openProfile } = useIdentity();
  const [provider, setProvider] = useState<Provider | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [consent, setConsent] = useState<Provider | null>(null);
  const create = useReverification((params: CreateExternalAccountParams) =>
    user?.createExternalAccount(params),
  );
  const reauthorize = useReverification(
    (account: ExternalAccountResource, scopes: string[]) =>
      account.reauthorize({
        additionalScopes: scopes,
        redirectUrl: window.location.origin + "/email",
      }),
  );
  useEffect(() => {
    setMessages([]);
    setProvider(null);
    setConsent(null);
    setError("");
  }, [user?.id]);
  function requestConnection(p: Provider) {
    if (!user) {
      openSignIn();
      return;
    }
    setConsent(p);
    setError("");
  }
  async function connect(p: Provider) {
    setBusy(true);
    setError("");
    try {
      const scopes =
        p === "google"
          ? ["https://www.googleapis.com/auth/gmail.readonly"]
          : ["https://graph.microsoft.com/Mail.Read", "offline_access"];
      const account = user?.externalAccounts.find((a) => a.provider === p);
      const response = account
        ? await reauthorize(account, scopes)
        : await create({
            strategy: p === "google" ? "oauth_google" : "oauth_microsoft",
            additionalScopes: scopes,
            redirectUrl: window.location.origin + "/email",
          });
      const redirect = response?.verification?.externalVerificationRedirectURL;
      if (redirect) {
        window.location.assign(redirect.href);
        return;
      }
      await user?.reload();
      setConsent(null);
      setProvider(p);
    } catch {
      setError(
        "Connection could not be started. Enable this provider with custom OAuth credentials in Clerk, then try again.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function load(p: Provider) {
    setBusy(true);
    setError("");
    setProvider(p);
    setMessages([]);
    try {
      const r = await fetch("/api/mailbox?provider=" + p, {
        cache: "no-store",
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail);
      setMessages(data.messages);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load your inbox.");
    } finally {
      setBusy(false);
    }
  }
  async function choose(message: Message) {
    if (!provider) return;
    setBusy(true);
    setError("");
    try {
      const r = await fetch(
        `/api/mailbox?provider=${provider}&id=${encodeURIComponent(message.id)}`,
        { cache: "no-store" },
      );
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail);
      onImport(data.content, data.headers);
      setMessages([]);
      setProvider(null);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "The message could not be imported.",
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="mailbox-panel">
      <div className="mailbox-heading">
        <Inbox size={20} />
        <div>
          <h3>Bring an email from your inbox.</h3>
          <p>Choose a message, review it, then analyze.</p>
        </div>
      </div>
      <div className="provider-buttons">
        {(["google", "microsoft"] as Provider[]).map((p) => {
          const account = user?.externalAccounts.find((a) => a.provider === p);
          const approved = account?.approvedScopes
            ?.split(/[ ,]+/)
            .some((s) =>
              p === "google"
                ? s === "https://www.googleapis.com/auth/gmail.readonly"
                : s === "Mail.Read" || s.endsWith("/Mail.Read"),
            );
          return (
            <div key={p}>
              <Button
                variant="secondary"
                disabled={busy || !loaded}
                onClick={() => (approved ? void load(p) : requestConnection(p))}
              >
                <ProviderLogo provider={p} />
                {approved ? "Choose from" : "Connect"}{" "}
                {p === "google" ? "Google" : "Microsoft"}
              </Button>
              {approved && (
                <button
                  className="text-button reconnect-link"
                  onClick={() => requestConnection(p)}
                >
                  Reconnect
                </button>
              )}
            </div>
          );
        })}
      </div>
      <p className="mailbox-privacy">
        <LockKeyhole size={12} /> Read-only access. We never send, delete, or
        automatically scan your emails.
      </p>
      {consent && (
        <div className="mail-consent">
          <strong>
            Connect your {consent === "google" ? "Google" : "Microsoft"} mailbox
          </strong>
          <p>
            You’ll grant read-only mail access through{" "}
            {consent === "google" ? "Google" : "Microsoft"}. PhishGuardX fetches
            the 10 latest inbox subjects only when you choose to browse. A
            selected message is loaded for your review and analyzed only when
            you press Analyze. You can manage or disconnect accounts from your
            profile.
          </p>
          <div>
            <Button
              size="small"
              onClick={() => void connect(consent)}
              disabled={busy}
            >
              Continue to {consent === "google" ? "Google" : "Microsoft"}{" "}
              <ChevronRight size={14} />
            </Button>
            <Button
              size="small"
              variant="ghost"
              onClick={() => setConsent(null)}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}
      {busy && (
        <div className="mail-loading" role="status">
          <LoaderCircle size={15} className="spin" /> Loading securely…
        </div>
      )}
      {error && (
        <div className="error-message" role="alert">
          {error}
        </div>
      )}
      {provider && !busy && !error && (
        <div className="inbox-picker">
          <div>
            <h4>Recent inbox messages</h4>
            <button
              className="icon-button"
              onClick={() => {
                setMessages([]);
                setProvider(null);
              }}
              aria-label="Close inbox picker"
            >
              <X size={15} />
            </button>
          </div>
          {messages.length ? (
            messages.map((m) => (
              <button
                key={m.id}
                className="inbox-message"
                onClick={() => void choose(m)}
              >
                <span>
                  <strong>{m.subject}</strong>
                  <small>{m.from}</small>
                </span>
                <ArrowDownToLine size={16} />
              </button>
            ))
          ) : (
            <p className="fine-print">No inbox messages were returned.</p>
          )}
          <p className="fine-print">
            Selecting a message imports it for review; it does not start a scan.
          </p>
        </div>
      )}
      {user && (
        <button
          className="text-button manage-connections"
          onClick={openProfile}
        >
          Manage connected accounts
        </button>
      )}
    </section>
  );
}
