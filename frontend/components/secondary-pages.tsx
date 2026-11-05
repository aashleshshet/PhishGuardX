"use client";
import { useEffect, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Check,
  ChevronRight,
  Download,
  FileText,
  Fingerprint,
  Info,
  LoaderCircle,
  LockKeyhole,
  MessageCircle,
  Moon,
  Search,
  Send,
  ShieldCheck,
  Sparkles,
  Sun,
  Trash2,
  X,
} from "lucide-react";
import { Button } from "./ui/button";
import { useIdentity } from "./auth-provider";
import { AnalysisResult, RiskBadge } from "./result";
import { articles, exportJSON, kindLabels } from "@/lib/content";
import type { Analysis, Page, Settings } from "@/lib/types";
export function HistoryPage({
  history,
  openResult,
  remove,
  navigate,
}: {
  history: Analysis[];
  openResult: (a: Analysis) => void;
  remove: (id: string) => void;
  navigate: (p: Page) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const filtered = history.filter(
    (r) =>
      (filter === "all" || r.risk === filter) &&
      (kindLabels[r.kind] + " " + r.summary + (r.sample ? " sample" : ""))
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  return (
    <>
      <div className="page-intro">
        <h1>Your analysis history.</h1>
        <p>
          A record of what you checked, kept on this device. Raw message content
          is never saved.
        </p>
      </div>
      <section className="glass history-panel">
        <div className="history-toolbar">
          <label className="search-input">
            <Search size={17} />
            <input
              aria-label="Search scan history"
              placeholder="Search your analyses…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
          <select
            aria-label="Filter by risk"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          >
            <option value="all">All results</option>
            <option value="high">High concern</option>
            <option value="review">Needs review</option>
            <option value="low">Few indicators</option>
          </select>
        </div>
        {filtered.length ? (
          <div className="history-table">
            <div className="history-table-head">
              <span>Analysis</span>
              <span>Result</span>
              <span>When</span>
              <span />
            </div>
            {filtered.map((r) => (
              <div className="history-table-row" key={r.id}>
                <button onClick={() => openResult(r)}>
                  <FileText size={19} />
                  <span>
                    <strong>{kindLabels[r.kind]}</strong>
                    <small>
                      {r.sample ? "Sample input" : "Personal scan"} ·{" "}
                      {r.signals.length} signals
                    </small>
                  </span>
                </button>
                <RiskBadge risk={r.risk} />
                <time>
                  {new Date(r.createdAt).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                  })}
                  <small>
                    {new Date(r.createdAt).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </small>
                </time>
                <button
                  className="icon-button"
                  onClick={() => remove(r.id)}
                  aria-label={`Delete ${kindLabels[r.kind]} from history`}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="large-empty">
            <FileText size={34} />
            <h3>
              {history.length
                ? "No matching analyses"
                : "Your next click can be an informed one."}
            </h3>
            <p>
              {history.length
                ? "Try another search or filter."
                : "Run an analysis to start building your private history."}
            </p>
            {!history.length && (
              <Button onClick={() => navigate("email")}>
                Start an analysis <ArrowRight size={16} />
              </Button>
            )}
          </div>
        )}
      </section>
    </>
  );
}
export function LearnPage({
  article,
  setArticle,
}: {
  article: string | null;
  setArticle: (id: string | null) => void;
}) {
  const selected = articles.find((a) => a.id === article);
  if (selected)
    return (
      <div className="article-view">
        <button className="text-button" onClick={() => setArticle(null)}>
          <ArrowLeft size={16} /> Back to learning center
        </button>
        <div className="page-intro">
          <h1>{selected.title}</h1>
          <p>{selected.intro}</p>
          <span className="article-meta">
            {selected.category.toLowerCase()} · {selected.minutes} min read
          </span>
        </div>
        <article className="glass article-body">
          {selected.body.map((p, i) => (
            <section key={i}>
              <h2>
                {
                  ["The thing to notice", "Why it matters", "What you can do"][
                    i
                  ]
                }
              </h2>
              <p>{p}</p>
            </section>
          ))}
          <div className="article-takeaway">
            <ShieldCheck size={22} />
            <p>
              Pause. Look for evidence. Verify through a channel you already
              trust.
            </p>
          </div>
        </article>
      </div>
    );
  return (
    <>
      <div className="page-intro">
        <h1>A little knowledge. A stronger instinct.</h1>
        <p>
          Practical guides to recognizing scams and making more informed
          decisions.
        </p>
      </div>
      <div className="learning-grid">
        {articles.map((a, i) => (
          <button
            className={`glass learning-card learning-${i}`}
            key={a.id}
            onClick={() => setArticle(a.id)}
          >
            <div className="learning-card-top">
              <BookOpen size={23} />
              <span>{a.minutes} min read</span>
            </div>
            <h2>{a.title}</h2>
            <p>{a.intro}</p>
            <div className="learning-card-bottom">
              <span>{a.category.toLowerCase()}</span>
              <ArrowRight size={18} />
            </div>
          </button>
        ))}
      </div>
    </>
  );
}
function responseFor(question: string, result: Analysis | null) {
  const q = question.toLowerCase();
  if (/last|result|scan|explain|found|signal/.test(q) && result)
    return `${result.summary}\n\n${
      result.signals.length
        ? result.signals
            .slice(0, 4)
            .map((s) => s.title + ": " + s.description)
            .join("\n\n")
        : "No strong indicators were identified. Missing checks still matter."
    }\n\nUnavailable checks: ${result.unavailable.join(", ")}.\n\n${result.recommendations[0]}`;
  if (/click|entered|password|already/.test(q))
    return "If you only opened a link, close it and avoid downloading or entering information. If you entered a password, change it through the official app or a trusted bookmark, review active sessions, and enable multifactor authentication. If you shared payment information, contact your bank through its official contact details.\n\nIf this happened on a work device, contact your security team.";
  if (/spf|dkim|dmarc|header/.test(q))
    return "SPF checks the sending server, DKIM checks a message signature, and DMARC checks alignment with the visible sender domain. A pass does not guarantee a harmless email, and forwarding can cause failures.\n\nPhishGuardX interprets pasted Authentication-Results only. Those results are not independently verified and could be forged.";
  if (/qr/.test(q))
    return "A QR code can hide a website destination. Decode it first, inspect its registered domain, and verify unexpected payment requests. PhishGuardX decodes the image locally and does not open the destination. A shortened link still hides its final target.";
  if (/model|probability|score|confidence/.test(q))
    return "The URL model is calibrated on a held-out historical phishing dataset. The email model is calibrated for historical spam, which is not the same as phishing.\n\nRisk categories combine explicit evidence rules with model classifications; they are not numeric probabilities. The models can miss new attacks and flag legitimate content. Reports includes measured evaluation results.";
  if (/private|privacy|store|save|data/.test(q))
    return "For URL/QR scans, live reputation checks share the submitted URL with enabled providers and can be turned off. Hash-only caches and redacted provider results may be retained temporarily. Images are decoded in your browser. The text or URL you submit is sent to the PhishGuardX analysis service, processed in memory, and not retained by that service. No external AI receives it. Optional local history saves redacted summaries on this device. You can turn it off or erase it in Settings.";
  if (/url|link|domain|https/.test(q))
    return "Find the actual registered domain, not just a familiar brand name. For example, in paypal.com.account-check.example the registered domain is account-check.example.\n\nHTTPS encrypts a connection but does not establish the website’s identity. Open the official app or type a known address to verify a sensitive request.";
  return "I can explain scan results, suspicious links, email authentication, QR codes, privacy, or steps to take after clicking a link. This assistant uses curated guidance and your most recent analysis; it is not a general-purpose language model.\n\nFor a specific message or URL, run it through a scanner first, then ask me to explain the result.";
}
export function AssistantPage({
  latest,
  navigate,
}: {
  latest: Analysis | null;
  navigate: (p: Page) => void;
}) {
  const [messages, setMessages] = useState<
    { role: "user" | "assistant"; text: string }[]
  >([]);
  const [input, setInput] = useState("");
  function send(q: string) {
    if (!q.trim()) return;
    setMessages((m) => [
      ...m,
      { role: "user", text: q },
      { role: "assistant", text: responseFor(q, latest) },
    ]);
    setInput("");
  }
  return (
    <>
      <div className="page-intro">
        <h1>Make sense of the signals.</h1>
        <p>
          Your security companion. Grounded in evidence, written for humans.
        </p>
      </div>
      <section className="glass assistant-panel">
        <div className="assistant-top">
          <span className="assistant-avatar">
            <Sparkles size={20} />
          </span>
          <div>
            <strong>Security assistant</strong>
            <span>Curated guidance + your analysis evidence</span>
          </div>
          <span className="private-assistant">
            <LockKeyhole size={13} /> No external AI
          </span>
        </div>
        <div className="chat-messages" aria-live="polite">
          {messages.length ? (
            messages.map((m, i) => (
              <div className={`message message-${m.role}`} key={i}>
                {m.role === "assistant" && (
                  <span className="message-avatar">
                    <Sparkles size={16} />
                  </span>
                )}
                <p>{m.text}</p>
              </div>
            ))
          ) : (
            <div className="assistant-welcome">
              <div className="assistant-orb">
                <Sparkles size={32} />
              </div>
              <h2>Let’s untangle the suspicious.</h2>
              <p>
                Understand a result, learn what to look for,
                <br />
                or figure out what to do next.
              </p>
              <div className="suggestion-grid">
                {[
                  latest
                    ? "Explain my last scan"
                    : "How do I check a suspicious link?",
                  "What if I already clicked?",
                  "What do SPF and DKIM mean?",
                  "How private is my analysis?",
                ].map((s) => (
                  <button onClick={() => send(s)} key={s}>
                    {s}
                    <ArrowUpRightIcon />
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
        <form
          className="chat-input"
          onSubmit={(e) => {
            e.preventDefault();
            send(input);
          }}
        >
          <label className="sr-only" htmlFor="assistant-input">
            Ask a security question
          </label>
          <input
            id="assistant-input"
            placeholder="Ask about a signal, a result, or your next step…"
            value={input}
            maxLength={2000}
            onChange={(e) => setInput(e.target.value)}
          />
          <Button
            type="submit"
            size="icon"
            disabled={!input.trim()}
            aria-label="Send question"
          >
            <ArrowRight size={20} />
          </Button>
        </form>
        <p className="chat-disclaimer">
          Educational support, not a guarantee of safety. For content-specific
          findings,{" "}
          <button onClick={() => navigate("email")}>start a scan</button>.
        </p>
      </section>
    </>
  );
}
function ArrowUpRightIcon() {
  return <ChevronRight size={15} />;
}
interface Metric {
  precision: number;
  recall: number;
  f1: number;
  accuracy: number;
  brier: number;
  confusion_matrix: number[][];
  count: number;
  split_sizes: Record<string, number>;
  positive_class: string;
}
export function ReportsPage({ history }: { history: Analysis[] }) {
  const [evaluation, setEvaluation] = useState<{
    models: Record<string, Metric>;
    limitations: string[];
  } | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/models", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error();
        return r.json();
      })
      .then(setEvaluation)
      .catch((e) => {
        if (e.name !== "AbortError") setError(true);
      });
    return () => controller.abort();
  }, []);
  return (
    <>
      <div className="page-intro">
        <h1>The evidence behind the engine.</h1>
        <p>
          Real evaluation results, transparent limitations, and your
          downloadable analysis records.
        </p>
      </div>
      <div className="glass export-banner">
        <div>
          <FileText size={26} />
          <div>
            <h2>Your analysis report</h2>
            <p>
              {history.length} local records. Includes redacted findings,
              provider evidence, timestamps, and model outputs.
            </p>
          </div>
        </div>
        <Button
          variant="secondary"
          disabled={!history.length}
          onClick={() =>
            exportJSON(
              { generatedAt: new Date().toISOString(), analyses: history },
              "phishguardx-history.json",
            )
          }
        >
          <Download size={16} /> Export records
        </Button>
      </div>
      {error ? (
        <div className="error-message">
          Evaluation data could not be loaded. Refresh the page to retry.
        </div>
      ) : !evaluation ? (
        <div className="loading-state">
          <LoaderCircle className="spin" /> Loading measured evaluation…
        </div>
      ) : (
        <>
          <div className="model-report-grid">
            {Object.entries(evaluation.models).map(([kind, m]) => (
              <section key={kind} className="glass model-report">
                <div className="panel-top">
                  <h2>
                    {kind === "url"
                      ? "URL classifier"
                      : "Email spam classifier"}
                  </h2>
                  <Fingerprint size={20} />
                </div>
                <p className="report-subtitle">
                  {m.count.toLocaleString()} held-out examples · positive class:{" "}
                  {m.positive_class}
                </p>
                <div className="metric-grid">
                  {[
                    ["Precision", m.precision],
                    ["Recall", m.recall],
                    ["F1 score", m.f1],
                  ].map(([label, value]) => (
                    <div key={String(label)}>
                      <strong>
                        {(Number(value) * 100).toFixed(1)}
                        <small>%</small>
                      </strong>
                      <span>{label}</span>
                    </div>
                  ))}
                </div>
                <div className="confusion-matrix">
                  <h3>Confusion matrix</h3>
                  <div>
                    <span>
                      True negatives{" "}
                      <b>{m.confusion_matrix[0][0].toLocaleString()}</b>
                    </span>
                    <span>
                      False positives{" "}
                      <b>{m.confusion_matrix[0][1].toLocaleString()}</b>
                    </span>
                    <span>
                      False negatives{" "}
                      <b>{m.confusion_matrix[1][0].toLocaleString()}</b>
                    </span>
                    <span>
                      True positives{" "}
                      <b>{m.confusion_matrix[1][1].toLocaleString()}</b>
                    </span>
                  </div>
                </div>
                <p className="fine-print">
                  Brier score: {m.brier.toFixed(4)} · Disjoint train,
                  validation, calibration, and test groups.
                </p>
              </section>
            ))}
          </div>
          <section className="glass limitations-panel">
            <h2>Where the models have limits</h2>
            {evaluation.limitations.map((l) => (
              <p key={l}>
                <Info size={17} />
                {l}
              </p>
            ))}
            <Button
              variant="ghost"
              size="small"
              onClick={() =>
                exportJSON(evaluation, "phishguardx-evaluation.json")
              }
            >
              <Download size={15} /> Download evaluation
            </Button>
          </section>
        </>
      )}
    </>
  );
}
export function SettingsPage({
  settings,
  update,
  clearHistory,
  cloudAvailable,
}: {
  settings: Settings;
  update: (s: Settings) => void;
  clearHistory: () => void;
  cloudAvailable: boolean;
}) {
  const [confirm, setConfirm] = useState(false);
  const identity = useIdentity();
  return (
    <>
      <div className="page-intro">
        <h1>Your account. Your choices.</h1>
        <p>Make yourself comfortable, and keep control of your data.</p>
      </div>
      <section className="glass account-settings">
        <div>
          <h2>
            {identity.user?.fullName ||
              identity.user?.firstName ||
              "Your account"}
          </h2>
          <p>
            {identity.user?.primaryEmailAddress?.emailAddress ||
              (identity.configured
                ? "Sign in with Clerk to connect your mailbox and personalize your account."
                : "Clerk sign-in is being connected to this deployment.")}
          </p>
        </div>
        <div>
          {identity.user ? (
            <>
              <Button variant="secondary" onClick={identity.openProfile}>
                Manage account
              </Button>
              <Button variant="ghost" onClick={() => void identity.signOut()}>
                Sign out
              </Button>
            </>
          ) : (
            <Button
              disabled={!identity.configured}
              onClick={identity.openSignIn}
            >
              Sign in
            </Button>
          )}
        </div>
      </section>
      <div className="settings-layout">
        <section className="glass settings-panel">
          <h2>Appearance</h2>
          <p>Choose the light that works for you.</p>
          <div className="theme-options">
            {(["light", "dark"] as const).map((theme) => (
              <button
                className={`theme-preview theme-preview-${theme} ${settings.theme === theme ? "selected" : ""}`}
                key={theme}
                onClick={() => update({ ...settings, theme })}
                aria-pressed={settings.theme === theme}
              >
                <span className="theme-window">
                  <span />
                  <span>
                    <i />
                    <i />
                    <i />
                  </span>
                </span>
                <span>
                  {theme === "light" ? <Sun size={16} /> : <Moon size={16} />}{" "}
                  {theme === "light" ? "Daylight" : "After hours"}{" "}
                  {settings.theme === theme && <Check size={15} />}
                </span>
              </button>
            ))}
          </div>
          <div className="settings-divider" />
          <h2>Privacy & history</h2>
          <div className="setting-row">
            <div>
              <strong>Remember analyses on this device</strong>
              <p>
                Save redacted summaries locally. Raw messages and images are
                excluded.
              </p>
            </div>
            <button
              className={`switch ${settings.saveHistory ? "on" : ""}`}
              role="switch"
              aria-checked={settings.saveHistory}
              aria-label="Remember analyses on this device"
              onClick={() =>
                update({ ...settings, saveHistory: !settings.saveHistory })
              }
            >
              <span />
            </button>
          </div>
          <div className="setting-row">
            <div>
              <strong>Sync anonymous scan metadata</strong>
              <p>
                {cloudAvailable
                  ? "Store scan type, verdict, and signal count in PostgreSQL. No content is sent."
                  : "Cloud storage is not configured. Your history stays on this device."}
              </p>
            </div>
            <button
              className={`switch ${settings.cloudSync ? "on" : ""}`}
              role="switch"
              aria-checked={settings.cloudSync}
              aria-label="Sync anonymous scan metadata"
              disabled={!cloudAvailable}
              onClick={() =>
                update({ ...settings, cloudSync: !settings.cloudSync })
              }
            >
              <span />
            </button>
          </div>
          <div className="setting-row">
            <div>
              <strong>Clear saved analyses</strong>
              <p>
                Remove locally saved records and any enabled cloud metadata.
              </p>
            </div>
            {confirm ? (
              <div className="clear-confirm">
                <Button
                  variant="secondary"
                  size="small"
                  onClick={() => {
                    clearHistory();
                    setConfirm(false);
                  }}
                >
                  Yes, clear
                </Button>
                <button
                  className="icon-button"
                  aria-label="Cancel clearing history"
                  onClick={() => setConfirm(false)}
                >
                  <X size={17} />
                </button>
              </div>
            ) : (
              <Button
                variant="ghost"
                size="small"
                onClick={() => setConfirm(true)}
              >
                <Trash2 size={15} /> Clear history
              </Button>
            )}
          </div>
        </section>
        <aside className="privacy-sidebar">
          <LockKeyhole size={26} />
          <h2>Private by design.</h2>
          <p>
            We process submitted text in memory. No messages are retained by the
            analysis server, and no external AI service receives your content.
          </p>
          <p>
            URL and QR scans can query independent reputation providers when
            live checks are enabled. Turn them off for private links. Only URL
            hashes and redacted results are cached.
          </p>
          <p>
            QR decoding and OCR happen in your browser. Fonts, OCR code, and
            language assets are hosted with the app.
          </p>
          <div className="privacy-fact">
            <Check size={16} /> No submitted URLs visited
          </div>
          <div className="privacy-fact">
            <Check size={16} /> No advertising trackers
          </div>
          <div className="privacy-fact">
            <Check size={16} /> No third-party AI requests
          </div>
          <p className="fine-print">
            Hosting infrastructure may retain standard access metadata such as
            timestamps and IP addresses.
          </p>
        </aside>
      </div>
    </>
  );
}
