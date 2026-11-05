"use client";
import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AnimatePresence, MotionConfig, motion } from "framer-motion";
import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Check,
  ChevronDown,
  CircleHelp,
  FileBarChart2,
  History,
  LayoutDashboard,
  Link2,
  LockKeyhole,
  Mail,
  Menu,
  MessageCircle,
  Moon,
  Plus,
  QrCode,
  ScanLine,
  Settings2,
  ShieldCheck,
  Sparkles,
  Sun,
  X,
} from "lucide-react";
import { Button } from "./ui/button";
import { useIdentity } from "./auth-provider";
import { Overview } from "./overview";
import { Scanner } from "./scanner";
import { ThreatDashboard } from "./threat-intelligence";
import { AnalysisResult } from "./result";
import {
  AssistantPage,
  HistoryPage,
  LearnPage,
  ReportsPage,
  SettingsPage,
} from "./secondary-pages";
import { samples } from "@/lib/content";
import type { Analysis, Page, Settings } from "@/lib/types";
const pages: { id: Page; label: string; icon: typeof Mail; group: string }[] = [
  {
    id: "overview",
    label: "Overview",
    icon: LayoutDashboard,
    group: "workspace",
  },
  { id: "email", label: "Email analyzer", icon: Mail, group: "analyze" },
  { id: "url", label: "URL scanner", icon: Link2, group: "analyze" },
  { id: "qr", label: "QR scanner", icon: QrCode, group: "analyze" },
  {
    id: "screenshot",
    label: "Screenshot analyzer",
    icon: ScanLine,
    group: "analyze",
  },
  {
    id: "assistant",
    label: "Security assistant",
    icon: Sparkles,
    group: "workspace",
  },
  {
    id: "history",
    label: "Analysis history",
    icon: History,
    group: "workspace",
  },
  { id: "learn", label: "Learning center", icon: BookOpen, group: "resources" },
  {
    id: "intelligence",
    label: "Threat intelligence",
    icon: ShieldCheck,
    group: "resources",
  },
  { id: "reports", label: "Reports", icon: FileBarChart2, group: "resources" },
];
const defaults: Settings = {
  saveHistory: true,
  theme: "light",
  cloudSync: false,
};
function redact(result: Analysis): Analysis {
  return {
    ...result,
    evidenceText: "",
    url: null,
    evidence: result.evidence?.map((e) => ({ ...e, indicator: null })),
    providers: result.providers
      ? Object.fromEntries(
          Object.entries(result.providers).map(([key, p]) => [
            key,
            { ...p, indicator: null },
          ]),
        )
      : undefined,
    links: [],
    details: {
      protocol: result.details.protocol,
      authentication: result.details.authentication,
    },
    signals: result.signals.map((s) => ({ ...s, evidence: "" })),
    models: result.models.map((m) => ({ ...m, features: [] })),
  };
}
function historyToken(storageKey: string) {
  let token = localStorage.getItem(storageKey);
  if (!token) {
    token = Array.from(crypto.getRandomValues(new Uint8Array(32)), (v) =>
      v.toString(16).padStart(2, "0"),
    ).join("");
    localStorage.setItem(storageKey, token);
  }
  return token;
}
export function Workspace({ children }: { children: React.ReactNode }) {
  const identity = useIdentity();
  const accountName =
    identity.user?.fullName ||
    identity.user?.firstName ||
    identity.user?.username ||
    identity.user?.primaryEmailAddress?.emailAddress ||
    "Sign in";
  const historyKey = `pgx-history-v1:${identity.user?.id || "guest"}`;
  const tokenKey = `pgx-cloud-token:${identity.user?.id || "guest"}`;
  const router = useRouter();
  const path = usePathname();
  const page = (path.slice(1) || "overview") as Page;
  const [settings, setSettings] = useState<Settings>(defaults);
  const [history, setHistory] = useState<Analysis[]>([]);
  const [latest, setLatest] = useState<Analysis | null>(null);
  const [selected, setSelected] = useState<Analysis | null>(null);
  const [menu, setMenu] = useState(false);
  const [article, setArticle] = useState<string | null>(null);
  const [seed, setSeed] = useState<string | undefined>();
  const [toast, setToast] = useState("");
  const [cloud, setCloud] = useState(false);
  const [online, setOnline] = useState<boolean | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    try {
      const saved = JSON.parse(
        localStorage.getItem("pgx-settings-v1") || "null",
      );
      if (saved) {
        const valid = {
          saveHistory:
            typeof saved.saveHistory === "boolean" ? saved.saveHistory : true,
          theme: saved.theme === "dark" ? "dark" : "light",
          cloudSync: !!saved.cloudSync,
        } as Settings;
        setSettings(valid);
        document.documentElement.dataset.theme = valid.theme;
      }
    } catch {
      setToast(
        "Saved preferences could not be read. This session will use defaults.",
      );
    }
    setReady(true);
    const controller = new AbortController();
    fetch("/api/health", { signal: controller.signal })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then((d) => {
        setOnline(d.status === "ok" && d.models);
        setCloud(!!d.cloudHistory);
      })
      .catch(() => setOnline(false));
    return () => controller.abort();
  }, []);
  useEffect(() => {
    setHistory([]);
    setLatest(null);
    setSelected(null);
    if (!identity.loaded) return;
    try {
      const records = JSON.parse(localStorage.getItem(historyKey) || "[]");
      if (Array.isArray(records))
        setHistory(
          records
            .filter(
              (r) =>
                r &&
                typeof r.id === "string" &&
                ["url", "email", "qr", "screenshot"].includes(r.kind) &&
                ["high", "review", "low"].includes(r.risk) &&
                Array.isArray(r.signals) &&
                Array.isArray(r.models) &&
                Array.isArray(r.unavailable) &&
                r.details &&
                Array.isArray(r.recommendations),
            )
            .slice(0, 100),
        );
    } catch {
      setToast("Saved history could not be read.");
    }
  }, [historyKey, identity.loaded]);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 6000);
    return () => clearTimeout(t);
  }, [toast]);
  useEffect(() => {
    const handle = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setMenu(false);
      }
    };
    document.addEventListener("keydown", handle);
    return () => document.removeEventListener("keydown", handle);
  }, []);
  function navigate(next: Page) {
    setSelected(null);
    setMenu(false);
    setSeed(undefined);
    router.push(next === "overview" ? "/" : "/" + next);
  }
  function updateSettings(next: Settings) {
    setSettings(next);
    document.documentElement.dataset.theme = next.theme;
    try {
      localStorage.setItem("pgx-settings-v1", JSON.stringify(next));
    } catch {
      setToast("Preferences could not be saved in this browser.");
    }
  }
  function writeHistory(records: Analysis[]) {
    setHistory(records);
    try {
      localStorage.setItem(historyKey, JSON.stringify(records));
    } catch {
      setToast(
        "The scan completed, but history could not be saved. Browser storage may be full.",
      );
    }
  }
  async function complete(result: Analysis) {
    setLatest(result);
    if (settings.saveHistory)
      writeHistory([redact(result), ...history].slice(0, 100));
    if (settings.cloudSync && cloud && !result.sample) {
      try {
        const response = await fetch("/api/history", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-History-Token": historyToken(tokenKey),
          },
          body: JSON.stringify({
            id: result.id,
            kind: result.kind,
            risk: result.risk,
            signal_count: result.signals.length,
          }),
        });
        if (!response.ok) throw new Error();
      } catch {
        setToast(
          "Analysis complete. Cloud metadata sync failed; your local result is available.",
        );
      }
    }
  }
  function startSample() {
    setSelected(null);
    setMenu(false);
    setSeed(samples.email);
    router.push("/email");
  }
  function openResult(result: Analysis) {
    setSelected(result);
    router.push("/history");
  }
  async function clearHistory() {
    writeHistory([]);
    setSelected(null);
    setLatest(null);
    if (cloud) {
      try {
        const token = localStorage.getItem(tokenKey);
        if (token) {
          const r = await fetch("/api/history", {
            method: "DELETE",
            headers: { "X-History-Token": token },
          });
          if (!r.ok) throw new Error();
        }
      } catch {
        setToast(
          "Local history cleared. Cloud deletion failed; try clearing again.",
        );
        return;
      }
    }
    setToast("Your saved analyses have been cleared.");
  }
  const current = pages.find((p) => p.id === page)?.label || "Settings";
  return (
    <MotionConfig reducedMotion="user">
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <div className="ambient-background" aria-hidden="true" />
      <div className="app-shell">
        {menu && (
          <button
            className="nav-scrim"
            aria-label="Close navigation"
            onClick={() => setMenu(false)}
          />
        )}
        <aside
          className={`sidebar ${menu ? "sidebar-open" : ""}`}
          aria-label="Main navigation"
        >
          <a
            className="brand"
            href="/"
            onClick={(e) => {
              e.preventDefault();
              navigate("overview");
            }}
          >
            <span className="brand-symbol">
              <ShieldCheck size={24} />
            </span>
            <span>
              PhishGuard<span className="brand-x">X</span>
              <small>Clarity before you click.</small>
            </span>
          </a>
          <button
            className="workspace-selector"
            onClick={() =>
              identity.user
                ? identity.openProfile()
                : identity.configured
                  ? identity.openSignIn()
                  : navigate("settings")
            }
          >
            <span className="workspace-avatar">
              {identity.user?.imageUrl ? (
                <img src={identity.user.imageUrl} alt="" />
              ) : identity.user ? (
                accountName[0].toUpperCase()
              ) : (
                <ShieldCheck size={17} />
              )}
            </span>
            <span>
              {identity.loaded ? accountName : "Loading account…"}
              <small>
                {identity.user?.primaryEmailAddress?.emailAddress ||
                  "Your secure account"}
              </small>
            </span>
            <ChevronDown size={14} />
          </button>
          <nav>
            {pages.map((item, i) => {
              const Icon = item.icon;
              return (
                <div key={item.id}>
                  {i === 1 && (
                    <div className="nav-group-label">Analysis tools</div>
                  )}
                  {i === 5 && <div className="nav-separator" />}
                  {i === 7 && (
                    <div className="nav-group-label">Your resources</div>
                  )}
                  <a
                    href={item.id === "overview" ? "/" : "/" + item.id}
                    className={`nav-item ${page === item.id ? "active" : ""}`}
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(item.id);
                    }}
                    aria-current={page === item.id ? "page" : undefined}
                  >
                    {page === item.id && (
                      <motion.span
                        className="nav-active-background"
                        layoutId="active-navigation"
                        transition={{
                          type: "spring",
                          stiffness: 380,
                          damping: 35,
                        }}
                      />
                    )}
                    <Icon size={18} />
                    <span>{item.label}</span>
                    {item.id === "assistant" && (
                      <span className="nav-new">AI</span>
                    )}
                  </a>
                </div>
              );
            })}
          </nav>
          <div className="sidebar-bottom">
            <div className="privacy-mini">
              <span>
                <LockKeyhole size={17} />
              </span>
              <strong>Your data stays yours.</strong>
              <p>
                Private analysis.
                <br />
                No unnecessary retention.
              </p>
              <button onClick={() => navigate("settings")}>
                Our approach <ArrowRight size={13} />
              </button>
            </div>
            <a
              href="/settings"
              className={`nav-item ${page === "settings" ? "active" : ""}`}
              onClick={(e) => {
                e.preventDefault();
                navigate("settings");
              }}
            >
              <Settings2 size={18} /> Settings
            </a>
            <div className="sidebar-footnote">
              <span className="status-dot" /> Made for peace of mind
            </div>
          </div>
        </aside>
        <div className="app-main">
          <header className="topbar">
            <div className="breadcrumb">
              <button
                className="icon-button mobile-menu"
                onClick={() => setMenu(!menu)}
                aria-label="Open navigation"
                aria-expanded={menu}
              >
                <Menu size={21} />
              </button>
              <span className="breadcrumb-workspace">
                {identity.user
                  ? identity.user.firstName || accountName
                  : "PhishGuardX"}
              </span>
              <span className="breadcrumb-slash">/</span>
              <strong>{current}</strong>
            </div>
            <div className="topbar-actions">
              <span
                className={`service-state ${online === false ? "offline" : ""}`}
              >
                <span />
                {online === null
                  ? "Connecting"
                  : online
                    ? "Analysis ready"
                    : "Service offline"}
              </span>
              <button
                className="icon-button theme-toggle"
                aria-label={
                  settings.theme === "light"
                    ? "Switch to dark theme"
                    : "Switch to light theme"
                }
                onClick={() =>
                  updateSettings({
                    ...settings,
                    theme: settings.theme === "light" ? "dark" : "light",
                  })
                }
              >
                {settings.theme === "light" ? (
                  <Moon size={18} />
                ) : (
                  <Sun size={18} />
                )}
              </button>
              <button
                className="icon-button help-button"
                onClick={() => navigate("learn")}
                aria-label="Open learning center"
              >
                <CircleHelp size={19} />
              </button>
              <button
                className="profile-avatar"
                aria-label={
                  identity.user
                    ? `Manage ${accountName} account`
                    : "Sign in to PhishGuardX"
                }
                onClick={() =>
                  identity.user
                    ? identity.openProfile()
                    : identity.configured
                      ? identity.openSignIn()
                      : navigate("settings")
                }
              >
                {identity.user?.imageUrl ? (
                  <img src={identity.user.imageUrl} alt="" />
                ) : identity.user ? (
                  accountName[0].toUpperCase()
                ) : (
                  <ShieldCheck size={16} />
                )}
              </button>
            </div>
          </header>
          <main id="main-content" tabIndex={-1}>
            {children}
            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                key={`${page}:${identity.user?.id || "guest"}`}
                initial={{ opacity: 0.65, y: 5 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0.7 }}
                transition={{ duration: 0.18 }}
              >
                {page === "overview" && (
                  <Overview
                    history={history}
                    navigate={navigate}
                    openResult={openResult}
                    startSample={startSample}
                    openArticle={(id) => {
                      setArticle(id);
                      navigate("learn");
                    }}
                  />
                )}
                {(["email", "url", "qr", "screenshot"] as string[]).includes(
                  page,
                ) && (
                  <Scanner
                    key={page}
                    kind={page as "email" | "url" | "qr" | "screenshot"}
                    onComplete={(r) => void complete(r)}
                    seed={seed}
                  />
                )}
                {page === "history" &&
                  (selected ? (
                    <>
                      <button
                        className="text-button back-to-history"
                        onClick={() => setSelected(null)}
                      >
                        <ArrowLeft size={16} /> Back to history
                      </button>
                      <div className="glass saved-result">
                        <p className="saved-notice">
                          <LockKeyhole size={15} /> Saved summary · original
                          content and evidence snippets are not retained.
                        </p>
                        <AnalysisResult result={selected} />
                      </div>
                    </>
                  ) : (
                    <HistoryPage
                      history={history}
                      openResult={openResult}
                      remove={(id) => {
                        writeHistory(history.filter((r) => r.id !== id));
                        setToast("Local record deleted.");
                      }}
                      navigate={navigate}
                    />
                  ))}
                {page === "assistant" && (
                  <AssistantPage
                    latest={latest || history[0] || null}
                    navigate={navigate}
                  />
                )}
                {page === "learn" && (
                  <LearnPage article={article} setArticle={setArticle} />
                )}
                {page === "intelligence" && <ThreatDashboard />}
                {page === "reports" && <ReportsPage history={history} />}
                {page === "settings" && (
                  <SettingsPage
                    settings={settings}
                    update={updateSettings}
                    clearHistory={() => void clearHistory()}
                    cloudAvailable={cloud}
                  />
                )}
              </motion.div>
            </AnimatePresence>
          </main>
          <footer className="app-footer">
            <span>
              PhishGuardX <span>·</span> Thoughtful security.
            </span>
            <a
              href="https://github.com/aashleshshet/PhishGuardX"
              target="_blank"
              rel="noopener noreferrer"
            >
              Open source <ArrowRight size={12} />
            </a>
          </footer>
        </div>
      </div>
      <AnimatePresence>
        {toast && (
          <motion.div
            className="toast"
            role="status"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <InfoToast />
            <span>{toast}</span>
            <button
              aria-label="Dismiss notification"
              onClick={() => setToast("")}
            >
              <X size={16} />
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </MotionConfig>
  );
}
function InfoToast() {
  return <Check size={18} />;
}
