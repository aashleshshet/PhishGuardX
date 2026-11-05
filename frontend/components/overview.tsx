"use client";
import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Check,
  Clock3,
  FileText,
  Link2,
  LockKeyhole,
  Mail,
  QrCode,
  ScanLine,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { Button } from "./ui/button";
import { ShieldArt } from "./shield-art";
import { RiskBadge } from "./result";
import { articles, kindLabels } from "@/lib/content";
import type { Analysis, Page, ScanKind } from "@/lib/types";
export const toolsList = [
  {
    id: "email" as ScanKind,
    title: "Email analyzer",
    description: "Read between the lines.",
    icon: Mail,
    color: "blue",
  },
  {
    id: "url" as ScanKind,
    title: "URL scanner",
    description: "Look before you click.",
    icon: Link2,
    color: "teal",
  },
  {
    id: "qr" as ScanKind,
    title: "QR scanner",
    description: "Reveal the destination.",
    icon: QrCode,
    color: "violet",
  },
  {
    id: "screenshot" as ScanKind,
    title: "Screenshot analyzer",
    description: "See the hidden signals.",
    icon: ScanLine,
    color: "orange",
  },
];
export function Overview({
  history,
  navigate,
  openResult,
  startSample,
  openArticle,
}: {
  history: Analysis[];
  navigate: (p: Page) => void;
  openResult: (r: Analysis) => void;
  startSample: () => void;
  openArticle: (id: string) => void;
}) {
  const live = history.filter((r) => !r.sample);
  const concerns = live.filter((r) => r.risk !== "low").length;
  return (
    <>
      <div className="overview-heading">
        <div>
          <h1>Your security, at a glance.</h1>
          <p>A little more clarity. A lot more confidence.</p>
        </div>
        <div className="local-tag">
          <span className="status-dot" /> Your private workspace
        </div>
      </div>
      <section className="glass welcome-panel">
        <div className="welcome-copy">
          <h2>
            Trust your instincts.
            <br />
            <span>We’ll check the details.</span>
          </h2>
          <p>
            Suspicious email? Unfamiliar link? Get a clearer picture of the
            risks, before you take the next step.
          </p>
          <div className="welcome-actions">
            <Button onClick={() => navigate("email")}>
              <ScanLine size={17} /> Start an analysis <ArrowRight size={17} />
            </Button>
            <Button variant="ghost" onClick={startSample}>
              Explore a sample <ArrowUpRight size={16} />
            </Button>
          </div>
          <div className="welcome-proof">
            <span>
              <LockKeyhole size={13} /> Privacy by design
            </span>
            <span>
              <Check size={14} /> Evidence you can understand
            </span>
          </div>
        </div>
        <ShieldArt />
      </section>
      <section className="quick-tools" aria-labelledby="quick-title">
        <div className="section-heading">
          <h2 id="quick-title">What would you like to check?</h2>
          <span>Four ways to stay one step ahead</span>
        </div>
        <div className="tool-grid">
          {toolsList.map(({ id, title, description, icon: Icon, color }) => (
            <button
              key={id}
              className={`glass tool-card tool-${color}`}
              onClick={() => navigate(id)}
            >
              <span className={`tool-icon ${color}`}>
                <Icon size={23} />
              </span>
              <ArrowUpRight className="tool-arrow" size={18} />
              <strong>{title}</strong>
              <span className="tool-description">{description}</span>
            </button>
          ))}
        </div>
      </section>
      <div className="overview-lower">
        <section className="glass activity-panel">
          <div className="panel-top">
            <h2>Recent activity</h2>
            <button className="text-button" onClick={() => navigate("history")}>
              View history <ArrowRight size={15} />
            </button>
          </div>
          {history.length ? (
            <div className="activity-list">
              {history.slice(0, 4).map((r) => (
                <button
                  className="activity-row"
                  key={r.id}
                  onClick={() => openResult(r)}
                >
                  <span className={`activity-icon icon-${r.kind}`}>
                    {r.kind === "email" ? (
                      <Mail size={18} />
                    ) : r.kind === "url" ? (
                      <Link2 size={18} />
                    ) : r.kind === "qr" ? (
                      <QrCode size={18} />
                    ) : (
                      <ScanLine size={18} />
                    )}
                  </span>
                  <span className="activity-name">
                    <strong>
                      {r.sample ? "Sample · " : ""}
                      {kindLabels[r.kind]}
                    </strong>
                    <span>
                      {new Date(r.createdAt).toLocaleTimeString([], {
                        hour: "2-digit",
                        minute: "2-digit",
                      })}{" "}
                      · {r.signals.length} signals
                    </span>
                  </span>
                  <RiskBadge risk={r.risk} />
                  <ArrowUpRight size={15} />
                </button>
              ))}
            </div>
          ) : (
            <div className="activity-empty">
              <div className="empty-stack">
                <div />
                <div />
                <FileText size={28} />
              </div>
              <h3>A fresh start. A clearer view.</h3>
              <p>
                Your analyses will appear here.
                <br />
                Start with a link, a message, or a sample.
              </p>
              <button className="text-button" onClick={startSample}>
                Try your first analysis <ArrowRight size={15} />
              </button>
            </div>
          )}
          <div className="activity-footer">
            <span>
              <Clock3 size={13} />
              {live.length} personal scans
            </span>
            <span>{concerns} flagged for review</span>
            <span>
              <LockKeyhole size={12} /> Stored on this device
            </span>
          </div>
        </section>
        <section className="insight-panel">
          <div className="section-heading">
            <h2>A sharper eye, every day.</h2>
            <Sparkles size={18} />
          </div>
          <button
            className="insight-feature"
            onClick={() => openArticle("domain")}
          >
            <div className="domain-illustration" aria-hidden="true">
              <div className="mini-browser">
                <div>
                  <span />
                  <span />
                  <span />
                </div>
                <p>
                  <LockKeyhole size={12} /> paypal.com.
                  <strong>not-paypal.example</strong>
                </p>
              </div>
              <div className="domain-pointer">
                <ArrowUpRight size={14} /> The actual domain
              </div>
            </div>
            <span className="article-meta">
              Link safety <span>·</span> 3 min read
            </span>
            <h3>Look past the familiar name.</h3>
            <p>
              A trusted name in a URL doesn’t always mean a trusted destination.
            </p>
            <span className="text-button">
              Know what to look for <ArrowRight size={15} />
            </span>
          </button>
          <button className="learning-link" onClick={() => navigate("learn")}>
            Explore the learning center <ArrowUpRight size={16} />
          </button>
        </section>
      </div>
      <div className="workspace-bottom">
        <div>
          <ShieldCheck size={16} />
          <span>Built for thoughtful clicks.</span>
        </div>
        <span>Model-assisted analysis. Human judgment always matters.</span>
      </div>
    </>
  );
}
