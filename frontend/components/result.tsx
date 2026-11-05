"use client";
import { useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Download,
  EyeOff,
  Fingerprint,
  Info,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Button } from "./ui/button";
import { exportJSON } from "@/lib/content";
import type { Analysis, Risk } from "@/lib/types";
export const riskLabels: Record<Risk, string> = {
  high: "High concern",
  review: "Needs review",
  low: "Few indicators",
};
export function RiskBadge({ risk }: { risk: Risk }) {
  return (
    <span className={`risk-badge risk-${risk}`}>
      <span />
      {riskLabels[risk]}
    </span>
  );
}
function HighlightedText({ text }: { text: string }) {
  return (
    <>
      {text
        .split(
          /(urgent|immediately|password|verification code|suspended|login credentials|within \d+ hours?)/gi,
        )
        .map((part, i) =>
          /^(urgent|immediately|password|verification code|suspended|login credentials|within \d+ hours?)$/i.test(
            part,
          ) ? (
            <mark key={i}>{part}</mark>
          ) : (
            part
          ),
        )}
    </>
  );
}
export function AnalysisResult({ result }: { result: Analysis }) {
  const [technical, setTechnical] = useState(false);
  const Icon = result.risk === "low" ? ShieldCheck : ShieldAlert;
  return (
    <section
      className="analysis-result"
      aria-label="Analysis results"
      tabIndex={-1}
    >
      <div className={`verdict verdict-${result.risk}`}>
        <div className="verdict-icon">
          <Icon size={29} />
        </div>
        <div>
          <div className="result-label">
            <RiskBadge risk={result.risk} />
            {result.sample && (
              <span className="sample-label">Sample input · real analysis</span>
            )}
          </div>
          <h2>
            {result.risk === "high"
              ? "Pause before you proceed."
              : result.risk === "review"
                ? "Worth a closer look."
                : "No strong signals. Stay thoughtful."}
          </h2>
          <p>{result.summary}</p>
        </div>
      </div>
      <div className="result-heading">
        <h3>
          What we found{" "}
          <span className="count-pill">{result.signals.length}</span>
        </h3>
        <Button
          variant="ghost"
          size="small"
          onClick={() =>
            exportJSON(result, `phishguardx-${result.id.slice(0, 8)}.json`)
          }
        >
          <Download size={15} /> Export report
        </Button>
      </div>
      <div className="evidence-list">
        {result.signals.length ? (
          result.signals.map((signal, i) => (
            <article className="evidence-item" key={signal.code + i}>
              <div className={`evidence-icon ${signal.severity}`}>
                {signal.severity === "info" ? (
                  <Info size={18} />
                ) : (
                  <AlertTriangle size={18} />
                )}
              </div>
              <div>
                <h4>{signal.title}</h4>
                <p>{signal.description}</p>
                {signal.evidence && <blockquote>{signal.evidence}</blockquote>}
              </div>
            </article>
          ))
        ) : (
          <div className="quiet-empty">
            <Check size={22} />
            <p>
              The available checks did not flag specific warning signs. Missing
              evidence can still hide a threat.
            </p>
          </div>
        )}
      </div>
      {result.details.registeredDomain && (
        <div className="domain-facts">
          <div>
            <span>Actual registered domain</span>
            <strong>{result.details.registeredDomain}</strong>
          </div>
          <div>
            <span>Connection</span>
            <strong>{result.details.protocol}</strong>
          </div>
          <div>
            <span>Destination visited</span>
            <strong>No</strong>
          </div>
        </div>
      )}
      {result.details.authentication && (
        <div className="auth-section">
          <h3>Email authentication</h3>
          <div className="auth-grid">
            {result.details.authentication.map((a) => (
              <div key={a.name}>
                <strong>{a.name}</strong>
                <span>{a.result}</span>
              </div>
            ))}
          </div>
          <p className="fine-print">
            Reported in pasted headers. These results have not been
            independently verified.
          </p>
        </div>
      )}
      {result.evidenceText && (
        <details className="text-evidence">
          <summary>
            View analyzed text <ChevronDown size={16} />
          </summary>
          <div>
            <HighlightedText text={result.evidenceText} />
          </div>
        </details>
      )}
      <div className="recommendations">
        <h3>Your next move</h3>
        {result.recommendations.map((r, i) => (
          <p key={r}>
            <span>{i + 1}</span>
            {r}
          </p>
        ))}
      </div>
      <div className="unavailable">
        <EyeOff size={18} />
        <div>
          <strong>What this analysis cannot verify</strong>
          <p>{result.unavailable.join(" · ")}</p>
        </div>
      </div>
      <button
        className="technical-toggle"
        onClick={() => setTechnical(!technical)}
        aria-expanded={technical}
      >
        <Fingerprint size={17} /> Model evidence & methodology{" "}
        <ChevronDown size={16} className={technical ? "rotate" : ""} />
      </button>
      {technical && (
        <div className="model-details">
          <p>
            {result.method} Scores below describe model outputs, not a guarantee
            about this content.
          </p>
          {result.models.map((m, i) => (
            <div className="model-row" key={i}>
              <strong>
                {m.name} <span>v{m.version}</span>
              </strong>
              <div className="model-score">
                <span>
                  {Math.round(m.probability * 100)}% {m.positiveClass} model
                  probability
                </span>
                <span>Threshold: {Math.round(m.threshold * 100)}%</span>
              </div>
              <div className="model-bar">
                <span style={{ width: `${m.probability * 100}%` }} />
              </div>
              <p>
                {m.positiveClass === "spam"
                  ? "Calibrated on historical email spam. This is not a phishing probability."
                  : "Calibrated on a held-out historical URL dataset; real-world calibration may differ."}
                {m.outOfDomain
                  ? " Screenshot text is outside the email training domain."
                  : ""}
              </p>
              {m.features.length > 0 && (
                <div className="feature-tags">
                  {m.features.map((f) => (
                    <code key={f.text}>{f.text}</code>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <div className="result-footer">
        <Check size={14} /> No destinations visited <span>·</span> No external
        AI used
      </div>
    </section>
  );
}
