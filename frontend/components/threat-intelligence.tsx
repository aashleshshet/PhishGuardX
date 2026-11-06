"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Database, RefreshCw, ShieldCheck } from "lucide-react";
import { Button } from "./ui/button";
import type { IntelligenceStatus, ProviderResult } from "@/lib/types";

const labels: Record<string, string> = {
  matched: "Confirmed match",
  unverified: "Unverified report",
  not_found: "No match",
  available: "Available",
  unavailable: "Unavailable",
  disabled: "Disabled",
  not_configured: "Not configured",
  not_checked: "Awaiting first check",
  rate_limited: "Rate limited",
  stale: "Stale snapshot",
  skipped: "Not queried",
  awaiting_sync: "Awaiting first sync",
  sync_failed: "Sync failed",
};
function date(value?: string | null) {
  if (!value) return "Not yet recorded";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toLocaleString();
}
function Status({ status }: { status: string }) {
  return (
    <span className={`provider-status provider-status-${status}`}>
      {labels[status] || "Unknown"}
    </span>
  );
}
function ProviderRow({
  provider,
  scan = false,
}: {
  provider: ProviderResult;
  scan?: boolean;
}) {
  return (
    <article className="provider-row">
      <div className="provider-heading">
        <h3>{provider.source}</h3>
        <Status status={provider.status} />
      </div>
      <p>{provider.message}</p>
      {provider.indicator && (
        <div className="matched-indicator">
          <strong>Matched URL indicator</strong>
          <code>{provider.indicator}</code>
        </div>
      )}
      {(provider.target_brand || provider.record_status) && (
        <p className="provider-meta">
          {provider.target_brand && `Target: ${provider.target_brand}`}
          {provider.target_brand && provider.record_status && " · "}
          {provider.record_status && `Record: ${provider.record_status}`}
        </p>
      )}
      <dl className="provider-facts">
        {scan && (
          <div>
            <dt>Checked</dt>
            <dd>
              {date(provider.checked_at)}
              {provider.cached ? " · cached" : ""}
            </dd>
          </div>
        )}
        <div>
          <dt>Last successful check</dt>
          <dd>{date(provider.last_successful_check)}</dd>
        </div>
        {provider.retry_at && (
          <div>
            <dt>Retry after</dt>
            <dd>{date(provider.retry_at)}</dd>
          </div>
        )}
      </dl>
    </article>
  );
}

export function ProviderEvidence({
  providers,
  checkedAt,
}: {
  providers: Record<string, ProviderResult>;
  checkedAt?: string;
}) {
  return (
    <section
      className="glass provider-evidence"
      aria-labelledby="scan-provider-heading"
    >
      <div className="panel-top">
        <h2 id="scan-provider-heading">Threat intelligence evidence</h2>
        <ShieldCheck size={20} aria-hidden="true" />
      </div>
      <p className="provider-intro">
        No match means the provider has no matching record. It does not
        establish that a URL is safe.
      </p>
      {Object.entries(providers).map(([key, provider]) => (
        <ProviderRow key={key} provider={provider} scan />
      ))}
      <p className="provider-meta">
        Scan recorded {date(checkedAt)} · Query values are hidden in displayed
        indicators.
      </p>
    </section>
  );
}

export function ThreatDashboard() {
  const [data, setData] = useState<IntelligenceStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 55000);
    let active = true;
    setLoading(true);
    setError("");
    fetch("/api/threat-intelligence", {
      cache: "no-store",
      signal: controller.signal,
    })
      .then(async (response) => {
        if (!response.ok) throw new Error("Unavailable");
        const value = await response.json();
        if (!value.providers || !value.feed || !value.checked_at)
          throw new Error("Invalid response");
        if (active) setData(value);
      })
      .catch(() => {
        if (active)
          setError(
            "Provider status could not be loaded. Refresh to try again.",
          );
      })
      .finally(() => {
        clearTimeout(timeout);
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      clearTimeout(timeout);
      controller.abort();
    };
  }, [revision]);
  return (
    <div className="intelligence-page">
      <div className="intelligence-heading">
        <div>
          <h1>Threat intelligence</h1>
          <p>Independent sources. Visible evidence. Honest uncertainty.</p>
        </div>
        <Button
          variant="secondary"
          disabled={loading}
          onClick={() => setRevision((v) => v + 1)}
        >
          <RefreshCw size={16} className={loading ? "spin" : ""} />
          {loading ? "Loading status…" : "Refresh status"}
        </Button>
      </div>
      {error && (
        <p className="error-message" role="alert">
          <AlertTriangle size={18} />
          {error}
          {data && " Previously loaded status is shown below."}
        </p>
      )}
      {!data && loading && (
        <p className="loading-state" role="status">
          Loading provider availability…
        </p>
      )}
      {data && (
        <>
          <section
            className="glass intelligence-feed"
            aria-labelledby="feed-heading"
          >
            <div className="provider-heading">
              <h2 id="feed-heading">
                <Database size={20} aria-hidden="true" />
                OpenPhish.com Community Feed
              </h2>
              <Status status={data.feed.status} />
            </div>
            <p>{data.feed.message}</p>
            <dl className="feed-facts">
              <div>
                <dt>Local URL indicators</dt>
                <dd>{data.feed.count.toLocaleString()}</dd>
              </div>
              <div>
                <dt>Last successful sync</dt>
                <dd>{date(data.feed.last_successful_sync)}</dd>
              </div>
              <div>
                <dt>Feed synchronization</dt>
                <dd>
                  {data.feed.sync_enabled
                    ? `Enabled · at most once per ${Math.round((data.feed.interval_seconds || 86400) / 3600)} hours`
                    : "Disabled"}
                </dd>
              </div>
              <div>
                <dt>Next eligible refresh</dt>
                <dd>{date(data.feed.next_sync_at)}</dd>
              </div>
            </dl>
            <p className="provider-meta">
              Exact URL hashes are stored in {data.storage}.{" "}
              {data.durable_storage
                ? "Storage persists across restarts."
                : "Storage is temporary; hosted feed sync is paused."}{" "}
              OpenPhish.com and OpenPhish.eu are separate services.
            </p>
          </section>
          <section
            className="glass intelligence-providers"
            aria-labelledby="providers-heading"
          >
            <div className="panel-top">
              <h2 id="providers-heading">URL lookup providers</h2>
              <ShieldCheck size={20} aria-hidden="true" />
            </div>
            <p className="provider-intro">
              Availability reflects the last real request. Refreshing this page
              does not send a URL or trigger a feed download.
            </p>
            {Object.entries(data.providers).map(([key, provider]) => (
              <ProviderRow key={key} provider={provider} />
            ))}
            <div className="provider-row">
              <div className="provider-heading">
                <h3>Local URL classifier & heuristics</h3>
                <span className="provider-status">
                  {data.model_available ? "Enabled" : "Unavailable"}
                </span>
              </div>
              <p>
                Local analysis remains part of every scan. A confirmed threat
                match raises the verdict to high risk; missing records never
                override suspicious evidence.
              </p>
            </div>
          </section>
          <p className="provider-meta">
            Status loaded {date(data.checked_at)}. <a href="/url">Scan a URL</a>{" "}
            to see evidence from each source in its report.
          </p>
        </>
      )}
    </div>
  );
}
