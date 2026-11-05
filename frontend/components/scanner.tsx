"use client";
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowRight,
  FileImage,
  ImagePlus,
  Link2,
  LoaderCircle,
  LockKeyhole,
  Mail,
  QrCode,
  ScanLine,
  Sparkles,
  Upload,
  X,
} from "lucide-react";
import { Button } from "./ui/button";
import { AnalysisResult } from "./result";
import { MailboxConnect } from "./mailbox-connect";
import { samples } from "@/lib/content";
import type { Analysis, ScanKind } from "@/lib/types";
const info = {
  email: {
    title: "A second opinion on your inbox.",
    description:
      "Paste a message or upload an .eml file. Understand the language, links, and sender signals.",
    icon: Mail,
  },
  url: {
    title: "Know the link. Before you click.",
    description:
      "Inspect a destination for suspicious patterns, misleading domains, and hidden warning signs.",
    icon: Link2,
  },
  qr: {
    title: "See where that QR code leads.",
    description:
      "Decode an image and inspect its destination. The link is never opened.",
    icon: QrCode,
  },
  screenshot: {
    title: "Read between the pixels.",
    description:
      "Extract text from a screenshot and uncover possible social-engineering signals.",
    icon: ScanLine,
  },
};
export function Scanner({
  kind,
  onComplete,
  seed,
}: {
  kind: ScanKind;
  onComplete: (r: Analysis) => void;
  seed?: string;
}) {
  const [content, setContent] = useState(seed || "");
  const [liveChecks, setLiveChecks] = useState(true);
  const [headers, setHeaders] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<Analysis | null>(null);
  const [sample, setSample] = useState(Boolean(seed));
  const [fileName, setFileName] = useState("");
  const [drag, setDrag] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const output = useRef<HTMLDivElement>(null);
  const run = useRef(0);
  useEffect(
    () => () => {
      run.current += 1;
    },
    [],
  );
  const Icon = info[kind].icon;
  const isImage = kind === "qr" || kind === "screenshot";
  async function loadFile(file: File) {
    setError("");
    setSample(false);
    setResult(null);
    setContent("");
    setFileName("");
    if (file.size > 8 * 1024 * 1024) {
      setError("This file is over 8 MB. Choose a smaller image or email.");
      return;
    }
    if (kind === "email") {
      if (!/\.(eml|txt)$/i.test(file.name)) {
        setError("Choose an .eml or .txt email file.");
        return;
      }
      const text = await file.text();
      if (text.length > 30000) {
        setError(
          "This email is too long. Paste the relevant section (up to 30,000 characters).",
        );
        return;
      }
      setContent(text);
      setFileName(file.name);
      return;
    }
    if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
      setError("Choose a PNG, JPG, or WebP image.");
      return;
    }
    const current = ++run.current;
    setBusy(true);
    setProgress(
      kind === "qr"
        ? "Decoding QR code locally…"
        : "Reading screenshot locally…",
    );
    try {
      const bitmap = await createImageBitmap(file);
      if (bitmap.width * bitmap.height > 24000000) {
        bitmap.close();
        throw new Error(
          "This image is too large to process. Use an image under 24 megapixels.",
        );
      }
      if (kind === "qr") {
        const jsQR = (await import("jsqr")).default;
        const canvas = document.createElement("canvas");
        const scale = Math.min(1, 2000 / Math.max(bitmap.width, bitmap.height));
        canvas.width = Math.round(bitmap.width * scale);
        canvas.height = Math.round(bitmap.height * scale);
        const ctx = canvas.getContext("2d");
        if (!ctx)
          throw new Error("Image processing is unavailable in this browser.");
        ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
        bitmap.close();
        const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(data.data, data.width, data.height, {
          inversionAttempts: "attemptBoth",
        });
        if (!code)
          throw new Error(
            "No readable QR code was found. Try a clearer, tightly cropped image.",
          );
        if (!/^https?:\/\//i.test(code.data))
          throw new Error(
            "This QR code contains non-web data. Only HTTP and HTTPS destinations can be analyzed.",
          );
        if (current === run.current) setContent(code.data);
      } else {
        bitmap.close();
        const { createWorker } = await import("tesseract.js");
        const worker = await createWorker("eng", 1, {
          workerPath: "/ocr/worker.min.js",
          corePath: "/ocr",
          langPath: "/ocr",
          logger: (m) => {
            if (current === run.current && m.status === "recognizing text")
              setProgress(
                `Reading screenshot… ${Math.round(m.progress * 100)}%`,
              );
          },
        });
        try {
          const { data } = await worker.recognize(file);
          if (data.text.trim().length < 5)
            throw new Error(
              "No readable text was found. Try a sharper image or paste the text below.",
            );
          if (current === run.current) setContent(data.text.slice(0, 30000));
        } finally {
          await worker.terminate();
        }
      }
      if (current === run.current) setFileName(file.name);
    } catch (e) {
      if (current === run.current)
        setError(
          e instanceof Error
            ? e.message
            : "The file could not be read. Try a different image.",
        );
    } finally {
      if (current === run.current) {
        setBusy(false);
        setProgress("");
      }
    }
  }
  async function analyze() {
    if (!content.trim() || busy) return;
    const current = ++run.current;
    setBusy(true);
    setError("");
    setResult(null);
    setProgress("Checking available intelligence and running classifiers…");
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          kind,
          content,
          headers,
          check_reputation: liveChecks,
        }),
        signal: AbortSignal.timeout(60000),
      });
      const data = await response.json();
      if (!response.ok)
        throw new Error(
          typeof data.detail === "string"
            ? data.detail
            : "The input could not be analyzed. Check the content and try again.",
        );
      if (current !== run.current) return;
      const value = { ...data, sample } as Analysis;
      setResult(value);
      onComplete(value);
      setTimeout(
        () =>
          output.current?.scrollIntoView({
            behavior: window.matchMedia("(prefers-reduced-motion: reduce)")
              .matches
              ? "instant"
              : "smooth",
            block: "start",
          }),
        80,
      );
    } catch (e) {
      if (current === run.current)
        setError(
          e instanceof Error ? e.message : "Analysis failed. Please try again.",
        );
    } finally {
      if (current === run.current) {
        setBusy(false);
        setProgress("");
      }
    }
  }
  function useSample() {
    setContent(samples[kind]);
    setHeaders("");
    setSample(true);
    setFileName("");
    setResult(null);
    setError("");
  }
  return (
    <div className="scanner-layout">
      <div className="scanner-main">
        <div className="page-intro">
          <div className={`page-icon icon-${kind}`}>
            <Icon size={23} />
          </div>
          <h1>{info[kind].title}</h1>
          <p>{info[kind].description}</p>
        </div>
        {kind === "email" && (
          <MailboxConnect
            onImport={(text, rawHeaders) => {
              setContent(text);
              setHeaders(rawHeaders);
              setSample(false);
              setFileName("");
              setResult(null);
              setError("");
            }}
          />
        )}
        <section className="glass scanner-panel">
          <div className="panel-top">
            <h2>
              {kind === "email"
                ? "Your email"
                : kind === "url"
                  ? "Destination URL"
                  : kind === "qr"
                    ? "QR code image"
                    : "Your screenshot"}
            </h2>
            <button className="text-button" onClick={useSample} disabled={busy}>
              <Sparkles size={15} /> Try a sample
            </button>
          </div>
          {(isImage || kind === "email") && (
            <>
              <input
                ref={input}
                type="file"
                accept={
                  kind === "email"
                    ? ".eml,.txt"
                    : "image/png,image/jpeg,image/webp"
                }
                className="sr-only"
                aria-label={`Upload ${kind === "email" ? "email" : "image"}`}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void loadFile(file);
                  e.target.value = "";
                }}
              />
              <button
                className={`upload-zone ${drag ? "drag-active" : ""} ${kind === "email" ? "upload-compact" : ""}`}
                disabled={busy}
                onClick={() => input.current?.click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDrag(true);
                }}
                onDragLeave={() => setDrag(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDrag(false);
                  if (busy) return;
                  const file = e.dataTransfer.files[0];
                  if (file) void loadFile(file);
                }}
              >
                <span className="upload-icon">
                  {isImage ? <ImagePlus size={25} /> : <Upload size={20} />}
                </span>
                <strong>
                  {fileName ||
                    (isImage
                      ? "Upload photo or drop an image"
                      : "Drop an email file, or browse")}
                </strong>
                <span>
                  {isImage
                    ? "Choose a photo · PNG, JPG, WebP · up to 8 MB"
                    : ".eml or .txt · up to 30,000 characters"}
                </span>
              </button>
            </>
          )}
          <label htmlFor="scan-input" className="field-label">
            {kind === "url"
              ? "Paste a link"
              : kind === "email"
                ? "Message content"
                : kind === "qr"
                  ? "Decoded destination (or paste a URL)"
                  : "Extracted text (review before analyzing)"}
          </label>
          {kind === "url" || kind === "qr" ? (
            <div className="url-input-wrap">
              <Link2 size={19} />
              <input
                id="scan-input"
                type="text"
                inputMode="url"
                placeholder="https://example.com/suspicious-link"
                autoComplete="off"
                spellCheck={false}
                value={content}
                maxLength={4096}
                disabled={busy}
                onChange={(e) => {
                  setContent(e.target.value);
                  setSample(false);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void analyze();
                }}
              />
            </div>
          ) : (
            <textarea
              id="scan-input"
              placeholder={
                kind === "email"
                  ? "Paste the email you want to check, including any links…"
                  : "Text from your screenshot will appear here. You can also paste it directly…"
              }
              value={content}
              maxLength={30000}
              disabled={busy}
              onChange={(e) => {
                setContent(e.target.value);
                setSample(false);
              }}
              rows={10}
            />
          )}
          {kind === "email" && (
            <details className="headers-input">
              <summary>
                Add email headers <span>Optional</span>
                <ChevronIcon />
              </summary>
              <label htmlFor="header-input" className="sr-only">
                Raw email headers
              </label>
              <textarea
                id="header-input"
                placeholder="Paste raw headers including Authentication-Results, From, and Reply-To…"
                value={headers}
                maxLength={20000}
                onChange={(e) => setHeaders(e.target.value)}
                rows={4}
              />
            </details>
          )}
          {sample && (
            <p className="sample-notice">
              <InfoIcon /> Demonstration input. The result will be calculated by
              the real analysis engine.
            </p>
          )}
          {error && (
            <div className="error-message" role="alert">
              {error}
            </div>
          )}
          {(kind === "url" || kind === "qr") && (
            <div className="reputation-consent">
              <label>
                <input
                  type="checkbox"
                  checked={liveChecks}
                  disabled={busy}
                  onChange={(e) => setLiveChecks(e.target.checked)}
                />{" "}
                Check live threat intelligence
              </label>
              <p>
                {liveChecks
                  ? "This URL, including its query parameters, may be sent to enabled reputation providers. Turn off for private links. Embedded credentials and fragments are never sent."
                  : "Only the local feed, URL heuristics, and ML model will be used."}{" "}
                <a href="/intelligence">View providers</a>
              </p>
            </div>
          )}
          <div className="scan-actions">
            <span>
              <LockKeyhole size={14} />{" "}
              {isImage
                ? "Images stay on your device"
                : kind === "url"
                  ? "No destinations visited"
                  : "No content retained by the server"}
            </span>
            <Button
              onClick={() => void analyze()}
              disabled={busy || !content.trim()}
            >
              {busy ? (
                <LoaderCircle size={17} className="spin" />
              ) : (
                <ScanLine size={17} />
              )}{" "}
              {busy
                ? "Working…"
                : "Analyze " +
                  (kind === "url"
                    ? "link"
                    : kind === "qr"
                      ? "destination"
                      : kind === "email"
                        ? "email"
                        : "text")}{" "}
              {!busy && <ArrowRight size={16} />}
            </Button>
          </div>
          <div className="scan-progress" aria-live="polite">
            {busy && (
              <>
                <span className="progress-line" />
                {progress}
              </>
            )}
          </div>
        </section>
        <div ref={output} className="result-anchor">
          <AnimatePresence>
            {result && (
              <motion.div
                initial={{ opacity: 0.4, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                className="glass result-panel"
              >
                <AnalysisResult result={result} />
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
      <aside className="scanner-aside">
        <div className="aside-note">
          <div className="aside-icon">
            <LockKeyhole size={20} />
          </div>
          <h3>A private second opinion.</h3>
          <p>
            {isImage
              ? "Your image is decoded on your device. Only reviewed text or destinations reach our server. Live URL checks also use enabled reputation providers."
              : kind === "url"
                ? "Local heuristics and ML are combined with available threat intelligence. Only URL hashes and redacted cache results are retained; destinations are never visited."
                : "Your content is processed for this scan and is not stored on the server or sent to external AI services."}
          </p>
        </div>
        <div className="aside-divider" />
        <h3>What gets checked</h3>
        <ul className="check-list">
          {(kind === "email"
            ? [
                "Language & pressure tactics",
                "Links & domain patterns",
                "Reported authentication headers",
                "Calibrated spam classifier",
              ]
            : kind === "screenshot"
              ? [
                  "Text extracted with local OCR",
                  "Requests for sensitive data",
                  "Urgency & coercion",
                  "Visible URLs & domain patterns",
                ]
              : [
                  "Actual destination domain",
                  "Brand & lookalike indicators",
                  "URL structure & encoding",
                  "Calibrated URL classifier",
                ]
          ).map((c) => (
            <li key={c}>
              <span />
              <span>{c}</span>
            </li>
          ))}
        </ul>
        <div className="limitation-note">
          <FingerprintIcon />
          <p>
            A signal, not a certainty.
            <br />
            Always verify sensitive requests independently.
          </p>
        </div>
      </aside>
    </div>
  );
}
function ChevronIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}
function InfoIcon() {
  return (
    <span aria-hidden="true" className="tiny-info">
      i
    </span>
  );
}
function FingerprintIcon() {
  return <EyeIcon />;
}
function EyeIcon() {
  return <LockKeyhole size={18} />;
}
