export type ScanKind = "email" | "url" | "qr" | "screenshot";
export type Page =
  | "overview"
  | ScanKind
  | "assistant"
  | "history"
  | "learn"
  | "reports"
  | "settings";
export type Risk = "low" | "review" | "high";
export interface Signal {
  code: string;
  title: string;
  description: string;
  severity: "warning" | "danger" | "info";
  evidence: string;
}
export interface Model {
  name: string;
  version: string;
  probability: number;
  threshold: number;
  positiveClass: string;
  outOfDomain: boolean;
  matchedFeatures: number;
  features: { text: string; contribution: number }[];
}
export interface Analysis {
  id: string;
  createdAt: string;
  kind: ScanKind;
  risk: Risk;
  summary: string;
  signals: Signal[];
  models: Model[];
  details: {
    hostname?: string;
    registeredDomain?: string;
    protocol?: string;
    reputation?: string;
    visited?: boolean;
    authentication?: { name: string; result: string; verified: boolean }[];
    destinations?: { hostname: string; registeredDomain: string }[];
  };
  links: string[];
  unavailable: string[];
  recommendations: string[];
  privacy: { retained: boolean; externalAI: boolean; urlsVisited: boolean };
  evidenceText: string;
  method: string;
  sample?: boolean;
}
export interface Settings {
  saveHistory: boolean;
  theme: "light" | "dark";
  cloudSync: boolean;
}
