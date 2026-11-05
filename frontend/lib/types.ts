export type ScanKind = "email" | "url" | "qr" | "screenshot";
export type Page =
  | "overview"
  | ScanKind
  | "assistant"
  | "history"
  | "learn"
  | "reports"
  | "intelligence"
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
export interface ProviderResult {
  source: string;
  status: string;
  matched?: boolean;
  confirmed?: boolean;
  available?: boolean;
  cached?: boolean;
  checked_at?: string | null;
  last_successful_check?: string | null;
  retry_at?: string | null;
  indicator?: string | null;
  target_brand?: string | null;
  record_status?: string | null;
  threat_type?: string | null;
  message: string;
  enabled?: boolean;
  configured?: boolean;
}
export interface FeedStatus {
  source: string;
  status: string;
  message: string;
  count: number;
  sync_enabled: boolean;
  last_successful_sync?: string | null;
  last_attempt?: string | null;
  next_sync_at?: string | null;
  interval_seconds?: number;
  storage?: string;
}
export interface IntelligenceStatus {
  providers: Record<string, ProviderResult>;
  feed: FeedStatus;
  checked_at: string;
  storage: string;
  durable_storage: boolean;
  model_available: boolean;
}
export interface Analysis {
  url?: string | null;
  verdict?: string;
  providers?: Record<string, ProviderResult>;
  evidence?: {
    source: string;
    confirmed: boolean;
    indicator: string | null;
    description: string;
  }[];
  checked_at?: string;
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
