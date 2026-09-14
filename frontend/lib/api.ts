const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export type JobStatus =
  | "pending" | "uploading" | "extracting" | "analyzing_identity"
  | "analyzing_similarity" | "analyzing_dex" | "scoring"
  | "generating_report" | "completed" | "failed";

export interface ApkInfo {
  role: string;
  original_filename: string | null;
  file_sha256: string | null;
  file_size_bytes: number | null;
  package_name: string | null;
  app_label: string | null;
  version_name: string | null;
  version_code: string | null;
  min_sdk: number | null;
  target_sdk: number | null;
  cert_sha256: string | null;
  permissions: string[];
  activities: string[];
  services: string[];
  receivers: string[];
  providers: string[];
  is_valid: boolean;
  parse_error: string | null;
}

export interface RiskFinding {
  finding_type: string;
  severity: "low" | "medium" | "high";
  evidence: string;
  source_apk: string | null;
}

export interface FinalScore {
  clone_probability: number;
  malware_risk: number;
  confidence: number;
  weights_used: Record<string, number>;
  component_scores: Record<string, number>;
  verdict_summary: string;
}

export interface FullAnalysisResult {
  job_id: string;
  status: JobStatus;
  error_message: string | null;
  apks: ApkInfo[];
  identity: {
    certificate_score: number;
    certificate_match: boolean;
    package_score: number;
    manifest_score: number;
    permissions_score: number;
    findings: any[];
  } | null;
  similarity: {
    icon_score: number;
    icon_phash_distance: number | null;
    string_score: number;
    layout_score: number;
    resource_score: number;
    diff_image_path: string | null;
    findings: any[];
  } | null;
  dex: {
    dex_score: number;
    malware_risk: number;
    class_count_original: number | null;
    class_count_candidate: number | null;
    method_count_original: number | null;
    method_count_candidate: number | null;
    ssdeep_score: number | null;
    api_call_similarity: number;
    weighted_api_similarity: number | null;
    method_api_similarity: number | null;
    cluster_similarity: number | null;
  } | null;
  risk_findings: RiskFinding[];
  final_score: FinalScore | null;
  report: { json_path: string | null; html_path: string | null; pdf_path: string | null } | null;
}

export async function submitAnalysis(original: File, candidate: File): Promise<{ job_id: string; status: string }> {
  const form = new FormData();
  form.append("original", original);
  form.append("candidate", candidate);
  const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: form });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Upload failed (${res.status})`);
  }
  return res.json();
}

export async function getStatus(jobId: string) {
  const res = await fetch(`${API_BASE}/api/analyze/${jobId}/status`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Status check failed (${res.status})`);
  return res.json();
}

export async function getFullResult(jobId: string): Promise<FullAnalysisResult> {
  const res = await fetch(`${API_BASE}/api/analyze/${jobId}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Result fetch failed (${res.status})`);
  return res.json();
}

export function downloadReportUrl(jobId: string, fmt: "pdf" | "html" | "json") {
  return `${API_BASE}/api/reports/${jobId}/download?fmt=${fmt}`;
}

export const STAGE_LABELS: Record<string, string> = {
  queued: "Queued",
  uploading: "Uploading APKs",
  extracting: "Extracting APK contents",
  analyzing_identity: "Analyzing identity",
  comparing_resources: "Comparing resources",
  analyzing_dex: "Analyzing DEX",
  calculating_risk: "Calculating risk",
  generating_report: "Generating report",
  completed: "Completed",
};

/* ------------------------------------------------------------------ */
/*  9-Signal display metadata                                         */
/* ------------------------------------------------------------------ */

export type SignalCategory = "identity" | "similarity" | "code";

export interface SignalMeta {
  key: string;
  label: string;
  category: SignalCategory;
  description: string;
}

export const SIGNAL_META: SignalMeta[] = [
  { key: "certificate", label: "Certificate",            category: "identity",   description: "Signing certificate match" },
  { key: "package",     label: "Package Name",            category: "identity",   description: "Namespace / package similarity" },
  { key: "manifest",    label: "Manifest Score",          category: "identity",   description: "Exported component overlap (activities, services, receivers, providers)" },
  { key: "permissions", label: "Permissions Score",       category: "identity",   description: "Declared permission overlap" },
  { key: "icon",        label: "Icon Hash",               category: "similarity", description: "Perceptual hash distance" },
  { key: "strings",     label: "Strings (Entropy-filtered)", category: "similarity", description: "TF-IDF cosine similarity of user-visible strings" },
  { key: "layout",      label: "Layout (Tree Paths)",     category: "similarity", description: "Blended tag-frequency + structural tree-path similarity" },
  { key: "resources",   label: "Resources",               category: "similarity", description: "Shared res/ file overlap" },
  { key: "dex",         label: "DEX (Sensitive Clusters)", category: "code",      description: "Weighted API + cluster similarity across DEX bytecode" },
];

export const CATEGORY_LABELS: Record<SignalCategory, string> = {
  identity: "Identity",
  similarity: "Similarity",
  code: "Code Analysis",
};

export const SENSITIVE_CLUSTER_LABELS: Record<string, string> = {
  crypto:               "Cryptography",
  network:              "Networking",
  sms_telephony:        "SMS / Telephony",
  reflection_dynamic:   "Reflection / Dynamic Loading",
  device_admin:         "Device Admin",
  accessibility:        "Accessibility Service",
  content_provider:     "Content Provider",
  camera_media:         "Camera / Media",
  location:             "Location",
  webview:              "WebView / JS Bridge",
};

export const DANGEROUS_PERMISSIONS = new Set([
  "android.permission.SEND_SMS",
  "android.permission.READ_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.BIND_DEVICE_ADMIN",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.CAMERA",
  "android.permission.RECORD_AUDIO",
  "android.permission.READ_CONTACTS",
  "android.permission.READ_CALL_LOG",
  "android.permission.READ_PHONE_STATE",
  "android.permission.RECEIVE_BOOT_COMPLETED",
  "android.permission.INSTALL_PACKAGES",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.WRITE_SETTINGS",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
]);
