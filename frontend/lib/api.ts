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
  cert_sha256: string | null;
  permissions: string[];
  is_valid: boolean;
  parse_error: string | null;
}

export interface IdentityResultOut {
  certificate_score: number;
  certificate_match: boolean;
  certificate_status: string | null;
  certificate_identity_score: number | null;
  package_score: number;
  package_similarity: number | null;
  package_match_state: string | null;
  manifest_score: number;
  permissions_score: number;
  manifest_findings: any[];
  findings: any[];
}

export interface DexResultOut {
  dex_score: number;
  malware_risk: number;
  malware_risk_score: number | null;
  bytecode_similarity: number | null;
  class_count_original: number | null;
  class_count_candidate: number | null;
  method_count_original: number | null;
  method_count_candidate: number | null;
  ssdeep_score: number | null;
  api_call_similarity: number;
  dex_files_baseline: string[];
  dex_files_candidate: string[];
  dex_count_baseline: number | null;
  dex_count_candidate: number | null;
  risk_findings: RiskFinding[];
  errors: any[];
}

export interface RiskFinding {
  finding_type: string;
  severity: "low" | "medium" | "high";
  evidence: string;
  source_apk: string | null;
  category: string | null;
  contribution: number | null;
  baseline_present: boolean | null;
  candidate_present: boolean | null;
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
  identity: IdentityResultOut | null;
  similarity: { icon_score: number; icon_phash_distance: number | null; string_score: number; layout_score: number; resource_score: number; diff_image_path: string | null; findings: any[] } | null;
  dex: DexResultOut | null;
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
