"use client";

import { useEffect, useRef, useState } from "react";
import {
  submitAnalysis, getStatus, getFullResult, downloadReportUrl,
  FullAnalysisResult, STAGE_LABELS,
} from "@/lib/api";
import { ScoreRing } from "@/components/ScoreRing";
import { StageTracker } from "@/components/StageTracker";

type Phase = "idle" | "submitting" | "running" | "done" | "error";

const SEVERITY_STYLE: Record<string, string> = {
  high: "border-rose/40 bg-rose/10 text-rose",
  medium: "border-amber/40 bg-amber/10 text-amber",
  low: "border-mint/40 bg-mint/10 text-mint",
};

export default function Home() {
  const [original, setOriginal] = useState<File | null>(null);
  const [candidate, setCandidate] = useState<File | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [jobId, setJobId] = useState<string | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [result, setResult] = useState<FullAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  async function handleAnalyze() {
    if (!original || !candidate) return;
    setPhase("submitting");
    setErrorMsg(null);
    try {
      const { job_id } = await submitAnalysis(original, candidate);
      setJobId(job_id);
      setPhase("running");
      pollRef.current = setInterval(() => poll(job_id), 1800);
    } catch (e: any) {
      setErrorMsg(e.message);
      setPhase("error");
    }
  }

  async function poll(id: string) {
    try {
      const s = await getStatus(id);
      setStage(s.progress_step);
      if (s.status === "completed") {
        if (pollRef.current) clearInterval(pollRef.current);
        const full = await getFullResult(id);
        setResult(full);
        setPhase("done");
      } else if (s.status === "failed") {
        if (pollRef.current) clearInterval(pollRef.current);
        setErrorMsg(s.error_message || "Analysis failed");
        setPhase("error");
      }
    } catch (e: any) {
      // transient network hiccup while backend is mid-restart — keep polling
    }
  }

  function reset() {
    setOriginal(null);
    setCandidate(null);
    setJobId(null);
    setStage(null);
    setResult(null);
    setErrorMsg(null);
    setPhase("idle");
  }

  return (
    <main className="mx-auto min-h-screen max-w-5xl px-6 py-12">
      <header className="mb-10">
        <div className="font-mono text-xs uppercase tracking-wide text-cyan">Static Analysis MVP</div>
        <h1 className="mt-2 text-3xl font-semibold text-ink">APK Clone &amp; Impersonation Detector</h1>
        <p className="mt-2 max-w-2xl text-sm text-dim">
          Upload a legitimate APK and a candidate APK. The system compares identity,
          icon &amp; resources, and DEX structure across independent signals, then
          reports clone probability, malware risk, and how confident that read is —
          never from a single signal alone.
        </p>
      </header>

      {(phase === "idle" || phase === "submitting" || phase === "error") && (
        <UploadPanel
          original={original}
          candidate={candidate}
          setOriginal={setOriginal}
          setCandidate={setCandidate}
          onAnalyze={handleAnalyze}
          submitting={phase === "submitting"}
          errorMsg={errorMsg}
        />
      )}

      {phase === "running" && (
        <div className="grid gap-6 md:grid-cols-[280px_1fr]">
          <StageTracker currentStep={stage} />
          <div className="flex items-center justify-center rounded-xl border border-line bg-panel p-10 text-dim">
            <div className="text-center">
              <div className="font-mono text-sm text-cyan">
                {stage ? STAGE_LABELS[stage] || stage : "Starting…"}
              </div>
              <p className="mt-2 text-xs">Job {jobId}</p>
            </div>
          </div>
        </div>
      )}

      {phase === "done" && result && (
        <ResultsDashboard result={result} onReset={reset} />
      )}
    </main>
  );
}

function UploadPanel({
  original, candidate, setOriginal, setCandidate, onAnalyze, submitting, errorMsg,
}: {
  original: File | null; candidate: File | null;
  setOriginal: (f: File | null) => void; setCandidate: (f: File | null) => void;
  onAnalyze: () => void; submitting: boolean; errorMsg: string | null;
}) {
  return (
    <div>
      <div className="grid gap-4 sm:grid-cols-2">
        <FileSlot label="Original APK" hint="The legitimate, known-good app" file={original} onChange={setOriginal} accent="mint" />
        <FileSlot label="Candidate APK" hint="The suspicious / unverified app" file={candidate} onChange={setCandidate} accent="rose" />
      </div>

      {errorMsg && (
        <div className="mt-4 rounded-lg border border-rose/40 bg-rose/10 px-4 py-3 text-sm text-rose">
          {errorMsg}
        </div>
      )}

      <button
        onClick={onAnalyze}
        disabled={!original || !candidate || submitting}
        className="mt-6 w-full rounded-lg bg-cyan px-6 py-3 font-medium text-base disabled:cursor-not-allowed disabled:opacity-30 text-[#04222b] transition hover:brightness-110"
      >
        {submitting ? "Uploading…" : "Analyze APKs"}
      </button>
    </div>
  );
}

function FileSlot({
  label, hint, file, onChange, accent,
}: { label: string; hint: string; file: File | null; onChange: (f: File | null) => void; accent: "mint" | "rose" }) {
  const border = accent === "mint" ? "hover:border-mint/50" : "hover:border-rose/50";
  return (
    <label
      className={`flex cursor-pointer flex-col gap-1 rounded-xl border border-dashed border-line bg-panel px-5 py-8 text-center transition ${border}`}
    >
      <input
        type="file"
        accept=".apk"
        className="hidden"
        onChange={(e) => onChange(e.target.files?.[0] || null)}
      />
      <span className="text-sm font-medium text-ink">{label}</span>
      <span className="text-xs text-dim">{hint}</span>
      <span className="mt-3 font-mono text-xs text-cyan">
        {file ? file.name : "Click to choose .apk"}
      </span>
    </label>
  );
}

function ResultsDashboard({ result, onReset }: { result: FullAnalysisResult; onReset: () => void }) {
  const fs = result.final_score;
  const orig = result.apks.find((a) => a.role === "original");
  const cand = result.apks.find((a) => a.role === "candidate");

  return (
    <div className="flex flex-col gap-8">
      <div className="grid gap-4 sm:grid-cols-3">
        <ScoreRing label="Clone Probability" value={fs?.clone_probability ?? 0} color="#7C5CFC" />
        <ScoreRing label="Malware Risk" value={fs?.malware_risk ?? 0} color="#FB4B67" />
        <ScoreRing label="Confidence" value={fs?.confidence ?? 0} color="#22D3EE" />
      </div>

      {fs?.verdict_summary && (
        <div className="rounded-xl border border-line bg-panel px-5 py-4 text-sm text-ink">
          {fs.verdict_summary}
        </div>
      )}

      <section>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-dim">Identity</h2>
        <div className="overflow-hidden rounded-xl border border-line">
          <table className="w-full text-sm">
            <thead className="bg-panel2 text-dim">
              <tr><th className="px-4 py-2 text-left font-normal"></th><th className="px-4 py-2 text-left font-normal">Original</th><th className="px-4 py-2 text-left font-normal">Candidate</th></tr>
            </thead>
            <tbody className="bg-panel">
              <Row label="Package" a={orig?.package_name} b={cand?.package_name} />
              <Row label="App label" a={orig?.app_label} b={cand?.app_label} />
              <Row label="Version" a={orig?.version_name} b={cand?.version_name} />
              <Row label="Cert SHA-256" a={orig?.cert_sha256} b={cand?.cert_sha256} mono />
            </tbody>
          </table>
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-dim">Evidence &amp; component scores</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {fs && Object.entries(fs.component_scores).map(([k, v]) => (
            <ScoreBar key={k} label={k} value={v} />
          ))}
        </div>
      </section>

      <section>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-dim">
          Risk findings ({result.risk_findings.length})
        </h2>
        {result.risk_findings.length === 0 ? (
          <p className="text-sm text-dim">No suspicious indicators detected.</p>
        ) : (
          <div className="flex flex-col gap-2">
            {result.risk_findings.map((f, i) => (
              <div key={i} className={`rounded-lg border px-4 py-3 text-sm ${SEVERITY_STYLE[f.severity]}`}>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs">{f.finding_type}</span>
                  <span className="font-mono text-[10px] uppercase">{f.severity}{f.source_apk ? ` · ${f.source_apk}` : ""}</span>
                </div>
                <p className="mt-1 text-ink/90">{f.evidence}</p>
              </div>
            ))}
          </div>
        )}
      </section>

      {result.similarity?.diff_image_path && (
        <section>
          <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-dim">Icon comparison</h2>
          <p className="text-xs text-dim">Side-by-side comparison saved to the job report directory (see downloadable HTML/PDF report for the embedded image).</p>
        </section>
      )}

      <section className="flex flex-wrap gap-3">
        {result.report?.pdf_path && (
          <a href={downloadReportUrl(result.job_id, "pdf")} className="rounded-lg border border-line bg-panel px-4 py-2 text-sm text-ink hover:border-cyan/50">Download PDF report</a>
        )}
        {result.report?.html_path && (
          <a href={downloadReportUrl(result.job_id, "html")} className="rounded-lg border border-line bg-panel px-4 py-2 text-sm text-ink hover:border-cyan/50">Download HTML report</a>
        )}
        {result.report?.json_path && (
          <a href={downloadReportUrl(result.job_id, "json")} className="rounded-lg border border-line bg-panel px-4 py-2 text-sm text-ink hover:border-cyan/50">Download JSON report</a>
        )}
        <button onClick={onReset} className="rounded-lg px-4 py-2 text-sm text-dim hover:text-ink">Run another analysis</button>
      </section>
    </div>
  );
}

function Row({ label, a, b, mono }: { label: string; a?: string | null; b?: string | null; mono?: boolean }) {
  const cls = mono ? "font-mono text-xs" : "text-sm";
  return (
    <tr className="border-t border-line">
      <td className="px-4 py-2 text-dim">{label}</td>
      <td className={`px-4 py-2 text-ink ${cls}`}>{a || "—"}</td>
      <td className={`px-4 py-2 text-ink ${cls}`}>{b || "—"}</td>
    </tr>
  );
}

function ScoreBar({ label, value }: { label: string; value: number }) {
  const pct = Math.round(value * 100);
  return (
    <div className="rounded-lg border border-line bg-panel px-4 py-3">
      <div className="mb-1.5 flex items-center justify-between text-xs">
        <span className="capitalize text-dim">{label}</span>
        <span className="font-mono text-ink">{pct}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-line">
        <div className="h-1.5 rounded-full bg-cyan" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
