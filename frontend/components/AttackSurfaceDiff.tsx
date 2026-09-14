"use client";

import { useState } from "react";
import {
  type ApkInfo,
  type FullAnalysisResult,
  SENSITIVE_CLUSTER_LABELS,
  DANGEROUS_PERMISSIONS,
} from "@/lib/api";

interface Props {
  result: FullAnalysisResult;
}

type Tab = "permissions" | "components" | "clusters";

const TABS: { key: Tab; label: string }[] = [
  { key: "permissions", label: "Permissions Diff" },
  { key: "components", label: "Exported Components" },
  { key: "clusters", label: "DEX Sensitive Clusters" },
];

export function AttackSurfaceDiff({ result }: Props) {
  const [tab, setTab] = useState<Tab>("permissions");

  const orig = result.apks.find((a) => a.role === "original");
  const cand = result.apks.find((a) => a.role === "candidate");

  return (
    <section>
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-dim">
        Attack Surface Comparison
      </h2>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.key}
            className="tab-btn"
            data-active={tab === t.key}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Panels */}
      <div className="rounded-b-xl rounded-tr-xl border border-t-0 border-line bg-panel p-5">
        {tab === "permissions" && <PermissionsDiff orig={orig} cand={cand} />}
        {tab === "components" && <ComponentsDiff orig={orig} cand={cand} />}
        {tab === "clusters" && <ClustersDiff result={result} />}
      </div>
    </section>
  );
}

/* ------------------------------------------------------------------ */
/*  Tab 1: Permissions Diff                                           */
/* ------------------------------------------------------------------ */

function PermissionsDiff({ orig, cand }: { orig?: ApkInfo; cand?: ApkInfo }) {
  const origPerms = new Set(orig?.permissions ?? []);
  const candPerms = new Set(cand?.permissions ?? []);

  const shared = [...origPerms].filter((p) => candPerms.has(p)).sort();
  const addedInCandidate = [...candPerms].filter((p) => !origPerms.has(p)).sort();
  const removedInCandidate = [...origPerms].filter((p) => !candPerms.has(p)).sort();

  const shortName = (p: string) => p.replace(/^android\.permission\./, "");

  return (
    <div className="tab-panel flex flex-col gap-4">
      {addedInCandidate.length > 0 && (
        <div>
          <div className="mb-2 text-xs font-medium text-rose">
            Added in Candidate ({addedInCandidate.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {addedInCandidate.map((p) => (
              <span key={p} className={`diff-added ${DANGEROUS_PERMISSIONS.has(p) ? "diff-dangerous" : ""}`}>
                {DANGEROUS_PERMISSIONS.has(p) && "⚠ "}
                {shortName(p)}
              </span>
            ))}
          </div>
        </div>
      )}

      {removedInCandidate.length > 0 && (
        <div>
          <div className="mb-2 text-xs font-medium text-amber">
            Removed in Candidate ({removedInCandidate.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {removedInCandidate.map((p) => (
              <span key={p} className="diff-removed">{shortName(p)}</span>
            ))}
          </div>
        </div>
      )}

      {shared.length > 0 && (
        <div>
          <div className="mb-2 text-xs font-medium text-dim">
            Shared ({shared.length})
          </div>
          <div className="flex flex-wrap gap-1.5">
            {shared.map((p) => (
              <span key={p} className={`diff-shared ${DANGEROUS_PERMISSIONS.has(p) ? "diff-dangerous" : ""}`}>
                {DANGEROUS_PERMISSIONS.has(p) && "⚠ "}
                {shortName(p)}
              </span>
            ))}
          </div>
        </div>
      )}

      {origPerms.size === 0 && candPerms.size === 0 && (
        <p className="text-xs text-dim">No permissions declared in either APK.</p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Tab 2: Exported Components Diff                                   */
/* ------------------------------------------------------------------ */

const COMPONENT_TYPES = [
  { key: "activities" as const, label: "Activities" },
  { key: "services" as const, label: "Services" },
  { key: "receivers" as const, label: "Receivers" },
  { key: "providers" as const, label: "Providers" },
];

function ComponentsDiff({ orig, cand }: { orig?: ApkInfo; cand?: ApkInfo }) {
  const [expanded, setExpanded] = useState<string | null>("activities");

  return (
    <div className="tab-panel flex flex-col gap-3">
      {COMPONENT_TYPES.map(({ key, label }) => {
        const origList = (orig as any)?.[key] as string[] ?? [];
        const candList = (cand as any)?.[key] as string[] ?? [];
        const origSet = new Set(origList);
        const candSet = new Set(candList);
        const added = candList.filter((c) => !origSet.has(c));
        const removed = origList.filter((c) => !candSet.has(c));
        const shared = origList.filter((c) => candSet.has(c));
        const isOpen = expanded === key;

        return (
          <div key={key} className="rounded-lg border border-line">
            <button
              className="flex w-full items-center justify-between px-4 py-2.5 text-left"
              onClick={() => setExpanded(isOpen ? null : key)}
            >
              <span className="text-xs font-medium text-ink">{label}</span>
              <div className="flex items-center gap-2">
                {added.length > 0 && (
                  <span className="rounded-full bg-rose/15 px-2 py-0.5 text-[10px] font-mono text-rose">
                    +{added.length}
                  </span>
                )}
                {removed.length > 0 && (
                  <span className="rounded-full bg-amber/15 px-2 py-0.5 text-[10px] font-mono text-amber">
                    −{removed.length}
                  </span>
                )}
                <span className="rounded-full bg-line px-2 py-0.5 text-[10px] font-mono text-dim">
                  {shared.length} shared
                </span>
                <span className={`text-dim text-xs transition-transform ${isOpen ? "rotate-180" : ""}`}>
                  ▾
                </span>
              </div>
            </button>

            {isOpen && (
              <div className="border-t border-line px-4 py-3">
                {added.length === 0 && removed.length === 0 && shared.length === 0 && (
                  <p className="text-xs text-dim">None declared.</p>
                )}

                {added.length > 0 && (
                  <div className="mb-2">
                    <div className="mb-1 text-[10px] font-medium uppercase text-rose">Added in candidate</div>
                    {added.map((c) => (
                      <div key={c} className="font-mono text-[11px] text-rose/90 truncate">{shortClass(c)}</div>
                    ))}
                  </div>
                )}

                {removed.length > 0 && (
                  <div className="mb-2">
                    <div className="mb-1 text-[10px] font-medium uppercase text-amber">Removed in candidate</div>
                    {removed.map((c) => (
                      <div key={c} className="font-mono text-[11px] text-amber/90 truncate">{shortClass(c)}</div>
                    ))}
                  </div>
                )}

                {shared.length > 0 && (
                  <div>
                    <div className="mb-1 text-[10px] font-medium uppercase text-dim">Shared</div>
                    {shared.map((c) => (
                      <div key={c} className="font-mono text-[11px] text-dim/70 truncate">{shortClass(c)}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function shortClass(fqcn: string): string {
  const parts = fqcn.split(".");
  if (parts.length <= 2) return fqcn;
  return `…${parts.slice(-2).join(".")}`;
}

/* ------------------------------------------------------------------ */
/*  Tab 3: DEX Sensitive API Clusters                                 */
/* ------------------------------------------------------------------ */

// The backend doesn't yet expose per-APK cluster membership in the API response,
// so we derive state from what we know: cluster_similarity + risk_findings.
// This is a best-effort visualization; it highlights candidate-only risks.

function ClustersDiff({ result }: { result: FullAnalysisResult }) {
  // Derive candidate-flagged categories from risk findings
  const candFlags = new Set<string>();
  const origFlags = new Set<string>();

  for (const f of result.risk_findings) {
    const mapped = mapFindingToCluster(f.finding_type);
    if (mapped) {
      if (f.source_apk === "candidate") candFlags.add(mapped);
      if (f.source_apk === "original") origFlags.add(mapped);
    }
  }

  const clusterSim = result.dex?.cluster_similarity;

  return (
    <div className="tab-panel">
      {clusterSim != null && (
        <div className="mb-4 rounded-lg border border-line bg-panel2 px-4 py-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-dim">Sensitive Cluster Overlap</span>
            <span className="font-mono text-sm text-ink">{Math.round(clusterSim * 100)}%</span>
          </div>
          <div className="mt-1.5 h-1.5 w-full rounded-full bg-line">
            <div
              className={`h-1.5 rounded-full transition-all duration-500 ${
                clusterSim >= 0.8 ? "bg-rose" : clusterSim >= 0.4 ? "bg-amber" : "bg-mint"
              }`}
              style={{ width: `${Math.round(clusterSim * 100)}%` }}
            />
          </div>
        </div>
      )}

      <div className="cluster-grid">
        {Object.entries(SENSITIVE_CLUSTER_LABELS).map(([key, label]) => {
          const inOrig = origFlags.has(key);
          const inCand = candFlags.has(key);
          let state: string;
          if (inCand && !inOrig) state = "candidate-only";
          else if (inCand && inOrig) state = "both";
          else if (inOrig && !inCand) state = "original-only";
          else state = "none";

          return (
            <div key={key} className="cluster-chip" data-state={state}>
              <div className="font-medium">{label}</div>
              <div className="mt-0.5 text-[10px] opacity-70">
                {state === "candidate-only" && "⚠ Candidate only"}
                {state === "both" && "Both APKs"}
                {state === "original-only" && "Original only"}
                {state === "none" && "Not detected"}
              </div>
            </div>
          );
        })}
      </div>

      {result.dex && (
        <div className="mt-4 grid gap-3 sm:grid-cols-3">
          <MiniStat label="Weighted API Sim" value={result.dex.weighted_api_similarity} />
          <MiniStat label="Method API Sim" value={result.dex.method_api_similarity} />
          <MiniStat label="ssdeep Score" value={result.dex.ssdeep_score} />
        </div>
      )}
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: number | null | undefined }) {
  if (value == null) return null;
  const pct = Math.round(value * 100);
  return (
    <div className="rounded-lg border border-line bg-panel2 px-3 py-2">
      <div className="text-[10px] text-dim">{label}</div>
      <div className="font-mono text-sm text-ink">{pct}%</div>
    </div>
  );
}

function mapFindingToCluster(findingType: string): string | null {
  const map: Record<string, string> = {
    SMS_ACCESS: "sms_telephony",
    ACCESSIBILITY_SERVICE: "accessibility",
    OVERLAY_PERMISSION: "webview",
    DEVICE_ADMIN: "device_admin",
    DYNAMIC_CODE_LOADING: "reflection_dynamic",
    WEBVIEW_JS_INTERFACE: "webview",
    SUSPICIOUS_NETWORK_API: "network",
    BOOT_PERSISTENCE: "device_admin",
  };
  return map[findingType] ?? null;
}
