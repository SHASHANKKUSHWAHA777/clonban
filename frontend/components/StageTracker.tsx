"use client";

const STAGES = [
  { key: "uploading", label: "Uploading" },
  { key: "analyzing_identity", label: "Analyzing identity" },
  { key: "comparing_resources", label: "Comparing resources" },
  { key: "analyzing_dex", label: "Analyzing DEX" },
  { key: "calculating_risk", label: "Calculating risk" },
  { key: "generating_report", label: "Generating report" },
  { key: "completed", label: "Done" },
];

export function StageTracker({ currentStep }: { currentStep: string | null }) {
  const currentIndex = Math.max(0, STAGES.findIndex((s) => s.key === currentStep));

  return (
    <div className="rounded-xl border border-line bg-panel p-6">
      <div className="mb-1 font-mono text-xs uppercase tracking-wide text-dim">Pipeline status</div>
      <div className="flex flex-col gap-3 mt-4">
        {STAGES.map((s, i) => {
          const done = i < currentIndex;
          const active = i === currentIndex;
          return (
            <div key={s.key} className="flex items-center gap-3">
              <div
                className={`h-2.5 w-2.5 rounded-full ${
                  done ? "bg-mint" : active ? "bg-cyan animate-pulse" : "bg-line"
                }`}
              />
              <span className={`text-sm ${active ? "text-ink" : done ? "text-dim" : "text-dim/60"}`}>
                {s.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
