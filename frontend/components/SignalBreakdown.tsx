"use client";

import { SIGNAL_META, CATEGORY_LABELS, type SignalCategory, type FinalScore } from "@/lib/api";

interface Props {
  finalScore: FinalScore;
}

const CATEGORY_ORDER: SignalCategory[] = ["identity", "similarity", "code"];

function barColorClass(value: number): string {
  if (value >= 0.8) return "signal-bar-high";
  if (value >= 0.4) return "signal-bar-mid";
  return "signal-bar-low";
}

export function SignalBreakdown({ finalScore }: Props) {
  const { component_scores, weights_used } = finalScore;

  return (
    <section>
      <h2 className="mb-4 text-sm font-medium uppercase tracking-wide text-dim">
        9-Signal Breakdown
      </h2>

      <div className="flex flex-col gap-6">
        {CATEGORY_ORDER.map((cat) => {
          const signals = SIGNAL_META.filter((s) => s.category === cat);
          return (
            <div key={cat}>
              <div className="category-label">{CATEGORY_LABELS[cat]}</div>

              <div className="grid gap-2 sm:grid-cols-2">
                {signals.map((sig) => {
                  const value = component_scores[sig.key] ?? 0;
                  const weight = weights_used[sig.key];
                  const pct = Math.round(value * 100);

                  return (
                    <div
                      key={sig.key}
                      className="group rounded-lg border border-line bg-panel px-4 py-3 transition hover:border-line/80"
                    >
                      {/* header row */}
                      <div className="mb-1.5 flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-medium text-ink truncate">
                            {sig.label}
                          </span>
                          {weight != null && (
                            <span className="shrink-0 rounded-full bg-panel2 px-1.5 py-0.5 font-mono text-[9px] text-dim">
                              w{Math.round(weight * 100)}
                            </span>
                          )}
                        </div>
                        <span className="shrink-0 font-mono text-xs text-ink">{pct}%</span>
                      </div>

                      {/* progress bar */}
                      <div className="h-1.5 w-full rounded-full bg-line">
                        <div
                          className={`h-1.5 rounded-full transition-all duration-500 ${barColorClass(value)}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>

                      {/* tooltip-like description on hover */}
                      <div className="mt-1 max-h-0 overflow-hidden text-[10px] text-dim/70 transition-all duration-200 group-hover:max-h-8">
                        {sig.description}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
