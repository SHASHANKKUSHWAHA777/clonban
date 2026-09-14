"use client";

export function ScoreRing({
  label,
  value,
  color,
  sublabel,
}: {
  label: string;
  value: number; // 0..1
  color: string;
  sublabel?: string;
}) {
  const pct = Math.round(value * 100);
  const r = 46;
  const c = 2 * Math.PI * r;
  const offset = c - (pct / 100) * c;

  return (
    <div className="flex flex-col items-center gap-3 rounded-xl border border-line bg-panel px-6 py-7">
      <div className="relative h-32 w-32">
        <svg viewBox="0 0 120 120" className="h-32 w-32 -rotate-90">
          <circle cx="60" cy="60" r={r} fill="none" stroke="#1E2330" strokeWidth="10" />
          <circle
            cx="60" cy="60" r={r} fill="none"
            stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={offset}
            style={{ transition: "stroke-dashoffset 700ms ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-semibold text-ink">{pct}%</span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-sm font-medium text-ink">{label}</div>
        {sublabel && <div className="text-xs text-dim">{sublabel}</div>}
      </div>
    </div>
  );
}
