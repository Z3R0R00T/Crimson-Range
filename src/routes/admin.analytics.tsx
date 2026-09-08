import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, DIFF_STYLE, useMe } from "~/components/shell";
import { analyticsOverview, getMe } from "~/server/functions";
import type { AnalyticsOverview } from "~/server/types";

export const Route = createFileRoute("/admin/analytics")({
  component: Analytics,
});

function pct(v: number | null): string {
  if (v === null) return "—";
  return `${(v * 100).toFixed(1)}%`;
}

function fmtDur(secs: number | null): string {
  if (secs === null) return "—";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function Analytics() {
  const navigate = useNavigate();
  const { me } = useMe();
  const [data, setData] = useState<AnalyticsOverview | null>(null);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    getMe()
      .then((r) => {
        if (!r.user) navigate({ to: "/login" });
        else if (r.user.role !== "ADMIN") setDenied(true);
        else
          analyticsOverview()
            .then(setData)
            .catch(() => setDenied(true));
      })
      .catch(() => navigate({ to: "/login" }));
  }, [navigate]);

  return (
    <Shell>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-bold text-[#f0f3f8]">
          <span className="text-[#e5484d]">&gt;</span> challenge analytics
        </h1>
        <Link to="/admin" className="ml-auto text-xs text-[#8b98ac] hover:text-[#e5484d]">
          ← admin console
        </Link>
      </div>

      {denied && (
        <Card className="p-6 text-xs">
          <p className="text-[#e5484d]">[403] FORBIDDEN — ADMIN role required.</p>
          <p className="mt-1 text-[#5a6a82]">current operator: {me ? `${me.username} (${me.role})` : "unknown"}</p>
        </Card>
      )}

      {!denied && !data && <p className="text-xs text-[#5a6a82]">loading analytics…</p>}

      {data && (
        <div className="space-y-4">
          <p className="text-[11px] text-[#5a6a82]">
            solve rate = full solvers ÷ engaged users (solvers + attempted-but-unsolved) · flagged rows need difficulty review
            (solve rate &lt;5% or &gt;80%) · generated {new Date(data.generatedAt).toISOString().slice(0, 19)}Z
          </p>
          {data.rows.map((r) => (
            <Card key={r.slug} className={`p-5 ${r.needsReview ? "border-[#d29922]/60" : ""}`}>
              <div className="flex flex-wrap items-center gap-2">
                <Link to="/challenges/$slug" params={{ slug: r.slug }} className="text-sm font-bold text-[#f0f3f8] hover:text-[#e5484d]">
                  {r.title}
                </Link>
                <span className={`rounded border px-1.5 text-[10px] ${DIFF_STYLE[r.difficulty]}`}>{r.difficulty}</span>
                <span className="text-[10px] text-[#5a6a82]">{r.category} · {r.points} pts</span>
                {r.needsReview && (
                  <span className="ml-auto rounded border border-[#d29922]/60 px-2 py-0.5 text-[10px] text-[#d29922]">
                    ⚠ needs difficulty review
                  </span>
                )}
              </div>

              <div className="mt-3">
                <div className="flex items-center gap-2 text-[11px] text-[#5a6a82]">
                  <span>solve rate</span>
                  <span className="ml-auto text-[#c9d4e3]">{pct(r.solveRate)} ({r.solvers} solved · {r.attemptersOnly} attempted only)</span>
                </div>
                <div className="mt-1 h-2 overflow-hidden rounded bg-[#1d2532]">
                  <div
                    className={`h-full rounded ${r.needsReview ? "bg-[#d29922]" : "bg-[#39d353]"}`}
                    style={{ width: `${r.solveRate !== null ? Math.round(r.solveRate * 100) : 0}%` }}
                  />
                </div>
              </div>

              <div className="mt-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
                <div className="rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                  <div className="text-[#c9d4e3]">{fmtDur(r.avgTimeToSolveSeconds)}</div>
                  <div className="text-[10px] text-[#5a6a82]">avg time-to-solve</div>
                </div>
                <div className="rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                  <div className="text-[#c9d4e3]">{r.avgHintsUsed}</div>
                  <div className="text-[10px] text-[#5a6a82]">avg hints used</div>
                </div>
                <div className="rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                  <div className="text-[#c9d4e3]">{r.failedToSolveRatio !== null ? `${(r.failedToSolveRatio * 100).toFixed(1)}%` : "—"}</div>
                  <div className="text-[10px] text-[#5a6a82]">failed / submissions</div>
                </div>
                <div className="rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                  <div className="truncate text-[#c9d4e3]" title={r.dropOffFlagName ?? ""}>{r.dropOffFlagId ?? "— all cleared —"}</div>
                  <div className="text-[10px] text-[#5a6a82]">drop-off flag</div>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </Shell>
  );
}
