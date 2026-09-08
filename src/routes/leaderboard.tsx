import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card } from "~/components/shell";
import { leaderboardData } from "~/server/functions";
import type { LeaderboardData } from "~/server/types";
import { TEAMS } from "~/server/types";

export const Route = createFileRoute("/leaderboard")({
  component: Leaderboard,
});

type Tab = "global" | "monthly" | "teams";

function fmtDate(ts: number | null): string {
  if (ts === null) return "—";
  return new Date(ts).toISOString().slice(0, 10);
}

function teamLabel(teamId: string | null): string {
  if (!teamId) return "—";
  return TEAMS.find((t) => t.id === teamId)?.name ?? teamId;
}

function Leaderboard() {
  const [data, setData] = useState<LeaderboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("global");

  useEffect(() => {
    leaderboardData()
      .then(setData)
      .catch(() => setError("Failed to load leaderboard from the server."));
  }, []);

  const tabs: Array<{ id: Tab; label: string }> = [
    { id: "global", label: "[global]" },
    { id: "monthly", label: "[monthly]" },
    { id: "teams", label: "[per-team]" },
  ];

  return (
    <Shell>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-bold text-[#f0f3f8]">
          <span className="text-[#e5484d]">&gt;</span> leaderboard
        </h1>
        <div className="ml-auto flex gap-2 text-xs">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`rounded border px-2 py-1 ${
                tab === t.id
                  ? "border-[#e5484d] text-[#e5484d]"
                  : "border-[#2a3a4d] text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {error && <Card className="p-4 text-xs text-[#e5484d]">{error}</Card>}
      {!error && !data && <p className="text-xs text-[#5a6a82]">loading leaderboard…</p>}

      {data && tab !== "teams" && (
        <Card className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-xs">
            <thead>
              <tr className="border-b border-[#1d2532] text-[#5a6a82]">
                <th className="px-4 py-2 font-normal">rank</th>
                <th className="px-4 py-2 font-normal">operator</th>
                <th className="px-4 py-2 font-normal">team</th>
                <th className="px-4 py-2 text-right font-normal">points</th>
                <th className="px-4 py-2 text-right font-normal">solves</th>
                <th className="px-4 py-2 text-right font-normal">first bloods</th>
                <th className="px-4 py-2 text-right font-normal">last solve</th>
              </tr>
            </thead>
            <tbody>
              {(tab === "global" ? data.global : data.monthly).map((r, i) => (
                <tr key={r.userId} className="border-b border-[#141a24] last:border-0 hover:bg-black/30">
                  <td className="px-4 py-2 text-[#3d4a5f]">#{i + 1}</td>
                  <td className="px-4 py-2 text-[#c9d4e3]">{r.username}</td>
                  <td className="px-4 py-2 text-[#8b98ac]">{teamLabel(r.teamId)}</td>
                  <td className="px-4 py-2 text-right text-[#d29922]">{r.points}</td>
                  <td className="px-4 py-2 text-right text-[#c9d4e3]">{r.solves}</td>
                  <td className="px-4 py-2 text-right text-[#e5484d]">{r.firstBloods > 0 ? `🩸 ${r.firstBloods}` : "—"}</td>
                  <td className="px-4 py-2 text-right text-[#5a6a82]">{fmtDate(r.lastSolveAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {tab === "monthly" && (
            <p className="border-t border-[#1d2532] px-4 py-2 text-[11px] text-[#5a6a82]">
              monthly window: {data.monthlyLabel} — ties broken by earliest last-solve.
            </p>
          )}
          {tab === "global" && (
            <p className="border-t border-[#1d2532] px-4 py-2 text-[11px] text-[#5a6a82]">
              all-time — ties broken by earliest last-solve.
            </p>
          )}
        </Card>
      )}

      {data && tab === "teams" && (
        <div className="grid gap-4 md:grid-cols-2">
          {data.teams.map((t, i) => (
            <Card key={t.teamId} className="p-5">
              <div className="flex items-center gap-2">
                <span className="text-[#3d4a5f]">#{i + 1}</span>
                <h2 className="text-sm font-bold text-[#f0f3f8]">{t.teamName}</h2>
                <span className="ml-auto text-xs text-[#d29922]">{t.points} pts</span>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-center text-xs">
                <div className="rounded border border-[#1d2532] bg-black/40 px-2 py-2">
                  <div className="text-[#c9d4e3]">{t.members}</div>
                  <div className="text-[10px] text-[#5a6a82]">members</div>
                </div>
                <div className="rounded border border-[#1d2532] bg-black/40 px-2 py-2">
                  <div className="text-[#c9d4e3]">{t.solves}</div>
                  <div className="text-[10px] text-[#5a6a82]">solves</div>
                </div>
                <div className="rounded border border-[#1d2532] bg-black/40 px-2 py-2">
                  <div className="text-[#e5484d]">{t.firstBloods}</div>
                  <div className="text-[10px] text-[#5a6a82]">first bloods</div>
                </div>
              </div>
              <div className="mt-3 space-y-1">
                {data.global
                  .filter((r) => r.teamId === t.teamId)
                  .map((r) => (
                    <div key={r.userId} className="flex items-center gap-2 text-xs">
                      <span className="text-[#8b98ac]">{r.username}</span>
                      <span className="ml-auto text-[#5a6a82]">{r.points} pts</span>
                    </div>
                  ))}
              </div>
            </Card>
          ))}
        </div>
      )}
    </Shell>
  );
}
