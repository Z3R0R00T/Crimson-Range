import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, useMe } from "~/components/shell";
import { adminOverview, getMe } from "~/server/functions";
import type { SafeUser, SecurityEvent } from "~/server/types";

export const Route = createFileRoute("/admin")({
  component: Admin,
});

function Admin() {
  const navigate = useNavigate();
  const { me } = useMe();
  const [data, setData] = useState<{
    users: SafeUser[];
    recent: Array<{ userId: string; username: string; challengeTitle: string; slug: string; flagId: string; at: number; pointsAwarded: number }>;
    events: SecurityEvent[];
    leaderboard: Array<{ userId: string; username: string; points: number }>;
  } | null>(null);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    getMe()
      .then((r) => {
        if (!r.user) navigate({ to: "/login" });
        else if (r.user.role !== "ADMIN") setDenied(true);
        else
          adminOverview()
            .then(setData)
            .catch(() => setDenied(true));
      })
      .catch(() => navigate({ to: "/login" }));
  }, [navigate]);

  const EV_STYLE: Record<string, string> = {
    SHARING_SUSPECTED: "border-[#e5484d] text-[#e5484d]",
    BRUTEFORCE_SUSPECTED: "border-[#d29922] text-[#d29922]",
    NEW_IP_MID_SOLVE: "border-[#7c5cff] text-[#c9a2ff]",
  };

  return (
    <Shell>
      <h1 className="mb-4 text-lg font-bold text-[#f0f3f8]">
        <span className="text-[#e5484d]">&gt;</span> admin console
      </h1>
      {denied && (
        <Card className="p-6 text-xs">
          <p className="text-[#e5484d]">[403] FORBIDDEN — ADMIN role required.</p>
          <p className="mt-1 text-[#5a6a82]">current operator: {me ? `${me.username} (${me.role})` : "unknown"}</p>
        </Card>
      )}
      {!denied && !data && <p className="text-xs text-[#5a6a82]">loading admin overview…</p>}
      {data && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <Card className="p-5">
              <h2 className="text-sm font-bold text-[#f0f3f8]">leaderboard</h2>
              <div className="mt-2 space-y-1.5 text-xs">
                {data.leaderboard.map((l, i) => (
                  <div key={l.userId} className="flex items-center gap-2 rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                    <span className="text-[#3d4a5f]">#{i + 1}</span>
                    <span className="text-[#c9d4e3]">{l.username}</span>
                    <span className="ml-auto text-[#d29922]">{l.points} pts</span>
                  </div>
                ))}
              </div>
            </Card>
            <Card className="p-5">
              <h2 className="text-sm font-bold text-[#f0f3f8]">operators</h2>
              <div className="mt-2 space-y-1.5 text-xs">
                {data.users.map((u) => (
                  <div key={u.id} className="flex items-center gap-2 rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                    <span className="text-[#39d353]">●</span>
                    <span className="text-[#c9d4e3]">{u.username}</span>
                    <span className="ml-auto rounded border border-[#2a3a4d] px-1.5 text-[10px] text-[#8b98ac]">{u.role}</span>
                  </div>
                ))}
              </div>
            </Card>
            <Card className="p-5">
              <h2 className="text-sm font-bold text-[#f0f3f8]">recent solves</h2>
              <div className="mt-2 space-y-1.5 text-xs">
                {data.recent.length === 0 && <p className="text-[#5a6a82]">no solves yet.</p>}
                {data.recent.map((r, i) => (
                  <div key={`${r.at}-${i}`} className="rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                    <span className="text-[#39d353]">✓</span>{" "}
                    <span className="text-[#c9d4e3]">{r.username}</span>
                    <span className="text-[#5a6a82]"> captured </span>
                    <span className="text-[#d29922]">{r.flagId}</span>
                    <span className="text-[#5a6a82]"> on </span>
                    <span className="text-[#c9d4e3]">{r.challengeTitle}</span>
                    <span className="text-[#39d353]"> +{r.pointsAwarded ?? 0}pts</span>
                    <span className="ml-2 text-[#3d4a5f]">{new Date(r.at).toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          {/* Security events — ADMIN only */}
          <Card className="p-5">
            <h2 className="text-sm font-bold text-[#f0f3f8]">
              security events <span className="rounded border border-[#e5484d]/60 px-1.5 text-[10px] text-[#e5484d]">ADMIN</span>
            </h2>
            <div className="mt-2 space-y-1.5 text-xs">
              {data.events.length === 0 && <p className="text-[#5a6a82]">no security events yet.</p>}
              {data.events.map((e, i) => (
                <div key={`${e.at}-${i}`} className={`rounded border bg-black/40 px-3 py-2 ${EV_STYLE[e.type] ?? "border-[#1d2532] text-[#c9d4e3]"}`}>
                  <span className="font-bold">{e.type}</span>
                  <span className="ml-2 text-[#8b98ac]">@{e.userId}</span>
                  <span className="text-[#5a6a82]"> · {e.challengeSlug}</span>
                  <span className="text-[#3d4a5f]"> · ip {e.ip ?? "unknown"}</span>
                  <div className="mt-0.5 text-[11px] text-[#5a6a82]">{e.detail}</div>
                  <div className="text-[10px] text-[#3d4a5f]">{new Date(e.at).toLocaleString()}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </Shell>
  );
}