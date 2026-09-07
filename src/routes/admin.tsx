import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, useMe } from "~/components/shell";
import { adminOverview, getMe } from "~/server/functions";
import type { SafeUser } from "~/server/store";

export const Route = createFileRoute("/admin")({
  component: Admin,
});

function Admin() {
  const navigate = useNavigate();
  const { me } = useMe();
  const [data, setData] = useState<{
    users: SafeUser[];
    recent: Array<{ userId: string; username: string; challengeTitle: string; slug: string; flagId: string; at: number }>;
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
        <div className="grid gap-4 md:grid-cols-2">
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
                  <span className="ml-2 text-[#3d4a5f]">{new Date(r.at).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </Shell>
  );
}
