import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, CAT_ICON } from "~/components/shell";
import { getMe, myDashboard } from "~/server/functions";
import type { MyDashboard } from "~/server/types";

export const Route = createFileRoute("/dashboard")({
  component: Dashboard,
});

function fmtTs(ts: number): string {
  const d = new Date(ts);
  return d.toISOString().replace("T", " ").slice(0, 16) + "Z";
}

function fmtDur(secs: number | null): string {
  if (secs === null) return "—";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

/** Pure SVG pentagon radar — no chart dependency (vendor-free inline code). */
function CategoryRadar({ data }: { data: MyDashboard["categoryPoints"] }) {
  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const r = size / 2 - 24;
  const max = Math.max(1, ...data.map((d) => d.points));
  const pt = (i: number, frac: number): [number, number] => {
    const angle = (Math.PI * 2 * i) / data.length - Math.PI / 2;
    return [cx + r * frac * Math.cos(angle), cy + r * frac * Math.sin(angle)];
  };
  const poly = (frac: number) => data.map((_, i) => pt(i, frac).join(",")).join(" ");
  const valuePoly = data.map((d, i) => pt(i, d.points / max).join(",")).join(" ");
  const grid = [0.25, 0.5, 0.75, 1];
  return (
    <svg viewBox={`0 0 ${size} ${size}`} className="mx-auto h-48 w-48" role="img" aria-label="category radar">
      {grid.map((g) => (
        <polygon key={g} points={poly(g)} fill="none" stroke="#1d2532" strokeWidth="1" />
      ))}
      {data.map((d, i) => {
        const [x, y] = pt(i, 1);
        const [lx, ly] = pt(i, 1.18);
        return (
          <g key={d.category}>
            <line x1={cx} y1={cy} x2={x} y2={y} stroke="#1d2532" strokeWidth="1" />
            <text x={lx} y={ly} textAnchor="middle" dominantBaseline="middle" fill="#5a6a82" fontSize="8">
              {CAT_ICON[d.category] ?? "•"}
            </text>
          </g>
        );
      })}
      <polygon points={valuePoly} fill="rgba(229,72,77,0.25)" stroke="#e5484d" strokeWidth="1.5" />
      {data.map((d, i) => {
        const [x, y] = pt(i, d.points / max);
        return <circle key={d.category} cx={x} cy={y} r="2.5" fill="#e5484d" />;
      })}
    </svg>
  );
}

function Dashboard() {
  const navigate = useNavigate();
  const [dash, setDash] = useState<MyDashboard | null>(null);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    getMe()
      .then((r) => {
        if (!r.user) navigate({ to: "/login" });
        else
          myDashboard()
            .then((d) => setDash(d.dashboard))
            .catch(() => setDenied(true));
      })
      .catch(() => navigate({ to: "/login" }));
  }, [navigate]);

  if (denied) {
    return (
      <Shell>
        <Card className="p-6 text-xs">
          <p className="text-[#e5484d]">[401] sign in required.</p>
        </Card>
      </Shell>
    );
  }

  return (
    <Shell>
      <h1 className="mb-4 text-lg font-bold text-[#f0f3f8]">
        <span className="text-[#e5484d]">&gt;</span> operator dashboard
      </h1>
      {!dash && <p className="text-xs text-[#5a6a82]">loading dashboard…</p>}
      {dash && (
        <div className="space-y-4">
          <div className="grid gap-4 md:grid-cols-5">
            {[
              { label: "points", value: String(dash.points), color: "text-[#d29922]" },
              { label: "rank", value: dash.rank !== null ? `#${dash.rank}/${dash.totalPlayers}` : "—", color: "text-[#f0f3f8]" },
              { label: "solves", value: String(dash.solves), color: "text-[#39d353]" },
              { label: "first bloods", value: String(dash.firstBloods), color: "text-[#e5484d]" },
              { label: "streak", value: `${dash.streakDays}d`, color: "text-[#7c5cff]" },
            ].map((s) => (
              <Card key={s.label} className="p-4 text-center">
                <div className={`text-xl font-bold ${s.color}`}>{s.value}</div>
                <div className="mt-1 text-[10px] uppercase tracking-widest text-[#5a6a82]">{s.label}</div>
              </Card>
            ))}
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <Card className="p-5">
              <h2 className="text-sm font-bold text-[#f0f3f8]">category radar</h2>
              <CategoryRadar data={dash.categoryPoints} />
              <div className="mt-2 grid grid-cols-2 gap-1 text-[11px]">
                {dash.categoryPoints.map((c) => (
                  <div key={c.category} className="flex items-center gap-1.5 text-[#8b98ac]">
                    <span>{CAT_ICON[c.category] ?? "•"}</span>
                    <span className="truncate">{c.category}</span>
                    <span className="ml-auto text-[#d29922]">{c.points}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="p-5">
              <h2 className="text-sm font-bold text-[#f0f3f8]">active instances</h2>
              <div className="mt-2 space-y-1.5 text-xs">
                {dash.activeInstances.length === 0 && (
                  <p className="text-[#5a6a82]">no running instances — start one from a challenge page.</p>
                )}
                {dash.activeInstances.map((i) => (
                  <div key={i.slug} className="flex items-center gap-2 rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                    <span className="text-[#39d353]">●</span>
                    <Link to="/challenges/$slug" params={{ slug: i.slug }} className="text-[#c9d4e3] hover:text-[#e5484d]">
                      {i.challengeTitle}
                    </Link>
                    <span className="ml-auto text-[10px] text-[#5a6a82]">
                      {i.expiresAt ? `expires ${fmtTs(i.expiresAt)}` : "no expiry"}
                    </span>
                  </div>
                ))}
              </div>
              <h2 className="mt-5 text-sm font-bold text-[#f0f3f8]">learning paths</h2>
              <div className="mt-2 space-y-2 text-xs">
                {dash.paths.map((p) => (
                  <Link key={p.slug} to="/paths/$slug" params={{ slug: p.slug }} className="block">
                    <div className="flex items-center gap-2">
                      <span className="text-[#c9d4e3] hover:text-[#e5484d]">{p.title}</span>
                      <span className="ml-auto text-[#5a6a82]">{p.solvedSteps}/{p.totalSteps} · {p.pct}%</span>
                    </div>
                    <div className="mt-1 h-1.5 overflow-hidden rounded bg-[#1d2532]">
                      <div className="h-full rounded bg-[#e5484d]" style={{ width: `${p.pct}%` }} />
                    </div>
                  </Link>
                ))}
              </div>
            </Card>
          </div>

          <Card className="p-5">
            <h2 className="text-sm font-bold text-[#f0f3f8]">recent solves</h2>
            <div className="mt-2 space-y-1.5 text-xs">
              {dash.recentSolves.length === 0 && <p className="text-[#5a6a82]">no solves yet — pick a lab from the catalogue.</p>}
              {dash.recentSolves.map((s, i) => (
                <div key={`${s.slug}-${s.flagId}-${i}`} className="flex items-center gap-2 rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                  <span className="text-[#39d353]">✓</span>
                  <Link to="/challenges/$slug" params={{ slug: s.slug }} className="text-[#c9d4e3] hover:text-[#e5484d]">
                    {s.challengeTitle}
                  </Link>
                  <span className="text-[#5a6a82]">{s.flagId}</span>
                  <span className="ml-auto text-[#5a6a82]">{fmtTs(s.at)}</span>
                  <span className="text-[#d29922]">+{s.pointsAwarded}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </Shell>
  );
}

