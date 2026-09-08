import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, DIFF_STYLE, useMe } from "~/components/shell";
import { pathProgress } from "~/server/functions";
import type { PathProgress } from "~/server/types";

export const Route = createFileRoute("/paths/$slug")({
  component: PathDetail,
});

const STEP_STYLE: Record<PathProgress["steps"][number]["state"], string> = {
  solved: "border-[#39d353]/60 text-[#39d353]",
  unlocked: "border-[#d29922]/60 text-[#d29922]",
  locked: "border-[#1d2532] text-[#5a6a82]",
};

function PathDetail() {
  const { slug } = Route.useParams();
  const { me } = useMe();
  const [path, setPath] = useState<PathProgress | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setPath(undefined);
    setError(null);
    pathProgress({ data: { slug } })
      .then((r) => setPath(r.path))
      .catch(() => setError("Failed to load path progress from the server."));
  }, [slug]);

  return (
    <Shell>
      <div className="mb-4 flex items-center gap-3 text-xs">
        <Link to="/paths" className="text-[#8b98ac] hover:text-[#e5484d]">
          ← paths
        </Link>
      </div>
      {error && <Card className="p-4 text-xs text-[#e5484d]">{error}</Card>}
      {path === undefined && !error && <p className="text-xs text-[#5a6a82]">loading path…</p>}
      {path === null && !error && (
        <Card className="p-6 text-xs">
          <p className="text-[#e5484d]">[404] unknown path: {slug}</p>
        </Card>
      )}
      {path && (
        <div className="space-y-4">
          <div>
            <h1 className="text-lg font-bold text-[#f0f3f8]">
              <span className="text-[#e5484d]">&gt;</span> {path.title}
            </h1>
            <p className="mt-1 text-xs text-[#8b98ac]">{path.blurb}</p>
            <div className="mt-3 flex items-center gap-3">
              <div className="h-2 flex-1 overflow-hidden rounded bg-[#1d2532]">
                <div
                  className="h-full rounded bg-[#e5484d] transition-all"
                  style={{ width: `${path.pct}%` }}
                />
              </div>
              <span className="text-xs text-[#8b98ac]">
                {path.solvedSteps}/{path.totalSteps} · {path.pct}%
              </span>
            </div>
            {!me && (
              <p className="mt-2 text-xs text-[#5a6a82]">
                anonymous view — <Link to="/login" className="text-[#e5484d] hover:underline">sign in</Link> to track solves.
              </p>
            )}
          </div>

          <ol className="space-y-2">
            {path.steps.map((s, i) => (
              <li key={s.slug}>
                <Card className={`flex items-center gap-3 border p-4 ${STEP_STYLE[s.state]}`}>
                  <span className="text-sm font-bold">{String(i + 1).padStart(2, "0")}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {s.state === "locked" ? (
                        <span className="text-sm text-[#5a6a82]">🔒 {s.title} — solve the previous step to unlock</span>
                      ) : (
                        <Link to="/challenges/$slug" params={{ slug: s.slug }} className="text-sm text-[#f0f3f8] hover:text-[#e5484d]">
                          {s.state === "solved" ? "✓ " : "▸ "}{s.title}
                        </Link>
                      )}
                      <span className={`rounded border px-1.5 text-[10px] ${DIFF_STYLE[s.difficulty]}`}>{s.difficulty}</span>
                      <span className="text-[10px] text-[#5a6a82]">{s.category} · {s.points} pts</span>
                    </div>
                  </div>
                  <span className="rounded border px-2 py-0.5 text-[10px] uppercase">{s.state}</span>
                </Card>
              </li>
            ))}
          </ol>

          {path.complete && me && (
            <Card className="p-6" >
              <div id="path-certificate" className="rounded border border-[#d29922]/60 bg-black/50 p-8 text-center">
                <p className="text-[11px] tracking-[0.3em] text-[#5a6a82]">CRIMSON RANGE // CERTIFICATE OF COMPLETION</p>
                <h2 className="mt-2 text-xl font-bold text-[#f0f3f8]">{path.title}</h2>
                <p className="mt-3 text-xs text-[#8b98ac]">awarded to</p>
                <p className="mt-1 text-2xl font-bold text-[#d29922]">{me.username}</p>
                <p className="mt-3 text-[11px] text-[#5a6a82]">
                  {path.solvedSteps} labs solved · {new Date().toISOString().slice(0, 10)} · crimson-range operator record
                </p>
              </div>
              <div className="mt-4 print:hidden">
                <button
                  onClick={() => window.print()}
                  className="rounded border border-[#d29922]/60 px-3 py-1.5 text-xs text-[#d29922] hover:bg-[#d29922]/10"
                >
                  ⎙ print certificate
                </button>
              </div>
            </Card>
          )}
        </div>
      )}
    </Shell>
  );
}
