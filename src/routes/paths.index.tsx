import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, useMe } from "~/components/shell";
import { pathList } from "~/server/functions";

export const Route = createFileRoute("/paths/")({
  component: Paths,
});

function Paths() {
  const { me } = useMe();
  const [paths, setPaths] = useState<Array<{
    slug: string;
    title: string;
    blurb: string;
    totalSteps: number;
    steps: string[];
  }> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    pathList()
      .then((r) => setPaths(r.paths))
      .catch(() => setError("Failed to load learning paths from the server."));
  }, []);

  return (
    <Shell>
      <h1 className="mb-1 text-lg font-bold text-[#f0f3f8]">
        <span className="text-[#e5484d]">&gt;</span> learning paths
      </h1>
      <p className="mb-4 text-xs text-[#5a6a82]">
        ordered tracks — each step unlocks when the previous lab is fully solved.
        {me ? (
          <> signed in as <span className="text-[#39d353]">{me.username}</span> — open a path to see your progress.</>
        ) : (
          <> sign in to track progress.</>
        )}
      </p>
      {error && <Card className="p-4 text-xs text-[#e5484d]">{error}</Card>}
      {!error && !paths && <p className="text-xs text-[#5a6a82]">loading paths…</p>}
      {paths && (
        <div className="grid gap-4 md:grid-cols-2">
          {paths.map((p) => (
            <Card key={p.slug} className="p-5">
              <h2 className="text-sm font-bold text-[#f0f3f8]">{p.title}</h2>
              <p className="mt-1 text-xs text-[#8b98ac]">{p.blurb}</p>
              <div className="mt-3 space-y-1 text-xs">
                {p.steps.map((s, i) => (
                  <div key={s} className="flex items-center gap-2 text-[#5a6a82]">
                    <span className="text-[#3d4a5f]">{String(i + 1).padStart(2, "0")}</span>
                    <span className="text-[#8b98ac]">{s}</span>
                  </div>
                ))}
              </div>
              <div className="mt-4">
                <Link
                  to="/paths/$slug"
                  params={{ slug: p.slug }}
                  className="inline-block rounded border border-[#2a3a4d] px-3 py-1.5 text-xs text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]"
                >
                  open path [{p.totalSteps} steps] →
                </Link>
              </div>
            </Card>
          ))}
        </div>
      )}
    </Shell>
  );
}
