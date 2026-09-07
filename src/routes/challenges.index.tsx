import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Shell, Card, DIFF_STYLE, CAT_ICON, useMe } from "~/components/shell";
import { listChallengeSummaries } from "~/server/functions";
import type { ChallengeSummary } from "~/server/types";

export const Route = createFileRoute("/challenges/")({
  component: Catalogue,
});

const CATEGORIES = ["AI Red-Team", "Active Directory", "Web/API", "Cloud", "Kill-Chain"];
const DIFFS = ["Easy", "Medium", "Hard", "Insane"];

function Catalogue() {
  const { me } = useMe();
  const [all, setAll] = useState<ChallengeSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [cats, setCats] = useState<string[]>([]);
  const [diffs, setDiffs] = useState<string[]>([]);
  const [mitre, setMitre] = useState("");
  const [solvedFilter, setSolvedFilter] = useState<"all" | "solved" | "unsolved">("all");

  useEffect(() => {
    listChallengeSummaries()
      .then((r) => setAll(r.challenges))
      .catch(() => setError("Failed to load challenges from the server."));
  }, []);

  const toggle = (list: string[], v: string, set: (x: string[]) => void) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const allTags = useMemo(() => {
    const s = new Set<string>();
    (all ?? []).forEach((c) => c.tags.forEach((t) => s.add(t)));
    return [...s].sort();
  }, [all]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (all ?? []).filter((c) => {
      if (cats.length && !cats.includes(c.category)) return false;
      if (diffs.length && !diffs.includes(c.difficulty)) return false;
      if (mitre.trim() && !c.mitreIds.some((m) => m.toLowerCase().includes(mitre.trim().toLowerCase()))) return false;
      if (solvedFilter === "solved" && !c.solved) return false;
      if (solvedFilter === "unsolved" && c.solved) return false;
      if (q && !(c.title.toLowerCase().includes(q) || c.tags.some((t) => t.toLowerCase().includes(q)))) return false;
      return true;
    });
  }, [all, query, cats, diffs, mitre, solvedFilter]);

  return (
    <Shell>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-bold text-[#f0f3f8]">
          <span className="text-[#e5484d]">&gt;</span> challenge catalogue
        </h1>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search title / tag…"
          className="ml-auto w-full rounded border border-[#2a3a4d] bg-black/60 px-3 py-1.5 text-xs text-[#c9d4e3] outline-none focus:border-[#e5484d] md:w-64"
        />
      </div>
      <div className="grid gap-4 md:grid-cols-[240px_1fr]">
        {/* Sidebar filters */}
        <aside className="h-fit rounded-md border border-[#1d2532] bg-[#0d1117] p-4 text-xs">
          <FilterGroup title="category">
            {CATEGORIES.map((c) => (
              <label key={c} className="flex cursor-pointer items-center gap-2 py-1 text-[#8b98ac] hover:text-[#c9d4e3]">
                <input type="checkbox" checked={cats.includes(c)} onChange={() => toggle(cats, c, setCats)} className="accent-[#e5484d]" />
                {CAT_ICON[c] ?? "•"} {c}
              </label>
            ))}
          </FilterGroup>
          <FilterGroup title="difficulty">
            {DIFFS.map((d) => (
              <label key={d} className="flex cursor-pointer items-center gap-2 py-1 text-[#8b98ac] hover:text-[#c9d4e3]">
                <input type="checkbox" checked={diffs.includes(d)} onChange={() => toggle(diffs, d, setDiffs)} className="accent-[#e5484d]" />
                {d}
              </label>
            ))}
          </FilterGroup>
          <FilterGroup title="mitre technique">
            <input
              value={mitre}
              onChange={(e) => setMitre(e.target.value)}
              placeholder="e.g. T1059"
              className="w-full rounded border border-[#2a3a4d] bg-black/60 px-2 py-1.5 text-[#c9d4e3] outline-none focus:border-[#e5484d]"
            />
          </FilterGroup>
          <FilterGroup title="status">
            {(["all", "solved", "unsolved"] as const).map((s) => (
              <label key={s} className="flex cursor-pointer items-center gap-2 py-1 text-[#8b98ac] hover:text-[#c9d4e3]">
                <input type="radio" name="solved" checked={solvedFilter === s} onChange={() => setSolvedFilter(s)} className="accent-[#e5484d]" />
                {s}
              </label>
            ))}
          </FilterGroup>
          <FilterGroup title="tags in range">
            <div className="flex flex-wrap gap-1">
              {allTags.map((t) => (
                <button
                  key={t}
                  onClick={() => setQuery(t)}
                  className="rounded border border-[#2a3a4d] px-1.5 py-0.5 text-[10px] text-[#5a6a82] hover:border-[#e5484d] hover:text-[#e5484d]"
                >
                  #{t}
                </button>
              ))}
            </div>
          </FilterGroup>
        </aside>

        {/* Card grid */}
        <div>
          {error && <p className="mb-3 text-xs text-[#e5484d]">[!] {error}</p>}
          {all === null && !error && <p className="text-xs text-[#5a6a82]">loading challenges…</p>}
          {all !== null && filtered.length === 0 && (
            <p className="text-xs text-[#5a6a82]">no challenges match — loosen the filters, operator.</p>
          )}
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {filtered.map((c) => (
              <Link key={c.slug} to="/challenges/$slug" params={{ slug: c.slug }}>
                <Card className="flex h-full flex-col p-4 transition-colors hover:border-[#e5484d]/60">
                  <div className="flex items-center gap-2 text-[11px] text-[#5a6a82]">
                    <span className="text-[#e5484d]">{CAT_ICON[c.category] ?? "•"}</span>
                    <span>{c.category}</span>
                    {c.solved && me && (
                      <span className="ml-auto rounded border border-[#39d353]/50 px-1.5 text-[#39d353]">✓ solved</span>
                    )}
                  </div>
                  <h2 className="mt-2 text-sm font-bold text-[#f0f3f8]">{c.title}</h2>
                  <div className="mt-2 flex items-center gap-2 text-[11px]">
                    <span className={`rounded border px-1.5 py-0.5 ${DIFF_STYLE[c.difficulty]}`}>{c.difficulty}</span>
                    <span className="text-[#d29922]">{c.points} pts</span>
                    <span className="ml-auto text-[#5a6a82]">◈ {c.solveCount} solves</span>
                  </div>
                  <div className="mt-1 text-[11px] text-[#5a6a82]">
                    {c.flagsCaptured}/{c.flagsTotal} flags
                    {c.firstBlood && <span className="ml-2">⚑ {c.firstBlood}</span>}
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {c.tags.slice(0, 4).map((t) => (
                      <span key={t} className="rounded bg-black/60 px-1.5 py-0.5 text-[10px] text-[#5a6a82]">#{t}</span>
                    ))}
                  </div>
                  <p className="mt-2 text-[10px] text-[#3d4a5f]">by {c.author}</p>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </Shell>
  );
}

function FilterGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-4 border-b border-[#1d2532] pb-3 last:mb-0 last:border-0 last:pb-0">
      <p className="mb-2 font-bold uppercase tracking-wider text-[#5a6a82]">{title}</p>
      {children}
    </div>
  );
}
