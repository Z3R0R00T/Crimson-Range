import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, useMe } from "~/components/shell";
import { cmsCreate, cmsList, cmsTransition, getMe } from "~/server/functions";
import type { Challenge, ChallengeStatus } from "~/server/types";

export const Route = createFileRoute("/admin_/challenges/")({
  component: CmsList,
});

const STATUS_STYLE: Record<ChallengeStatus, string> = {
  DRAFT: "border-[#3d4a5f]/60 text-[#8b98ac]",
  REVIEW: "border-[#d29922]/60 text-[#d29922]",
  VALIDATED: "border-[#7c5cff]/60 text-[#c9a2ff]",
  PUBLISHED: "border-[#39d353]/60 text-[#39d353]",
  RETIRED: "border-[#e5484d]/60 text-[#e5484d]",
};

function pointsOf(c: Challenge): number {
  return c.pointsOverride ?? c.flags.reduce((s, f) => s + (f.points ?? 0), 0);
}

function CmsList() {
  const navigate = useNavigate();
  const { me } = useMe();
  const [items, setItems] = useState<Challenge[] | null>(null);
  const [denied, setDenied] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const reload = async () => {
    try {
      const r = await cmsList();
      setItems(r.challenges);
    } catch {
      setDenied(true);
    }
  };

  useEffect(() => {
    getMe()
      .then((r) => {
        if (!r.user) navigate({ to: "/login" });
        else if (r.user.role === "STUDENT") setDenied(true);
        else void reload();
      })
      .catch(() => navigate({ to: "/login" }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [navigate]);

  const newDraft = async () => {
    if (!me) return;
    setBusy("__new");
    setErr(null);
    try {
      const r = await cmsCreate({
        input: {
          title: `Untitled draft ${new Date().toISOString().slice(0, 16).replace("T", " ")}`,
          category: "Web/API",
          difficulty: "Medium",
          descriptionMd: "## Overview\n\nDescribe the challenge here.",
          objectives: ["Capture the flag."],
          mitre: [],
          cves: [],
          tags: [],
          flags: [{ id: "f-1", name: "flag.1", points: 100, flagType: "DYNAMIC" }],
          hints: [],
          artifacts: [],
          writeupMd: "",
          instanceType: "web",
          cpuLimit: "1",
          memLimit: "512Mi",
          author: me.username,
        },
      });
      if (!r.ok || !r.challenge) setErr(r.error ?? "create failed.");
      else await navigate({ to: "/admin/challenges/$slug", params: { slug: r.challenge.slug } });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "create failed.");
    } finally {
      setBusy(null);
    }
  };

  const submitReview = async (slug: string) => {
    setBusy(slug);
    setErr(null);
    try {
      const r = await cmsTransition({ slug, to: "REVIEW" });
      if (!r.ok) setErr(r.error ?? "transition failed.");
      else await reload();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "transition failed.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <Shell>
      <div className="mb-4 flex items-center gap-3">
        <h1 className="text-lg font-bold text-[#f0f3f8]">
          <span className="text-[#e5484d]">&gt;</span> challenge cms
        </h1>
        <span className="text-[11px] text-[#5a6a82]">author review queue (server-scoped; VENDOR sees own only)</span>
        <button
          onClick={newDraft}
          disabled={busy === "__new"}
          className="ml-auto rounded border border-[#39d353]/60 px-3 py-1.5 text-xs text-[#39d353] hover:bg-[#39d353]/10 disabled:opacity-50"
        >
          {busy === "__new" ? "creating…" : "+ new draft"}
        </button>
      </div>
      {denied && (
        <Card className="p-6 text-xs">
          <p className="text-[#e5484d]">[403] FORBIDDEN — AUTHOR / REVIEWER / ADMIN / VENDOR role required (STUDENT blocked).</p>
          <p className="mt-1 text-[#5a6a82]">current operator: {me ? `${me.username} (${me.role})` : "unknown"}</p>
        </Card>
      )}
      {!denied && !items && <p className="text-xs text-[#5a6a82]">loading review queue…</p>}
      {err && (
        <Card className="mb-3 border-[#e5484d]/50 p-3 text-xs text-[#e5484d]">[error] {err}</Card>
      )}
      {items && (
        <Card className="divide-y divide-[#1d2532]">
          {items.length === 0 && <p className="p-5 text-xs text-[#5a6a82]">queue empty — nothing awaiting review.</p>}
          {items.map((c) => {
            const own = me && c.createdBy === me.username;
            return (
              <div key={c.slug} className="flex flex-wrap items-center gap-3 px-4 py-3 text-xs">
                <span className={`rounded border px-1.5 py-0.5 text-[10px] ${STATUS_STYLE[c.status]}`}>{c.status}</span>
                <div className="min-w-0">
                  <p className="truncate font-bold text-[#f0f3f8]">{c.title}</p>
                  <p className="text-[11px] text-[#5a6a82]">
                    {c.slug} · by {c.createdBy} · {pointsOf(c)} pts · ✓{c.signoffs.length}/2
                  </p>
                </div>
                <div className="ml-auto flex items-center gap-2">
                  {c.status === "DRAFT" && !!own && (
                    <button
                      onClick={() => submitReview(c.slug)}
                      disabled={busy === c.slug}
                      className="rounded border border-[#d29922]/60 px-2 py-1 text-[#d29922] hover:bg-[#d29922]/10 disabled:opacity-50"
                    >
                      {busy === c.slug ? "…" : "submit → REVIEW"}
                    </button>
                  )}
                  <Link
                    to="/admin/challenges/$slug"
                    params={{ slug: c.slug }}
                    className="rounded border border-[#2a3a4d] px-2 py-1 text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]"
                  >
                    open
                  </Link>
                </div>
              </div>
            );
          })}
        </Card>
      )}
    </Shell>
  );
}
