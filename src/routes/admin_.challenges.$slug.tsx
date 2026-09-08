import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { Shell, Card, useMe } from "~/components/shell";
import {
  cmsGet,
  cmsSignoff,
  cmsTransition,
  cmsUpdate,
  cmsValidateManifest,
  getMe,
} from "~/server/functions";
import type {
  Challenge,
  ChallengePatch,
  ChallengeStatus,
  ChecklistKey,
  Difficulty,
  FlagDef,
  ManifestIssue,
} from "~/server/types";
import { CHECKLIST_ITEMS } from "~/server/types";

export const Route = createFileRoute("/admin_/challenges/$slug")({
  component: CmsEditor,
});

// ---------------------------------------------------------------------------
// Minimal YAML parser.
// LIMITATION (documented): supports flat `key: value` pairs plus ONE level of
// `- item` lists under a key. No nested maps, no multi-line blocks, no anchors.
// Enough for the challenge manifest shape; anything richer must be edited via
// the form fields below.
// ---------------------------------------------------------------------------
function parseMiniYaml(src: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  let curList: string | null = null;
  for (const raw of src.split("\n")) {
    const line = raw.replace(/\t/g, "  ");
    if (!line.trim() || line.trimStart().startsWith("#")) continue;
    const m = line.match(/^(\s*)([^:#]+?):\s*(.*)$/);
    if (m && m[1].length <= 1) {
      const key = m[2].trim();
      const val = m[3].trim();
      if (val === "") {
        out[key] = [];
        curList = key;
      } else {
        out[key] = scalar(val);
        curList = null;
      }
      continue;
    }
    const li = line.match(/^\s*-\s+(.*)$/);
    if (li && curList) {
      (out[curList] as unknown[]).push(scalar(li[1].trim()));
      continue;
    }
    if (m && m[1].length > 1) throw new Error("nested maps not supported (key \"" + m[2].trim() + "\").");
    throw new Error("cannot parse line: \"" + raw.trim() + "\"");
  }
  return out;
}

function scalar(v: string): unknown {
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) return v.slice(1, -1);
  if (v === "true") return true;
  if (v === "false") return false;
  if (v === "null" || v === "~") return null;
  if (/^-?\d+$/.test(v)) return Number(v);
  if (/^-?\d+\.\d+$/.test(v)) return Number(v);
  if (v.startsWith("[") && v.endsWith("]"))
    return v.slice(1, -1).split(",").map((s) => scalar(s.trim())).filter((s) => s !== "");
  return v;
}

// Minimal markdown preview (same pattern as challenges.$slug renderMd:
// escape HTML, **bold**, `code`, # headings, line breaks).
function renderMd(md: string): string {
  return md
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/^### (.*)$/gm, "<p><strong>$1</strong></p>")
    .replace(/^## (.*)$/gm, "<p><strong>$1</strong></p>")
    .replace(/^# (.*)$/gm, "<p><strong>$1</strong></p>")
    .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-[#f0f3f8]">$1</strong>')
    .replace(/`([^`]+)`/g, '<code class="rounded bg-black/70 px-1 text-[#39d353]">$1</code>')
    .replace(/\n/g, "<br/>");
}

const FLAG_PEPPER = "crimson-range:v1:";
async function hashAnswer(answer: string): Promise<string> {
  const data = new TextEncoder().encode(FLAG_PEPPER + answer.trim());
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const NEXT: Record<ChallengeStatus, ChallengeStatus[]> = {
  DRAFT: ["REVIEW", "RETIRED"],
  REVIEW: ["VALIDATED", "RETIRED"],
  VALIDATED: ["PUBLISHED", "RETIRED"],
  PUBLISHED: ["RETIRED"],
  RETIRED: [],
};

const CATS: Challenge["category"][] = ["AI Red-Team", "Active Directory", "Web/API", "Cloud", "Kill-Chain"];
const DIFFS: Difficulty[] = ["Easy", "Medium", "Hard", "Insane"];

const inputCls =
  "w-full rounded border border-[#2a3a4d] bg-black/40 px-2 py-1.5 text-xs text-[#c9d4e3] placeholder:text-[#3d4a5f] focus:border-[#e5484d] focus:outline-none";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Card className="p-4">
      <h2 className="mb-3 text-xs font-bold uppercase tracking-widest text-[#8b98ac]">{title}</h2>
      <div className="space-y-3">{children}</div>
    </Card>
  );
}

function CmsEditor() {
  const { slug } = Route.useParams();
  const navigate = useNavigate();
  const { me } = useMe();
  const [c, setC] = useState<Challenge | null>(null);
  const [denied, setDenied] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [yaml, setYaml] = useState("");
  const [issues, setIssues] = useState<ManifestIssue[] | null>(null);
  const [yamlErr, setYamlErr] = useState<string | null>(null);

  useEffect(() => {
    getMe()
      .then((r) => {
        if (!r.user) navigate({ to: "/login" });
        else if (r.user.role === "STUDENT") setDenied(true);
        else
          cmsGet({ data: { slug } })
            .then((x) => {
              if (!x.challenge) setDenied(true);
              else setC(x.challenge);
            })
            .catch(() => setDenied(true));
      })
      .catch(() => navigate({ to: "/login" }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [slug]);

  if (denied)
    return (
      <Shell>
        <Card className="p-6 text-xs">
          <p className="text-[#e5484d]">[403/404] — not allowed or unknown challenge.</p>
        </Card>
      </Shell>
    );
  if (!c || !me)
    return (
      <Shell>
        <p className="text-xs text-[#5a6a82]">loading editor…</p>
      </Shell>
    );

  const set = (patch: Partial<Challenge>) => setC({ ...c, ...patch });
  const canEdit = me.role === "ADMIN" || c.createdBy === me.username;
  const canReview = me.role === "REVIEWER" || me.role === "ADMIN";

  const save = async () => {
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const patch: Record<string, unknown> = { ...c };
      delete patch.slug;
      delete patch.status;
      delete patch.signoffs;
      delete patch.createdBy;
      const r = await cmsUpdate({ slug: c.slug, patch: patch as ChallengePatch });
      if (!r.ok || !r.challenge) setErr(r.error ?? "save failed.");
      else {
        setC(r.challenge);
        setMsg("[+] saved.");
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "save failed.");
    } finally {
      setBusy(false);
    }
  };

  const transition = async (to: ChallengeStatus) => {
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const r = await cmsTransition({ slug: c.slug, to });
      if (!r.ok || !r.challenge) setErr(r.error ?? "transition failed.");
      else {
        setC(r.challenge);
        setMsg("[+] moved to " + to + ".");
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "transition failed.");
    } finally {
      setBusy(false);
    }
  };

  const signoff = async () => {
    setBusy(true);
    setErr(null);
    setMsg(null);
    try {
      const checklist: Partial<Record<ChecklistKey, boolean>> = {};
      for (const k of Object.keys(c.checklist) as ChecklistKey[]) checklist[k] = c.checklist[k];
      const r = await cmsSignoff({ slug: c.slug, checklist });
      if (!r.ok || !r.challenge) setErr(r.error ?? "sign-off failed.");
      else {
        setC(r.challenge);
        setMsg("[+] signed off (" + r.challenge.signoffs.length + "/2).");
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "sign-off failed.");
    } finally {
      setBusy(false);
    }
  };

  const doValidateManifest = async () => {
    setYamlErr(null);
    setIssues(null);
    try {
      const obj = parseMiniYaml(yaml);
      const r = await cmsValidateManifest({ data: { obj } });
      setIssues(r.issues);
      if (r.issues.length === 0) {
        const o = obj as Record<string, unknown>;
        const next: Challenge = { ...c };
        const str = (v: unknown) => (typeof v === "string" ? v : undefined);
        if (str(o.title)) next.title = str(o.title)!;
        if (str(o.category) && (CATS as string[]).includes(str(o.category)!)) next.category = str(o.category)! as Challenge["category"];
        if (str(o.difficulty) && (DIFFS as string[]).includes(str(o.difficulty)!)) next.difficulty = str(o.difficulty)! as Difficulty;
        if (str(o.descriptionMd)) next.descriptionMd = str(o.descriptionMd)!;
        if (str(o.author)) next.author = str(o.author)!;
        if (str(o.instanceType)) next.instanceType = str(o.instanceType)!;
        if (str(o.cpuLimit)) next.cpuLimit = str(o.cpuLimit)!;
        if (str(o.memLimit)) next.memLimit = str(o.memLimit)!;
        if (str(o.writeupMd)) next.writeupMd = str(o.writeupMd)!;
        if (Array.isArray(o.objectives)) next.objectives = o.objectives.map(String);
        if (Array.isArray(o.tags)) next.tags = o.tags.map(String);
        if (typeof o.pointsOverride === "number") next.pointsOverride = o.pointsOverride;
        if (typeof o.instanceTtlMinutes === "number") next.instanceTtlMinutes = o.instanceTtlMinutes;
        setC(next);
        setMsg("[+] manifest valid — editor prefilled.");
      }
    } catch (e) {
      setYamlErr(e instanceof Error ? e.message : "YAML parse failed.");
    }
  };

  return (
    <Shell>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-bold text-[#f0f3f8]">
          <span className="text-[#e5484d]">&gt;</span> edit <span className="text-[#8b98ac]">{c.slug}</span>
        </h1>
        <span className="rounded border border-[#2a3a4d] px-1.5 text-[10px] text-[#8b98ac]">{c.status}</span>
        <span className="text-[11px] text-[#5a6a82]">by {c.createdBy}</span>
        <div className="ml-auto">
          <button onClick={save} disabled={!canEdit || busy} className="rounded border border-[#39d353]/60 px-3 py-1.5 text-xs text-[#39d353] hover:bg-[#39d353]/10 disabled:opacity-50">
            {busy ? "…" : "save"}
          </button>
        </div>
      </div>
      {err && <Card className="mb-3 border-[#e5484d]/50 p-3 text-xs text-[#e5484d]">[error] {err}</Card>}
      {msg && <Card className="mb-3 border-[#39d353]/50 p-3 text-xs text-[#39d353]">{msg}</Card>}

      <div className="space-y-4">
        <Section title="metadata">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="block text-[11px] text-[#5a6a82]">title<input className={inputCls} value={c.title} disabled={!canEdit} onChange={(e) => set({ title: e.target.value })} /></label>
            <label className="block text-[11px] text-[#5a6a82]">author<input className={inputCls} value={c.author} disabled={!canEdit} onChange={(e) => set({ author: e.target.value })} /></label>
            <label className="block text-[11px] text-[#5a6a82]">category
              <select className={inputCls} value={c.category} disabled={!canEdit} onChange={(e) => set({ category: e.target.value as Challenge["category"] })}>
                {CATS.map((x) => <option key={x}>{x}</option>)}
              </select>
            </label>
            <label className="block text-[11px] text-[#5a6a82]">difficulty
              <select className={inputCls} value={c.difficulty} disabled={!canEdit} onChange={(e) => set({ difficulty: e.target.value as Difficulty })}>
                {DIFFS.map((x) => <option key={x}>{x}</option>)}
              </select>
            </label>
            <label className="block text-[11px] text-[#5a6a82]">tags (comma-separated)<input className={inputCls} value={c.tags.join(", ")} disabled={!canEdit} onChange={(e) => set({ tags: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })} /></label>
            <label className="block text-[11px] text-[#5a6a82]">points override (blank = auto)<input className={inputCls} type="number" value={c.pointsOverride ?? ""} disabled={!canEdit} onChange={(e) => set({ pointsOverride: e.target.value === "" ? null : Number(e.target.value) })} /></label>
          </div>
        </Section>

        <Section title="description (markdown + live preview)">
          <div className="grid gap-3 md:grid-cols-2">
            <textarea className={inputCls + " min-h-40 font-mono"} value={c.descriptionMd} disabled={!canEdit} onChange={(e) => set({ descriptionMd: e.target.value })} />
            <div className="rounded border border-[#1d2532] bg-black/40 p-3 text-xs text-[#c9d4e3]" dangerouslySetInnerHTML={{ __html: renderMd(c.descriptionMd) }} />
          </div>
          <label className="block text-[11px] text-[#5a6a82]">writeup (shown after solve)<textarea className={inputCls + " min-h-20 font-mono"} value={c.writeupMd} disabled={!canEdit} onChange={(e) => set({ writeupMd: e.target.value })} /></label>
        </Section>

        <Section title="objectives">
          {c.objectives.map((o, i) => (
            <div key={i} className="flex gap-2">
              <input className={inputCls} value={o} disabled={!canEdit} onChange={(e) => set({ objectives: c.objectives.map((x, j) => (j === i ? e.target.value : x)) })} />
              <button disabled={!canEdit} onClick={() => set({ objectives: c.objectives.filter((_, j) => j !== i) })} className="rounded border border-[#e5484d]/50 px-2 text-xs text-[#e5484d] disabled:opacity-50">x</button>
            </div>
          ))}
          <button disabled={!canEdit} onClick={() => set({ objectives: [...c.objectives, ""] })} className="rounded border border-[#2a3a4d] px-2 py-1 text-xs text-[#8b98ac] disabled:opacity-50">+ objective</button>
        </Section>

        <Section title="flags (STATIC answer hashed client-side / DYNAMIC toggle)">
          {c.flags.map((f, i) => (
            <FlagRow key={f.id + i} flag={f} disabled={!canEdit} onChange={(nf) => set({ flags: c.flags.map((x, j) => (j === i ? nf : x)) })} onRemove={() => set({ flags: c.flags.filter((_, j) => j !== i) })} />
          ))}
          <button disabled={!canEdit} onClick={() => set({ flags: [...c.flags, { id: "f-" + (c.flags.length + 1), name: "flag.new", points: 100, flagType: "DYNAMIC" }] })} className="rounded border border-[#2a3a4d] px-2 py-1 text-xs text-[#8b98ac] disabled:opacity-50">+ flag</button>
        </Section>

        <Section title="hints (with costs)">
          {c.hints.map((h, i) => (
            <div key={h.id + i} className="grid gap-2 rounded border border-[#1d2532] bg-black/40 p-2 md:grid-cols-[1fr_2fr_80px_auto]">
              <input className={inputCls} value={h.title} placeholder="title" disabled={!canEdit} onChange={(e) => set({ hints: c.hints.map((x, j) => (j === i ? { ...x, title: e.target.value } : x)) })} />
              <input className={inputCls} value={h.body} placeholder="body" disabled={!canEdit} onChange={(e) => set({ hints: c.hints.map((x, j) => (j === i ? { ...x, body: e.target.value } : x)) })} />
              <input className={inputCls} type="number" value={h.cost} disabled={!canEdit} onChange={(e) => set({ hints: c.hints.map((x, j) => (j === i ? { ...x, cost: Number(e.target.value) } : x)) })} />
              <button disabled={!canEdit} onClick={() => set({ hints: c.hints.filter((_, j) => j !== i) })} className="rounded border border-[#e5484d]/50 px-2 text-xs text-[#e5484d] disabled:opacity-50">x</button>
            </div>
          ))}
          <button disabled={!canEdit} onClick={() => set({ hints: [...c.hints, { id: "h-" + (c.hints.length + 1), title: "", body: "", cost: 20 }] })} className="rounded border border-[#2a3a4d] px-2 py-1 text-xs text-[#8b98ac] disabled:opacity-50">+ hint</button>
        </Section>

        <Section title="artifacts">
          {c.artifacts.map((a, i) => (
            <div key={i} className="grid gap-2 rounded border border-[#1d2532] bg-black/40 p-2 md:grid-cols-[1fr_100px_80px_2fr_auto]">
              {(["name", "kind", "size", "url"] as const).map((k) => (
                <input key={k} className={inputCls} value={a[k]} placeholder={k} disabled={!canEdit} onChange={(e) => set({ artifacts: c.artifacts.map((x, j) => (j === i ? { ...x, [k]: e.target.value } : x)) })} />
              ))}
              <button disabled={!canEdit} onClick={() => set({ artifacts: c.artifacts.filter((_, j) => j !== i) })} className="rounded border border-[#e5484d]/50 px-2 text-xs text-[#e5484d] disabled:opacity-50">x</button>
            </div>
          ))}
          <button disabled={!canEdit} onClick={() => set({ artifacts: [...c.artifacts, { name: "", kind: "file", size: "", url: "" }] })} className="rounded border border-[#2a3a4d] px-2 py-1 text-xs text-[#8b98ac] disabled:opacity-50">+ artifact</button>
        </Section>

        <Section title="ttl / limits">
          <div className="grid gap-3 md:grid-cols-4">
            <label className="block text-[11px] text-[#5a6a82]">instanceType<input className={inputCls} value={c.instanceType} disabled={!canEdit} onChange={(e) => set({ instanceType: e.target.value })} /></label>
            <label className="block text-[11px] text-[#5a6a82]">cpuLimit<input className={inputCls} value={c.cpuLimit} disabled={!canEdit} onChange={(e) => set({ cpuLimit: e.target.value })} /></label>
            <label className="block text-[11px] text-[#5a6a82]">memLimit<input className={inputCls} value={c.memLimit} disabled={!canEdit} onChange={(e) => set({ memLimit: e.target.value })} /></label>
            <label className="block text-[11px] text-[#5a6a82]">instanceTtlMinutes<input className={inputCls} type="number" value={c.instanceTtlMinutes ?? ""} placeholder="120" disabled={!canEdit} onChange={(e) => set({ instanceTtlMinutes: e.target.value === "" ? undefined : Number(e.target.value) })} /></label>
          </div>
        </Section>

        <Section title="reviewer checklist + sign-off">
          {!canReview && <p className="text-[11px] text-[#5a6a82]">REVIEWER / ADMIN only.</p>}
          <div className="space-y-1.5">
            {CHECKLIST_ITEMS.map((it) => (
              <label key={it.key} className="flex items-center gap-2 text-xs text-[#c9d4e3]">
                <input type="checkbox" checked={!!c.checklist[it.key]} disabled={!canReview} onChange={(e) => set({ checklist: { ...c.checklist, [it.key]: e.target.checked } })} />
                {it.label}
              </label>
            ))}
          </div>
          <div className="text-[11px] text-[#5a6a82]">
            sign-offs: {c.signoffs.length > 0 ? c.signoffs.map((s) => s.reviewer + " @ " + new Date(s.at).toLocaleString()).join(" · ") : "none yet"} (need 2 distinct non-author)
          </div>
          <button onClick={signoff} disabled={!canReview || busy} className="rounded border border-[#7c5cff]/60 px-3 py-1.5 text-xs text-[#c9a2ff] hover:bg-[#7c5cff]/10 disabled:opacity-50">
            {busy ? "…" : "sign off (checklist saved with sign-off)"}
          </button>
        </Section>

        <Section title="lifecycle transitions">
          <div className="flex flex-wrap gap-2">
            {NEXT[c.status].length === 0 && <p className="text-[11px] text-[#5a6a82]">terminal state — no transitions.</p>}
            {NEXT[c.status].map((to) => (
              <button key={to} onClick={() => transition(to)} disabled={busy} className="rounded border border-[#d29922]/60 px-3 py-1.5 text-xs text-[#d29922] hover:bg-[#d29922]/10 disabled:opacity-50">
                → {to}
              </button>
            ))}
          </div>
        </Section>

        <Section title="manifest import (paste YAML → validate → prefill)">
          <textarea className={inputCls + " min-h-32 font-mono"} placeholder="title: My Box" value={yaml} onChange={(e) => setYaml(e.target.value)} />
          <div className="flex gap-2">
            <button onClick={doValidateManifest} className="rounded border border-[#2a3a4d] px-3 py-1.5 text-xs text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]">validate manifest</button>
          </div>
          {yamlErr && <p className="text-xs text-[#e5484d]">[yaml] {yamlErr}</p>}
          {issues && issues.length === 0 && <p className="text-xs text-[#39d353]">manifest valid — editor prefilled.</p>}
          {issues && issues.length > 0 && (
            <ul className="space-y-1 text-xs">
              {issues.map((iss, k) => (
                <li key={k} className="rounded border border-[#e5484d]/40 bg-black/40 px-2 py-1">
                  <span className="text-[#e5484d]">{iss.field}:</span> <span className="text-[#c9d4e3]">{iss.message}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </div>
    </Shell>
  );
}

function FlagRow({ flag, disabled, onChange, onRemove }: { flag: FlagDef; disabled: boolean; onChange: (f: FlagDef) => void; onRemove: () => void }) {
  const [answer, setAnswer] = useState("");
  const [hashing, setHashing] = useState(false);
  const isStatic = flag.flagType === "STATIC";
  return (
    <div className="grid gap-2 rounded border border-[#1d2532] bg-black/40 p-2 md:grid-cols-[100px_1fr_90px_130px_1fr_auto]">
      <input className={inputCls} value={flag.id} placeholder="id" disabled={disabled} onChange={(e) => onChange({ ...flag, id: e.target.value })} />
      <input className={inputCls} value={flag.name} placeholder="name" disabled={disabled} onChange={(e) => onChange({ ...flag, name: e.target.value })} />
      <input className={inputCls} type="number" value={flag.points} disabled={disabled} onChange={(e) => onChange({ ...flag, points: Number(e.target.value) })} />
      <label className="flex items-center gap-2 text-[11px] text-[#8b98ac]">
        <input type="checkbox" checked={isStatic} disabled={disabled} onChange={(e) => onChange({ ...flag, flagType: e.target.checked ? "STATIC" : "DYNAMIC", answerHash: e.target.checked ? flag.answerHash : undefined })} />
        {isStatic ? "STATIC" : "DYNAMIC"}
      </label>
      {isStatic ? (
        <div className="flex gap-1">
          <input className={inputCls} value={answer} placeholder={flag.answerHash ? "hash set — retype to change" : "plaintext answer"} disabled={disabled} onChange={(e) => setAnswer(e.target.value)} />
          <button
            disabled={disabled || !answer.trim() || hashing}
            onClick={async () => {
              setHashing(true);
              try {
                onChange({ ...flag, answerHash: await hashAnswer(answer) });
                setAnswer("");
              } finally {
                setHashing(false);
              }
            }}
            className="shrink-0 rounded border border-[#2a3a4d] px-2 text-[11px] text-[#8b98ac] disabled:opacity-50"
          >
            {hashing ? "…" : "hash"}
          </button>
        </div>
      ) : (
        <span className="text-[11px] text-[#5a6a82]">derived per-user at solve time</span>
      )}
      <button disabled={disabled} onClick={onRemove} className="rounded border border-[#e5484d]/50 px-2 text-xs text-[#e5484d] disabled:opacity-50">x</button>
    </div>
  );
}
