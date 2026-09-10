import { createFileRoute, Link } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Shell, Card, DIFF_STYLE, CAT_ICON, useMe } from "~/components/shell";
import {
  getChallengeDetail,
  getInstance,
  instanceAction,
  submitFlag,
  unlockHint,
} from "~/server/functions";
import type { ChallengeDetail, InstanceRecord } from "~/server/types";

export const Route = createFileRoute("/challenges/$slug")({
  component: Detail,
});

/** Minimal markdown renderer (headings, bold/code/inline, lists, paragraphs).
 *  HTML-escapes input first — never injects raw HTML. */
export function renderMd(md: string): React.ReactNode[] {
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const inline = (s: string) => {
    const parts: React.ReactNode[] = [];
    const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    let last = 0;
    let m: RegExpExecArray | null;
    let k = 0;
    const pushText = (t: string) => {
      if (t) parts.push(<span key={k++} dangerouslySetInnerHTML={{ __html: esc(t) }} />);
    };
    while ((m = re.exec(s))) {
      pushText(s.slice(last, m.index));
      const tok = m[0];
      if (tok.startsWith("**"))
        parts.push(<strong key={k++} className="text-[#f0f3f8]">{tok.slice(2, -2)}</strong>);
      else parts.push(<code key={k++} className="rounded bg-black/70 px-1 text-[#39d353]">{tok.slice(1, -1)}</code>);
      last = m.index + tok.length;
    }
    pushText(s.slice(last));
    return parts;
  };
  const out: React.ReactNode[] = [];
  const lines = md.split("\n");
  let i = 0;
  let k = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^#{1,3}\s/.test(line)) {
      const level = line.match(/^#+/)![0].length;
      const text = line.replace(/^#+\s*/, "");
      const cls = level === 1 ? "text-base font-bold text-[#f0f3f8]" : "text-sm font-bold text-[#f0f3f8]";
      out.push(<p key={k++} className={`${cls} mb-1 mt-3 first:mt-0`}>{inline(text)}</p>);
    } else if (/^\d+\.\s/.test(line) || /^[-*]\s/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && (/^\d+\.\s/.test(lines[i]) || /^[-*]\s/.test(lines[i]))) {
        items.push(lines[i].replace(/^(\d+\.\s|[-*]\s)/, ""));
        i++;
      }
      out.push(
        <ul key={k++} className="mb-2 list-disc space-y-1 pl-5">
          {items.map((t, j) => (
            <li key={j}>{inline(t)}</li>
          ))}
        </ul>
      );
      continue;
    } else if (line.trim() === "") {
      // skip
    } else {
      out.push(<p key={k++} className="mb-2">{inline(line)}</p>);
    }
    i++;
  }
  return out;
}

function mitreUrl(id: string): string {
  const base = id.split(".")[0];
  return `https://attack.mitre.org/techniques/${base}${id.includes(".") ? "/" + id.split(".")[1] : ""}`;
}

function fmtCountdown(ms: number): string {
  if (ms <= 0) return "expired";
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
}

function Detail() {
  const { slug } = Route.useParams();
  const { me } = useMe();
  const [detail, setDetail] = useState<ChallengeDetail | null | undefined>(undefined);
  const [tab, setTab] = useState<"brief" | "writeup">("brief");
  const [instance, setInstance] = useState<InstanceRecord | null>(null);
  const [instBusy, setInstBusy] = useState(false);
  const [instMsg, setInstMsg] = useState<string | null>(null);
  const [flagInputs, setFlagInputs] = useState<Record<string, string>>({});
  const [flagMsg, setFlagMsg] = useState<Record<string, string>>({});
  const [now, setNow] = useState(Date.now());
  const [hintOpen, setHintOpen] = useState<Record<string, boolean>>({});

  const reload = useCallback(async () => {
    const r = await getChallengeDetail({ data: { slug } });
    setDetail(r.challenge);
  }, [slug]);

  useEffect(() => {
    setDetail(undefined);
    reload().catch(() => setDetail(null));
    getInstance({ data: { slug } })
      .then((r) => setInstance(r.instance))
      .catch(() => {});
  }, [slug, reload]);

  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const doInstance = async (action: "start" | "reset" | "extend" | "stop") => {
    setInstBusy(true);
    setInstMsg(null);
    try {
      const r = await instanceAction({ data: { slug, action } });
      if (r.ok && r.instance) {
        setInstance(r.instance);
        setInstMsg(`[+] instance ${action} ok`);
      } else {
        setInstMsg(`[!] ${r.error ?? "action failed"}`);
      }
    } catch {
      setInstMsg("[!] instance action failed — are you logged in?");
    } finally {
      setInstBusy(false);
    }
  };

  const doSubmit = async (flagId: string) => {
    const value = flagInputs[flagId] ?? "";
    if (!value.trim()) return;
    setFlagMsg((m) => ({ ...m, [flagId]: "checking…" }));
    try {
      const r = await submitFlag({ data: { slug, flagId, value } });
      if (!r.ok) {
        setFlagMsg((m) => ({ ...m, [flagId]: `[!] ${r.error}` }));
      } else if (r.correct) {
        setFlagMsg((m) => ({ ...m, [flagId]: r.already ? "[=] already captured" : "[+] flag accepted!" }));
        await reload();
      } else {
        setFlagMsg((m) => ({ ...m, [flagId]: "[-] incorrect flag" }));
      }
    } catch {
      setFlagMsg((m) => ({ ...m, [flagId]: "[!] submit failed — are you logged in?" }));
    }
  };

  const doUnlockHint = async (hintId: string, cost: number, title: string) => {
    if (!window.confirm(`Unlock hint "${title}" for ${cost} pts? (MVP: cost is acknowledged, not deducted from score.)`)) return;
    try {
      await unlockHint({ data: { slug, hintId } });
      await reload();
    } catch {
      // ignore — likely logged out
    }
  };

  const solved = detail?.solved ?? false;

  const tabs = useMemo(
    () => [
      { id: "brief" as const, label: "brief" },
      { id: "writeup" as const, label: "writeup", locked: !solved },
    ],
    [solved]
  );

  return (
    <Shell>
      <Link to="/challenges" className="text-xs text-[#5a6a82] hover:text-[#e5484d]">
        &lt;-- catalogue
      </Link>
      {detail === undefined && <p className="mt-4 text-xs text-[#5a6a82]">loading challenge…</p>}
      {detail === null && <p className="mt-4 text-xs text-[#e5484d]">[!] challenge not found.</p>}
      {detail && (
        <div className="mt-3 space-y-4">
          {/* Header */}
          <Card className="p-5">
            <div className="flex flex-wrap items-center gap-2 text-[11px] text-[#5a6a82]">
              <span className="text-[#e5484d]">{CAT_ICON[detail.category] ?? "•"}</span>
              <span>{detail.category}</span>
              <span className={`rounded border px-1.5 py-0.5 ${DIFF_STYLE[detail.difficulty]}`}>{detail.difficulty}</span>
              <span className="text-[#d29922]">{detail.points} pts</span>
              {detail.solved && <span className="rounded border border-[#39d353]/50 px-1.5 text-[#39d353]">✓ solved</span>}
            </div>
            <h1 className="mt-2 text-2xl font-bold text-[#f0f3f8]">{detail.title}</h1>
            <p className="mt-1 text-xs text-[#5a6a82]">
              by <span className="text-[#8b98ac]">{detail.author}</span>
              <span className="mx-2">·</span>◈ {detail.solveCount} solves
              {detail.firstBlood && (
                <span className="ml-2">⚑ first blood: <span className="text-[#d29922]">{detail.firstBlood}</span></span>
              )}
            </p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {detail.mitre.map((m) => (
                <a
                  key={m.id}
                  href={mitreUrl(m.id)}
                  target="_blank"
                  rel="noreferrer"
                  title={`${m.id} — ${m.tactic}`}
                  className="rounded border border-[#2a3a4d] px-2 py-0.5 text-[11px] text-[#8b98ac] hover:border-[#e5484d] hover:text-[#e5484d]"
                >
                  {m.id} <span className="text-[#3d4a5f]">{m.tactic}</span>
                </a>
              ))}
              {detail.cves.map((c) => (
                <a
                  key={c.id}
                  href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${c.id}`}
                  target="_blank"
                  rel="noreferrer"
                  title={c.note}
                  className="rounded border border-[#2a3a4d] border-dashed px-2 py-0.5 text-[11px] text-[#5a6a82] hover:border-[#e5484d] hover:text-[#e5484d]"
                >
                  {c.id}
                </a>
              ))}
            </div>
            <div className="mt-3 flex gap-4 border-b border-[#1d2532] text-xs">
              {tabs.map((t) => (
                <button
                  key={t.id}
                  onClick={() => !t.locked && setTab(t.id)}
                  className={`pb-2 ${tab === t.id ? "border-b-2 border-[#e5484d] text-[#f0f3f8]" : "text-[#5a6a82] hover:text-[#c9d4e3]"} ${t.locked ? "cursor-not-allowed opacity-50" : ""}`}
                  title={t.locked ? "Solve the challenge to unlock the writeup" : undefined}
                >
                  [{t.label}]{t.locked ? " 🔒" : ""}
                </button>
              ))}
            </div>
          </Card>

          {tab === "brief" && (
            <>
              <Card className="p-5 text-xs leading-6 text-[#c9d4e3]">
                {renderMd(detail.descriptionMd)}
                <p className="mb-1 mt-3 text-sm font-bold text-[#f0f3f8]">Objectives</p>
                <ul className="list-disc space-y-1 pl-5">
                  {detail.objectives.map((o, i) => (
                    <li key={i}>{o}</li>
                  ))}
                </ul>
              </Card>

              {/* Artifacts */}
              <Card className="p-5">
                <h2 className="text-sm font-bold text-[#f0f3f8]">artifacts</h2>
                <div className="mt-2 space-y-1.5 text-xs">
                  {detail.artifacts.map((a) =>
                    a.url && a.url !== "#stub" ? (
                      <a
                        key={a.name}
                        href={a.url}
                        download
                        className="flex items-center gap-3 rounded border border-[#1d2532] bg-black/40 px-3 py-2 text-[#c9d4e3] hover:border-[#39d353]/60 hover:text-[#39d353]"
                      >
                        <span className="text-[#39d353]">↓</span>
                        <span>{a.name}</span>
                        <span className="text-[#3d4a5f]">{a.kind} · {a.size}</span>
                        <span className="ml-auto rounded border border-[#39d353]/40 px-1.5 text-[10px] text-[#39d353]">download</span>
                      </a>
                    ) : (
                      <div key={a.name} className="flex items-center gap-3 rounded border border-[#1d2532] bg-black/40 px-3 py-2">
                        <span className="text-[#39d353]">↓</span>
                        <span className="text-[#c9d4e3]">{a.name}</span>
                        <span className="text-[#3d4a5f]">{a.kind} · {a.size}</span>
                        <span className="ml-auto rounded border border-dashed border-[#2a3a4d] px-1.5 text-[10px] text-[#5a6a82]">stub</span>
                      </div>
                    )
                  )}
                </div>
              </Card>

              {/* Instance control panel */}
              <Card className="p-5">
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-sm font-bold text-[#f0f3f8]">
                    instance{" "}
                    {instance?.lab ? (
                      <span className="rounded border border-[#39d353]/60 px-1.5 text-[10px] text-[#39d353]">LIVE</span>
                    ) : (
                      <span className="rounded border border-dashed border-[#2a3a4d] px-1.5 text-[10px] text-[#5a6a82]">range</span>
                    )}
                  </h2>
                  <span className="ml-auto text-xs">
                    {instance && instance.status === "running" && instance.expiresAt ? (
                      <span className="text-[#39d353]">● running — T-{fmtCountdown(instance.expiresAt - now)}</span>
                    ) : instance && instance.status === "stopped" ? (
                      <span className="text-[#5a6a82]">○ stopped</span>
                    ) : (
                      <span className="text-[#5a6a82]">○ no instance</span>
                    )}
                  </span>
                </div>
                {instance?.lab && instance.status === "running" && (
                  <div className="mt-2 space-y-1.5 rounded bg-black/60 px-3 py-2 text-[11px]">
                    <p className="flex items-center gap-2 text-[#3d4a5f]">
                      <span className="w-16 shrink-0 text-[#5a6a82]">api base</span>
                      <code className="truncate text-[#39d353]">{`${window.location.origin}${instance.lab.baseUrl}`}</code>
                      <button
                        onClick={() => navigator.clipboard?.writeText(`${window.location.origin}${instance.lab?.baseUrl ?? ""}`)}
                        className="ml-auto shrink-0 rounded border border-[#2a3a4d] px-1.5 text-[10px] text-[#8b98ac] hover:border-[#39d353] hover:text-[#39d353]"
                      >
                        copy
                      </button>
                    </p>
                    <p className="flex items-center gap-2 text-[#3d4a5f]">
                      <span className="w-16 shrink-0 text-[#5a6a82]">bearer</span>
                      <code className="truncate text-[#39d353]">{instance.lab.token}</code>
                      <button
                        onClick={() => navigator.clipboard?.writeText(instance.lab?.token ?? "")}
                        className="ml-auto shrink-0 rounded border border-[#2a3a4d] px-1.5 text-[10px] text-[#8b98ac] hover:border-[#39d353] hover:text-[#39d353]"
                      >
                        copy
                      </button>
                    </p>
                    <p className="text-[#3d4a5f]">// Authorization: Bearer {"<token>"} — login with pentest01 / Winter2026! to mint your own</p>
                  </div>
                )}
                {!instance?.lab && instance?.endpoint && (
                  <p className="mt-2 truncate rounded bg-black/60 px-3 py-2 text-[11px] text-[#39d353]">$ target --connect {instance.endpoint}</p>
                )}
                {instance?.note && <p className="mt-1 text-[11px] text-[#3d4a5f]">// {instance.note}</p>}
                {instMsg && <p className="mt-1 text-[11px] text-[#8b98ac]">{instMsg}</p>}
                {!me && <p className="mt-2 text-[11px] text-[#d29922]">[!] log in to control an instance.</p>}
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {(["start", "reset", "extend", "stop"] as const).map((a) => (
                    <button
                      key={a}
                      disabled={instBusy || !me}
                      onClick={() => doInstance(a)}
                      className="rounded border border-[#2a3a4d] px-3 py-1.5 text-[#8b98ac] hover:border-[#39d353] hover:text-[#39d353] disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      {instBusy ? "…" : `> ${a}`}
                    </button>
                  ))}
                </div>
              </Card>

              {/* Flag form — one input per flag */}
              <Card className="p-5">
                <h2 className="text-sm font-bold text-[#f0f3f8]">flags</h2>
                {!me && <p className="mt-2 text-[11px] text-[#d29922]">[!] log in to submit flags.</p>}
                <div className="mt-2 space-y-3">
                  {detail.flags.map((f) => (
                    <div key={f.id} className={`rounded border p-3 ${f.captured ? "border-[#39d353]/50 bg-[#39d353]/5" : "border-[#1d2532] bg-black/40"}`}>
                      <div className="flex items-center gap-2 text-xs">
                        <span className={f.captured ? "text-[#39d353]" : "text-[#c9d4e3]"}>
                          {f.captured ? "✓" : "○"} {f.name}
                        </span>
                        <span className="ml-auto text-[#d29922]">{f.points} pts</span>
                      </div>
                      {f.captured ? (
                        <p className="mt-1 text-[11px] text-[#39d353]">
                          captured{f.capturedAt ? ` — ${new Date(f.capturedAt).toLocaleString()}` : ""}
                        </p>
                      ) : (
                        <div className="mt-2 flex gap-2">
                          <input
                            value={flagInputs[f.id] ?? ""}
                            onChange={(e) => setFlagInputs((m) => ({ ...m, [f.id]: e.target.value }))}
                            placeholder="CR{…}"
                            disabled={!me}
                            className="w-full rounded border border-[#2a3a4d] bg-black/60 px-3 py-1.5 text-xs text-[#c9d4e3] outline-none focus:border-[#e5484d] disabled:opacity-40"
                          />
                          <button
                            onClick={() => doSubmit(f.id)}
                            disabled={!me}
                            className="shrink-0 rounded border border-[#e5484d] bg-[#e5484d]/10 px-3 py-1.5 text-xs font-bold text-[#ff7b72] hover:bg-[#e5484d]/20 disabled:opacity-40"
                          >
                            submit
                          </button>
                        </div>
                      )}
                      {flagMsg[f.id] && <p className="mt-1 text-[11px] text-[#8b98ac]">{flagMsg[f.id]}</p>}
                    </div>
                  ))}
                </div>
              </Card>

              {/* Hints */}
              <Card className="p-5">
                <h2 className="text-sm font-bold text-[#f0f3f8]">hints</h2>
                <div className="mt-2 space-y-2">
                  {detail.hints.map((h) => (
                    <div key={h.id} className="rounded border border-[#1d2532] bg-black/40 text-xs">
                      <button
                        onClick={() => setHintOpen((m) => ({ ...m, [h.id]: !m[h.id] }))}
                        className="flex w-full items-center gap-2 px-3 py-2 text-left text-[#c9d4e3]"
                      >
                        <span className="text-[#5a6a82]">{hintOpen[h.id] ? "▾" : "▸"}</span>
                        {h.title}
                        <span className="ml-auto shrink-0 text-[#d29922]">{h.unlocked ? "unlocked" : `${h.cost} pts`}</span>
                      </button>
                      {hintOpen[h.id] && (
                        <div className="border-t border-[#1d2532] px-3 py-2 text-[#8b98ac]">
                          {h.unlocked && h.body ? (
                            <p>{h.body}</p>
                          ) : (
                            <button
                              onClick={() => doUnlockHint(h.id, h.cost, h.title)}
                              disabled={!me}
                              className="rounded border border-[#d29922]/60 px-3 py-1.5 text-[#d29922] hover:bg-[#d29922]/10 disabled:opacity-40"
                            >
                              unlock for {h.cost} pts
                            </button>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </Card>
            </>
          )}

          {tab === "writeup" && (
            <Card className="p-5 text-xs leading-6 text-[#c9d4e3]">
              {solved && detail.writeupMd ? (
                renderMd(detail.writeupMd)
              ) : (
                <p className="text-[#d29922]">🔒 solve all flags to unlock the writeup, operator.</p>
              )}
            </Card>
          )}
        </div>
      )}
    </Shell>
  );
}
