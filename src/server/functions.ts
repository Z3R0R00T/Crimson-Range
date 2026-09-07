import { createServerFn } from "@tanstack/react-start";
import { deleteCookie, getCookie, setCookie, useSession } from "@tanstack/react-start/server";
import {
  detailChallenge,
  getStore,
  hashFlag,
  matchFlag,
  summarizeChallenge,
  type ChallengeDetail,
  type ChallengeSummary,
  type InstanceRecord,
  type SafeUser,
} from "~/server/store";

// ---------------------------------------------------------------------------
// Sessions are server-side records in the store; the browser only holds an
// opaque random token cookie (`cr_session`). No localStorage anywhere.
// ---------------------------------------------------------------------------

const COOKIE = "cr_session";

function sessionConfig() {
  return {
    // MVP demo secret — Phase 2 reads a 32+ byte secret from env.
    password: process.env.CRIMSON_SESSION_SECRET ?? "crimson-range-mvp-dev-secret-please-rotate",
    name: COOKIE,
    cookie: { httpOnly: true, sameSite: "lax" as const, path: "/", maxAge: 7 * 24 * 3600 },
  };
}

async function currentUser(): Promise<{ user: SafeUser; token: string } | null> {
  const token = getCookie(COOKIE);
  if (!token) return null;
  const store = getStore();
  const rec = await store.getSession(token);
  if (!rec) return null;
  const user = await store.getSafeUser(rec.userId);
  if (!user) return null;
  return { user, token };
}

async function requireUser(): Promise<{ user: SafeUser; token: string }> {
  const me = await currentUser();
  if (!me) throw new Error("UNAUTHORIZED");
  return me;
}

// --- Auth ------------------------------------------------------------------

export const getMe = createServerFn({ method: "GET" }).handler(async (): Promise<{ user: SafeUser | null }> => {
  const me = await currentUser();
  return { user: me ? me.user : null };
});

export const login = createServerFn({ method: "POST" })
  .validator((data: { username: string; password: string }) => data)
  .handler(async ({ data }): Promise<{ ok: boolean; user?: SafeUser; error?: string }> => {
    const store = getStore();
    const record = await store.findUserByUsername((data.username ?? "").trim());
    if (!record || !store.verifyPassword(record, data.password ?? "")) {
      return { ok: false, error: "Invalid username or password." };
    }
    const session = await store.createSession(record.id);
    // Keep the framework session cookie in sync (defense in depth); the
    // store record is the authority.
    const mgr = await useSession(sessionConfig());
    await mgr.update({ uid: record.id });
    setCookie(COOKIE, session.token, { httpOnly: true, sameSite: "lax", path: "/", maxAge: 7 * 24 * 3600 });
    return { ok: true, user: { id: record.id, username: record.username, role: record.role } };
  });

export const logout = createServerFn({ method: "POST" }).handler(async (): Promise<{ ok: boolean }> => {
  const token = getCookie(COOKIE);
  if (token) await getStore().destroySession(token);
  const mgr = await useSession(sessionConfig());
  await mgr.clear();
  deleteCookie(COOKIE);
  return { ok: true };
});

// --- Challenges --------------------------------------------------------------

export const listChallengeSummaries = createServerFn({ method: "GET" }).handler(async (): Promise<{
  challenges: ChallengeSummary[];
}> => {
  const store = getStore();
  const me = await currentUser();
  const all = await store.listChallenges();
  const challenges: ChallengeSummary[] = [];
  for (const c of all) challenges.push(await summarizeChallenge(store, c, me ? me.user.id : null));
  return { challenges };
});

export const getChallengeDetail = createServerFn({ method: "GET" })
  .validator((data: { slug: string }) => data)
  .handler(async ({ data }): Promise<{ challenge: ChallengeDetail | null }> => {
    const store = getStore();
    const c = await store.getChallenge(data.slug);
    if (!c) return { challenge: null };
    const me = await currentUser();
    return { challenge: await detailChallenge(store, c, me ? me.user.id : null) };
  });

// --- Flags (stub server-side check against seed answers) ---------------------

export const submitFlag = createServerFn({ method: "POST" })
  .validator((data: { slug: string; flagId: string; value: string }) => data)
  .handler(async ({ data }): Promise<{ ok: boolean; correct?: boolean; already?: boolean; error?: string }> => {
    const me = await requireUser();
    const store = getStore();
    const c = await store.getChallenge(data.slug);
    if (!c) return { ok: false, error: "Unknown challenge." };
    const def = c.flags.find((f) => f.id === data.flagId);
    if (!def) return { ok: false, error: "Unknown flag." };
    const matched = matchFlag(c, data.value ?? "");
    if (!matched || matched.id !== def.id) {
      // Timing-safe comparison happens inside matchFlag; a wrong flag for
      // this slot is simply incorrect (no cross-slot credit).
      void hashFlag(data.value ?? "");
      return { ok: true, correct: false };
    }
    const res = await store.submitSolve(me.user.id, c.slug, def.id);
    return { ok: true, correct: true, already: res.already };
  });

// --- Hints -------------------------------------------------------------------

export const unlockHint = createServerFn({ method: "POST" })
  .validator((data: { slug: string; hintId: string }) => data)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const me = await requireUser();
    const store = getStore();
    const c = await store.getChallenge(data.slug);
    if (!c) return { ok: false, error: "Unknown challenge." };
    if (!c.hints.some((h) => h.id === data.hintId)) return { ok: false, error: "Unknown hint." };
    await store.unlockHint(me.user.id, data.slug, data.hintId);
    return { ok: true };
  });

// --- Instance controls (STUB — no Docker; fake state for MVP) ----------------
// Phase 2 implements these against the Range API contract (BRD §6).

const STUB_TTL_MS = 2 * 3600_000;

function stubEndpoint(slug: string, userId: string): string {
  const short = userId.replace(/[^a-z0-9]/gi, "").slice(0, 6).toLowerCase() || "op";
  return `https://stub-${slug.slice(0, 12)}-${short}.range.local:8443`;
}

export const getInstance = createServerFn({ method: "GET" })
  .validator((data: { slug: string }) => data)
  .handler(async ({ data }): Promise<{ instance: InstanceRecord | null }> => {
    const me = await currentUser();
    if (!me) return { instance: null };
    return { instance: await getStore().getInstance(me.user.id, data.slug) };
  });

export const instanceAction = createServerFn({ method: "POST" })
  .validator((data: { slug: string; action: "start" | "reset" | "extend" | "stop" }) => data)
  .handler(async ({ data }): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> => {
    const me = await requireUser();
    const store = getStore();
    const c = await store.getChallenge(data.slug);
    if (!c) return { ok: false, error: "Unknown challenge." };
    const now = Date.now();
    const prev = await store.getInstance(me.user.id, data.slug);
    let rec: InstanceRecord;
    switch (data.action) {
      case "start":
        rec = {
          userId: me.user.id,
          slug: data.slug,
          status: "running",
          endpoint: stubEndpoint(data.slug, me.user.id),
          expiresAt: now + STUB_TTL_MS,
          updatedAt: now,
          note: "STUB — no container provisioned. Phase 2 wires this to the Range API.",
        };
        break;
      case "reset":
        if (!prev || prev.status !== "running") return { ok: false, error: "No running instance to reset." };
        rec = { ...prev, expiresAt: now + STUB_TTL_MS, updatedAt: now, note: "STUB — reset simulated." };
        break;
      case "extend":
        if (!prev || prev.status !== "running") return { ok: false, error: "No running instance to extend." };
        rec = { ...prev, expiresAt: (prev.expiresAt ?? now) + STUB_TTL_MS, updatedAt: now, note: "STUB — extended +2h (fake)." };
        break;
      case "stop":
        if (!prev) return { ok: false, error: "No instance to stop." };
        rec = { ...prev, status: "stopped", endpoint: null, expiresAt: null, updatedAt: now, note: "STUB — stopped (fake)." };
        break;
    }
    await store.setInstance(rec);
    return { ok: true, instance: rec };
  });

// --- Admin / scoreboard ------------------------------------------------------

export const adminOverview = createServerFn({ method: "GET" }).handler(async (): Promise<{
  users: SafeUser[];
  recent: Array<{ userId: string; username: string; challengeTitle: string; slug: string; flagId: string; at: number }>;
}> => {
  const me = await requireUser();
  if (me.user.role !== "ADMIN") throw new Error("FORBIDDEN");
  const store = getStore();
  return { users: await store.listUsers(), recent: await store.recentSolves(20) };
});
