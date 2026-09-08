import { createServerFn } from "@tanstack/react-start";
import { deleteCookie, getCookie, setCookie, useSession, getRequestHeaders } from "@tanstack/react-start/server";
import {
  detailChallenge,
  findDynamicFlagOwner,
  getStore,
  matchesDynamicFlag,
  matchFlag,
  summarizeChallenge,
  validateManifest,
} from "~/server/store";
import type {
  Challenge,
  ChallengeCreateInput,
  ChallengeDetail,
  ChallengePatch,
  ChallengeStatus,
  ChallengeSummary,
  ChecklistKey,
  CmsResult,
  CmsSignoffInput,
  InstanceRecord,
  ManifestIssue,
  SafeUser,
  SecurityEvent,
} from "~/server/types";
import {
  extendInstance,
  readInstance,
  reapExpiredInstances,
  resetInstance,
  startInstance,
  stopInstance,
} from "~/server/range-service";

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

/** Best-effort client IP: x-forwarded-for (first hop) then x-real-ip. */
function clientIp(): string | null {
  try {
    const h = getRequestHeaders();
    const fwd = h.get("x-forwarded-for");
    if (fwd) return fwd.split(",")[0].trim() || null;
    return h.get("x-real-ip") || null;
  } catch {
    return null;
  }
}

/** Total hint point cost the user has unlocked on this challenge. */
async function unlockedHintCost(userId: string, slug: string): Promise<number> {
  const store = getStore();
  const c = await store.getChallenge(slug);
  if (!c) return 0;
  const unlocks = await store.getHintUnlocks(userId, slug);
  const unlocked = new Set(unlocks.map((u) => u.hintId));
  return c.hints.filter((h) => unlocked.has(h.id)).reduce((s, h) => s + h.cost, 0);
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

// --- Flags ---
// Scoring engine (backlog item 2):
//  * rate limiting  — max 10 submissions / challenge / user / 60s sliding window
//  * STATIC flags   — original sha256 answerHash check (unchanged behavior)
//  * DYNAMIC flags  — expected value derived per user via HMAC-SHA256:
//      hmac    = HMAC-SHA256(SERVER_SECRET, `${userId}:${challengeSlug}:${flagId}`)
//      expected = "CR{" + hmac-hex.slice(0, 24) + "}"
//      SERVER_SECRET from env (dev fallback in store.ts). The range operator
//      mints the per-player value from the same derivation at provision time,
//      so no per-user plaintext flag is ever stored or shipped to the client.
//  * anti-sharing   — a submitted value that is a valid DYNAMIC flag for a
//      DIFFERENT user (recomputed HMAC) logs SHARING_SUSPECTED and is rejected
//  * brute-force    — >= 8 wrong submissions in 5 min logs BRUTEFORCE_SUSPECTED
//  * NEW_IP_MID_SOLVE — submission IP differing from the user's first IP on the
//      challenge logs an event
//  * points — final flag completes the challenge: awarded = challenge total
//      minus unlocked hint costs; solve stores pointsAwarded, hintsUsed, and
//      timeToSolveSeconds (first instance start; falls back to first submission).

export const submitFlag = createServerFn({ method: "POST" })
  .validator((data: { slug: string; flagId: string; value: string }) => data)
  .handler(async ({ data }): Promise<{
    ok: boolean;
    correct?: boolean;
    already?: boolean;
    error?: string;
    remainingFlags?: number;
    userPoints?: number;
    pointsAwarded?: number;
  }> => {
    const me = await requireUser();
    const store = getStore();
    const ip = clientIp();
    const c = await store.getChallenge(data.slug);
    if (!c) return { ok: false, error: "Unknown challenge." };
    const def = c.flags.find((f) => f.id === data.flagId);
    if (!def) return { ok: false, error: "Unknown flag." };

    // ---- Rate limit (all submissions count, correct or not) ----
    const att = await store.recordSubmissionAttempt(me.user.id, c.slug, false, ip);
    if (att.rateLimited) {
      const secs = Math.max(1, Math.ceil(att.retryAfterMs / 1000));
      return { ok: false, error: `Rate limited — retry after ${secs}s.` };
    }

    // ---- Determine correctness ----
    let correct = false;
    if (def.flagType === "DYNAMIC") {
      correct = matchesDynamicFlag(data.value ?? "", me.user.id, c.slug, def.id);
    } else {
      const matched = matchFlag(c, data.value ?? "");
      correct = !!matched && matched.id === def.id;
    }

    if (!correct) {
      // Recompute the attempt bookkeeping with the true correctness flag so the
      // brute-force window counts only wrong answers.
      await store.recordSubmissionAttempt(me.user.id, c.slug, true, ip);

      // Anti-sharing: is this value a valid DYNAMIC flag for another user?
      const otherOwner = findDynamicFlagOwner(c, def.id, data.value ?? "", me.user.id);
      if (otherOwner) {
        await store.recordSecurityEvent({
          type: "SHARING_SUSPECTED",
          userId: me.user.id,
          challengeSlug: c.slug,
          detail: `Submitted a flag valid for another user (${otherOwner}) on flag ${def.id}.`,
          ip,
          at: Date.now(),
        });
      }

      // Brute force: log exactly once per user+challenge at threshold.
      if (att.bruteForced) {
        const alreadyLogged = (await store.listSecurityEvents(50)).some(
          (e) => e.type === "BRUTEFORCE_SUSPECTED" && e.userId === me.user.id && e.challengeSlug === c.slug
        );
        if (!alreadyLogged) {
          await store.recordSecurityEvent({
            type: "BRUTEFORCE_SUSPECTED",
            userId: me.user.id,
            challengeSlug: c.slug,
            detail: `Repeated wrong submissions (>= 8 in 5 min) on flag ${def.id}.`,
            ip,
            at: Date.now(),
          });
        }
      }

      // NEW_IP_MID_SOLVE: first submission on the challenge came from a different IP.
      if (att.newIpMidSolve) {
        await store.recordSecurityEvent({
          type: "NEW_IP_MID_SOLVE",
          userId: me.user.id,
          challengeSlug: c.slug,
          detail: `Submission from a new IP (${ip ?? "unknown"}) mid-solve.`,
          ip,
          at: Date.now(),
        });
      }

      return { ok: true, correct: false };
    }

    // ---- Correct: record the solve with full scoring metadata ----
    const alreadySolved = (await store.getUserSolves(me.user.id)).some(
      (r) => r.slug === c.slug && r.flagId === def.id
    );
    if (alreadySolved) {
      return { ok: true, correct: true, already: true };
    }

    const hintsUsed = (await store.getHintUnlocks(me.user.id, c.slug)).map((u) => u.hintId);
    const hintCost = await unlockedHintCost(me.user.id, c.slug);
    const flagPoints = def.points;
    // Awarded points = flag value minus ALL hint costs the user unlocked on the
    // challenge (per spec: challenge total minus unlocked hint costs, applied at
    // final-flag solve). MVP: costs apply to the flag that completes the run.
    const pointsAwarded = Math.max(0, flagPoints - hintCost);

    // timeToSolveSeconds: from first instance start; fall back to first submission.
    let base: number | null = null;
    const inst = await store.getInstance(me.user.id, c.slug);
    const now = Date.now();
    if (inst && inst.status === "running" && inst.updatedAt <= now) base = inst.updatedAt;
    if (base === null) {
      const solves = await store.getUserSolves(me.user.id);
      const mine = solves.filter((r) => r.slug === c.slug).sort((a, b) => a.at - b.at);
      if (mine.length > 0) base = mine[0].at;
    }
    const timeToSolveSeconds = base === null ? 0 : Math.max(0, Math.round((now - base) / 1000));

    // Count a correct submission toward the attempt window too (spec counts all submissions).
    await store.recordSubmissionAttempt(me.user.id, c.slug, false, ip);

    const res = await store.submitSolve(me.user.id, c.slug, def.id, {
      pointsAwarded,
      hintsUsed,
      timeToSolveSeconds,
      ip,
    });

    // ---- Remaining flags + refreshed user points ----
    const userTotal = await store.userPoints(me.user.id);
    const captured = new Set((await store.getUserSolves(me.user.id)).filter((r) => r.slug === c.slug).map((r) => r.flagId));
    const remainingFlags = c.flags.filter((f) => !captured.has(f.id)).length;

    return {
      ok: true,
      correct: true,
      already: res.already,
      remainingFlags,
      userPoints: userTotal,
      pointsAwarded,
    };
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

// --- Instance controls (Range API — never Docker) ---------------------------
// Every action goes through ~/server/range (HTTP client) which talks to the
// external Range API (RANGE_API_URL + RANGE_API_KEY) or, by default, the
// in-process mock-range at /mock-range (dev only; ENABLE_MOCK_RANGE=0 turns
// it off). Policy (cap/TTL/extension/reap) lives in ~/server/range-service.

export const getInstance = createServerFn({ method: "GET" })
  .validator((data: { slug: string }) => data)
  .handler(async ({ data }): Promise<{ instance: InstanceRecord | null }> => {
    const me = await currentUser();
    if (!me) return { instance: null };
    return { instance: await readInstance(me.user.id, data.slug) };
  });

export const instanceAction = createServerFn({ method: "POST" })
  .validator((data: { slug: string; action: "start" | "reset" | "extend" | "stop" }) => data)
  .handler(async ({ data }): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> => {
    const me = await requireUser();
    switch (data.action) {
      case "start":
        return startInstance(me.user.id, data.slug);
      case "reset":
        return resetInstance(me.user.id, data.slug);
      case "extend":
        return extendInstance(me.user.id, data.slug);
      case "stop":
        return stopInstance(me.user.id, data.slug);
    }
  });

/** Admin/diagnostic + cron/manual trigger: reap every expired instance. */
export const reapInstances = createServerFn({ method: "POST" }).handler(async (): Promise<{
  ok: boolean;
  reaped: number;
}> => {
  const me = await requireUser();
  if (me.user.role !== "ADMIN") throw new Error("FORBIDDEN");
  return { ok: true, reaped: await reapExpiredInstances() };
});

// --- Admin / scoreboard ------------------------------------------------------

export const adminOverview = createServerFn({ method: "GET" }).handler(async (): Promise<{
  users: SafeUser[];
  recent: Array<{ userId: string; username: string; challengeTitle: string; slug: string; flagId: string; at: number; pointsAwarded: number }>;
  events: SecurityEvent[];
  leaderboard: Array<{ userId: string; username: string; points: number }>;
}> => {
  const me = await requireUser();
  if (me.user.role !== "ADMIN") throw new Error("FORBIDDEN");
  const store = getStore();
  const users = await store.listUsers();
  const leaderboard: Array<{ userId: string; username: string; points: number }> = [];
  for (const u of users) {
    leaderboard.push({ userId: u.id, username: u.username, points: await store.userPoints(u.id) });
  }
  leaderboard.sort((a, b) => b.points - a.points);
  return {
    users,
    recent: await store.recentSolves(20),
    events: await store.listSecurityEvents(50),
    leaderboard,
  };
});

// --- Author CMS (backlog: author CMS) ------------------------------------------
// Role rules:
//  * AUTHOR  — create/update own + submit DRAFT→REVIEW.
//  * VENDOR  — same as AUTHOR but never validate/publish, and sees only own
//    items in the queue (store.listReviewQueue already scopes VENDOR to own).
//  * REVIEWER — read queue + signoff.
//  * ADMIN   — everything.
// CMS mutations themselves are enforced again inside the store (author check,
// signoff checks, lifecycle checks); the function layer applies the role
// pre-checks below and throws FORBIDDEN/UNAUTHORIZED like adminOverview.

const CMS_ROLES = ["AUTHOR", "VENDOR", "REVIEWER", "ADMIN"] as const;

async function requireCmsRole(): Promise<{ user: SafeUser; token: string }> {
  const me = await requireUser();
  if (!CMS_ROLES.includes(me.user.role as (typeof CMS_ROLES)[number])) throw new Error("FORBIDDEN");
  return me;
}

/** Queue view: AUTHOR/VENDOR own scope via listReviewQueue for non-admin; ADMIN all. */
export const cmsList = createServerFn({ method: "GET" }).handler(async (): Promise<{
  challenges: Challenge[];
}> => {
  const me = await requireCmsRole();
  const store = getStore();
  if (me.user.role === "ADMIN") return { challenges: await store.listAllChallenges() };
  return { challenges: await store.listReviewQueue(me.user) };
});

export const cmsGet = createServerFn({ method: "GET" })
  .validator((data: { slug: string }) => data)
  .handler(async ({ data }): Promise<{ challenge: Challenge | null }> => {
    const me = await requireCmsRole();
    const store = getStore();
    const c = await store.getChallenge(data.slug);
    if (!c) return { challenge: null };
    if (me.user.role !== "ADMIN" && me.user.role !== "REVIEWER" && c.createdBy !== me.user.username) {
      throw new Error("FORBIDDEN");
    }
    return { challenge: c };
  });

export const cmsCreate = createServerFn({ method: "POST" })
  .validator((data: { input: ChallengeCreateInput }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    if (me.user.role !== "AUTHOR" && me.user.role !== "VENDOR" && me.user.role !== "ADMIN") {
      throw new Error("FORBIDDEN");
    }
    return getStore().createChallenge(data.input, me.user.username);
  });

export const cmsUpdate = createServerFn({ method: "POST" })
  .validator((data: { slug: string; patch: ChallengePatch }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    if (me.user.role !== "AUTHOR" && me.user.role !== "VENDOR" && me.user.role !== "ADMIN") {
      throw new Error("FORBIDDEN");
    }
    if (me.user.role !== "ADMIN") {
      const cur = await getStore().getChallenge(data.slug);
      if (cur && cur.createdBy !== me.user.username) throw new Error("FORBIDDEN");
    }
    return getStore().updateChallenge(data.slug, data.patch, me.user);
  });

export const cmsTransition = createServerFn({ method: "POST" })
  .validator((data: { slug: string; to: ChallengeStatus }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    if (me.user.role === "AUTHOR" || me.user.role === "VENDOR") {
      // Authors/vendors may only submit their own DRAFT→REVIEW (and retire own).
      if (data.to === "VALIDATED" || data.to === "PUBLISHED") throw new Error("FORBIDDEN");
      if (data.to === "REVIEW") {
        const cur = await getStore().getChallenge(data.slug);
        if (cur && cur.createdBy !== me.user.username) throw new Error("FORBIDDEN");
      }
    }
    return getStore().transitionStatus(data.slug, data.to, me.user);
  });

export const cmsSignoff = createServerFn({ method: "POST" })
  .validator((data: { slug: string; checklist?: Partial<Record<ChecklistKey, boolean>> }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    if (me.user.role !== "REVIEWER" && me.user.role !== "ADMIN") throw new Error("FORBIDDEN");
    const input: CmsSignoffInput = { userId: me.user.id, username: me.user.username, checklist: data.checklist };
    return getStore().addSignoff(data.slug, input, me.user);
  });

export const cmsValidateManifest = createServerFn({ method: "POST" })
  .validator((data: { obj: Record<string, unknown> }) => data)
  .handler(async ({ data }): Promise<{ issues: ManifestIssue[] }> => {
    const me = await requireCmsRole();
    if (me.user.role === "VENDOR") throw new Error("FORBIDDEN");
    return { issues: validateManifest(data.obj) };
  });