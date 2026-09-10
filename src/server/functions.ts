import { createServerFn } from "@tanstack/react-start";
import { deleteCookie, getCookie, setCookie, useSession, getRequestHeaders } from "@tanstack/react-start/server";
import {
  buildAnalytics,
  buildDashboard,
  buildLeaderboard,
  buildPathProgress,
  detailChallenge,
  findDynamicFlagOwner,
  getStore,
  matchesDynamicFlag,
  matchFlag,
  summarizeChallenge,
  validateManifest,
} from "~/server/store";
import type {
  AnalyticsOverview,
  AuditEntry,
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
  LeaderboardData,
  ManifestIssue,
  MyDashboard,
  PathProgress,
  SafeUser,
  SecurityEvent,
  Team,
} from "~/server/types";
import { LEARNING_PATHS } from "~/server/types";
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

// ---------------------------------------------------------------------------
// Hardening (final backlog item).
//
// VALIDATION — zero-dep choice (no zod): TanStack server-function `.validator`
// only echoes the payload, so every mutating function below ALSO runs a strict
// server-side check via `need()`/shape helpers. Rule: unknown fields rejected,
// strings trimmed + length-capped, slugs match kebab-case, enums whitelisted.
// Validators that return `data` unchanged are transport only — the real gate is
// the `v.*` check at the top of each mutating handler.
//
// RATE LIMITS — in-memory per-IP + per-user sliding windows, generic
// `hitRateLimited(key, max, windowMs)` helper (same pattern as the store's
// attempt ledger — see store.recordSubmissionAttempt) one level up so every
// mutating function shares one implementation (single-process MVP; a
// multi-instance deploy moves these counters into Postgres/Redis):
//   login           5 attempts / 60s per IP            (brute-force shield)
//   submitFlag      30 attempts / 60s per user+IP      (on top of the store's
//                     per-challenge 10/60s window)
//   hint unlock     20 attempts / 60s per user
//   instance action 20 attempts / 60s per user
//   cms mutations   20 attempts / 60s per user
// Exceeding a window returns `{ ok:false, error:"Rate limited …" }` (429-style)
// without touching passwords, flags, or the store.
//
// AUDIT LOG — every CMS mutation (create/update/transition/signoff, ok or
// denied), reap, failed login, and rate-limit hit appends
// { actor, action, target, at, ip } via store.recordAudit. ADMIN reads it in
// adminOverview (`audit`) and /admin renders the newest 20.
//
// SECRETS — CRIMSON_SESSION_SECRET, SERVER_SECRET, RANGE_API_URL,
// RANGE_API_KEY all read process.env with DEV-ONLY fallbacks (marked below
// and in README "Environment & secrets"). Prod sets real values; the mock
// range is disabled with ENABLE_MOCK_RANGE=0.
// ---------------------------------------------------------------------------

/** DEV-ONLY fallback marker: prod MUST set CRIMSON_SESSION_SECRET (32+ bytes). */
const DEV_SESSION_SECRET = "crimson-range-mvp-dev-secret-please-rotate";
/** DEV-ONLY fallbacks (README "Environment & secrets"; never real secrets). */
const DEV_LOGIN_WINDOW_MAX = 5;
const LOGIN_WINDOW_MS = 60_000;
const DEV_SUBMIT_WINDOW_MAX = 30;
const SUBMIT_WINDOW_MS = 60_000;
const DEV_HINT_WINDOW_MAX = 20;
const HINT_WINDOW_MS = 60_000;
const DEV_INSTANCE_WINDOW_MAX = 20;
const INSTANCE_WINDOW_MS = 60_000;
const DEV_CMS_WINDOW_MAX = 20;
const CMS_WINDOW_MS = 60_000;

/** Sliding-window hit ledger: key -> timestamps (ms). Single-process MVP. */
const hits = new Map<string, number[]>();

/** Record a hit; true when the key exceeded max hits inside windowMs. */
function hitRateLimited(key: string, max: number, windowMs: number): { limited: boolean; retryAfterMs: number } {
  const now = Date.now();
  const arr = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  if (arr.length >= max) {
    hits.set(key, arr);
    return { limited: true, retryAfterMs: Math.max(0, windowMs - (now - arr[0])) };
  }
  arr.push(now);
  hits.set(key, arr);
  return { limited: false, retryAfterMs: 0 };
}

function rateLimitMsg(retryAfterMs: number): string {
  const secs = Math.max(1, Math.ceil(retryAfterMs / 1000));
  return `Rate limited — retry after ${secs}s.`;
}

// --- Tiny zero-dep validation helpers (no zod — see block comment above) ---

// Spec: ^[a-z0-9-]{1,64}$ — kebab-case, 1..64 chars.
const SLUG_RE = /^[a-z0-9-]{1,64}$/;
const FLAG_ID_RE = /^[A-Za-z0-9_-]+$/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Fail when `obj` carries keys outside `allowed` (whitelist). */
function needNoExtra(obj: Record<string, unknown>, allowed: string[]): string | null {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) return `Unexpected field "${k}".`;
  }
  return null;
}

/** Trimmed string within 1..max chars, else an error message. */
function needStr(v: unknown, max: number, label: string): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof v !== "string") return { ok: false, error: `${label} must be a string.` };
  const t = v.trim();
  if (t.length === 0) return { ok: false, error: `${label} is required.` };
  if (t.length > max) return { ok: false, error: `${label} too long (max ${max}).` };
  return { ok: true, value: t };
}

function needSlug(v: unknown): { ok: true; value: string } | { ok: false; error: string } {
  const r = needStr(v, 64, "slug");
  if (!r.ok) return r;
  if (!SLUG_RE.test(r.value)) return { ok: false, error: "slug must be kebab-case (a-z, 0-9, hyphens)." };
  return r;
}

function needFlagId(v: unknown): { ok: true; value: string } | { ok: false; error: string } {
  const r = needStr(v, 64, "flagId");
  if (!r.ok) return r;
  if (!FLAG_ID_RE.test(r.value)) return { ok: false, error: "flagId has invalid characters." };
  return r;
}

function needFlagValue(v: unknown): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof v !== "string") return { ok: false, error: "value must be a string." };
  const t = v.trim();
  if (t.length === 0) return { ok: false, error: "value is required." };
  if (t.length > 256) return { ok: false, error: "value too long (max 256)." };
  return { ok: true, value: t };
}

/** Integer within [min,max] — bare number, no strings/floats/NaN/Infinity. */
function needInt(v: unknown, min: number, max: number, label: string): { ok: true; value: number } | { ok: false; error: string } {
  if (typeof v !== "number" || !Number.isFinite(v) || !Number.isInteger(v))
    return { ok: false, error: `${label} must be an integer.` };
  if (v < min || v > max) return { ok: false, error: `${label} out of range (${min}..${max}).` };
  return { ok: true, value: v };
}

/** Non-empty array with at most maxLen items. */
function needArr(v: unknown, maxLen: number, label: string): { ok: true; value: unknown[] } | { ok: false; error: string } {
  if (!Array.isArray(v)) return { ok: false, error: `${label} must be an array.` };
  if (v.length > maxLen) return { ok: false, error: `${label} too many items (max ${maxLen}).` };
  return { ok: true, value: v };
}

/** String whitelisted against a fixed enum. */
function needOneOf(v: unknown, allowed: readonly string[], label: string): { ok: true; value: string } | { ok: false; error: string } {
  if (typeof v !== "string" || !allowed.includes(v)) return { ok: false, error: `${label} must be one of: ${allowed.join(", ")}.` };
  return { ok: true, value: v };
}

// --- CMS field rules (shared by cmsCreate input + cmsUpdate patch) ---
const CATEGORIES = ["AI Red-Team", "Active Directory", "Web/API", "Cloud", "Kill-Chain"] as const;
const DIFFICULTIES = ["Easy", "Medium", "Hard", "Insane"] as const;
const FLAG_TYPES = ["STATIC", "DYNAMIC"] as const;
const CREATE_KEYS = [
  "slug", "title", "category", "difficulty", "descriptionMd", "objectives", "mitre", "cves",
  "tags", "flags", "hints", "artifacts", "writeupMd", "instanceType", "cpuLimit", "memLimit", "author",
] as const;
const CREATE_REQUIRED = [
  "title", "category", "difficulty", "descriptionMd", "objectives", "flags",
  "instanceType", "cpuLimit", "memLimit", "author",
] as const;

/**
 * Validate a CMS object (create input or update patch) against fixed rules:
 * strings trimmed + length-capped, numbers range-capped, enums whitelisted,
 * nested arrays bounded. Read-only; returns a user-safe error string or null.
 * Unknown keys are rejected separately by needNoExtra.
 */
function validateCmsBody(b: Record<string, unknown>, required: readonly string[]): string | null {
  for (const k of required) if (b[k] === undefined) return `Missing required field "${k}".`;

  const strErr = (k: string, max: number): string | null => {
    if (b[k] === undefined) return null;
    const r = needStr(b[k], max, k);
    return r.ok ? null : r.error;
  };
  const intErr = (k: string, min: number, max: number, nullable = false): string | null => {
    if (b[k] === undefined || (nullable && b[k] === null)) return null;
    const r = needInt(b[k], min, max, k);
    return r.ok ? null : r.error;
  };
  const oneOfErr = (k: string, allowed: readonly string[]): string | null => {
    if (b[k] === undefined) return null;
    const r = needOneOf(b[k], allowed, k);
    return r.ok ? null : r.error;
  };
  const strArrErr = (k: string, maxLen: number, itemMax: number): string | null => {
    if (b[k] === undefined) return null;
    const r = needArr(b[k], maxLen, k);
    if (!r.ok) return r.error;
    for (const it of r.value) {
      const rr = needStr(it, itemMax, `${k}[]`);
      if (!rr.ok) return rr.error;
    }
    return null;
  };
  // Nested object arrays: fields = { name: { cap } | { type: "int", min, max } }.
  const objectsErr = (
    k: string,
    maxLen: number,
    fields: Record<string, { cap?: number; type?: "int"; min?: number; max?: number }>,
  ): string | null => {
    if (b[k] === undefined) return null;
    const r = needArr(b[k], maxLen, k);
    if (!r.ok) return r.error;
    for (const it of r.value) {
      if (!isPlainObject(it)) return `${k}: each item must be an object.`;
      for (const [fk, rule] of Object.entries(fields)) {
        if (it[fk] === undefined) continue;
        if (rule.type === "int") {
          const rr = needInt(it[fk], rule.min ?? 0, rule.max ?? 1_000_000, `${k}[].${fk}`);
          if (!rr.ok) return rr.error;
        } else {
          const rr = needStr(it[fk], rule.cap ?? 200, `${k}[].${fk}`);
          if (!rr.ok) return rr.error;
        }
      }
    }
    return null;
  };
  const flagsErr = (): string | null => {
    if (b.flags === undefined) return null;
    const r = needArr(b.flags, 12, "flags");
    if (!r.ok) return r.error;
    for (const it of r.value) {
      if (!isPlainObject(it)) return "flags: each flag must be an object.";
      const id = needFlagId(it.id);
      if (!id.ok) return id.error;
      const name = needStr(it.name, 120, "flag name");
      if (!name.ok) return name.error;
      const pts = needInt(it.points, 0, 100_000, "flag points");
      if (!pts.ok) return pts.error;
      const ft = needOneOf(it.flagType, FLAG_TYPES, "flagType");
      if (!ft.ok) return ft.error;
      if (it.answerHash !== undefined) {
        const ah = needStr(it.answerHash, 128, "answerHash");
        if (!ah.ok) return ah.error;
      }
    }
    return null;
  };

  return (
    strErr("title", 120) ?? strErr("descriptionMd", 50_000) ?? strErr("writeupMd", 100_000) ??
    strErr("instanceType", 40) ?? strErr("cpuLimit", 16) ?? strErr("memLimit", 16) ??
    strErr("author", 64) ?? oneOfErr("category", CATEGORIES) ?? oneOfErr("difficulty", DIFFICULTIES) ??
    intErr("pointsOverride", 0, 1_000_000, true) ?? intErr("instanceTtlMinutes", 5, 1440) ??
    strArrErr("objectives", 12, 500) ?? strArrErr("tags", 24, 64) ??
    objectsErr("mitre", 8, { id: { cap: 64 }, tactic: { cap: 200 } }) ??
    objectsErr("cves", 8, { id: { cap: 128 }, note: { cap: 500 } }) ??
    objectsErr("artifacts", 12, { name: { cap: 120 }, kind: { cap: 40 }, size: { cap: 16 }, url: { cap: 500 } }) ??
    objectsErr("hints", 12, { id: { cap: 64 }, title: { cap: 120 }, body: { cap: 2000 }, cost: { type: "int", min: 0, max: 10_000 } }) ??
    flagsErr()
  );
}

/** Append an audit entry (actor/action/target/ip). Never carries flag values. */
async function audit(actor: string, action: string, target: string, ip: string | null): Promise<void> {
  try {
    await getStore().recordAudit({ at: Date.now(), actor, action, target, ip });
  } catch {
    /* audit is best-effort — never break the request path */
  }
}

function sessionConfig() {
  return {
    // MVP demo secret — Phase 2 reads a 32+ byte secret from env.
    password: process.env.CRIMSON_SESSION_SECRET ?? DEV_SESSION_SECRET,
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
    const ip = clientIp();
    // Per-IP brute-force shield (before any credential work).
    const rl = hitRateLimited(`login:${ip ?? "unknown"}`, DEV_LOGIN_WINDOW_MAX, LOGIN_WINDOW_MS);
    if (rl.limited) {
      await audit("anonymous", "auth.login.ratelimited", (data as Record<string, unknown>)?.username as string ?? "?", ip);
      return { ok: false, error: rateLimitMsg(rl.retryAfterMs) };
    }
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const extra = needNoExtra(data as unknown as Record<string, unknown>, ["username", "password"]);
    if (extra) return { ok: false, error: extra };
    const u = needStr((data as { username: unknown }).username, 64, "username");
    if (!u.ok) return { ok: false, error: u.error };
    const pw = (data as { password: unknown }).password;
    if (typeof pw !== "string" || pw.length === 0 || pw.length > 256)
      return { ok: false, error: "Invalid username or password." };
    const store = getStore();
    const record = await store.findUserByUsername(u.value);
    if (!record || !store.verifyPassword(record, pw)) {
      await audit("anonymous", "auth.login.failed", u.value, ip);
      return { ok: false, error: "Invalid username or password." };
    }
    const session = await store.createSession(record.id);
    // Keep the framework session cookie in sync (defense in depth); the
    // store record is the authority.
    const mgr = await useSession(sessionConfig());
    await mgr.update({ uid: record.id });
    setCookie(COOKIE, session.token, { httpOnly: true, sameSite: "lax", path: "/", maxAge: 7 * 24 * 3600 });
    return { ok: true, user: { id: record.id, username: record.username, role: record.role, teamId: record.teamId ?? null } };
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
  .validator((data: { slug: string }) => {
    if (!data || typeof data.slug !== "string") return { slug: "" };
    const t = data.slug.trim().slice(0, 64);
    return { slug: SLUG_RE.test(t) ? t : "" };
  })
  .handler(async ({ data }): Promise<{ challenge: ChallengeDetail | null }> => {
    if (!data.slug) return { challenge: null };
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
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const extra = needNoExtra(data as unknown as Record<string, unknown>, ["slug", "flagId", "value"]);
    if (extra) return { ok: false, error: extra };
    const slug = needSlug((data as { slug: unknown }).slug);
    if (!slug.ok) return { ok: false, error: slug.error };
    const flagId = needFlagId((data as { flagId: unknown }).flagId);
    if (!flagId.ok) return { ok: false, error: flagId.error };
    const value = needFlagValue((data as { value: unknown }).value);
    if (!value.ok) return { ok: true, correct: false };
    // Function-level burst shield (per user+IP) on top of the store's
    // per-challenge 10/60s window enforced below.
    const frl = hitRateLimited(`submit:${me.user.id}:${ip ?? "unknown"}`, DEV_SUBMIT_WINDOW_MAX, SUBMIT_WINDOW_MS);
    if (frl.limited) return { ok: false, error: rateLimitMsg(frl.retryAfterMs) };
    (data as { slug: string; flagId: string; value: string }).slug = slug.value;
    (data as { slug: string; flagId: string; value: string }).flagId = flagId.value;
    (data as { slug: string; flagId: string; value: string }).value = value.value;
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
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const hextra = needNoExtra(data as unknown as Record<string, unknown>, ["slug", "hintId"]);
    if (hextra) return { ok: false, error: hextra };
    const hslug = needSlug((data as { slug: unknown }).slug);
    if (!hslug.ok) return { ok: false, error: hslug.error };
    const hintId = needStr((data as { hintId: unknown }).hintId, 64, "hintId");
    if (!hintId.ok) return { ok: false, error: hintId.error };
    const hrl = hitRateLimited(`hint:${me.user.id}`, DEV_HINT_WINDOW_MAX, HINT_WINDOW_MS);
    if (hrl.limited) return { ok: false, error: rateLimitMsg(hrl.retryAfterMs) };
    const c = await store.getChallenge(hslug.value);
    if (!c) return { ok: false, error: "Unknown challenge." };
    if (!c.hints.some((h) => h.id === hintId.value)) return { ok: false, error: "Unknown hint." };
    (data as { slug: string; hintId: string }).slug = hslug.value;
    (data as { slug: string; hintId: string }).hintId = hintId.value;
    await store.unlockHint(me.user.id, data.slug, data.hintId);
    return { ok: true };
  });

// --- Instance controls (Range API — never Docker) ---------------------------
// Every action goes through ~/server/range (HTTP client) which talks to the
// external Range API (RANGE_API_URL + RANGE_API_KEY) or, by default, the
// in-process mock-range at /mock-range (dev only; ENABLE_MOCK_RANGE=0 turns
// it off). Policy (cap/TTL/extension/reap) lives in ~/server/range-service.

export const getInstance = createServerFn({ method: "GET" })
  .validator((data: { slug: string }) => {
    if (!data || typeof data.slug !== "string") return { slug: "" };
    const t = data.slug.trim().slice(0, 64);
    return { slug: SLUG_RE.test(t) ? t : "" };
  })
  .handler(async ({ data }): Promise<{ instance: InstanceRecord | null }> => {
    if (!data.slug) return { instance: null };
    const me = await currentUser();
    if (!me) return { instance: null };
    return { instance: await readInstance(me.user.id, data.slug) };
  });

export const instanceAction = createServerFn({ method: "POST" })
  .validator((data: { slug: string; action: "start" | "reset" | "extend" | "stop" }) => data)
  .handler(async ({ data }): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> => {
    const me = await requireUser();
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const iextra = needNoExtra(data as unknown as Record<string, unknown>, ["slug", "action"]);
    if (iextra) return { ok: false, error: iextra };
    const islug = needSlug((data as { slug: unknown }).slug);
    if (!islug.ok) return { ok: false, error: islug.error };
    const action = (data as { action: unknown }).action;
    if (action !== "start" && action !== "reset" && action !== "extend" && action !== "stop")
      return { ok: false, error: "Unknown action." };
    const irl = hitRateLimited(`instance:${me.user.id}`, DEV_INSTANCE_WINDOW_MAX, INSTANCE_WINDOW_MS);
    if (irl.limited) return { ok: false, error: rateLimitMsg(irl.retryAfterMs) };
    (data as { slug: string }).slug = islug.value;
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
  const reaped = await reapExpiredInstances();
  await audit(me.user.username, "admin.reap", `${reaped} expired`, clientIp());
  return { ok: true, reaped };
});

// --- Admin / scoreboard ------------------------------------------------------

export const adminOverview = createServerFn({ method: "GET" }).handler(async (): Promise<{
  users: SafeUser[];
  recent: Array<{ userId: string; username: string; challengeTitle: string; slug: string; flagId: string; at: number; pointsAwarded: number }>;
  events: SecurityEvent[];
  leaderboard: Array<{ userId: string; username: string; points: number }>;
  audit: AuditEntry[];
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
    audit: await store.listAudit(100),
  };
});

// --- Engagement layer (backlog: leaderboards + paths + dashboard + analytics) ---

export const leaderboardData = createServerFn({ method: "GET" }).handler(async (): Promise<LeaderboardData> => {
  return buildLeaderboard(getStore());
});

export const pathList = createServerFn({ method: "GET" }).handler(async (): Promise<{
  paths: Array<{ slug: string; title: string; blurb: string; totalSteps: number; steps: string[] }>;
}> => {
  return {
    paths: LEARNING_PATHS.map((p) => ({
      slug: p.slug,
      title: p.title,
      blurb: p.blurb,
      totalSteps: p.steps.length,
      steps: [...p.steps],
    })),
  };
});

export const pathProgress = createServerFn({ method: "GET" })
  .validator((data: { slug: string }) => {
    if (!data || typeof data.slug !== "string") return { slug: "" };
    const t = data.slug.trim().slice(0, 64);
    return { slug: SLUG_RE.test(t) ? t : "" };
  })
  .handler(async ({ data }): Promise<{ path: PathProgress | null }> => {
    if (!data.slug) return { path: null };
    const def = LEARNING_PATHS.find((p) => p.slug === data.slug) ?? null;
    if (!def) return { path: null };
    const me = await currentUser();
    // Anonymous viewers see the path skeleton with every step locked.
    if (!me) {
      const store = getStore();
      const challenges = await store.listChallenges();
      const byId = new Map(challenges.map((c) => [c.slug, c]));
      const steps = def.steps
        .map((slug) => byId.get(slug))
        .filter((c): c is Challenge => !!c)
        .map((c, i) => ({
          slug: c.slug,
          title: c.title,
          category: c.category,
          difficulty: c.difficulty,
          points: c.flags.reduce((s, f) => s + (f.points ?? 0), 0),
          state: (i === 0 ? "unlocked" : "locked") as PathProgress["steps"][number]["state"],
        }));
      return {
        path: {
          slug: def.slug,
          title: def.title,
          blurb: def.blurb,
          totalSteps: steps.length,
          solvedSteps: 0,
          pct: 0,
          complete: false,
          steps,
        },
      };
    }
    return { path: await buildPathProgress(getStore(), me.user.id, def) };
  });

export const myDashboard = createServerFn({ method: "GET" }).handler(async (): Promise<{
  dashboard: MyDashboard | null;
}> => {
  const me = await requireUser();
  return { dashboard: await buildDashboard(getStore(), me.user.id) };
});

export const listTeams = createServerFn({ method: "GET" }).handler(async (): Promise<{ teams: Team[] }> => {
  return { teams: await getStore().listTeams() };
});

export const analyticsOverview = createServerFn({ method: "GET" }).handler(async (): Promise<AnalyticsOverview> => {
  const me = await requireUser();
  if (me.user.role !== "ADMIN") throw new Error("FORBIDDEN");
  return buildAnalytics(getStore());
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
  .validator((data: { slug: string }) => {
    if (!data || typeof data.slug !== "string") return { slug: "" };
    const t = data.slug.trim().slice(0, 64);
    return { slug: SLUG_RE.test(t) ? t : "" };
  })
  .handler(async ({ data }): Promise<{ challenge: Challenge | null }> => {
    if (!data.slug) return { challenge: null };
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
    const ip = clientIp();
    const crl = hitRateLimited(`cms:${me.user.id}`, DEV_CMS_WINDOW_MAX, CMS_WINDOW_MS);
    if (crl.limited) {
      await audit(me.user.username, "cms.ratelimited", "create", ip);
      return { ok: false, error: rateLimitMsg(crl.retryAfterMs) };
    }
    if (me.user.role !== "AUTHOR" && me.user.role !== "VENDOR" && me.user.role !== "ADMIN") {
      await audit(me.user.username, "cms.create.denied", "forbidden-role", ip);
      throw new Error("FORBIDDEN");
    }
    if (!isPlainObject(data as unknown as Record<string, unknown>) || !isPlainObject((data as { input: unknown }).input as Record<string, unknown>)) {
      return { ok: false, error: "Invalid request shape." };
    }
    const input = (data as { input: unknown }).input as Record<string, unknown>;
    const iextra = needNoExtra(input, CREATE_KEYS);
    if (iextra) return { ok: false, error: iextra };
    const ierr = validateCmsBody(input, CREATE_REQUIRED);
    if (ierr) return { ok: false, error: ierr };
    const res = await getStore().createChallenge(data.input, me.user.username);
    await audit(me.user.username, res.ok ? "cms.create" : "cms.create.failed", res.challenge?.slug ?? "?", ip);
    return res;
  });

export const cmsUpdate = createServerFn({ method: "POST" })
  .validator((data: { slug: string; patch: ChallengePatch }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    const ip = clientIp();
    const crl = hitRateLimited(`cms:${me.user.id}`, DEV_CMS_WINDOW_MAX, CMS_WINDOW_MS);
    if (crl.limited) {
      await audit(me.user.username, "cms.ratelimited", "update", ip);
      return { ok: false, error: rateLimitMsg(crl.retryAfterMs) };
    }
    if (me.user.role !== "AUTHOR" && me.user.role !== "VENDOR" && me.user.role !== "ADMIN") {
      await audit(me.user.username, "cms.update.denied", "forbidden-role", ip);
      throw new Error("FORBIDDEN");
    }
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const uslug = needSlug((data as { slug: unknown }).slug);
    if (!uslug.ok) return { ok: false, error: uslug.error };
    const patch = (data as { patch: unknown }).patch;
    if (!isPlainObject(patch as Record<string, unknown>)) return { ok: false, error: "patch must be an object." };
    const pextra = needNoExtra(patch as Record<string, unknown>, ["title","category","difficulty","descriptionMd","objectives","mitre","cves","tags","flags","hints","artifacts","writeupMd","pointsOverride","instanceType","cpuLimit","memLimit","instanceTtlMinutes","author","checklist"]);
    if (pextra) return { ok: false, error: pextra };
    const perr = validateCmsBody(patch as Record<string, unknown>, []);
    if (perr) return { ok: false, error: perr };
    if (me.user.role !== "ADMIN") {
      const cur = await getStore().getChallenge(uslug.value);
      if (cur && cur.createdBy !== me.user.username) {
        await audit(me.user.username, "cms.update.denied", uslug.value, ip);
        throw new Error("FORBIDDEN");
      }
    }
    const res = await getStore().updateChallenge(uslug.value, patch as ChallengePatch, me.user);
    await audit(me.user.username, res.ok ? "cms.update" : "cms.update.failed", uslug.value, ip);
    return res;
  });

export const cmsTransition = createServerFn({ method: "POST" })
  .validator((data: { slug: string; to: ChallengeStatus }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    const ip = clientIp();
    const crl = hitRateLimited(`cms:${me.user.id}`, DEV_CMS_WINDOW_MAX, CMS_WINDOW_MS);
    if (crl.limited) {
      await audit(me.user.username, "cms.ratelimited", "transition", ip);
      return { ok: false, error: rateLimitMsg(crl.retryAfterMs) };
    }
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const tslug = needSlug((data as { slug: unknown }).slug);
    if (!tslug.ok) return { ok: false, error: tslug.error };
    const to = (data as { to: unknown }).to;
    const STATES = ["DRAFT", "REVIEW", "VALIDATED", "PUBLISHED", "RETIRED"];
    if (typeof to !== "string" || !STATES.includes(to)) return { ok: false, error: "Unknown target status." };
    if (me.user.role === "AUTHOR" || me.user.role === "VENDOR") {
      // Authors/vendors may only submit their own DRAFT→REVIEW (and retire own).
      if (to === "VALIDATED" || to === "PUBLISHED") {
        await audit(me.user.username, "cms.transition.denied", tslug.value, ip);
        throw new Error("FORBIDDEN");
      }
      if (to === "REVIEW") {
        const cur = await getStore().getChallenge(tslug.value);
        if (cur && cur.createdBy !== me.user.username) {
          await audit(me.user.username, "cms.transition.denied", tslug.value, ip);
          throw new Error("FORBIDDEN");
        }
      }
    }
    const res = await getStore().transitionStatus(tslug.value, to as ChallengeStatus, me.user);
    await audit(me.user.username, res.ok ? `cms.transition.${to}` : "cms.transition.failed", tslug.value, ip);
    return res;
  });

export const cmsSignoff = createServerFn({ method: "POST" })
  .validator((data: { slug: string; checklist?: Partial<Record<ChecklistKey, boolean>> }) => data)
  .handler(async ({ data }): Promise<CmsResult> => {
    const me = await requireCmsRole();
    const ip = clientIp();
    const crl = hitRateLimited(`cms:${me.user.id}`, DEV_CMS_WINDOW_MAX, CMS_WINDOW_MS);
    if (crl.limited) {
      await audit(me.user.username, "cms.ratelimited", "signoff", ip);
      return { ok: false, error: rateLimitMsg(crl.retryAfterMs) };
    }
    if (me.user.role !== "REVIEWER" && me.user.role !== "ADMIN") {
      await audit(me.user.username, "cms.signoff.denied", "forbidden-role", ip);
      throw new Error("FORBIDDEN");
    }
    if (!isPlainObject(data as unknown as Record<string, unknown>)) return { ok: false, error: "Invalid request shape." };
    const sslug = needSlug((data as { slug: unknown }).slug);
    if (!sslug.ok) return { ok: false, error: sslug.error };
    const checklist = (data as { checklist: unknown }).checklist;
    if (checklist !== undefined && !isPlainObject(checklist as Record<string, unknown>))
      return { ok: false, error: "checklist must be an object." };
    const input: CmsSignoffInput = { userId: me.user.id, username: me.user.username, checklist: checklist as CmsSignoffInput["checklist"] };
    const res = await getStore().addSignoff(sslug.value, input, me.user);
    await audit(me.user.username, res.ok ? "cms.signoff" : "cms.signoff.failed", sslug.value, ip);
    return res;
  });

export const cmsValidateManifest = createServerFn({ method: "POST" })
  .validator((data: { obj: Record<string, unknown> }) => data)
  .handler(async ({ data }): Promise<{ issues: ManifestIssue[] }> => {
    const me = await requireCmsRole();
    if (me.user.role === "VENDOR") throw new Error("FORBIDDEN");
    if (!isPlainObject(data as unknown as Record<string, unknown>) || !isPlainObject((data as { obj: unknown }).obj as Record<string, unknown>))
      return { issues: [{ field: "obj", message: "obj must be an object." }] };
    return { issues: validateManifest((data as { obj: Record<string, unknown> }).obj) };
  });