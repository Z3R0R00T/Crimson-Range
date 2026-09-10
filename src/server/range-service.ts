// ---------------------------------------------------------------------------
// Crimson Range — range layer core (server-only).
//
// Policy + orchestration around the Range API contract. The portal NEVER
// touches Docker — every instance action goes through `~/server/range`
// (HTTP client) which points at the external Range API (`RANGE_API_URL`, with
// `RANGE_API_KEY` auth) or, by default, at the in-process mock-range
// (`/mock-range`, dev-only; disabled via `ENABLE_MOCK_RANGE=0`).
//
// Rules enforced here:
//   * max 2 concurrent RUNNING instances per user
//   * TTL comes from the challenge manifest (`instanceTtlMinutes`); fallback 2h
//   * ONE 30-minute extension per instance (`extended` flag; second is rejected)
//   * reap expanded instances on every read (status -> stopped, endpoint dropped)
//   * DYNAMIC flags come from the range (mock mints them from the same HMAC
//     derivation as store.ts `dynamicFlagValue`); STATIC flags stay portal-side.
//
// This module is node-only and must never be imported by client code.
// ---------------------------------------------------------------------------

import { getStore, dynamicFlagValue } from "~/server/store";
import { rangeClient, rangeUrl } from "~/server/range";
// LIVE in-process labs: bola-invoice-api's instance carries the real API base
// URL + bearer token (LabAccess) so the player gets a genuine target.
import { labAccessFor } from "~/server/labs/invoice-api";
import type { Challenge, InstanceRecord, RangeApi, RangeInstance } from "~/server/types";

/** Challenges served in-process under /api/labs/<slug> get a LabAccess block. */
const LABS_BY_SLUG: Record<string, (userId: string) => { baseUrl: string; token: string }> = {
  "bola-invoice-api": labAccessFor,
};

/** Max simultaneously RUNNING instances per user (portal-enforced hard cap). */
export const MAX_RUNNING_INSTANCES = 2;
/** Fallback TTL when the challenge manifest omits `instanceTtlMinutes`. */
export const DEFAULT_TTL_MINUTES = 120;
/** The one allowed extension length. */
export const EXTENSION_MINUTES = 30;

export function instanceTtlMinutes(c: Challenge): number {
  return typeof c.instanceTtlMinutes === "number" && c.instanceTtlMinutes > 0
    ? Math.round(c.instanceTtlMinutes)
    : DEFAULT_TTL_MINUTES;
}

function toEndpointString(e: { kind: string; host: string; port: number }): string {
  return `${e.host}:${e.port}`;
}

/** Compact portal projection of a range instance (never exposes flag values). */
function toInstanceRecord(
  userId: string,
  slug: string,
  ri: RangeInstance,
  extra?: { extended?: boolean; startedAt?: number }
): InstanceRecord {
  const now = Date.now();
  return {
    userId,
    slug,
    status: ri.status === "running" ? "running" : "stopped",
    endpoint: ri.endpoints.length ? toEndpointString(ri.endpoints[0]) : null,
    expiresAt: ri.expires_at,
    updatedAt: extra?.startedAt ?? now,
    note: "range api",
    rangeInstanceId: ri.instance_id,
    extended: extra?.extended ?? false,
  };
}

async function listInstances(userId: string): Promise<InstanceRecord[]> {
  const s = getStore();
  const all = await s.listChallenges();
  const out: InstanceRecord[] = [];
  for (const c of all) {
    const rec = await s.getInstance(userId, c.slug);
    if (rec) out.push(rec);
  }
  return out;
}

/**
 * Reap: expire instances whose Range API TTL has passed. Called on every
 * instance read (getInstance) and before every action. Also intended as a
 * manual/cron trigger: `reapExpiredInstances()` exported below iterates ALL
 * users' instances.
 */
async function reapFor(userId: string): Promise<void> {
  const s = getStore();
  const now = Date.now();
  for (const rec of await listInstances(userId)) {
    if (rec.status === "running" && rec.expiresAt != null && rec.expiresAt <= now) {
      const updated = { ...rec, status: "stopped" as const, endpoint: null, expiresAt: null, updatedAt: now, note: "expired (reaped)" };
      await s.setInstance(updated);
    }
  }
}

/** Cron/manual trigger — reaps expired instances for every known user. */
export async function reapExpiredInstances(): Promise<number> {
  const s = getStore();
  const now = Date.now();
  let reaped = 0;
  for (const uid of s.listUserIds()) {
    for (const rec of await listInstances(uid)) {
      if (rec.status === "running" && rec.expiresAt != null && rec.expiresAt <= now) {
        await s.setInstance({ ...rec, status: "stopped", endpoint: null, expiresAt: null, updatedAt: now, note: "expired (reaped)" });
        reaped++;
      }
    }
  }
  return reaped;
}

async function stateFor(userId: string, slug: string): Promise<{ challenge: Challenge | null; instance: InstanceRecord | null }> {
  const s = getStore();
  const challenge = await s.getChallenge(slug);
  const rec = await s.getInstance(userId, slug);
  return { challenge, instance: rec };
}

/** Atomic-ish guard: recompute count after reap and set the new instance only
 *  when the cap is not exceeded. JSON-file store = single process, so this is
 *  race-free within the server. */
async function acquireSlot(userId: string, rec: InstanceRecord): Promise<boolean> {
  const running = (await listInstances(userId)).filter((r) => r.status === "running");
  if (running.length >= MAX_RUNNING_INSTANCES) return false;
  await getStore().setInstance(rec);
  return true;
}

async function runAction(
  userId: string,
  slug: string,
  action: "start" | "reset" | "extend" | "stop",
  api: RangeApi
): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> {
  const s = getStore();
  const { challenge, instance: prev } = await stateFor(userId, slug);
  if (!challenge) return { ok: false, error: "Unknown challenge." };
  await reapFor(userId);

  switch (action) {
    case "start": {
      if (prev && prev.status === "running") {
        return { ok: false, error: "Instance already running for this challenge." };
      }
      const ttl = instanceTtlMinutes(challenge);
      const ri = await api.provision({ challenge_slug: slug, user_id: userId, ttl_minutes: ttl });
      const rec = toInstanceRecord(userId, slug, ri, { startedAt: Date.now() });
      // Store the dynamic flag values server-side (never sent to the client) so
      // the scoring engine's matchesDynamicFlag stays the single verifier.
      const dyn: Record<string, string> = {};
      for (const f of challenge.flags) if (f.flagType === "DYNAMIC") dyn[f.id] = dynamicFlagValue(userId, slug, f.id);
      rec.dynamicFlags = dyn;
      // LIVE in-process labs: attach the real target (base URL + bearer token).
      const labFn = LABS_BY_SLUG[slug];
      if (labFn) rec.lab = labFn(userId);
      const ok = await acquireSlot(userId, rec);
      if (!ok) {
        // Roll back the range provision so we do not leak a box we refuse.
        try {
          await api.destroy(ri.instance_id);
        } catch {
          /* best effort */
        }
        return { ok: false, error: `Instance cap reached — max ${MAX_RUNNING_INSTANCES} running instances per player. Stop one to start this lab.` };
      }
      return { ok: true, instance: publicInstance(rec) };
    }
    case "reset": {
      if (!prev || prev.status !== "running") return { ok: false, error: "No running instance to reset." };
      if (!prev.rangeInstanceId) return { ok: false, error: "Instance has no range id." };
      const ri = await api.reset(prev.rangeInstanceId);
      const rec: InstanceRecord = { ...toInstanceRecord(userId, slug, ri), dynamicFlags: prev.dynamicFlags, extended: prev.extended, lab: prev.lab };
      await s.setInstance(rec);
      return { ok: true, instance: publicInstance(rec) };
    }
    case "extend": {
      if (!prev || prev.status !== "running") return { ok: false, error: "No running instance to extend." };
      if (prev.extended) return { ok: false, error: "Extension already used — one 30-minute extension per instance." };
      if (!prev.rangeInstanceId) return { ok: false, error: "Instance has no range id." };
      const ri = await api.extend(prev.rangeInstanceId);
      const rec: InstanceRecord = { ...toInstanceRecord(userId, slug, ri), dynamicFlags: prev.dynamicFlags, extended: true, lab: prev.lab };
      await s.setInstance(rec);
      return { ok: true, instance: publicInstance(rec) };
    }
    case "stop": {
      if (!prev) return { ok: false, error: "No instance to stop." };
      if (prev.rangeInstanceId) {
        try {
          await api.destroy(prev.rangeInstanceId);
        } catch {
          /* best effort — still mark stopped */
        }
      }
      const rec: InstanceRecord = {
        ...prev,
        status: "stopped",
        endpoint: null,
        expiresAt: null,
        updatedAt: Date.now(),
        note: "stopped",
      };
      await s.setInstance(rec);
      return { ok: true, instance: publicInstance(rec) };
    }
  }
  return { ok: false, error: "Unknown action." };
}

/** Strip dynamic flag values before anything reaches a client response. */
function publicInstance(rec: InstanceRecord): InstanceRecord {
  const { dynamicFlags: _drop, ...rest } = rec;
  return rest;
}

/** getInstance equivalent through the range: reap + refresh + public record. */
export async function readInstance(
  userId: string,
  slug: string,
  api: RangeApi = rangeClient()
): Promise<InstanceRecord | null> {
  await reapFor(userId);
  const s = getStore();
  const rec = await s.getInstance(userId, slug);
  if (!rec || rec.status !== "running" || !rec.rangeInstanceId) return rec ? publicInstance(rec) : null;
  // Refresh from the range so TTL/status stay authoritative.
  try {
    const ri = await api.get(rec.rangeInstanceId);
    const fresh: InstanceRecord = { ...toInstanceRecord(userId, slug, ri), dynamicFlags: rec.dynamicFlags, extended: rec.extended, lab: rec.lab };
    await s.setInstance(fresh);
    return publicInstance(fresh);
  } catch {
    return publicInstance(rec);
  }
}

export async function startInstance(
  userId: string,
  slug: string,
  api: RangeApi = rangeClient()
): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> {
  return runAction(userId, slug, "start", api);
}
export async function resetInstance(
  userId: string,
  slug: string,
  api: RangeApi = rangeClient()
): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> {
  return runAction(userId, slug, "reset", api);
}
export async function extendInstance(
  userId: string,
  slug: string,
  api: RangeApi = rangeClient()
): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> {
  return runAction(userId, slug, "extend", api);
}
export async function stopInstance(
  userId: string,
  slug: string,
  api: RangeApi = rangeClient()
): Promise<{ ok: boolean; instance?: InstanceRecord; error?: string }> {
  return runAction(userId, slug, "stop", api);
}