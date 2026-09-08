// ---------------------------------------------------------------------------
// Crimson Range — mock-range server (DEV ONLY).
//
// Implements the full Range API contract in-process so the portal works with
// zero real infra:
//   POST   /instances  {challenge_slug, user_id, ttl_minutes} -> provisioned
//   GET    /instances/:id
//   POST   /instances/:id/extend   (single +30min, tracked)
//   POST   /instances/:id/reset
//   DELETE /instances/:id
//
// Fake endpoints per challenge category + per-user DYNAMIC flag minting
// consistent with `dynamicFlagValue` in store.ts (same HMAC derivation), so
// `matchesDynamicFlag` accepts what the mock mints. STATIC flags are not
// minted here — the portal verifies them.
//
// Keyed by `x-range-key` header (echoes RANGE_API_KEY config).
// MUST be disabled in prod: set `ENABLE_MOCK_RANGE=0` (the default when
// RANGE_API_URL is configured). Path prefix /mock-range is dev-only.
// ---------------------------------------------------------------------------

import { createHash } from "node:crypto";
import { getStore, dynamicFlagValue } from "~/server/store";
import type { Challenge, RangeInstance } from "~/server/types";

interface MockInstance extends RangeInstance {
  extended: boolean;
  createdAt: number;
  ttlMinutes: number;
}

const instances = new Map<string, MockInstance>();

function challengeFor(slug: string): Challenge | null {
  // getStore() singleton; listChallenges is async — helper resolves sync cache.
  const c = challengesCache.get(slug);
  return c ?? null;
}
const challengesCache = new Map<string, Challenge>();
void (async () => {
  for (const c of await getStore().listChallenges()) challengesCache.set(c.slug, c);
})();

function id(): string {
  return createHash("sha256").update(`${Date.now()}:${Math.random()}`).digest("hex").slice(0, 16);
}

/** Fake endpoint per category — believable targets without real infra. */
function fakeEndpoints(slug: string): RangeInstance["endpoints"] {
  const c = challengeFor(slug);
  const cat = c?.category ?? "Web/API";
  switch (cat) {
    case "AI Red-Team":
      return [
        { kind: "https", host: "paybuddy.range.local", port: 443 },
        { kind: "api", host: "10.13.37.20", port: 8443 },
      ];
    case "Active Directory":
      return [
        { kind: "rdp", host: "10.13.37.10", port: 3389 },
        { kind: "ssh", host: "kali-jump.range.local", port: 22 },
        { kind: "smb", host: "10.13.37.10", port: 445 },
      ];
    case "Cloud":
      return [
        { kind: "ssh", host: "jumpbox.range.local", port: 22 },
        { kind: "https", host: "s3.range.local", port: 443 },
      ];
    case "Kill-Chain":
      return [
        { kind: "smtp", host: "relay.range.local", port: 25 },
        { kind: "ssh", host: "portal.range.local", port: 22 },
        { kind: "rdp", host: "ws-cr-04.range.local", port: 3389 },
      ];
    default: // Web/API
      return [
        { kind: "https", host: "api.acme.local", port: 443 },
        { kind: "http", host: "10.13.37.30", port: 8080 },
      ];
  }
}

/** Mint per-user DYNAMIC flag values using the SAME derivation as store.ts. */
function mintFlags(slug: string, userId: string): RangeInstance["flags"] {
  const c = challengeFor(slug);
  if (!c) return [];
  return c.flags
    .filter((f) => f.flagType === "DYNAMIC")
    .map((f) => ({ flag_id: f.id, value: dynamicFlagValue(userId, slug, f.id) }));
}

function now(): number {
  return Date.now();
}

export function mockRange(): {
  handle(req: Request): Promise<Response>;
  list(): MockInstance[];
} {
  function json(data: unknown, status = 200): Response {
    return new Response(JSON.stringify(data), {
      status,
      headers: { "content-type": "application/json" },
    });
  }
  async function handle(req: Request): Promise<Response> {
    if (process.env.ENABLE_MOCK_RANGE === "0") {
      return json({ error: "mock range disabled" }, 403);
    }
    const url = new URL(req.url);
    // Accept both the full public path (/mock-range/instances/...) and the
    // mount-stripped path (/instances/...) — Vite middleware mounted at
    // /mock-range strips the prefix before the handler sees req.url.
    const m = url.pathname.match(/^\/(?:mock-range\/)?instances(?:\/([^/]+))?(?:\/(extend|reset))?$/);
    if (!m) return json({ error: "not found" }, 404);
    const [, instanceId, action] = m;
    const method = req.method;

    // POST /mock-range/instances  (provision)
    if (method === "POST" && !instanceId) {
      let body: { challenge_slug?: string; user_id?: string; ttl_minutes?: number };
      try {
        body = (await req.json()) as typeof body;
      } catch {
        return json({ error: "bad json" }, 400);
      }
      const slug = body.challenge_slug;
      const userId = body.user_id;
      const ttl = typeof body.ttl_minutes === "number" && body.ttl_minutes > 0 ? Math.round(body.ttl_minutes) : 120;
      if (!slug || !userId) return json({ error: "challenge_slug and user_id required" }, 400);
      const c = challengeFor(slug);
      if (!c) return json({ error: `unknown challenge: ${slug}` }, 404);
      const createdAt = now();
      const inst: MockInstance = {
        instance_id: id(),
        challenge_slug: slug,
        user_id: userId,
        status: "running",
        endpoints: fakeEndpoints(slug),
        flags: mintFlags(slug, userId),
        expires_at: createdAt + ttl * 60_000,
        extended: false,
        createdAt,
        ttlMinutes: ttl,
      };
      instances.set(inst.instance_id, inst);
      return json(inst, 201);
    }

    if (!instanceId) return json({ error: "not found" }, 404);
    const inst = instances.get(instanceId);
    if (!inst) return json({ error: "instance not found" }, 404);

    // GET /mock-range/instances/:id
    if (method === "GET") return json(inst);

    // DELETE /mock-range/instances/:id
    if (method === "DELETE") {
      instances.delete(instanceId);
      return json({ ok: true });
    }

    // POST /mock-range/instances/:id/extend
    if (method === "POST" && action === "extend") {
      if (inst.extended) return json({ error: "extension already used" }, 409);
      inst.extended = true;
      inst.expires_at = inst.expires_at + 30 * 60_000;
      inst.ttlMinutes += 30;
      return json(inst);
    }

    // POST /mock-range/instances/:id/reset
    if (method === "POST" && action === "reset") {
      inst.expires_at = now() + inst.ttlMinutes * 60_000;
      inst.status = "running";
      return json(inst);
    }

    return json({ error: "method not allowed" }, 405);
  }
  return { handle, list: () => [...instances.values()] };
}