#!/usr/bin/env bun
/**
 * test-api.ts — Crimson Range portal HTTP API smoke test (hardening slice 2)
 *
 * Run:  bun scripts/test-api.ts            (against http://localhost:3000)
 *       BASE=https://example.com bun scripts/test-api.ts
 *
 * What this covers (plain HTTP surface of the dev/prod server):
 *   - catalogue:        GET / and GET /challenges return 200
 *   - mock-range        POST /mock-range/instances            (provision → 201)
 *   - mock-range        GET  /mock-range/instances/:id        (get → 200)
 *   - mock-range        POST /mock-range/instances/:id/extend (extend → 200)
 *   - mock-range        POST /mock-range/instances/:id/extend (2nd extend → 409, reject)
 *   - mock-range        POST /mock-range/instances/:id/reset  (reset → 200)
 *   - mock-range        DELETE /mock-range/instances/:id      (delete → ok)
 *   - error paths:      bad provision payloads, unknown ids, bad method
 *
 * What is NOT covered here (needs UI-driven testing — see checklist below):
 * The app's auth / flag-submission / instance-start flows run through TanStack
 * Start *server functions* (login, submitFlag, instanceAction in
 * src/server/functions.ts). Their HTTP endpoints are framework-internal RPC:
 * each function gets a generated base64 id baked into the client bundle per
 * build, requests are seroval-framed (+ x-tsr-serverFn/CSRF headers), and the
 * dev server does not expose a stable, documented HTTP contract for them.
 * Hitting those endpoints from a raw-fetch script is brittle by design, so they
 * are exercised through the UI instead. Manual/agent-browser checklist:
 *
 *   [ ] login as neo / crimson-neo            → lands on /challenges
 *   [ ] submit wrong flag on a challenge      → "correct": false response
 *   [ ] rate-limit probe: 11+ submissions in 60s → error "Rate limited"
 *       (submitFlag limit is 10/60s per user+challenge; login is 5/60s per IP)
 *   [ ] start an instance on a challenge      → instance appears running,
 *       second "extend" is rejected (one extension per instance)
 *
 * Exit code: 0 on full pass, 1 if any check fails or the server is unreachable.
 */
const BASE = (process.env.BASE ?? "http://localhost:3000").replace(/\/$/, "");

let failures = 0;
let passes = 0;

function ok(name: string, detail = "") {
  passes++;
  console.log(`  \x1b[32mPASS\x1b[0m  ${name}${detail ? ` — ${detail}` : ""}`);
}

function fail(name: string, detail = "") {
  failures++;
  console.log(`  \x1b[31mFAIL\x1b[0m  ${name}${detail ? ` — ${detail}` : ""}`);
}

async function req(
  path: string,
  init?: RequestInit,
): Promise<{ status: number; body: unknown; text: string }> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
  });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  return { status: res.status, body, text };
}

function check(name: string, cond: boolean, detail?: string) {
  if (cond) ok(name, detail);
  else fail(name, detail);
}

async function main() {
  console.log(`\x1b[1mCrimson Range — API smoke test\x1b[0m  (BASE=${BASE})`);
  console.log("─".repeat(60));

  // ---- Reachability -------------------------------------------------------
  try {
    await fetch(`${BASE}/`);
  } catch (err) {
    console.error(
      `\x1b[31mFATAL\x1b[0m server unreachable at ${BASE}: ${(err as Error).message}`,
    );
    console.error("  Is the dev server running? (bun run dev in the site dir)");
    process.exit(1);
  }

  // ---- Catalogue ----------------------------------------------------------
  console.log("\n[1] Catalogue");
  const home = await req("/");
  check("GET / returns 200", home.status === 200, `status=${home.status}`);
  const cat = await req("/challenges");
  const html = (cat.text ?? "").toLowerCase();
  check(
    "GET /challenges returns 200 (SSR catalogue)",
    cat.status === 200,
    `status=${cat.status}`,
  );
  check(
    "/challenges renders challenge content",
    html.includes("challenge") || html.includes("crimson") || html.includes("flag"),
    "page is HTML, not an error",
  );

  // ---- Mock-range lifecycle ----------------------------------------------
  console.log("\n[2] Mock-range instance lifecycle");
  let instId = "";
  let created = false;
  try {
    const prov = await req("/mock-range/instances", {
      method: "POST",
      body: JSON.stringify({
        challenge_slug: "shadow-ledger",
        user_id: "api-test",
        ttl_minutes: 30,
      }),
    });
    const p = prov.body as Record<string, unknown> | null;
    instId = (p?.instance_id as string) ?? "";
    created = prov.status === 201 && !!instId;
    check(
      "POST /mock-range/instances provisions (201 + instance_id)",
      created,
      prov.status === 201
        ? `instance_id=${instId}`
        : `status=${prov.status} body=${prov.text.slice(0, 120)}`,
    );

    if (created) {
      const get = await req(`/mock-range/instances/${instId}`);
      const g = get.body as Record<string, unknown> | null;
      check(
        "GET /mock-range/instances/:id returns the instance",
        get.status === 200 && g?.instance_id === instId && g?.status === "running",
        `status=${get.status} instance_status=${String(g?.status)}`,
      );

      const ext = await req(`/mock-range/instances/${instId}/extend`, {
        method: "POST",
      });
      const e = ext.body as Record<string, unknown> | null;
      check(
        "POST :id/extend extends the instance",
        ext.status === 200 && e?.extended === true,
        `status=${ext.status} extended=${String(e?.extended)}`,
      );

      const ext2 = await req(`/mock-range/instances/${instId}/extend`, {
        method: "POST",
      });
      check(
        "POST :id/extend again is REJECTED (409, one extension per instance)",
        ext2.status === 409,
        `status=${ext2.status} body=${(ext2.text ?? "").slice(0, 80)}`,
      );

      const rst = await req(`/mock-range/instances/${instId}/reset`, {
        method: "POST",
      });
      const r = rst.body as Record<string, unknown> | null;
      check(
        "POST :id/reset resets the instance",
        rst.status === 200 && r?.status === "running",
        `status=${rst.status} instance_status=${String(r?.status)}`,
      );

      const del = await req(`/mock-range/instances/${instId}`, {
        method: "DELETE",
      });
      check(
        "DELETE /mock-range/instances/:id deletes (ok:true)",
        del.status === 200 && (del.body as Record<string, unknown> | null)?.ok === true,
        `status=${del.status}`,
      );

      const gone = await req(`/mock-range/instances/${instId}`);
      check("instance is gone after delete (404)", gone.status === 404, `status=${gone.status}`);
      instId = "";
    }
  } catch (err) {
    fail("mock-range lifecycle", (err as Error).message);
  } finally {
    if (instId) {
      await req(`/mock-range/instances/${instId}`, { method: "DELETE" }).catch(() => {});
    }
  }

  // ---- Error paths --------------------------------------------------------
  console.log("\n[3] Error paths");
  const noSlug = await req("/mock-range/instances", {
    method: "POST",
    body: JSON.stringify({ user_id: "api-test" }),
  });
  check("provision without challenge_slug → 400", noSlug.status === 400, `status=${noSlug.status}`);

  const badSlug = await req("/mock-range/instances", {
    method: "POST",
    body: JSON.stringify({ challenge_slug: "does-not-exist", user_id: "api-test" }),
  });
  check("provision with unknown slug → 404", badSlug.status === 404, `status=${badSlug.status}`);

  const badJson = await req("/mock-range/instances", {
    method: "POST",
    body: "{not json",
  });
  check("provision with malformed JSON → 400", badJson.status === 400, `status=${badJson.status}`);

  const unknownId = await req("/mock-range/instances/nope-nope-nope");
  check("GET unknown instance id → 404", unknownId.status === 404, `status=${unknownId.status}`);

  const badMethod = await req("/mock-range/instances/x", { method: "PATCH" });
  check(
    "unsupported method on instance → 405/404 without side effects",
    badMethod.status === 405 || badMethod.status === 404,
    `status=${badMethod.status}`,
  );

  // ---- Summary -------------------------------------------------------------
  console.log("─".repeat(60));
  console.log(`\x1b[1m${passes} passed, ${failures} failed\x1b[0m`);
  if (failures > 0) {
    console.log("\nServer-function flows (login/flag-submit/instance-start) are UI-tested —");
    console.log("see the checklist at the top of this file.");
    process.exit(1);
  }
  console.log(
    "Note: auth/flag/rate-limit flows are UI-driven (server functions) — see checklist above.",
  );
  process.exit(0);
}

main().catch((err) => {
  console.error(`\x1b[31mFATAL\x1b[0m ${(err as Error).stack ?? err}`);
  process.exit(1);
});