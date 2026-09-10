#!/usr/bin/env bun
/**
 * load-test.ts — Crimson Range portal burst smoke/load test (hardening slice 2)
 *
 * Run:  bun scripts/load-test.ts
 *       bun scripts/load-test.ts --concurrency 20 --rounds 5 --base http://localhost:3000
 *       bun scripts/load-test.ts --ratio 0.5        (share of requests that provision)
 *
 * Default: 20 parallel requests x 5 rounds against:
 *   - GET  /challenges             (SSR catalogue page)
 *   - POST /mock-range/instances   (mock-range provision)
 *
 * ⚠️  APPROXIMATION, NOT A LOAD TEST. This is a burst simulation against a
 * single-process dev server on localhost: a flat concurrency fan-out, no ramp,
 * no think time, no connection tuning, no remote infra, and the app is a Vite
 * dev SSR server plus an in-memory mock. Reported p50/p95 are a smoke/regression
 * signal for this dev box ONLY — they must NOT be read as capacity numbers, and
 * they are NOT a 500-user test. For real numbers: run against the production
 * build (bun run build && bun run start) on a provisioned box, with a proper
 * tool (k6/wrk) and a ramp.
 *
 * Flags (also via env: LOAD_TEST_CONCURRENCY, LOAD_TEST_ROUNDS, LOAD_TEST_BASE,
 * LOAD_TEST_RATIO, LOAD_TEST_SLUG):
 *   --concurrency N   parallel requests per round            (default 20)
 *   --rounds N        number of rounds                       (default 5)
 *   --base URL        server base URL                        (default http://localhost:3000)
 *   --ratio 0..1      fraction of requests that provision    (default 0.5)
 *   --slug SLUG       challenge slug to provision            (default shadow-ledger)
 *
 * Exit code: 0 if every request completed with an expected status; 1 if the
 * server is unreachable or any request fails (network error / non-2xx).
 */
const args = process.argv.slice(2);
function opt(name: string, def: string): string {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : def;
}

const CONCURRENCY = Math.max(1, parseInt(opt("--concurrency", process.env.LOAD_TEST_CONCURRENCY ?? "20"), 10) || 20);
const ROUNDS = Math.max(1, parseInt(opt("--rounds", process.env.LOAD_TEST_ROUNDS ?? "5"), 10) || 5);
const BASE = (opt("--base", process.env.LOAD_TEST_BASE ?? "http://localhost:3000")).replace(/\/$/, "");
const RATIO = Math.min(1, Math.max(0, parseFloat(opt("--ratio", process.env.LOAD_TEST_RATIO ?? "0.5")) || 0.5));
const SLUG = opt("--slug", process.env.LOAD_TEST_SLUG ?? "shadow-ledger");

const CATALOG_URL = `${BASE}/challenges`;
const PROVISION_URL = `${BASE}/mock-range/instances`;

function pct(sorted: number[], q: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil((q / 100) * sorted.length) - 1);
  return Math.round(sorted[idx]);
}

async function fire(mode: "catalog" | "provision"): Promise<{
  mode: "catalog" | "provision";
  ms: number;
  ok: boolean;
  id?: string;
  err?: string;
}> {
  const t0 = performance.now();
  try {
    const res =
      mode === "catalog"
        ? await fetch(CATALOG_URL)
        : await fetch(PROVISION_URL, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ challenge_slug: SLUG, user_id: "load-test", ttl_minutes: 15 }),
          });
    const ms = performance.now() - t0;
    const expected = mode === "catalog" ? 200 : 201;
    const ok = res.status === expected;
    let id: string | undefined;
    if (mode === "provision" && ok) {
      try {
        id = (await res.json())?.instance_id as string | undefined;
      } catch {
        /* keep id undefined; response parsing failure is still ok=false? no: leave ok as status check */
      }
    }
    return { mode, ms, ok, id, err: ok ? undefined : `HTTP ${res.status}` };
  } catch (err) {
    return { mode, ms: performance.now() - t0, ok: false, err: (err as Error).message };
  }
}

async function main() {
  const tStart = performance.now();
  const N_PER_ROUND = CONCURRENCY;
  const PROVISIONS_PER_ROUND = Math.round(N_PER_ROUND * RATIO);
  const CATALOGS_PER_ROUND = N_PER_ROUND - PROVISIONS_PER_ROUND;

  const catMs: number[] = [];
  const provMs: number[] = [];
  const provisionIds: string[] = [];
  let total = 0;
  let failed = 0;
  let firstRoundFailed = 0;

  console.log("Crimson Range — burst simulation (APPROXIMATION — see header comments)");
  console.log("─".repeat(64));
  console.log(`base       : ${BASE}`);
  console.log(`concurrency: ${CONCURRENCY} per round`);
  console.log(`rounds     : ${ROUNDS}`);
  console.log(`mix        : ${CATALOGS_PER_ROUND}x GET /challenges + ${PROVISIONS_PER_ROUND}x POST /mock-range/instances per round`);
  console.log("─".repeat(64));

  for (let round = 1; round <= ROUNDS; round++) {
    const plan: Array<"catalog" | "provision"> = [
      ...Array(CATALOGS_PER_ROUND).fill("catalog"),
      ...Array(PROVISIONS_PER_ROUND).fill("provision"),
    ];
    // shuffle-ish: interleave so the two endpoints mix within the fan-out
    for (let i = plan.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [plan[i], plan[j]] = [plan[j], plan[i]];
    }

    const results = await Promise.all(plan.map((m) => fire(m)));
    for (const r of results) {
      total++;
      if (r.mode === "catalog") catMs.push(r.ms);
      else {
        provMs.push(r.ms);
        if (r.id) provisionIds.push(r.id);
      }
      if (!r.ok) {
        failed++;
        if (round === 1) firstRoundFailed++;
        if (r.err) console.log(`  [r${round}] FAIL ${r.mode} — ${r.err}`);
      }
    }
    console.log(`  round ${round}/${ROUNDS}: ${N_PER_ROUND} requests done`);
  }

  // Cleanup: delete every provisioned instance (not measured).
  const cleanup = await Promise.allSettled(
    provisionIds.map((id) =>
      fetch(`${BASE}/mock-range/instances/${id}`, { method: "DELETE" }),
    ),
  );
  const deleted = cleanup.filter((r) => r.status === "fulfilled" && (r.value as Response).ok).length;

  const catSorted = [...catMs].sort((a, b) => a - b);
  const provSorted = [...provMs].sort((a, b) => a - b);
  const elapsed = ((performance.now() - tStart) / 1000).toFixed(1);

  console.log("─".repeat(64));
  console.log(`\x1b[1mGET /challenges\x1b[0m            n=${catMs.length}  p50=${pct(catSorted, 50)}ms  p95=${pct(catSorted, 95)}ms  min=${catSorted[0] ?? 0}ms  max=${catSorted[catSorted.length - 1] ?? 0}ms`);
  console.log(`\x1b[1mPOST mock-range/instances\x1b[0m  n=${provMs.length}  p50=${pct(provSorted, 50)}ms  p95=${pct(provSorted, 95)}ms  min=${provSorted[0] ?? 0}ms  max=${provSorted[provSorted.length - 1] ?? 0}ms`);
  console.log(`total: ${total} requests in ${elapsed}s  |  failures: ${failed}  |  cleaned up ${deleted}/${provisionIds.length} provisioned instances`);
  console.log("─".repeat(64));
  console.log(
    "\x1b[33mNOTE:\x1b[0m burst simulation on a dev server — an APPROXIMATION only, NOT a",
  );
  console.log("500-user load test. Treat p50/p95 as a regression signal, not capacity.");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(`\x1b[31mFATAL\x1b[0m ${(err as Error).stack ?? err}`);
  process.exit(1);
});