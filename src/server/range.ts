// ---------------------------------------------------------------------------
// Crimson Range — Range API HTTP client (server-only).
//
// Talks to the external Range API contract (BRD §6):
//   POST   {RANGE_API_URL}/instances            {challenge_slug, user_id, ttl_minutes} -> instance
//   GET    {RANGE_API_URL}/instances/:id        -> instance
//   POST   {RANGE_API_URL}/instances/:id/extend -> instance
//   DELETE {RANGE_API_URL}/instances/:id        -> { ok }
//   POST   {RANGE_API_URL}/instances/:id/reset  -> instance
//
// Includes: 3 retries with exponential backoff (300ms * 2^n, capped 2s),
// 10s per-attempt timeout, simple circuit breaker (opens after 5 consecutive
// failures, half-open probe after 30s).
//
// Config from env:
//   RANGE_API_URL  — base URL of the range. Defaults to the in-process mock
//                    mounted at `/mock-range` (dev only; disable with
//                    ENABLE_MOCK_RANGE=0).
//   RANGE_API_KEY  — bearer token sent as `Authorization: Bearer <key>`.
//
// Node-only: never import from client code (fetch + timers + env).
// ---------------------------------------------------------------------------

import type { RangeApi, RangeProvisionRequest, RangeInstance } from "~/server/types";

export const RANGE_DEFAULT_TIMEOUT_MS = 10_000;
export const RANGE_MAX_RETRIES = 3;
export const RANGE_CIRCUIT_FAILURES = 5;
export const RANGE_CIRCUIT_OPEN_MS = 30_000;

/**
 * Range base URL resolved from env. When `ENABLE_MOCK_RANGE !== "0"` (default,
 * dev), the platform resolves to the in-process mock via a loop-back URL that
 * the dev middleware / serve.ts handler serves at /mock-range.
 */
export function rangeUrl(): string {
  const explicit = process.env.RANGE_API_URL;
  if (explicit && explicit.trim().length > 0) {
    return explicit.replace(/\/+$/, "");
  }
  if (process.env.ENABLE_MOCK_RANGE === "0") {
    throw new Error("RANGE_API_URL is not set and the mock range is disabled (ENABLE_MOCK_RANGE=0).");
  }
  return "http://127.0.0.1:3000/mock-range";
}

function rangeKey(): string {
  return process.env.RANGE_API_KEY ?? "";
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface CircuitState {
  consecutiveFailures: number;
  openUntil: number | null;
}

const circuit: CircuitState = { consecutiveFailures: 0, openUntil: null };

function circuitOpen(): boolean {
  return circuit.openUntil !== null && Date.now() < circuit.openUntil;
}

function recordFailure(): void {
  circuit.consecutiveFailures += 1;
  if (circuit.consecutiveFailures >= RANGE_CIRCUIT_FAILURES) {
    circuit.openUntil = Date.now() + RANGE_CIRCUIT_OPEN_MS;
  }
}

function recordSuccess(): void {
  circuit.consecutiveFailures = 0;
  circuit.openUntil = null;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (circuitOpen()) {
    throw new Error("range-circuit-open");
  }
  const url = `${rangeUrl()}${path}`;
  let lastErr: Error | null = null;
  for (let attempt = 0; attempt <= RANGE_MAX_RETRIES; attempt++) {
    if (attempt > 0) await delay(300 * 2 ** (attempt - 1)); // 300ms, 600ms, 1.2s
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), RANGE_DEFAULT_TIMEOUT_MS);
    try {
      const res = await fetch(url, {
        method,
        headers: {
          "content-type": "application/json",
          ...(rangeKey() ? { authorization: `Bearer ${rangeKey()}` } : {}),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      if (!res.ok) {
        lastErr = new Error(`range-http-${res.status}`);
        throw lastErr;
      }
      recordSuccess();
      return (await res.json()) as T;
    } catch (err) {
      clearTimeout(timer);
      lastErr = err instanceof Error ? err : new Error(String(err));
      if (err instanceof Error && err.name === "AbortError") {
        lastErr = new Error("range-timeout");
      }
      if (lastErr.message === "range-http-404") throw lastErr; // not retryable
    }
  }
  recordFailure();
  throw lastErr ?? new Error("range-request-failed");
}

/** Range API client. All methods hit the same contract endpoints. */
export function rangeClient(): RangeApi {
  return {
    async provision(req: RangeProvisionRequest): Promise<RangeInstance> {
      return request<RangeInstance>("POST", "/instances", req);
    },
    async get(instanceId: string): Promise<RangeInstance> {
      return request<RangeInstance>("GET", `/instances/${encodeURIComponent(instanceId)}`);
    },
    async extend(instanceId: string): Promise<RangeInstance> {
      return request<RangeInstance>("POST", `/instances/${encodeURIComponent(instanceId)}/extend`);
    },
    async destroy(instanceId: string): Promise<{ ok: boolean }> {
      return request<{ ok: boolean }>("DELETE", `/instances/${encodeURIComponent(instanceId)}`);
    },
    async reset(instanceId: string): Promise<RangeInstance> {
      return request<RangeInstance>("POST", `/instances/${encodeURIComponent(instanceId)}/reset`);
    },
  };
}