// Production server for the built site. The TanStack Start build emits a portable
// fetch handler (dist/server/server.js) plus static client assets (dist/client);
// this wraps them in a Bun server on port 3000 — static files first, SSR for the
// rest. Run `bun run build` before starting. Restart it with `bun run publish`.
//
// Starting a new instance supersedes the old one: it frees the port no matter
// which user owns the current server (provisioning starts it as `engine`; a team
// member's `bun run publish` runs as their own user), so publish never collides
// with an already-running server. Every sandbox user has passwordless sudo, so
// the takeover works across user boundaries.
import handler from "./dist/server/server.js";
// Mock Range API for the production build (dev-only). The full contract
// handler lives in ./src/server/mock-range.ts; this is the transport shim for
// the built server. Disabled in prod via ENABLE_MOCK_RANGE=0.
import { mockRange } from "./src/server/mock-range";
// LIVE in-process lab target (Invoice Inspector BOLA API). Served by the
// production build exactly like the dev middleware serves it, so the lab stays
// reachable on the published site. Handler lives in ./src/server/labs.
import { invoiceApi } from "./src/server/labs/invoice-api";

// ---------------------------------------------------------------------------
// Security headers (hardening). Applied to EVERY response from this production
// server (mock-range, static assets, SSR). The dev server (vite.config.ts)
// INTENTIONALLY omits HSTS and CSP: HSTS would pin the local dev host, and a
// dev CSP adds no protection while getting in the way of Vite HMR — the full
// set ships only here, in the production server. To verify with curl, run this
// server (bun run build && bun run start) or the built preview; the dev server
// at vite:3000 will NOT show these headers by design.
// NOTE: the TanStack Start SSR HTML embeds inline scripts/styles, so the CSP
// uses 'unsafe-inline' for script-src/style-src (baseline, no per-request
// nonce in MVP) while still blocking object/embed, framing, and mixed content.
// HSTS is harmless behind the TLS-terminating proxy and required for prod.
// ---------------------------------------------------------------------------
export const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; upgrade-insecure-requests",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
};

export function withSecurityHeaders(res: Response): Response {
  const h = new Headers(res.headers);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) h.set(k, v);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers: h });
}

const mockRangeHandler = async (req: Request): Promise<Response | null> => {
  const { pathname } = new URL(req.url);
  if (!pathname.startsWith("/mock-range")) return null;
  if (process.env.ENABLE_MOCK_RANGE === "0") {
    return new Response(JSON.stringify({ error: "mock range disabled" }), {
      status: 403,
      headers: { "content-type": "application/json" },
    });
  }
  return mockRange().handle(req);
};
// Live lab targets (/api/labs/invoice...) — same in-process handlers the dev
// middleware serves, reachable on the production build too.
const labApiHandler = async (req: Request): Promise<Response | null> => {
  const { pathname } = new URL(req.url);
  if (!pathname.startsWith("/api/labs/invoice")) return null;
  return invoiceApi().handle(req);
};

// Pinned, NOT read from the environment. The published preview URL
// (<label>.<PUBLIC_SITE_DOMAIN>) is reverse-proxied to 0.0.0.0:3000 inside the
// sandbox, so the default site MUST bind there. Bun auto-loads .env files, so
// honouring process.env.PORT/HOST would let a stray env var or a .env in the site
// dir silently move the site off :3000 (or onto loopback) and break the public URL.
const PORT = 3000;
const HOST = "0.0.0.0";
const CLIENT_DIR = `${import.meta.dir}/dist/client`;

// Free PORT regardless of which user owns the current listener. lsof runs under
// sudo so it can see (and the kill can signal) a process owned by another user;
// the loop waits for the socket to actually release before we bind.
const freePort =
  `for _ in $(seq 1 25); do ` +
  `pids=$(lsof -t -iTCP:${String(PORT)} -sTCP:LISTEN 2>/dev/null || true); ` +
  `if [ -z "$pids" ]; then exit 0; fi; ` +
  `kill $pids 2>/dev/null || true; sleep 0.2; ` +
  `done`;

// Take over the port, re-freeing and retrying if another publish grabbed it in the
// gap between freeing and binding (last publish wins). Bun.serve throws EADDRINUSE
// synchronously, so without this a raced publish would die while the shell already
// reported success.
for (let attempt = 1; ; attempt++) {
  await Bun.$`sudo sh -c ${freePort}`.quiet().nothrow();
  try {
    Bun.serve({
      port: PORT,
      hostname: HOST,
      async fetch(req) {
        const mock = await mockRangeHandler(req);
        if (mock) return withSecurityHeaders(mock);
        const lab = await labApiHandler(req);
        if (lab) return withSecurityHeaders(lab);
        const { pathname } = new URL(req.url);
        if (pathname !== "/") {
          const file = Bun.file(CLIENT_DIR + pathname);
          if (await file.exists()) return withSecurityHeaders(new Response(file));
        }
        return withSecurityHeaders(
          await (handler as { fetch: (r: Request) => Response | Promise<Response> }).fetch(req)
        );
      },
    });
    break;
  } catch (err) {
    if (attempt >= 10) throw err;
    await Bun.sleep(200);
  }
}

console.log(`team-site serving on http://${HOST}:${String(PORT)}`);
