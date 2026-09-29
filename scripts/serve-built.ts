// ---------------------------------------------------------------------------
// Crimson Range — built-output harness (verification only).
//
// Serves the PRODUCTION build exactly the way the deployed runtime does: it
// imports the TanStack Start SSR fetch handler that `vite build` emits
// (dist/server/server.js) plus the static client assets (dist/client) and
// nothing else.
//
// Why this exists: the labs used to be mounted by a dev-only Vite middleware
// (and a matching shim in serve.ts), so "works on :3000" did not prove the
// published site could serve them. This harness deliberately does NOT mount
// any lab handler — if /api/labs/* answers here, it is because the lab API
// routes are part of the built route tree.
//
//   bun run build && bun scripts/serve-built.ts [port]     # default 3100
//   bash scripts/lab-paybuddy-check.sh http://localhost:3100/api/labs/paybuddy
//   bash scripts/lab-invoice-check.sh  http://localhost:3100/api/labs/invoice/v2
//
// Loopback port only — it never touches :3000 (the managed dev/live server).
// ---------------------------------------------------------------------------
import handler from "../dist/server/server.js";

const PORT = Number(process.env.BUILT_PORT ?? process.argv[2] ?? 3100);
const HOST = process.env.BUILT_HOST ?? "127.0.0.1";
const CLIENT_DIR = new URL("../dist/client", import.meta.url).pathname;

const fetchHandler = handler as { fetch: (req: Request) => Response | Promise<Response> };

Bun.serve({
  port: PORT,
  hostname: HOST,
  async fetch(req) {
    const { pathname } = new URL(req.url);
    if (pathname !== "/") {
      const file = Bun.file(CLIENT_DIR + pathname);
      if (await file.exists()) return new Response(file);
    }
    return fetchHandler.fetch(req);
  },
});

console.log(`built site (dist/server/server.js) serving on http://${HOST}:${String(PORT)}`);
