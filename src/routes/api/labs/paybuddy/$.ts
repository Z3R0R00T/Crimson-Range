// ---------------------------------------------------------------------------
// Crimson Range — Payroll Whisperer (prompt-injection-payroll) HTTP mount.
//
// The lab target itself (the PayBuddy agent sim) lives in
// ~/server/labs/paybuddy-api.ts and is the single implementation used by BOTH
// the dev server and the published build. This route file is the production
// mount point: it is part of the generated TanStack Start route tree, so it is
// compiled into dist/server/server.js and served by the deployed SSR handler.
//
// Sub-paths (/health, /chat, /openapi.json, /artifacts/*) all delegate to the
// lab handler unchanged — auth header pass-through, status codes and
// content-type come straight from the handler's Response. Lab modules are
// server-only (node:crypto), hence the in-handler dynamic import: the handler
// body never reaches the client bundle.
// ---------------------------------------------------------------------------
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/labs/paybuddy/$")({
  server: {
    handlers: {
      ANY: async ({ request }) => {
        const { paybuddyApi } = await import("~/server/labs/paybuddy-api");
        return paybuddyApi().handle(request);
      },
    },
  },
});
