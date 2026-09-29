// ---------------------------------------------------------------------------
// Crimson Range — Invoice Inspector (bola-invoice-api) HTTP mount.
//
// The lab target itself (the vulnerable Acme Billing v2 API) lives in
// ~/server/labs/invoice-api.ts and is the single implementation used by BOTH
// the dev server and the published build. This route file is the production
// mount point: it is part of the generated TanStack Start route tree, so it is
// compiled into dist/server/server.js and served by the deployed SSR handler.
//
// Sub-paths (/v2/health, /v2/auth/login, /v2/invoices/:id, /v2/admin/export,
// /artifacts/*) all delegate to the lab handler unchanged — auth header
// pass-through, status codes and content-type come straight from the handler's
// Response. Lab modules are server-only (node:crypto), hence the in-handler
// dynamic import: the handler body never reaches the client bundle.
// ---------------------------------------------------------------------------
import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/labs/invoice/$")({
  server: {
    handlers: {
      ANY: async ({ request }) => {
        const { invoiceApi } = await import("~/server/labs/invoice-api");
        return invoiceApi().handle(request);
      },
    },
  },
});
