import tailwindcss from "@tailwindcss/vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import tsConfigPaths from "vite-tsconfig-paths";

// Mock Range API (dev only). Serves the Range API contract at /mock-range so
// the default RANGE_API_URL (loop-back :3000/mock-range) works in dev. Disable
// in prod: set ENABLE_MOCK_RANGE=0. This middleware is intentionally tiny —
// all logic lives in ~/server/mock-range (server-only).
function mockRangeMiddleware(): {
  name: string;
  configureServer(server: {
    middlewares: { use: (p: string, h: (req: Request, res: Response, next: () => void) => void) => void };
    ssrLoadModule(url: string): Promise<Record<string, unknown>>;
  }): void;
} {
  return {
    name: "crimson-mock-range",
    configureServer(server) {
      server.middlewares.use("/mock-range", async (req, res, next) => {
        if (process.env.ENABLE_MOCK_RANGE === "0") {
          res.statusCode = 403;
          res.setHeader("content-type", "application/json");
          res.end(JSON.stringify({ error: "mock range disabled" }));
          return;
        }
        try {
          // Load via Vite's own SSR module runner: it resolves the project's
          // tsconfig paths (the `~` alias) and externalizes node builtins, so
          // mock-range.ts + store.ts load with their real imports intact. (A
          // raw dynamic import() from the bundled config context cannot
          // resolve `~` — that was the ERR_MODULE_NOT_FOUND failure.)
          const mod = (await server.ssrLoadModule("/src/server/mock-range.ts")) as unknown as {
            mockRange: () => { handle(req: Request): Promise<Response> };
          };
          const { mockRange } = mod;
          const body =
            req.method === "GET" || req.method === "HEAD"
              ? undefined
              : await new Promise<string>((resolve, reject) => {
                  const chunks: Buffer[] = [];
                  req.on("data", (c: Buffer) => chunks.push(c));
                  req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
                  req.on("error", reject);
                });
          const url = `${req.headers["x-forwarded-proto"] ?? "http"}://${req.headers.host ?? "localhost"}${req.url ?? ""}`;
          const webReq = new Request(url, {
            method: req.method,
            headers: req.headers as Record<string, string>,
            ...(body ? { body } : {}),
          });
          const webRes = await mockRange().handle(webReq);
          res.statusCode = webRes.status;
          webRes.headers.forEach((v, k) => res.setHeader(k, v));
          const text = await webRes.text();
          res.end(text);
        } catch (err) {
          console.error("[mock-range] failed", err);
          res.statusCode = 500;
          res.end("mock range error");
        }
      });
    },
  };
}

export default defineConfig({
  server: {
    port: 3000,
    host: true,
    // The site is reverse-proxied behind <label>.<PUBLIC_SITE_DOMAIN>; the proxy
    // masks the Host to localhost:3000, but accept any host so a dev server never
    // rejects a proxied request with "Blocked request".
    allowedHosts: true,
    // The dev server is reachable through the TLS proxy, so the HMR websocket
    // must dial back on 443, not the dev port. If the socket can't connect,
    // pages still serve — hot reload degrades, never breaks.
    hmr: { clientPort: 443 },
    // The dev server can serve source files; never let it serve local secrets,
    // and never let it serve anything outside the site dir. Gotchas this list
    // encodes: a custom `deny` REPLACES Vite's defaults (so .git must be
    // restated), patterns containing "/" match the ABSOLUTE path (so dir
    // patterns need a leading **/), and `allow` left to its default widens to
    // the nearest workspace root — a stray .git or workspaces package.json in
    // /home/team/shared would expose the whole shared dir.
    fs: {
      strict: true,
      allow: [import.meta.dirname],
      deny: [".env", ".env.*", "*.{crt,pem,key}", "**/.run/**", "**/.git/**"],
    },
  },
  plugins: [
    mockRangeMiddleware(),
    tailwindcss(),
    tsConfigPaths({
      projects: ["./tsconfig.json"],
    }),
    tanstackStart(),
    viteReact(),
  ],
});
