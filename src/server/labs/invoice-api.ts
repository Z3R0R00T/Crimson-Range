// ---------------------------------------------------------------------------
// Crimson Range — Invoice Inspector (bola-invoice-api) LIVE lab target.
//
// A genuinely hackable, in-process simulation of "Acme Billing API v2"
// served at /api/labs/invoice (vite middleware in dev, serve.ts in prod).
// No Docker, no placeholders: every endpoint below behaves like a real
// (vulnerable) production API — the player reaches for Burp/curl, and both
// flags are obtainable ONLY by exploiting the two real flaws:
//
//   1. BOLA on GET /v2/invoices/{id} — auth is required, ownership is NOT
//      checked. Any authenticated tenant can read any invoice.
//   2. POST /v2/admin/export trusts the client-supplied "role" field in the
//      JSON body instead of the bearer token's claims.
//
// Auth is "JWT-ish": tokens are HS256-SHAPED (3 dot segments) but the server
// NEVER verifies the signature — it only base64-decodes the payload and reads
// the `tenant` claim (mirrors real-world alg-confusion/unsigned-token bugs).
// The seeded pentest01 token carries tenant "acme.dev"; forged tokens with any
// payload shape are accepted as long as they parse. Login is rate limited
// (5/min/IP) so brute-forcing creds is a dead end — the BOLA reads are NOT
// rate limited so enumeration works.
//
// Flag values are fixture content OF the target (they must appear in API
// responses for the player to find them). Dev defaults below match the
// portal's STATIC answer hashes in store.ts so scoring stays in sync; prod
// can override via env. This module is server-only — never import it from
// client code (it pulls node:crypto into the browser bundle).
// ---------------------------------------------------------------------------

import { createHash, randomBytes } from "node:crypto";

// --- Flags (match store.ts STATIC answer hashes; env-overridable) -----------

const FLAG_INVOICE = process.env.LAB_INVOICE_FLAG1 ?? "CR{1d0r_1nv01c3_pwn3d}";
const FLAG_EXPORT = process.env.LAB_INVOICE_FLAG2 ?? "CR{b0l4_4dm1n_r3s3t}";

// --- Demo credential (lab-internal; the portal brief documents it) -----------

const DEMO_USER = "pentest01";
const DEMO_PASS = "Winter2026!";
const DEMO_TENANT = "acme.dev";
const TOKEN_TTL_SECONDS = 3600;

// --- Login rate limit: 5 attempts / minute / IP (brute-force shield) --------
const LOGIN_MAX = 5;
const LOGIN_WINDOW_MS = 60_000;
const loginHits = new Map<string, number[]>();

function loginRateLimited(ip: string): { limited: boolean; retryAfterMs: number } {
  const now = Date.now();
  const arr = (loginHits.get(ip) ?? []).filter((t) => now - t < LOGIN_WINDOW_MS);
  if (arr.length >= LOGIN_MAX) {
    loginHits.set(ip, arr);
    return { limited: true, retryAfterMs: Math.max(0, LOGIN_WINDOW_MS - (now - arr[0])) };
  }
  arr.push(now);
  loginHits.set(ip, arr);
  return { limited: false, retryAfterMs: 0 };
}

// ---------------------------------------------------------------------------
// Token minting (JWT-ish, HS256-shaped, signature NEVER verified by the API —
// that is the intended auth weakness; the payload is decoded and trusted).
// ---------------------------------------------------------------------------

const b64url = (buf: Buffer | string): string =>
  Buffer.from(buf).toString("base64url");

function mintToken(claims: Record<string, unknown>): string {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
      ...claims,
    })
  );
  // Deterministic-looking signature (fixture flavor — server never checks it).
  const sig = createHash("sha256").update(`${header}.${payload}`).digest("hex").slice(0, 32);
  return `${header}.${payload}.${sig}`;
}

interface TokenClaims {
  sub: string;
  tenant: string;
  role?: string;
  iat: number;
  exp: number;
}

/** Parse + validate a bearer token SHAPE; returns claims or an error code. */
function parseToken(token: string): { ok: true; claims: TokenClaims } | { ok: false; code: string; message: string } {
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { ok: false, code: "INVALID_TOKEN", message: "Bearer token is malformed." };
  }
  let payload: unknown;
  try {
    const json = Buffer.from(parts[1], "base64url").toString("utf8");
    payload = JSON.parse(json);
  } catch {
    return { ok: false, code: "INVALID_TOKEN", message: "Bearer token payload is not valid JSON." };
  }
  if (typeof payload !== "object" || payload === null) {
    return { ok: false, code: "INVALID_TOKEN", message: "Bearer token payload is not an object." };
  }
  const p = payload as Record<string, unknown>;
  if (typeof p.tenant !== "string" || p.tenant.length === 0 || p.tenant.length > 128) {
    return { ok: false, code: "INVALID_TOKEN", message: "Bearer token is missing the tenant claim." };
  }
  if (typeof p.sub !== "string" || p.sub.length === 0) {
    return { ok: false, code: "INVALID_TOKEN", message: "Bearer token is missing the subject claim." };
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof p.exp === "number" && p.exp < now) {
    return { ok: false, code: "INVALID_TOKEN", message: "Bearer token has expired." };
  }
  const exp = typeof p.exp === "number" ? p.exp : now + TOKEN_TTL_SECONDS;
  const iat = typeof p.iat === "number" ? p.iat : now;
  return {
    ok: true,
    claims: {
      sub: String(p.sub),
      tenant: p.tenant,
      role: typeof p.role === "string" ? p.role : "user",
      iat,
      exp,
    },
  };
}

/**
 * Per-user lab access handed to the portal at instance provision time. sub is
 * always the seeded demo user; tenant is the seeded demo tenant, so the token
 * the UI shows behaves exactly like the one a real login returns.
 */
export function labAccessFor(userId: string): { baseUrl: string; token: string } {
  return {
    baseUrl: "/api/labs/invoice/v2",
    token: mintToken({ sub: DEMO_USER, tenant: DEMO_TENANT, role: "user", uid: userId }),
  };
}

// ---------------------------------------------------------------------------
// Seeded invoice data — 3 tenants, 17 invoices, sequential ids 8990..9007
// (9000 was voided). All amounts computed, Gulf-region believable, AED.
// ---------------------------------------------------------------------------

interface LineItem {
  description: string;
  quantity: number;
  unit_price: number;
  vat_rate: number; // 0.05 = 5%
}
interface Party {
  name: string;
  vat_number: string;
  address: string;
}
interface Invoice {
  id: number;
  invoice_number: string;
  status: "paid" | "pending" | "overdue" | "voided";
  issue_date: string;
  due_date: string;
  currency: "AED";
  po_number: string;
  payment_terms: string;
  owner: Party & { id: string };
  bill_to: Party;
  line_items: LineItem[];
  subtotal: number;
  vat_total: number;
  total: number;
  notes: string | null;
}

const ROUND2 = (n: number): number => Math.round(n * 100) / 100;

function mkInvoice(
  id: number,
  owner: Party & { id: string },
  bill_to: Party,
  opts: {
    issue: string;
    terms: "Net 15" | "Net 30" | "Net 45" | "Net 60";
    po: string;
    status: Invoice["status"];
    lines: LineItem[];
    notes?: string;
  }
): Invoice {
  const subtotal = ROUND2(opts.lines.reduce((s, l) => s + l.quantity * l.unit_price, 0));
  const vat_total = ROUND2(opts.lines.reduce((s, l) => s + l.quantity * l.unit_price * l.vat_rate, 0));
  const dueDays = opts.terms === "Net 15" ? 15 : opts.terms === "Net 30" ? 30 : opts.terms === "Net 45" ? 45 : 60;
  const due = new Date(Date.parse(opts.issue) + dueDays * 86_400_000).toISOString().slice(0, 10);
  return {
    id,
    invoice_number: `INV-2026-${id}`,
    status: opts.status,
    issue_date: opts.issue,
    due_date: due,
    currency: "AED",
    po_number: opts.po,
    payment_terms: opts.terms,
    owner,
    bill_to,
    line_items: opts.lines,
    subtotal,
    vat_total,
    total: ROUND2(subtotal + vat_total),
    notes: opts.notes ?? null,
  };
}

const acme = {
  id: "acme.dev",
  name: "Acme Billing FZ-LLC",
  vat_number: "AE400123456789123",
  address: "Building 5, Dubai Internet City, Dubai, UAE",
};
const gulfMarine = {
  id: "gulf-marine.ae",
  name: "Gulf Marine Contracting W.L.L",
  vat_number: "AE300987654321456",
  address: "Mussafah Industrial Area M-42, Abu Dhabi, UAE",
};
const falcon = {
  id: "falcon-logistics.ae",
  name: "Falcon Logistics L.L.C",
  vat_number: "AE401234567890987",
  address: "Warehouse 14, Jebel Ali Free Zone, Dubai, UAE",
};

const custAlNoor = { name: "Al Noor Trading Est.", vat_number: "AE500556677889900", address: "Al Qasimia, Sharjah, UAE" };
const custEmiratesHealth = { name: "Emirates Healthcare Group LLC", vat_number: "AE400112233445566", address: "Al Karama, Dubai, UAE" };
const custQasr = { name: "Qasr Al Bahr Facilities Management", vat_number: "AE300778899001122", address: "Corniche Road, Abu Dhabi, UAE" };
const custDxbRetail = { name: "DXB Retail Holdings FZ-LLC", vat_number: "AE401122334455667", address: "Dubai Mall, Downtown Dubai, UAE" };
const custGulfAirlines = { name: "Gulf Sky Aviation Services", vat_number: "AE300443322110099", address: "Cargo Village, DXB Airport, Dubai, UAE" };
const custSharjahPort = { name: "Sharjah Port Services Co.", vat_number: "AE500998877665544", address: "Port Khalid, Sharjah, UAE" };
const custAlMasa = { name: "Al Masa Foodstuff Trading", vat_number: "AE500123123123123", address: "Naif Souq, Deira, Dubai, UAE" };
const custRasGas = { name: "Ras Al Khaimah Gas Industries", vat_number: "AE200556644332211", address: "Al Hamra Industrial Zone, RAK, UAE" };

const INVOICES: Invoice[] = [
  // ---- Gulf Marine Contracting (tenant B): 8990-8994 -----------------------
  mkInvoice(8990, gulfMarine, custQasr, {
    issue: "2026-05-04", terms: "Net 45", po: "PO-QB-2026-0117", status: "paid",
    lines: [
      { description: "Fabrication & erection — structural steel (tonne)", quantity: 42, unit_price: 6850, vat_rate: 0.05 },
      { description: "Crane hire — 250T mobile (day)", quantity: 6, unit_price: 12500, vat_rate: 0.05 },
      { description: "Site electrical containment works (lot)", quantity: 1, unit_price: 148750, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(8991, gulfMarine, custQasr, {
    issue: "2026-05-19", terms: "Net 45", po: "PO-QB-2026-0124", status: "paid",
    lines: [
      { description: "Project management services (month)", quantity: 2, unit_price: 48500, vat_rate: 0.05 },
      { description: "Survey & setting-out works (lot)", quantity: 1, unit_price: 31200, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(8992, gulfMarine, custSharjahPort, {
    issue: "2026-06-08", terms: "Net 30", po: "PO-SP-2026-0021", status: "paid",
    lines: [
      { description: "Marine bollard installation — berth 4 (unit)", quantity: 18, unit_price: 9200, vat_rate: 0.05 },
      { description: "Diving inspection & NDT (day)", quantity: 4, unit_price: 7600, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(8993, gulfMarine, custAlMasa, {
    issue: "2026-07-02", terms: "Net 30", po: "PO-AM-2026-0088", status: "overdue",
    lines: [
      { description: "Cold storage extension — civil works (lot)", quantity: 1, unit_price: 265000, vat_rate: 0.05 },
      { description: "Fire-rated partition installation (sqm)", quantity: 340, unit_price: 315, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(8994, gulfMarine, custRasGas, {
    issue: "2026-07-21", terms: "Net 60", po: "PO-RG-2026-0055", status: "pending",
    lines: [
      { description: "Piping stress analysis (hrs)", quantity: 96, unit_price: 480, vat_rate: 0.05 },
      { description: "Hydraulic testing — pipe spools (lot)", quantity: 1, unit_price: 89400, vat_rate: 0.05 },
      { description: "As-built documentation pack (lot)", quantity: 1, unit_price: 18500, vat_rate: 0.0 },
    ],
  }),

  // ---- Falcon Logistics (tenant C): 8995-8999 (8996 voided) -----------------
  mkInvoice(8995, falcon, custGulfAirlines, {
    issue: "2026-06-03", terms: "Net 30", po: "PO-GS-2026-0133", status: "paid",
    lines: [
      { description: "Container freight — DXB to AUH, 40ft (unit)", quantity: 8, unit_price: 4250, vat_rate: 0.05 },
      { description: "Customs clearance services (consignment)", quantity: 8, unit_price: 950, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(8996, falcon, custGulfAirlines, {
    issue: "2026-06-11", terms: "Net 30", po: "PO-GS-2026-0139", status: "voided",
    lines: [{ description: "Chartered freighter — auxiliary legs (hrs)", quantity: 12, unit_price: 11500, vat_rate: 0.05 }],
    notes: "Voided — duplicate of INV-2026-8995; finance to reverse GL entry.",
  }),
  mkInvoice(8997, falcon, custDxbRetail, {
    issue: "2026-06-24", terms: "Net 15", po: "PO-DX-2026-0202", status: "overdue",
    lines: [
      { description: "Warehousing — climate controlled (pallet/month)", quantity: 120, unit_price: 275, vat_rate: 0.05 },
      { description: "Last-mile delivery — Dubai metro area (stop)", quantity: 460, unit_price: 38, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(8998, falcon, custEmiratesHealth, {
    issue: "2026-07-14", terms: "Net 45", po: "PO-EH-2026-0091", status: "pending",
    lines: [
      { description: "Medical cold-chain transport — DXB to AUH (trip)", quantity: 22, unit_price: 1380, vat_rate: 0.05 },
      { description: "Temperature data logger rental (unit/day)", quantity: 66, unit_price: 95, vat_rate: 0.05 },
      { description: "GxP documentation & release pack (lot)", quantity: 1, unit_price: 24000, vat_rate: 0.0 },
    ],
  }),
  mkInvoice(8999, falcon, custEmiratesHealth, {
    issue: "2026-08-05", terms: "Net 45", po: "PO-EH-2026-0103", status: "pending",
    lines: [
      { description: "Cold-chain consolidation — June/July (lot)", quantity: 1, unit_price: 312500, vat_rate: 0.05 },
      { description: "Reefer container storage (unit/day)", quantity: 14, unit_price: 320, vat_rate: 0.05 },
    ],
    notes:
      `Credit note CN-2026-031 pending finance review. ` +
      `Hold payment until legal closes dispute reference ${FLAG_INVOICE} — ` +
      `duplicate chargeback on the June freight consolidation.`,
  }),

  // ---- Acme Billing (tenant A, demo account): 9001-9007 --------------------
  mkInvoice(9001, acme, custDxbRetail, {
    issue: "2026-02-10", terms: "Net 30", po: "PO-DX-2025-0441", status: "paid",
    lines: [
      { description: "SaaS license — Billing Suite Pro (annual)", quantity: 12, unit_price: 1450, vat_rate: 0.05 },
      { description: "Implementation & onboarding (day)", quantity: 6, unit_price: 3800, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(9002, acme, custDxbRetail, {
    issue: "2026-03-02", terms: "Net 30", po: "PO-DX-2025-0447", status: "paid",
    lines: [
      { description: "Premium support retainer (month)", quantity: 3, unit_price: 2600, vat_rate: 0.05 },
      { description: "API overage — 1.4M calls (block)", quantity: 1, unit_price: 5800, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(9003, acme, custAlNoor, {
    issue: "2026-04-07", terms: "Net 30", po: "PO-AN-2026-0105", status: "paid",
    lines: [
      { description: "SaaS license — Billing Suite Starter (annual)", quantity: 5, unit_price: 1180, vat_rate: 0.05 },
      { description: "Training — admin console (session)", quantity: 2, unit_price: 2900, vat_rate: 0.0 },
    ],
  }),
  mkInvoice(9004, acme, custAlNoor, {
    issue: "2026-05-12", terms: "Net 30", po: "PO-AN-2026-0119", status: "overdue",
    lines: [
      { description: "Premium support retainer (month)", quantity: 2, unit_price: 2600, vat_rate: 0.05 },
      { description: "Custom report pack — IFRS15 (lot)", quantity: 1, unit_price: 15400, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(9005, acme, custQasr, {
    issue: "2026-06-16", terms: "Net 45", po: "PO-QB-2026-0117-A", status: "paid",
    lines: [
      { description: "Enterprise license — Billing Suite Pro (annual)", quantity: 24, unit_price: 1450, vat_rate: 0.05 },
      { description: "Private instance hosting (month)", quantity: 12, unit_price: 3200, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(9006, acme, custEmiratesHealth, {
    issue: "2026-07-20", terms: "Net 45", po: "PO-EH-2026-0144", status: "pending",
    lines: [
      { description: "Solutions architect engagement (hrs)", quantity: 40, unit_price: 620, vat_rate: 0.05 },
      { description: "SAML SSO configuration (lot)", quantity: 1, unit_price: 9600, vat_rate: 0.05 },
    ],
  }),
  mkInvoice(9007, acme, custEmiratesHealth, {
    issue: "2026-08-18", terms: "Net 45", po: "PO-EH-2026-0160", status: "pending",
    lines: [
      { description: "SaaS license — Billing Suite Pro (annual)", quantity: 18, unit_price: 1450, vat_rate: 0.05 },
      { description: "Premium support retainer (month)", quantity: 1, unit_price: 2600, vat_rate: 0.05 },
      { description: "API overage — 2.1M calls (block)", quantity: 1, unit_price: 8400, vat_rate: 0.05 },
    ],
  }),
];

const INVOICE_INDEX = new Map<number, Invoice>(INVOICES.map((i) => [i.id, i]));

// ---------------------------------------------------------------------------
// Route manifest — the single source of truth for the OpenAPI artifact, the
// /v2/openapi.json endpoint, and the recon-notes artifact ("generated from the
// live routes").
// ---------------------------------------------------------------------------

interface RouteMeta {
  method: "GET" | "POST";
  path: string;
  summary: string;
  tag: string;
  auth: boolean;
}
const ROUTE_MANIFEST: RouteMeta[] = [
  { method: "GET", path: "/v2/health", summary: "Service health, version and uptime", tag: "System", auth: false },
  { method: "POST", path: "/v2/auth/login", summary: "Authenticate with credentials and receive a bearer token", tag: "Auth", auth: false },
  { method: "GET", path: "/v2/openapi.json", summary: "OpenAPI 3.0 specification for this service", tag: "System", auth: false },
  { method: "GET", path: "/v2/invoices", summary: "List invoices for the authenticated tenant", tag: "Invoices", auth: true },
  { method: "GET", path: "/v2/invoices/{invoice_id}", summary: "Fetch a single invoice by id", tag: "Invoices", auth: true },
  { method: "POST", path: "/v2/admin/export", summary: "Export the full invoice archive (administrator only)", tag: "Admin", auth: true },
];

function buildOpenApiJson(): Record<string, unknown> {
  const paths: Record<string, unknown> = {};
  for (const r of ROUTE_MANIFEST) {
    paths[r.path] = {
      [r.method.toLowerCase()]: {
        operationId: `${r.method.toLowerCase()}_${r.path.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_|_$/g, "")}`,
        summary: r.summary,
        tags: [r.tag],
        ...(r.auth ? { security: [{ bearerAuth: [] }] } : {}),
        responses: {
          "200": { description: "Successful response" },
          "401": { description: "Authentication required or token invalid" },
          "404": { description: "Resource not found" },
        },
      },
    };
  }
  return {
    openapi: "3.0.3",
    info: {
      title: "Acme Billing API",
      description: "Billing and invoicing API v2 — private service.",
      version: "2.4.1",
    },
    servers: [{ url: "/api/labs/invoice/v2", description: "Engagement target" }],
    paths,
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      },
    },
  };
}

function yamlScalar(s: string): string {
  return /^[A-Za-z0-9 .,'()/-]+$/.test(s) ? s : JSON.stringify(s);
}

function buildOpenApiYaml(): string {
  const doc = buildOpenApiJson();
  const lines: string[] = [
    `openapi: ${doc.openapi}`,
    "info:",
    `  title: ${yamlScalar((doc.info as { title: string }).title)}`,
    `  description: ${yamlScalar((doc.info as { description: string }).description)}`,
    `  version: ${(doc.info as { version: string }).version}`,
    "servers:",
    "  - url: /api/labs/invoice/v2",
    "    description: Engagement target",
    "paths:",
  ];
  const order = [...ROUTE_MANIFEST.map((r) => r.path)], 
    seen = new Set<string>();
  for (const p of order) {
    if (seen.has(p)) continue;
    seen.add(p);
    const methods = (doc.paths as Record<string, Record<string, unknown>>)[p];
    lines.push(`  ${p}:`);
    for (const [m, op] of Object.entries(methods)) {
      const o = op as { summary: string; tags: string[] };
      lines.push(`    ${m}:`);
      lines.push(`      operationId: ${m}_${p.replace(/[^a-zA-Z0-9]+/g, "_").replace(/^_|_$/g, "")}`);
      lines.push(`      summary: ${yamlScalar(o.summary)}`);
      lines.push(`      tags:`);
      for (const t of o.tags) lines.push(`        - ${yamlScalar(t)}`);
      if (o.security) lines.push(`      security:\n        - bearerAuth: []`);
      lines.push(`      responses:`);
      lines.push(`        "200":\n          description: Successful response`);
      lines.push(`        "401":\n          description: Authentication required or token invalid`);
      lines.push(`        "404":\n          description: Resource not found`);
    }
  }
  lines.push(
    "components:",
    "  securitySchemes:",
    "    bearerAuth:",
    "      type: http",
    "      scheme: bearer",
    "      bearerFormat: JWT"
  );
  return lines.join("\n") + "\n";
}

function buildReconNotes(): string {
  const lines: string[] = [
    "Acme Billing API v2 — initial reconnaissance notes",
    "===============================================",
    "Engagement target base: /api/labs/invoice/v2",
    "Service banner: acme-billing-api v2.4.1 (GET /v2/health)",
    "",
    "Auth",
    "----",
    "POST /v2/auth/login {username, password} -> {token: ...}",
    "All other endpoints require: Authorization: Bearer <token>",
    "Tokens are JWT-shaped (3 dot-delimited segments, base64 payload).",
    "* TODO: verify signature validation before trusting the tenant claim.",
    "",
    "Endpoints observed",
    "------------------",
    ...ROUTE_MANIFEST.map((r) => `${r.method.padEnd(4)} ${r.path} — ${r.summary}${r.auth ? " [auth]" : ""}`),
    "",
    "Field notes",
    "-----------",
    "* Invoice ids look sequential in the 8990-9010 range; some ids 404 (voided).",
    "* /v2/admin/export 403s without an admin role — need to map how the role is",
    "  resolved server-side (token claim vs request body?).",
    "* OpenAPI spec is served unauthenticated at /v2/openapi.json (see acme-api-v2.yaml).",
  ];
  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Response helpers (realistic framework-shaped envelope + errors).
// ---------------------------------------------------------------------------

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "cache-control": "no-store",
    },
  });
}
function err(code: string, message: string, status: number, extra?: Record<string, unknown>): Response {
  return json({ error: { code, message, ...extra } }, status);
}
function text(body: string, contentType: string): Response {
  return new Response(body, {
    status: 200,
    headers: { "content-type": contentType, "cache-control": "no-store" },
  });
}

// ---------------------------------------------------------------------------
// Request routing + handlers
// ---------------------------------------------------------------------------

function clientIp(req: Request): string {
  return (
    (req.headers.get("x-forwarded-for") ?? "").split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "direct"
  );
}

function bearerOf(req: Request): { ok: true; token: string } | { ok: false; response: Response } {
  const h = req.headers.get("authorization");
  if (!h) {
    return { ok: false, response: err("AUTH_REQUIRED", "Authentication required. Provide a Bearer token in the Authorization header.", 401) };
  }
  const m = /^Bearer\s+(\S+)$/i.exec(h.trim());
  if (!m) {
    return { ok: false, response: err("INVALID_AUTH_HEADER", "Authorization header must use the 'Bearer <token>' scheme.", 401) };
  }
  return { ok: true, token: m[1] };
}

async function readJsonBody(req: Request): Promise<{ ok: true; value: Record<string, unknown> } | { ok: false; response: Response }> {
  try {
    const raw = await req.text();
    if (!raw.trim()) return { ok: false, response: err("INVALID_JSON", "Request body is required and must be valid JSON.", 400) };
    const value = JSON.parse(raw);
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return { ok: false, response: err("INVALID_JSON", "Request body must be a JSON object.", 400) };
    }
    return { ok: true, value: value as Record<string, unknown> };
  } catch {
    return { ok: false, response: err("INVALID_JSON", "Request body is not valid JSON.", 400) };
  }
}

interface LabApi {
  handle(req: Request): Promise<Response>;
}

export function invoiceApi(): LabApi {
  async function handle(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const method = req.method;
    // Accept the full public path AND the middleware-stripped path.
    const base = "/api/labs/invoice";
    let p = url.pathname;
    if (p.startsWith(base)) p = p.slice(base.length) || "/";
    if (!p.startsWith("/")) p = "/" + p;

    const m = p.match(/^\/v2\/invoices\/(\d+)$/);
    if (m && method === "GET") return handleInvoiceRead(req, Number(m[1]));
    if (m) return methodNotAllowed(["GET"]);

    switch (p) {
      case "/v2/health":
        if (method !== "GET") return methodNotAllowed(["GET"]);
        return json({
          status: "ok",
          service: "acme-billing-api",
          version: "2.4.1",
          uptime_seconds: Math.floor(process.uptime()),
          time: new Date().toISOString(),
        });
      case "/v2/auth/login":
        if (method !== "POST") return methodNotAllowed(["POST"]);
        return handleLogin(req);
      case "/v2/invoices":
        if (method !== "GET") return methodNotAllowed(["GET"]);
        return handleInvoiceList(req);
      case "/v2/admin/export":
        if (method !== "POST") return methodNotAllowed(["POST"]);
        return handleExport(req);
      case "/v2/openapi.json":
        if (method !== "GET") return methodNotAllowed(["GET"]);
        return json(buildOpenApiJson());
      case "/artifacts/acme-api-v2.yaml":
        if (method !== "GET") return methodNotAllowed(["GET"]);
        return text(buildOpenApiYaml(), "application/yaml; charset=utf-8");
      case "/artifacts/recon-notes.txt":
        if (method !== "GET") return methodNotAllowed(["GET"]);
        return text(buildReconNotes(), "text/plain; charset=utf-8");
      default:
        return err("NOT_FOUND", `No route matches ${method} ${p}.`, 404);
    }
  }

  function methodNotAllowed(allowed: string[]): Response {
    const res = err("METHOD_NOT_ALLOWED", `Method not allowed for this endpoint.`, 405);
    res.headers.set("allow", allowed.join(", "));
    return res;
  }

  function authed(req: Request): { ok: true; claims: TokenClaims } | { ok: false; response: Response } {
    const bearer = bearerOf(req);
    if (!bearer.ok) return bearer;
    const parsed = parseToken(bearer.token);
    if (!parsed.ok) return { ok: false, response: err(parsed.code, parsed.message, 401) };
    return { ok: true, claims: parsed.claims };
  }

  async function handleLogin(req: Request): Promise<Response> {
    const ip = clientIp(req);
    const rl = loginRateLimited(ip);
    if (rl.limited) {
      const retry = Math.max(1, Math.ceil(rl.retryAfterMs / 1000));
      const res = err("RATE_LIMITED", `Too many login attempts. Try again in ${retry} seconds.`, 429);
      res.headers.set("retry-after", String(retry));
      return res;
    }
    const body = await readJsonBody(req);
    if (!body.ok) return body.response;
    const { value } = body;
    const allowed = ["username", "password"];
    for (const k of Object.keys(value)) {
      if (!allowed.includes(k)) {
        return err("VALIDATION_ERROR", `Unexpected field "${k}".`, 422);
      }
    }
    const username = value.username;
    const password = value.password;
    if (typeof username !== "string" || typeof password !== "string" || username.length === 0 || password.length === 0) {
      return err("VALIDATION_ERROR", "username and password are required.", 422);
    }
    if (username !== DEMO_USER || password !== DEMO_PASS) {
      return err("INVALID_CREDENTIALS", "Invalid username or password.", 401);
    }
    const token = mintToken({ sub: DEMO_USER, tenant: DEMO_TENANT, role: "user" });
    return json({
      token,
      token_type: "Bearer",
      expires_in: TOKEN_TTL_SECONDS,
      user: { username: DEMO_USER, tenant: DEMO_TENANT, role: "user" },
    }, 200);
  }

  function handleInvoiceList(req: Request): Response {
    const a = authed(req);
    if (!a.ok) return a.response;
    const mine = INVOICES
      .filter((i) => i.owner.id === a.claims.tenant && i.status !== "voided")
      .map((i) => summaryOf(i));
    return json({
      data: mine,
      meta: { count: mine.length, tenant: a.claims.tenant },
    });
  }

  function handleInvoiceRead(req: Request, id: number): Response {
    const a = authed(req);
    if (!a.ok) return a.response;
    // BOLA: authentication is enforced, but ownership is NEVER checked — any
    // authenticated tenant can read any invoice id. (INTENDED FLAW 1.)
    const inv = INVOICE_INDEX.get(id);
    if (!inv || inv.status === "voided") {
      return err("NOT_FOUND", `Invoice ${id} was not found or has been voided.`, 404);
    }
    return json({ data: inv });
  }

  async function handleExport(req: Request): Promise<Response> {
    const a = authed(req);
    if (!a.ok) return a.response;
    const body = await readJsonBody(req);
    if (!body.ok) return body.response;
    const { value } = body;
    // INTENDED FLAW 2: the authorization decision trusts the client-supplied
    // "role" field in the JSON body instead of the token claims.
    if (value.role !== "admin") {
      return err("FORBIDDEN", "This endpoint requires an administrator role.", 403);
    }
    const rows = INVOICES
      .filter((i) => i.status !== "voided")
      .map((i) => ({
        record_type: "invoice",
        id: i.id,
        invoice_number: i.invoice_number,
        tenant: i.owner.id,
        customer: i.bill_to.name,
        issue_date: i.issue_date,
        total: i.total,
        currency: i.currency,
      }));
    return json({
      export_id: `exp_${randomBytes(6).toString("hex")}`,
      format: "full-audit",
      generated_at: new Date().toISOString(),
      generated_by: a.claims.sub,
      record_count: rows.length + 1,
      records: [
        ...rows,
        {
          record_type: "service_account",
          account: "svc.billing-sync",
          scope: "invoices:read, reports:write",
          status: "active",
          // The admin seed record — holds the second flag (fixture target data).
          secret: FLAG_EXPORT,
          note: "rotated 2026-08-01; wire via secrets manager",
        },
      ],
    });
  }

  function summaryOf(i: Invoice): unknown {
    return {
      id: i.id,
      invoice_number: i.invoice_number,
      status: i.status,
      issue_date: i.issue_date,
      due_date: i.due_date,
      total: i.total,
      currency: i.currency,
      bill_to: i.bill_to.name,
    };
  }

  return { handle };
}