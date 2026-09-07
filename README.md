# Crimson Range — Red-Team CTF Portal

Challenge catalogue, flag submission, scoring, and leaderboards for AI red-team,
Active Directory, web/API, cloud, and kill-chain labs.

**Stack:** TanStack Start (React + Vite + Tailwind), TypeScript, server functions,
JSON-file store behind a `Store` interface (swappable for Postgres later).

**Status:** MVP skeleton (Sept 2026). Auth with roles, challenge catalogue with
filters, challenge detail pages, stub instance controls, stub flag checks, seed data.
No Docker, no dynamic flags yet — that's Phase 2. The platform never touches Docker
directly: all instance control goes through the Range API contract (see plan).

## Run it

```bash
bun install
bun run dev      # serves on :3000
bun run build    # production build check
```

## Demo logins (MVP seeds only)

- student: `neo / crimson-neo`
- student: `trinity / crimson-trinity`
- admin: `admin / crimson-admin`

## Layout

- `src/routes/` — pages: `/`, `/login`, `/challenges`, `/challenges/$slug`, `/admin`
- `src/server/store.ts` — data layer + seed challenges
- `src/server/functions.ts` — server functions (auth, flags, hints, stub instances)
- `src/components/shell.tsx` — dark terminal theme shell
