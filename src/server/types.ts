// ---------------------------------------------------------------------------
// Crimson Range — shared server types.
//
// IMPORTANT: this file must stay a PURE TYPE MODULE. It may not import
// anything from node builtins (fs/crypto/path) and may not import anything
// from `~/server/store` (or any other module). Client files import types only
// from here (`~/server/types`) so the node-only store module never leaks into
// the browser bundle. If you need a NEW type for server code, define it here
// and import it with `import type { ... } from "~/server/types"`.
// ---------------------------------------------------------------------------

export type Role = "STUDENT" | "AUTHOR" | "REVIEWER" | "ADMIN";
export type Difficulty = "Easy" | "Medium" | "Hard" | "Insane";
export type FlagType = "STATIC" | "DYNAMIC";

export interface User {
  id: string;
  username: string;
  role: Role;
  /** sha256("crimson-range:pw:v1:" + password). Demo seeds only — Phase 2 uses bcrypt/scrypt. */
  passwordHash: string;
  createdAt: number;
}

export interface SafeUser {
  id: string;
  username: string;
  role: Role;
}

export interface MitreRef {
  /** e.g. "T1059" or "T1558.003" */
  id: string;
  tactic: string;
}

export interface CveRef {
  id: string;
  note: string;
}

export interface FlagDef {
  id: string;
  name: string;
  points: number;
  /**
   * STATIC  — plaintext answer committed as a hash; verified via sha256 digest.
   * DYNAMIC — no static answer exists; the expected value is derived per user:
   *   hmachmac = HMAC-SHA256(secret, `${userId}:${challengeSlug}:${flagId}`)
   *   expected = "CR{" + hex(hmac).slice(0, 24) + "}"
   *   Secret: SERVER_SECRET env (dev fallback "crimson-range-dev-secret").
   *   Derivation is documented in functions.ts submitFlag.
   * STATIC keeps the original behavior (answerHash comparison).
   */
  flagType: FlagType;
  /** Present only for STATIC flags. DYNAMIC flags never carry a plaintext/hash answer. */
  answerHash?: string;
}

export interface Hint {
  id: string;
  title: string;
  body: string;
  /** Point cost acknowledged via confirm dialog before unlock. */
  cost: number;
}

export interface Artifact {
  name: string;
  kind: string;
  size: string;
  /** Stub URL for MVP — Phase 2 serves real downloads via the Range API. */
  url: string;
}

export interface Challenge {
  slug: string;
  title: string;
  category: "AI Red-Team" | "Active Directory" | "Web/API" | "Cloud" | "Kill-Chain";
  difficulty: Difficulty;
  author: string;
  /**
   * Optional instance lifetime in minutes from the challenge manifest (Phase 2
   * content field). When absent the portal falls back to 120 minutes (2h).
   * ONE 30-minute extension is allowed per instance (tracked via `extended`).
   */
  instanceTtlMinutes?: number;
  descriptionMd: string;
  objectives: string[];
  mitre: MitreRef[];
  cves: CveRef[];
  tags: string[];
  flags: FlagDef[];
  hints: Hint[];
  artifacts: Artifact[];
  writeupMd: string;
}

// ---- Client-safe projections (answer hashes and locked content stripped) ---

export interface ChallengeSummary {
  slug: string;
  title: string;
  category: Challenge["category"];
  difficulty: Difficulty;
  points: number;
  author: string;
  tags: string[];
  mitreIds: string[];
  solveCount: number;
  flagsTotal: number;
  flagsCaptured: number;
  solved: boolean;
  firstBlood: string | null;
}

export interface SafeFlag {
  id: string;
  name: string;
  points: number;
  captured: boolean;
  capturedAt: number | null;
}

export interface SafeHint {
  id: string;
  title: string;
  cost: number;
  unlocked: boolean;
  body: string | null;
}

export interface ChallengeDetail extends Omit<ChallengeSummary, "flagsCaptured"> {
  descriptionMd: string;
  objectives: string[];
  mitre: MitreRef[];
  cves: CveRef[];
  artifacts: Artifact[];
  flags: SafeFlag[];
  hints: SafeHint[];
  /** Only present once the viewer fully solved the challenge. */
  writeupMd: string | null;
  solvedAt: number | null;
}

export interface SolveRecord {
  userId: string;
  slug: string;
  flagId: string;
  at: number;
  /** Points actually awarded for this flag after hint-cost deduction at solve time. */
  pointsAwarded: number;
  /** Hint ids unlocked by this user on this challenge before this flag's solve. */
  hintsUsed: string[];
  /** Seconds from first instance start on this challenge to challenge completion. */
  timeToSolveSeconds: number | null;
  /** IP of the first submission against this challenge (for NEW_IP_MID_SOLVE). */
  firstIp: string | null;
}

export interface HintUnlock {
  userId: string;
  slug: string;
  hintId: string;
  at: number;
}

export type InstanceStatus = "running" | "stopped";

export interface InstanceRecord {
  userId: string;
  slug: string;
  status: InstanceStatus;
  /** Endpoint(s) returned by the Range API — Phase 2 proxies the Range API contract. */
  endpoint: string | null;
  expiresAt: number | null;
  updatedAt: number;
  note: string;
  /** Range API instance id (mock mints one; real infra returns one). */
  rangeInstanceId?: string;
  /** True once the single allowed +30min extension has been used. */
  extended?: boolean;
  /** Per-user DYNAMIC flag values minted by the mock — never shipped to the client. */
  dynamicFlags?: Record<string, string>;
}

export interface SessionRecord {
  token: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
}

export type SecurityEventType = "SHARING_SUSPECTED" | "BRUTEFORCE_SUSPECTED" | "NEW_IP_MID_SOLVE";

export interface SecurityEvent {
  type: SecurityEventType;
  userId: string;
  challengeSlug: string;
  /** Human-readable detail — NEVER contains flag values. */
  detail: string;
  ip: string | null;
  at: number;
}

/** Sliding-window rate-limit + brute-force + IP tracking for one user on one challenge. */
export interface ChallengeAttempt {
  userId: string;
  slug: string;
  /** Submission timestamps (ms) for the 60s sliding window. */
  recent: number[];
  /** Wrong-submission timestamps (ms) for the 5-minute brute-force window. */
  wrong: number[];
  /** First IP observed for this user on this challenge (NEW_IP_MID_SOLVE baseline). */
  firstIp: string | null;
}

export interface PersistedState {
  sessions: SessionRecord[];
  solves: SolveRecord[];
  hintUnlocks: HintUnlock[];
  instances: InstanceRecord[];
  securityEvents: SecurityEvent[];
  attempts: ChallengeAttempt[];
}

/**
 * Store contract — all portal data access goes through this interface. The
 * JSON-file implementation lives in `~/server/store` (node-only); swapping to
 * Postgres later means re-implementing these methods with SQL — no route or
 * component changes required. Pure type: safe to import from client code.
 */
export interface Store {
  listUsers(): Promise<SafeUser[]>;
  findUserByUsername(username: string): Promise<User | null>;
  getSafeUser(id: string): Promise<SafeUser | null>;
  verifyPassword(user: User, password: string): boolean;
  listUserIds(): string[];

  createSession(userId: string): Promise<SessionRecord>;
  getSession(token: string): Promise<SessionRecord | null>;
  destroySession(token: string): Promise<void>;

  listChallenges(): Promise<Challenge[]>;
  getChallenge(slug: string): Promise<Challenge | null>;

  getUserSolves(userId: string): Promise<SolveRecord[]>;
  getChallengeSolves(slug: string): Promise<SolveRecord[]>;
  submitSolve(
    userId: string,
    slug: string,
    flagId: string,
    extra?: { pointsAwarded: number; hintsUsed: string[]; timeToSolveSeconds: number | null; ip: string | null }
  ): Promise<{ ok: boolean; already: boolean; at: number }>;
  /** Points a user earned across all solves (excluding hint costs already deducted). */
  userPoints(userId: string): Promise<number>;

  getHintUnlocks(userId: string, slug: string): Promise<HintUnlock[]>;
  unlockHint(userId: string, slug: string, hintId: string): Promise<{ ok: boolean; already: boolean }>;

  getInstance(userId: string, slug: string): Promise<InstanceRecord | null>;
  setInstance(rec: InstanceRecord): Promise<void>;

  recentSolves(limit: number): Promise<Array<SolveRecord & { username: string; challengeTitle: string }>>;

  // --- Rate limiting / brute-force / IP tracking (scoring engine) ---
  /** Records an attempt; returns sliding-window + brute-force + IP results. */
  recordSubmissionAttempt(userId: string, slug: string, correct: boolean, ip: string | null): Promise<SubmissionAttemptResult>;

  // --- Security events ---
  recordSecurityEvent(ev: SecurityEvent): Promise<void>;
  listSecurityEvents(limit: number): Promise<SecurityEvent[]>;
}

// --- Scoring engine result types ---

// ---------------------------------------------------------------------------
// Range API contract (BRD §6). The portal NEVER touches Docker — every
// instance control call goes through the external Range API. The mock-range
// (src/server/mock-range.ts + dev middleware) implements this same contract so
// local/dev runs need no real infra. These types are PURE (no node imports).
// ---------------------------------------------------------------------------

export interface RangeEndpoint {
  /** Protocol/target label, e.g. "rdp", "ssh", "https". */
  kind: string;
  /** Hostname/IP the player dials, e.g. "10.13.37.10". */
  host: string;
  port: number;
}

export interface RangeProvisionRequest {
  challenge_slug: string;
  user_id: string;
  ttl_minutes: number;
}

export interface RangeInstance {
  instance_id: string;
  challenge_slug: string;
  user_id: string;
  /** Status from the range's perspective ("running" | "stopped"). */
  status: string;
  endpoints: RangeEndpoint[];
  /** Per-user flag values. DYNAMIC flags are minted server-side using the same
   *  HMAC derivation as `dynamicFlagValue` in store.ts, so submissions match. */
  flags: Array<{ flag_id: string; value: string }>;
  /** Epoch ms at which the range auto-tears the instance down. */
  expires_at: number;
}

export interface RangeApi {
  provision(req: RangeProvisionRequest): Promise<RangeInstance>;
  get(instanceId: string): Promise<RangeInstance>;
  extend(instanceId: string): Promise<RangeInstance>;
  destroy(instanceId: string): Promise<{ ok: boolean }>;
  reset(instanceId: string): Promise<RangeInstance>;
}

// --- Scoring engine result types ---

export interface SubmissionAttemptResult {
  rateLimited: boolean;
  retryAfterMs: number;
  bruteForced: boolean;
  newIpMidSolve: boolean;
}

export interface SubmitResult {
  ok: boolean;
  correct?: boolean;
  already?: boolean;
  error?: string;
  remainingFlags?: number;
  userPoints?: number;
  pointsAwarded?: number;
}

export interface RecentSolveRow extends SolveRecord {
  username: string;
  challengeTitle: string;
}

export interface AdminLeaderboardRow {
  userId: string;
  username: string;
  points: number;
}

export interface AdminRecentRow {
  userId: string;
  username: string;
  challengeTitle: string;
  slug: string;
  flagId: string;
  at: number;
  pointsAwarded: number;
}

export interface AdminOverview {
  users: SafeUser[];
  recent: AdminRecentRow[];
  events: SecurityEvent[];
  leaderboard: AdminLeaderboardRow[];
}