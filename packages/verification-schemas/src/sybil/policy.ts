/**
 * The plan policy: one versioned document per (provider, plan), the operator's levers for an active sybil attack
 * (provider-fact specification §2.1, §4; identity policy specification §1).
 *
 * Persisted by the identity (apps/api/src/plan-policy), administered by `plan-admin.ts`, published **verbatim** under
 * `policy` in `/verification-config` as a {@link PlanPolicySet}, and read by the app to explain its rules. No field
 * here is a secret, and none is a timelock: a change is instant.
 *
 * Units: `updatedAt`/`pausedAt` are epoch **milliseconds** (the identity ledger's unit); `createdBefore` as a number is
 * unix **seconds** (chain time, like `launchTs`).
 */
import {isProviderId, type BillingPlatform, type ProviderId, BILLING_PLATFORMS} from "./facts.ts";

export const PLAN_POLICY_FORMAT = "pines-plan-policy-v1";
export const PLAN_POLICY_SET_FORMAT = "pines-plan-policy-set-v1";

/**
 * The plan keys per provider, as `packages/chain/src/subscription-plans.ts` spells them. Duplicated here because this
 * package has no dependencies and is imported by the browser; `apps/api/src/plan-policy/parity.test.ts` pins the two
 * tables together. Keep every list closed (owner: no ChatGPT Go, no Grok $8 tier).
 */
export const PLAN_KEYS: Readonly<Record<ProviderId, readonly string[]>> = Object.freeze({
  chatgpt: Object.freeze(["plus", "pro", "prolite", "promax"]),
  claude: Object.freeze(["pro", "max"]),
  grok: Object.freeze(["premium-plus", "supergrok-lite", "supergrok", "supergrok-plus", "supergrok-pro"]),
});
export const isPlanKey = (provider: ProviderId, plan: unknown): plan is string => typeof plan === "string" && PLAN_KEYS[provider].includes(plan);

export type EmailChallenge = "off" | "flagged" | "all";
export const EMAIL_CHALLENGES = Object.freeze(["off", "flagged", "all"] as const);
/** Rules on the receipt's facts. A fact a receipt lacks is not evaluated (identity policy specification §4). */
export type PlanRules = Readonly<{
  /**
   * The snapshot rule (S5): the account's tenure fact must predate the launch. `"launch"` compares with the drop's
   * `launchTs`; a number is an absolute unix-seconds cutoff; `"off"` disables it for the plan.
   */
  createdBefore: "launch" | "off" | number;
  /** Minimum age of the tenure fact in days (S5: platform default 30; a launch may raise it, see {@link LaunchPolicy}). */
  minTenureDays: number;
  /** `"used"` requires a usage bucket other than `none`. */
  usage: "any" | "used";
  billingDeny: readonly BillingPlatform[];
}>;
export type Throttles = Readonly<{
  /** ISO 3166-1 alpha-2, upper case, from the connection (GeoLite2), never from a provider. */
  countryDeny: readonly string[];
  asnDeny: readonly number[];
  /** Verification starts per network (one address bucket, counted by its keyed hash) per hour, or `null` for the process-wide admission limits alone. */
  perNetworkRate: number | null;
}>;
/** `networks` entries are `asn:<number>` or the keyed hash of an address bucket ({@link NETWORK}); never an address. */
export type Quarantine = Readonly<{subjects: readonly string[]; wallets: readonly string[]; networks: readonly string[]}>;
export type PlanPolicy = Readonly<{
  format: typeof PLAN_POLICY_FORMAT;
  provider: ProviderId; plan: string;
  paused: boolean; reason: string | null; pausedAt: number | null;
  /** Receipts of this plan under a schema version below this are not claimable (S3). 0 means none. */
  minSchemaVersion: number;
  /** S1: `all` once the e-mail fact exists; relaxable to `flagged` or `off`. */
  emailChallenge: EmailChallenge;
  rules: PlanRules; throttles: Throttles; quarantine: Quarantine;
  /** S6: claims per subject per rolling window, counted at the co-signature. */
  subjectClaimBudget: Readonly<{count: number; windowDays: number}>;
  /** S6: claims per launch per hour as basis points of the launch's `maxClaims`; 1,000 = a tenth. */
  launchClaimRate: Readonly<{perHourBpsOfCap: number}>;
  version: number; updatedAt: number;
}>;
/** A per-launch override the operator sets for a drop: today only the platform drop's 90 days (S5). */
export type LaunchPolicy = Readonly<{claimContract: string; minTenureDays: number; note: string | null}>;
export type PlanPolicySet = Readonly<{
  format: typeof PLAN_POLICY_SET_FORMAT;
  /** The highest `version` among the plans, or 0 for an untouched set; the app refetches on a change. */
  version: number; updatedAt: number;
  /** The document every unlisted (provider, plan) is governed by. */
  defaults: Omit<PlanPolicy, "format" | "provider" | "plan" | "version" | "updatedAt" | "paused" | "reason" | "pausedAt">;
  plans: readonly PlanPolicy[];
  launches: readonly LaunchPolicy[];
}>;

export class PlanPolicyError extends Error {
  readonly code: string;
  constructor(code: string) {super(code); this.code = code;}
}
function fail(condition: unknown, code = "PLAN_POLICY_INVALID"): asserts condition {if (!condition) throw new PlanPolicyError(code);}
const integer = (value: unknown, min: number, max: number): number => {
  fail(typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max); return value;
};
const record = (value: unknown): Record<string, unknown> => {fail(value && typeof value === "object" && !Array.isArray(value)); return value as Record<string, unknown>;};
const exact = (value: Record<string, unknown>, keys: readonly string[]) => {
  const present = Object.keys(value); fail(present.length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key)), "PLAN_POLICY_FIELDS");
};
function strings(value: unknown, pattern: RegExp, max = 1024): readonly string[] {
  fail(Array.isArray(value) && value.length <= max && value.every(item => typeof item === "string" && pattern.test(item)));
  fail(new Set(value).size === value.length, "PLAN_POLICY_DUPLICATE"); return Object.freeze([...value as string[]]);
}
export const COUNTRY = /^[A-Z]{2}$/, SUBJECT = /^0x[0-9a-f]{64}$/, WALLET = /^0x[0-9a-f]{40}$/;
/**
 * A quarantine `networks` entry: `asn:<number>`, or the **keyed hash** of an address bucket — 64 lower-case hex, the
 * identity's `HMAC-SHA256(rate key, "sybil-network:" + bucket)` (`apps/api/src/plan-policy/network.ts`). A raw address
 * or bucket is refused: the set is published under `/verification-config`, and the identity keeps no address
 * (apps/web-next `legal-privacy.ts`: "the verification records hold the hash, not the address"). `plan-admin` hashes a
 * raw address an operator types before it is stored.
 */
export const NETWORK = /^(?:asn:[1-9][0-9]{0,9}|[0-9a-f]{64})$/;

export function parsePlanRules(raw: unknown): PlanRules {
  const value = record(raw); exact(value, ["createdBefore", "minTenureDays", "usage", "billingDeny"]);
  fail(value.createdBefore === "launch" || value.createdBefore === "off" || (typeof value.createdBefore === "number" && Number.isSafeInteger(value.createdBefore) && value.createdBefore > 0 && value.createdBefore < 4_102_444_800));
  fail(value.usage === "any" || value.usage === "used");
  const billingDeny = strings(value.billingDeny, /^[a-z]+$/, BILLING_PLATFORMS.length);
  fail(billingDeny.every(platform => (BILLING_PLATFORMS as readonly string[]).includes(platform)));
  return Object.freeze({createdBefore: value.createdBefore as PlanRules["createdBefore"], minTenureDays: integer(value.minTenureDays, 0, 3650), usage: value.usage, billingDeny: billingDeny as readonly BillingPlatform[]});
}
export function parseThrottles(raw: unknown): Throttles {
  const value = record(raw); exact(value, ["countryDeny", "asnDeny", "perNetworkRate"]);
  fail(Array.isArray(value.asnDeny) && value.asnDeny.length <= 4096 && value.asnDeny.every(asn => typeof asn === "number" && Number.isSafeInteger(asn) && asn > 0 && asn <= 4_294_967_295));
  fail(new Set(value.asnDeny as number[]).size === (value.asnDeny as number[]).length, "PLAN_POLICY_DUPLICATE");
  fail(value.perNetworkRate === null || (typeof value.perNetworkRate === "number" && Number.isSafeInteger(value.perNetworkRate) && value.perNetworkRate >= 1 && value.perNetworkRate <= 1_000_000));
  return Object.freeze({countryDeny: strings(value.countryDeny, COUNTRY, 250), asnDeny: Object.freeze([...value.asnDeny as number[]]), perNetworkRate: value.perNetworkRate as number | null});
}
export function parseQuarantine(raw: unknown): Quarantine {
  const value = record(raw); exact(value, ["subjects", "wallets", "networks"]);
  return Object.freeze({subjects: strings(value.subjects, SUBJECT, 100_000), wallets: strings(value.wallets, WALLET, 100_000), networks: strings(value.networks, NETWORK, 100_000)});
}
function parseBudget(raw: unknown) {
  const value = record(raw); exact(value, ["count", "windowDays"]);
  return Object.freeze({count: integer(value.count, 0, 1_000_000), windowDays: integer(value.windowDays, 1, 365)});
}
function parseRate(raw: unknown) {
  const value = record(raw); exact(value, ["perHourBpsOfCap"]);
  return Object.freeze({perHourBpsOfCap: integer(value.perHourBpsOfCap, 1, 10_000)});
}
const parseEmailChallenge = (value: unknown): EmailChallenge => {fail((EMAIL_CHALLENGES as readonly string[]).includes(value as string)); return value as EmailChallenge;};
const BODY_KEYS = Object.freeze(["minSchemaVersion", "emailChallenge", "rules", "throttles", "quarantine", "subjectClaimBudget", "launchClaimRate"] as const);
function parseBody(value: Record<string, unknown>): PlanPolicySet["defaults"] {
  return Object.freeze({minSchemaVersion: integer(value.minSchemaVersion, 0, 1_000_000), emailChallenge: parseEmailChallenge(value.emailChallenge),
    rules: parsePlanRules(value.rules), throttles: parseThrottles(value.throttles), quarantine: parseQuarantine(value.quarantine),
    subjectClaimBudget: parseBudget(value.subjectClaimBudget), launchClaimRate: parseRate(value.launchClaimRate)});
}
export function parsePlanPolicy(raw: unknown): PlanPolicy {
  const value = record(raw);
  exact(value, ["format", "provider", "plan", "paused", "reason", "pausedAt", ...BODY_KEYS, "version", "updatedAt"]);
  fail(value.format === PLAN_POLICY_FORMAT, "PLAN_POLICY_FORMAT");
  fail(isProviderId(value.provider)); const provider = value.provider;
  fail(isPlanKey(provider, value.plan), "PLAN_POLICY_PLAN");
  fail(typeof value.paused === "boolean");
  fail(value.reason === null || (typeof value.reason === "string" && value.reason.length >= 1 && value.reason.length <= 280 && !/[\u0000-\u001f\u007f]/.test(value.reason)));
  fail(value.pausedAt === null || (typeof value.pausedAt === "number" && Number.isSafeInteger(value.pausedAt) && value.pausedAt > 0));
  fail(value.paused ? value.pausedAt !== null : value.pausedAt === null, "PLAN_POLICY_PAUSE");
  return Object.freeze({format: PLAN_POLICY_FORMAT, provider, plan: value.plan, paused: value.paused, reason: value.reason as string | null, pausedAt: value.pausedAt as number | null,
    ...parseBody(value), version: integer(value.version, 1, Number.MAX_SAFE_INTEGER), updatedAt: integer(value.updatedAt, 1, Number.MAX_SAFE_INTEGER)});
}
export function parseLaunchPolicy(raw: unknown): LaunchPolicy {
  const value = record(raw); exact(value, ["claimContract", "minTenureDays", "note"]);
  fail(typeof value.claimContract === "string" && WALLET.test(value.claimContract));
  fail(value.note === null || (typeof value.note === "string" && value.note.length <= 280 && !/[\u0000-\u001f\u007f]/.test(value.note)));
  return Object.freeze({claimContract: value.claimContract, minTenureDays: integer(value.minTenureDays, 0, 3650), note: value.note as string | null});
}
export function parsePlanPolicySet(raw: unknown): PlanPolicySet {
  const value = record(raw); exact(value, ["format", "version", "updatedAt", "defaults", "plans", "launches"]);
  fail(value.format === PLAN_POLICY_SET_FORMAT, "PLAN_POLICY_FORMAT");
  const defaults = record(value.defaults); exact(defaults, BODY_KEYS);
  fail(Array.isArray(value.plans) && value.plans.length <= PROVIDER_PLAN_COUNT && Array.isArray(value.launches) && value.launches.length <= 10_000);
  const plans = Object.freeze((value.plans as unknown[]).map(parsePlanPolicy));
  fail(new Set(plans.map(plan => `${plan.provider}/${plan.plan}`)).size === plans.length, "PLAN_POLICY_DUPLICATE");
  const launches = Object.freeze((value.launches as unknown[]).map(parseLaunchPolicy));
  fail(new Set(launches.map(launch => launch.claimContract)).size === launches.length, "PLAN_POLICY_DUPLICATE");
  const version = integer(value.version, 0, Number.MAX_SAFE_INTEGER);
  fail(version >= Math.max(0, ...plans.map(plan => plan.version)), "PLAN_POLICY_VERSION");
  return Object.freeze({format: PLAN_POLICY_SET_FORMAT, version, updatedAt: integer(value.updatedAt, 0, Number.MAX_SAFE_INTEGER), defaults: parseBody(defaults), plans, launches});
}
const PROVIDER_PLAN_COUNT = Object.values(PLAN_KEYS).reduce((n, keys) => n + keys.length, 0);

/** The owner's defaults (S1, S5, S6): nothing paused, snapshot rule on, 30 days, e-mail challenge on, 10 per 30 days, a tenth of the cap per hour. */
export const DEFAULT_PLAN_POLICY_BODY: PlanPolicySet["defaults"] = Object.freeze({
  minSchemaVersion: 0, emailChallenge: "all",
  rules: Object.freeze({createdBefore: "launch" as const, minTenureDays: 30, usage: "any" as const, billingDeny: Object.freeze([])}),
  throttles: Object.freeze({countryDeny: Object.freeze([]), asnDeny: Object.freeze([]), perNetworkRate: null}),
  quarantine: Object.freeze({subjects: Object.freeze([]), wallets: Object.freeze([]), networks: Object.freeze([])}),
  subjectClaimBudget: Object.freeze({count: 10, windowDays: 30}),
  launchClaimRate: Object.freeze({perHourBpsOfCap: 1000}),
});
/** The platform's own drop uses 90 days (S5); the operator adds its clone with this value through `plan-admin launch set`. */
export const PLATFORM_DROP_MIN_TENURE_DAYS = 90;
export const DEFAULT_PLAN_POLICY_SET: PlanPolicySet = Object.freeze({format: PLAN_POLICY_SET_FORMAT, version: 0, updatedAt: 0, defaults: DEFAULT_PLAN_POLICY_BODY, plans: Object.freeze([]), launches: Object.freeze([])});

/** A fresh document for a plan that has no row yet: the set's defaults, version 1, unpaused. */
export function defaultPlanPolicy(set: PlanPolicySet, provider: ProviderId, plan: string, now: number): PlanPolicy {
  fail(isPlanKey(provider, plan), "PLAN_POLICY_PLAN");
  return Object.freeze({format: PLAN_POLICY_FORMAT, provider, plan, paused: false, reason: null, pausedAt: null, ...set.defaults, version: 1, updatedAt: now});
}
/** The document that governs (provider, plan): its row, or the defaults as an unversioned view. */
export function planPolicyFor(set: PlanPolicySet, provider: ProviderId, plan: string | null): PlanPolicy {
  const found = plan === null ? undefined : set.plans.find(entry => entry.provider === provider && entry.plan === plan);
  if (found) return found;
  return Object.freeze({format: PLAN_POLICY_FORMAT, provider, plan: plan ?? "", paused: false, reason: null, pausedAt: null, ...set.defaults, version: 0, updatedAt: set.updatedAt});
}
/** The tenure a launch demands: the plan's rule, raised by the launch's override when one exists (never lowered). */
export function minTenureDaysFor(set: PlanPolicySet, policy: PlanPolicy, claimContract: string): number {
  const launch = set.launches.find(entry => entry.claimContract === claimContract.toLowerCase());
  return Math.max(policy.rules.minTenureDays, launch?.minTenureDays ?? 0);
}

/** The editable fields of a plan document, as the admin CLI names them. */
export const PLAN_POLICY_FIELDS = Object.freeze(["paused", "reason", "minSchemaVersion", "emailChallenge", "rules", "throttles", "quarantine", "subjectClaimBudget", "launchClaimRate"] as const);
export type PlanPolicyField = typeof PLAN_POLICY_FIELDS[number];
/**
 * Apply one field change: the version advances by one and `pausedAt` follows `paused`. Returns a parsed document, so an
 * invalid value never reaches storage.
 */
export function withPlanPolicyField(policy: PlanPolicy, field: PlanPolicyField, value: unknown, now: number): PlanPolicy {
  const next: Record<string, unknown> = {...policy, [field]: value, version: policy.version + 1, updatedAt: now};
  if (field === "paused") {fail(typeof value === "boolean"); next.pausedAt = value ? (policy.paused ? policy.pausedAt : now) : null; if (!value) next.reason = null;}
  return parsePlanPolicy(next);
}
