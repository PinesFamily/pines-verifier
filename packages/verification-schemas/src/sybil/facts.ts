/**
 * The receipt facts the sybil rules read, named once so the tracks code against them before any enclave produces
 * them (provider-fact specification §3; identity policy specification §4). Every fact below is **not yet produced**: the live
 * native schemas disclose a plan and a keyed pseudonym only. Track B's schema release flips `produced` per provider.
 *
 * A fact arrives on the receipt as a disclosed value under the provider's own field name; `receiptFactsOf` maps those
 * to the canonical names here. The e-mail is the one fact the identity may see and must never persist
 * (v1 exposes the address in flight; the address is used for the challenge and dropped).
 */
export const FACT_NAMES = Object.freeze(["tenureStartAt", "createdAt", "usageBucket", "billingPlatform", "email"] as const);
export type FactName = typeof FACT_NAMES[number];
export const USAGE_BUCKETS = Object.freeze(["none", "low", "medium", "high"] as const);
export type UsageBucket = typeof USAGE_BUCKETS[number];
export const BILLING_PLATFORMS = Object.freeze(["stripe", "apple", "google", "x", "unknown"] as const);
export type BillingPlatform = typeof BILLING_PLATFORMS[number];
export const PROVIDER_IDS = Object.freeze(["chatgpt", "claude", "grok"] as const);
export type ProviderId = typeof PROVIDER_IDS[number];
export const isProviderId = (value: unknown): value is ProviderId => typeof value === "string" && (PROVIDER_IDS as readonly string[]).includes(value);

/** The facts a receipt may carry, canonical names and units. Times are unix **seconds**, like `verifiedAt` on chain. */
export type ReceiptFacts = Readonly<{
  /** When paid tenure began: the subscription's own start where the provider states one. */
  tenureStartAt?: number;
  /** When the account (or, for Claude, the organisation) was created. */
  createdAt?: number;
  /** Whether the account has actually been used, bucketed by the enclave from the provider's usage windows. */
  usageBucket?: UsageBucket;
  billingPlatform?: BillingPlatform;
  /** In flight only. Never written to a row, a log or a receipt record. */
  email?: string;
  /** The receipt's commitment to the address (`FACT_COMMITMENT_FIELDS.email`): what a saved record keeps of the e-mail fact. */
  emailCommitment?: string;
}>;

export type FactSource = Readonly<{
  /** The provider route the fact is read from, as provider-fact specification §3 names it. */
  route: string;
  /** The field in that response. */
  field: string;
  /** How the enclave's disclosed value becomes the canonical fact. */
  transform: "unix-seconds" | "iso-8601" | "usage-bucket" | "billing-platform" | "email";
  /** Whether a live schema discloses it yet. All false in the foundation; track B flips each one it ships. */
  produced: boolean;
  /** The provider's schema version from which the fact is produced; set when `produced` is flipped. A receipt under an
   *  older schema lacks the fact by construction and is never failed closed for it (owner S3: re-verification is explicit). */
  sinceSchemaVersion?: number;
  /** What is still unconfirmed: a capture the owner must perform, or a route not yet qualified. */
  note?: string;
}>;

/**
 * Per provider, per fact: where it comes from. A provider with no entry for a fact has no source for it yet, and the
 * rules treat the fact as absent (identity policy specification §4: a missing fact is **not evaluated** in the foundation;
 * track B decides fail-closed per provider when its schema produces it).
 */
// Produced by the sybil-facts schemas from qualified provider captures.
// `sinceSchemaVersion` is the provider's ENCLAVE schema version
// (pines.<provider>.tee.native) that first discloses the fact; the measured image carrying it is not yet built.
export const FACT_SOURCES: Readonly<Record<ProviderId, Readonly<Partial<Record<FactName, FactSource>>>>> = Object.freeze({
  chatgpt: Object.freeze({
    tenureStartAt: Object.freeze({route: "GET /backend-api/wham/usage/plan_limit_history?days=30", field: "earliest accepted-plan period starts_at, else data_as_of (no paid period in the 30-day window)", transform: "iso-8601", produced: true, sinceSchemaVersion: 7,
      note: "Second exchange, bound to the first by the public chatgpt-account-id header echoed as account_id. `days` is the depth and coverage is always 30 days (days=90 refused), so tenure beyond 30 days is not provable here."} as const),
    createdAt: Object.freeze({route: "GET /backend-api/me", field: "created", transform: "unix-seconds", produced: false, note: "Confirmed present (unix seconds, id equal to user_id) but not disclosed: a third exchange of 1.2 KB the session budget does not need while tenure comes from the history."} as const),
    usageBucket: Object.freeze({route: "GET /backend-api/wham/usage/plan_limit_history?days=30", field: "max used_basis_points over accounting_complete periods, bucketed; unknown when none carries a figure", transform: "usage-bucket", produced: true, sinceSchemaVersion: 7} as const),
    billingPlatform: Object.freeze({route: "GET /backend-api/accounts/check/v4-2023-04-27", field: "last_active_subscription.purchase_origin_platform", transform: "billing-platform", produced: false, note: "Not read: not in the owner's capture list."} as const),
    email: Object.freeze({route: "GET /backend-api/wham/usage", field: "email", transform: "email", produced: true, sinceSchemaVersion: 7, note: "On the live route; equal to /backend-api/me's. Delivered outside the retained receipt (FACT_COMMITMENT_FIELDS)."} as const),
  }),
  claude: Object.freeze({
    createdAt: Object.freeze({route: "GET /api/organizations/{org_uuid}", field: "created_at", transform: "iso-8601", produced: true, sinceSchemaVersion: 4, note: "The organisation's age, not the paid period's (sybil-defense-plan §3.1)."} as const),
    billingPlatform: Object.freeze({route: "GET /api/organizations/{org_uuid}", field: "billing_type (stripe_subscription | apple_subscription seen)", transform: "billing-platform", produced: true, sinceSchemaVersion: 4} as const),
    email: Object.freeze({route: "GET /api/account", field: "email_address", transform: "email", produced: true, sinceSchemaVersion: 4, note: "Second exchange (35,926 bytes raw), on the facts-complete class whose session budget admits it (owner D4); bound to the proven organization through memberships[].organization.uuid. Delivered outside the retained receipt (FACT_COMMITMENT_FIELDS)."} as const),
  }),
  grok: Object.freeze({
    tenureStartAt: Object.freeze({route: "GET /rest/subscriptions?status=SUBSCRIPTION_STATUS_ACTIVE", field: "subscriptions[].createTime", transform: "iso-8601", produced: true, sinceSchemaVersion: 4} as const),
    createdAt: Object.freeze({route: "GET /rest/auth/get-user", field: "createTime", transform: "iso-8601", produced: true, sinceSchemaVersion: 4, note: "Second exchange, bound by userId = xaiUserId."} as const),
    billingPlatform: Object.freeze({route: "GET /rest/subscriptions?status=SUBSCRIPTION_STATUS_ACTIVE", field: "the one billing object present (stripe | apple | google | x), else unknown; billingSystem LEGACY appeared beside a stripe object", transform: "billing-platform", produced: true, sinceSchemaVersion: 4} as const),
    email: Object.freeze({route: "GET /rest/auth/get-user", field: "email, only when emailConfirmed is true", transform: "email", produced: true, sinceSchemaVersion: 4, note: "820-byte response. Delivered outside the retained receipt (FACT_COMMITMENT_FIELDS)."} as const),
  }),
});

/**
 * Track B's per-provider fail-closed decision (identity policy specification §4, §8): the facts whose absence from a receipt
 * refuses, once the provider's schema produces them. Empty everywhere until a provider's facts ship, so the default stays:
 * a missing fact is not evaluated. `missingProducedFacts` is the one reader; the seams raise `fact_unavailable` on it.
 */
export const FAIL_CLOSED_FACTS: Readonly<Record<ProviderId, readonly FactName[]>> = Object.freeze({
  // ChatGPT: the tenure fact is always produced (data_as_of when no paid period) and the e-mail is on the live route, so
  // either missing means the shape changed; the usage bucket may legitimately be `unknown` (dropped), so it never fails closed.
  chatgpt: Object.freeze<FactName[]>(["tenureStartAt", "email"]),
  // Claude: both facts sit on the object the plan is read from; the e-mail is the second exchange's one field.
  claude: Object.freeze<FactName[]>(["createdAt", "billingPlatform", "email"]),
  // Grok: the four facts sit on the two routes the proof already reads; an unconfirmed e-mail is absent and so refused
  // (S1's challenge cannot be skipped by leaving an address unconfirmed).
  grok: Object.freeze<FactName[]>(["tenureStartAt", "createdAt", "billingPlatform", "email"]),
});
export type FactTables = Readonly<{sources: typeof FACT_SOURCES; failClosed: typeof FAIL_CLOSED_FACTS}>;
export const DEFAULT_FACT_TABLES: FactTables = Object.freeze({sources: FACT_SOURCES, failClosed: FAIL_CLOSED_FACTS});
/**
 * Whether a receipt under `schemaVersion` of the provider's enclave schema carries the fact by construction: `produced`
 * says a schema discloses it, `sinceSchemaVersion` from which version. A receipt under an older schema lacks it and is
 * never judged on its absence (owner S3: re-verification is explicit). The one reader of the two flags: track B's
 * `missingProducedFacts` and track C's e-mail fail-closed (`possession/runtime.ts` `producesEmail`) both ask it.
 */
export function factProducedAt(provider: ProviderId, name: FactName, schemaVersion: number, tables: FactTables = DEFAULT_FACT_TABLES): boolean {
  // Grok v5 is the subscriptions-only clearance companion; v6 restores the
  // two-exchange facts. Monotonic version numbers do not imply monotonic facts.
  if (provider === "grok" && schemaVersion === 5) return false;
  const source = tables.sources[provider][name];
  // Written as "not older" so a version that does not compare is judged (fail closed), as before this helper existed.
  return source !== undefined && source.produced && source.sinceSchemaVersion !== undefined && !(schemaVersion < source.sinceSchemaVersion);
}
/** The fail-closed facts this receipt should carry and does not: produced for its provider from a schema version it is at or above. */
export function missingProducedFacts(provider: ProviderId, schemaVersion: number, facts: ReceiptFacts, tables: FactTables = DEFAULT_FACT_TABLES): readonly FactName[] {
  return Object.freeze(tables.failClosed[provider].filter(name => {
    if (!factProducedAt(provider, name, schemaVersion, tables)) return false;
    // The e-mail fact is present on a receipt as its commitment; the address itself is in flight only.
    return name === "email" ? facts.email === undefined && facts.emailCommitment === undefined : facts[name] === undefined;
  }));
}

/** The disclosed field names an enclave will use for each canonical fact. Fixed here so the three parties agree. */
export const FACT_FIELDS: Readonly<Record<FactName, string>> = Object.freeze({
  tenureStartAt: "pines_tenure_start_at", createdAt: "pines_created_at", usageBucket: "pines_usage_bucket",
  billingPlatform: "pines_billing_platform", email: "pines_email",
});
/**
 * How the e-mail fact and its commitment relate (multi-exchange protocol §2.5): the identity
 * RETAINS the enclave's signed bundle (saved evidence, receipt record, outbox, fixtures), so the address must never be a
 * value inside the signed receipt. A schema still discloses the address under `FACT_FIELDS.email` — that is the fact's
 * canonical name and what the enclave reads — but what the receipt's `values` carries is `pines_email_commitment`
 * = {@link emailCommitment}; the plaintext travels in the delivery packet's non-retained `transient.email` member, which
 * the identity reads once for the challenge (track C's `emailOf`) and drops. The commitment is what later binds a
 * passed challenge to the receipt, and what lets the identity check the transient address belongs to that receipt.
 */
export const FACT_COMMITMENT_FIELDS: Readonly<Record<"email", string>> = Object.freeze({email: "pines_email_commitment"});
export const EMAIL_COMMITMENT_DOMAIN = "pines/email-commitment/v1";
/** The fields a receipt's `values` may carry: every fact field but the e-mail's, plus the e-mail's commitment. */
export const RECEIPT_VALUE_FIELDS: readonly string[] = Object.freeze([...FACT_NAMES.filter(name => name !== "email").map(name => FACT_FIELDS[name]), FACT_COMMITMENT_FIELDS.email]);
/** The address as the commitment sees it: trimmed and lower-cased, so a provider's casing never splits one mailbox in two. */
export const normalizeEmail = (email: string): string => email.trim().toLowerCase();
/**
 * SHA-256(domain ‖ "\n" ‖ session ‖ "\n" ‖ normalized address), hex. Salted by the enclave session (random per attempt,
 * known to the enclave, the client and the identity), so two receipts of one mailbox do not match, and the identity can
 * verify an in-flight address against a receipt. Not keyed: the identity sees the address in flight anyway (owner S1).
 */
export async function emailCommitment(session: string, email: string): Promise<string> {
  if (typeof session !== "string" || !/^[a-f0-9]{64}$/.test(session) || typeof email !== "string" || email.length === 0 || email.length > 254) throw new Error("EMAIL_COMMITMENT_INPUT");
  const bytes = new TextEncoder().encode(`${EMAIL_COMMITMENT_DOMAIN}\n${session}\n${normalizeEmail(email)}`);
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("");
}

const unixSeconds = (value: unknown): number | undefined => {
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value < 4_102_444_800) return value;
  if (typeof value === "string" && /^[1-9][0-9]{8,9}$/.test(value)) return Number(value);
  if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}T/.test(value)) {const ms = Date.parse(value); return Number.isFinite(ms) ? Math.floor(ms / 1000) : undefined;}
  return undefined;
};
/**
 * Canonical facts from a receipt's disclosed values. Tolerant on purpose: a value a schema does not disclose is simply
 * absent, and a malformed one is dropped rather than refused, because the enclave already validated what it signed.
 */
export function receiptFactsOf(values: Readonly<Record<string, unknown>>): ReceiptFacts {
  const facts: {-readonly [K in keyof ReceiptFacts]: ReceiptFacts[K]} = {};
  const tenure = unixSeconds(values[FACT_FIELDS.tenureStartAt]); if (tenure !== undefined) facts.tenureStartAt = tenure;
  const created = unixSeconds(values[FACT_FIELDS.createdAt]); if (created !== undefined) facts.createdAt = created;
  const usage = values[FACT_FIELDS.usageBucket]; if (typeof usage === "string" && (USAGE_BUCKETS as readonly string[]).includes(usage)) facts.usageBucket = usage as UsageBucket;
  const billing = values[FACT_FIELDS.billingPlatform]; if (typeof billing === "string" && (BILLING_PLATFORMS as readonly string[]).includes(billing)) facts.billingPlatform = billing as BillingPlatform;
  const email = values[FACT_FIELDS.email]; if (typeof email === "string" && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) facts.email = email;
  const commitment = values[FACT_COMMITMENT_FIELDS.email]; if (typeof commitment === "string" && /^[a-f0-9]{64}$/.test(commitment)) facts.emailCommitment = commitment;
  return Object.freeze(facts);
}

/** `email` must never reach a durable record; this is what a persistence path strips (and a test pins). */
export const persistableFacts = ({email: _email, ...rest}: ReceiptFacts): ReceiptFacts => Object.freeze(rest);
export const PERSISTED_FACT_NAMES = Object.freeze(FACT_NAMES.filter(name => name !== "email"));
/** The disclosed field names a durable record may keep: every fact field but the e-mail's, and the e-mail's commitment. */
export const PERSISTED_FACT_FIELDS: readonly string[] = Object.freeze([...PERSISTED_FACT_NAMES.map(name => FACT_FIELDS[name]), FACT_COMMITMENT_FIELDS.email]);
export const isPersistedFactField = (field: string): boolean => PERSISTED_FACT_FIELDS.includes(field);
/** A receipt's disclosed values reduced to what a durable record may keep of the facts: the persisted fact fields, never `pines_email`. */
export function persistableFactValues<T>(values: Readonly<Record<string, T>>): Readonly<Record<string, T>> {
  const kept: Record<string, T> = {};
  for (const field of PERSISTED_FACT_FIELDS) if (values[field] !== undefined) kept[field] = values[field]!;
  return Object.freeze(kept);
}

export const TENURE_BUCKETS = Object.freeze(["unknown", "<7d", "7-30d", "30-90d", "90-365d", ">365d"] as const);
export type TenureBucket = typeof TENURE_BUCKETS[number];
/** Buckets for metrics and the fingerprint: the board reads buckets only (owner S8). */
export function tenureBucket(startAt: number | undefined, nowSeconds: number): TenureBucket {
  if (startAt === undefined) return "unknown";
  const days = (nowSeconds - startAt) / 86_400;
  if (days < 7) return "<7d"; if (days < 30) return "7-30d"; if (days < 90) return "30-90d"; if (days < 365) return "90-365d";
  return ">365d";
}
export type FactBuckets = Readonly<{tenure: TenureBucket; created: TenureBucket; usage: UsageBucket | "unknown"; billing: BillingPlatform | "unknown"}>;
export const factBuckets = (facts: ReceiptFacts, nowSeconds: number): FactBuckets => Object.freeze({
  tenure: tenureBucket(facts.tenureStartAt, nowSeconds), created: tenureBucket(facts.createdAt, nowSeconds),
  usage: facts.usageBucket ?? "unknown", billing: facts.billingPlatform ?? "unknown"});
