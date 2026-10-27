/**
 * The attempt fingerprint: what the identity records about a verification attempt's connection and shape so an
 * anomaly can be attributed to a cluster and throttled by fact (provider-fact specification §3.3–§3.4, §4; owner S8:
 * 90-day retention, the board reads buckets only).
 *
 * Written twice: at admission (`POST /verification-attempts`, the only moment the user's own connection is seen) and
 * at completion (the enclave's result, which carries the plan, the facts and the timings). Nothing here identifies a
 * person: no IP (the ASN and the country are kept, the address is not), no wallet, no subject, no disclosed value.
 * Country and ASN come from the connection through {@link GeoResolver} (GeoLite2 in production, O1), never from a
 * provider; they are resolved from the bucket in memory, before the bucket is hashed.
 */
import {factBuckets, type FactBuckets, type ProviderId, type ReceiptFacts} from "./facts.ts";

export const FINGERPRINT_FORMAT = "pines-attempt-fingerprint-v1";
export const FINGERPRINT_RETENTION_MS = 90 * 86_400_000;
/** A fingerprint's `network`: the keyed hash of the address bucket, or `unknown`. Nothing else is ever stored. */
export const FINGERPRINT_NETWORK = /^(?:[0-9a-f]{64}|unknown)$/;
/** The connection facts of one request. `country` is ISO 3166-1 alpha-2 or `null`; `asn` is the autonomous system number or `null`. */
export type GeoResult = Readonly<{country: string | null; asn: number | null}>;
export const UNKNOWN_GEO: GeoResult = Object.freeze({country: null, asn: null});
/**
 * Resolves a client address bucket (`client-address.ts`: IPv4 exact, IPv6 `/64`) to country and network. Production
 * binds a bundled GeoLite2 country + ASN database, updated monthly; no third-party lookup per request (O1).
 */
export interface GeoResolver {
  lookup(addressBucket: string): GeoResult | Promise<GeoResult>;
}
/** The resolver a stack without a database runs with: every lookup is unknown, and nothing is refused for it. */
export const unknownGeoResolver: GeoResolver = Object.freeze({lookup: () => UNKNOWN_GEO});
/** Tests and the local stack: a fixed table of address bucket (or its prefix) → result. */
export class FakeGeoResolver implements GeoResolver {
  readonly #table: readonly (readonly [prefix: string, result: GeoResult])[];
  constructor(table: Readonly<Record<string, GeoResult>>) {
    this.#table = Object.entries(table).sort((a, b) => b[0].length - a[0].length).map(([prefix, result]) => [prefix, Object.freeze({...result})] as const);
  }
  lookup(addressBucket: string): GeoResult {
    return this.#table.find(([prefix]) => addressBucket === prefix || addressBucket.startsWith(prefix))?.[1] ?? UNKNOWN_GEO;
  }
}

export type ProviderOutcome = "completed" | "failed" | "cancelled" | "expired" | "refused";
export type StepTimings = Readonly<{
  /** Admission to the enclave's receipt (or terminal), in milliseconds. */
  proofMs: number | null;
  /** The receipt's issuance to its delivery at the identity. */
  deliveryMs: number | null;
}>;
export type AttemptFingerprint = Readonly<{
  format: typeof FINGERPRINT_FORMAT;
  attemptId: string;
  provider: ProviderId;
  /** The plan key once disclosed; `null` until completion, or when the plan is not a catalogued key. */
  plan: string | null;
  schemaVersion: number;
  country: string | null; asn: number | null;
  /**
   * The connection's network as the identity's **keyed hash** of its address bucket (64 hex,
   * `HMAC-SHA256(rate key, "sybil-network:" + bucket)`), or `"unknown"` when the address could not be bucketed. Never
   * the address or the bucket: the hash is what `perNetworkRate` counts and what a `networks` quarantine entry names.
   */
  network: string;
  userAgentBucket: string;
  extensionVersion: string | null;
  admittedAt: number;
  completedAt: number | null;
  stepTimings: StepTimings;
  providerOutcome: ProviderOutcome | null;
  /** The enclave's failure code or the policy's refusal code when the outcome is not `completed`. */
  outcomeCode: string | null;
  factBuckets: FactBuckets | null;
  retainUntil: number;
}>;

/**
 * A coarse User-Agent class: browser family, major version and OS family. Chrome's reduced UA leaves nothing finer, and
 * finer would identify. Anything unparsed is `other`.
 */
export function userAgentBucket(userAgent: string | undefined): string {
  const ua = (userAgent ?? "").slice(0, 512);
  if (!ua) return "none";
  const os = /Windows/.test(ua) ? "windows" : /Android/.test(ua) ? "android" : /CrOS/.test(ua) ? "chromeos" : /Mac OS X|Macintosh/.test(ua) ? "mac" : /iPhone|iPad/.test(ua) ? "ios" : /Linux/.test(ua) ? "linux" : "other";
  const browser = /Edg\/(\d+)/.exec(ua) ? ["edge", /Edg\/(\d+)/.exec(ua)![1]] : /OPR\/(\d+)/.exec(ua) ? ["opera", /OPR\/(\d+)/.exec(ua)![1]]
    : /Chrome\/(\d+)/.exec(ua) ? ["chrome", /Chrome\/(\d+)/.exec(ua)![1]] : /Firefox\/(\d+)/.exec(ua) ? ["firefox", /Firefox\/(\d+)/.exec(ua)![1]]
    : /Version\/(\d+).*Safari/.exec(ua) ? ["safari", /Version\/(\d+).*Safari/.exec(ua)![1]] : ["other", "0"];
  return `${browser[0]}-${browser[1]}-${os}`;
}
/** The extension's version as it reports it, or null; never free text. */
export const extensionVersionOf = (value: unknown): string | null => typeof value === "string" && /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(value) ? value : null;

export type AdmissionInput = Readonly<{attemptId: string; provider: ProviderId; schemaVersion: number; network: string; geo: GeoResult;
  userAgent: string | undefined; extensionVersion: unknown; now: number}>;
export function admissionFingerprint(input: AdmissionInput): AttemptFingerprint {
  if (!/^[0-9a-f-]{36}$/.test(input.attemptId)) throw new Error("FINGERPRINT_ATTEMPT_INVALID");
  if (!Number.isSafeInteger(input.now) || input.now <= 0) throw new Error("FINGERPRINT_TIME_INVALID");
  // Fail closed: an address or a bucket can never become a record, whatever the caller passed.
  if (!FINGERPRINT_NETWORK.test(input.network)) throw new Error("FINGERPRINT_NETWORK_INVALID");
  return Object.freeze({format: FINGERPRINT_FORMAT, attemptId: input.attemptId, provider: input.provider, plan: null, schemaVersion: input.schemaVersion,
    country: input.geo.country, asn: input.geo.asn, network: input.network, userAgentBucket: userAgentBucket(input.userAgent),
    extensionVersion: extensionVersionOf(input.extensionVersion), admittedAt: input.now, completedAt: null,
    stepTimings: Object.freeze({proofMs: null, deliveryMs: null}), providerOutcome: null, outcomeCode: null, factBuckets: null,
    retainUntil: input.now + FINGERPRINT_RETENTION_MS});
}
export type CompletionInput = Readonly<{plan: string | null; providerOutcome: ProviderOutcome; outcomeCode: string | null;
  /** The enclave's receipt or terminal time (ms) and the identity's acceptance time (ms). */
  eventAt: number; now: number; facts: ReceiptFacts | null}>;
/** The completion half: plan, outcome, timings and fact **buckets** (never the facts). Retention is counted from completion. */
export function completionFingerprint(admitted: AttemptFingerprint, input: CompletionInput): AttemptFingerprint {
  if (!Number.isSafeInteger(input.now) || input.now < admitted.admittedAt) throw new Error("FINGERPRINT_TIME_INVALID");
  const eventAt = Number.isSafeInteger(input.eventAt) && input.eventAt >= admitted.admittedAt ? input.eventAt : null;
  return Object.freeze({...admitted, plan: input.plan, completedAt: input.now,
    stepTimings: Object.freeze({proofMs: eventAt === null ? null : eventAt - admitted.admittedAt, deliveryMs: eventAt === null ? null : Math.max(0, input.now - eventAt)}),
    providerOutcome: input.providerOutcome, outcomeCode: input.outcomeCode,
    factBuckets: input.facts ? factBuckets(input.facts, Math.floor(input.now / 1000)) : null,
    retainUntil: input.now + FINGERPRINT_RETENTION_MS});
}
/** Whether a record has outlived its retention and must be deleted (S8). */
export const fingerprintExpired = (record: Pick<AttemptFingerprint, "retainUntil">, now: number) => now >= record.retainUntil;
