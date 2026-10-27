/**
 * The connection throttles and the quarantine at admission (`POST /verification-attempts`), before the enclave spends a
 * session on an attempt the completion seam would refuse anyway (identity policy specification §9 decision 6; docs/sybil-
 * clusters.md §3). Not a third seam with its own rules: it asks {@link evaluateAtCompletion} — the seam, in its fixed
 * order — what it would answer for **every plan the provider could disclose**, because the plan is not known until the
 * enclave discloses it.
 *
 * The attempt is refused at admission only when every candidate plan (each catalogued key, and `null` for a plan the
 * catalogue does not name) would be refused by a code this moment can judge: the quarantine (`not_eligible`, generic by
 * design), `rule_country` or `rule_network` (the deny lists and `perNetworkRate`). A plan whose answer is anything else
 * — admitted, paused, a schema minimum, a fact rule — lets the attempt run, and the completion seam answers it with the
 * plan's own code. The answer is the earliest code in the seam's order among the plans' answers, so a quarantined
 * connection always reads `not_eligible`, never a more specific code.
 */
import {PLAN_KEYS} from "./policy.ts";
import type {PlanPolicySet} from "./policy.ts";
import type {ProviderId} from "./facts.ts";
import {evaluateAtCompletion, type Connection} from "./evaluate.ts";
import type {Refusal, RefusalCode} from "./refusals.ts";

/** The codes admission can raise, in the seams' order. Never a new code. */
export const ADMISSION_CODES: readonly RefusalCode[] = Object.freeze(["not_eligible", "rule_country", "rule_network"] as const);
export type AdmissionEvaluation = Readonly<{
  provider: ProviderId;
  schemaVersion: number;
  connection: Connection;
  /** The start's recipient, lower-case hex; the wallet quarantine applies to it. No subject exists yet. */
  wallet: string | null;
  /** Starts from this network bucket for this provider in the last hour, this one included; `undefined` when not counted. */
  networkStarts?: number;
}>;
/** The plans a start for `provider` could turn out to be: every catalogued key, and `null` (an uncatalogued plan). */
export const candidatePlans = (provider: ProviderId): readonly (string | null)[] => [...PLAN_KEYS[provider], null];
/**
 * Whether `perNetworkRate` can refuse this provider at admission at all: only when every candidate plan has a rate.
 * The identity counts the network's starts only then, so a stack without the throttle never reads the fingerprints.
 */
export function admissionCountsNetwork(set: PlanPolicySet, provider: ProviderId): boolean {
  return candidatePlans(provider).every(plan => {
    const found = plan === null ? undefined : set.plans.find(entry => entry.provider === provider && entry.plan === plan);
    return (found ?? set.defaults).throttles.perNetworkRate !== null;
  });
}
export function evaluateAtAdmission(set: PlanPolicySet, input: AdmissionEvaluation): Refusal | undefined {
  let first: Refusal | undefined;
  for (const plan of candidatePlans(input.provider)) {
    const refused = evaluateAtCompletion(set, {provider: input.provider, plan, schemaVersion: input.schemaVersion, facts: {}, connection: input.connection,
      subject: null, wallet: input.wallet, ...(input.networkStarts !== undefined ? {networkStarts: input.networkStarts} : {})});
    if (!refused || !ADMISSION_CODES.includes(refused.code)) return undefined;
    if (!first || ADMISSION_CODES.indexOf(refused.code) < ADMISSION_CODES.indexOf(first.code)) first = refused;
  }
  // The detail names the provider only: the plan is unknown here, and the copy's `{plan}` must not claim one.
  return first && Object.freeze({...first, detail: Object.freeze({...first.detail, plan: null})});
}
