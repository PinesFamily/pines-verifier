/**
 * The two enforcement seams as pure functions (provider-fact specification §2.2, §4 step 4; identity policy specification
 * §7). The identity calls {@link evaluateAtCompletion} when the enclave's receipt arrives and {@link evaluateAtIssuance}
 * before it asks S and the co-signer for a claim; both return the first refusal, or `undefined`.
 *
 * Order matters and is fixed: quarantine first, so a listed subject learns nothing from a more specific code; then the
 * pause; then the schema minimum; then the connection throttles; then the fact rules; then the budgets; the e-mail
 * challenge last, because it is a step the user can complete, not a refusal of the account.
 *
 * A fact the receipt lacks is **not evaluated**: with no enclave producing facts yet, a rule on them must not refuse
 * every claim. Track B's per-provider fail-closed decision is `FAIL_CLOSED_FACTS` (facts.ts): a listed fact the provider's
 * schema produces (from `sinceSchemaVersion`) and the receipt lacks raises `fact_unavailable`, after the connection
 * throttles and before the fact rules it guards. Empty tables keep the foundation's behaviour exactly.
 */
import {missingProducedFacts, type FactTables, type ReceiptFacts} from "./facts.ts";
import type {ProviderId} from "./facts.ts";
import {minTenureDaysFor, planPolicyFor, type PlanPolicy, type PlanPolicySet} from "./policy.ts";
import {refusal, type Refusal} from "./refusals.ts";

/** The admission's connection: GeoLite2 country and ASN, and `network` as the identity's keyed hash of the address bucket (never the bucket). */
export type Connection = Readonly<{country: string | null; asn: number | null; network: string | null}>;
export const UNKNOWN_CONNECTION: Connection = Object.freeze({country: null, asn: null, network: null});
export type CompletionEvaluation = Readonly<{
  provider: ProviderId;
  /** The catalogued plan key, or `null` when the disclosed plan is not one (then only the defaults govern). */
  plan: string | null;
  schemaVersion: number;
  facts: ReceiptFacts;
  connection: Connection;
  /** The identity's subject hash and the wallet, lower-case hex, for the quarantine lists. */
  subject: string | null; wallet: string | null;
  /** Whether the e-mail challenge has been passed for this receipt (track C). `undefined` means no challenge exists yet. */
  emailChallengePassed?: boolean;
  /** For `flagged`: whether something else flagged this attempt (track D's clusters). */
  flagged?: boolean;
  /**
   * For `throttles.perNetworkRate` (track D, identity grouping specification §3): the verifications this provider saw started
   * from the attempt's network bucket in the trailing hour of its admission, the attempt itself included. `undefined`
   * means not counted, and the rate is not evaluated (issuance never counts).
   */
  networkStarts?: number;
}>;
export type IssuanceEvaluation = CompletionEvaluation & Readonly<{
  launch: Readonly<{claimContract: string; launchTs: number; maxClaims: number}>;
  /** Chain time, unix seconds. */
  now: number;
  /** Claims this subject has had signed in the budget window, and claims signed for this launch in the last hour. */
  subjectClaimsInWindow: number; launchClaimsLastHour: number;
}>;

export type EvaluationOptions = Readonly<{factTables?: FactTables}>;
const lower = (value: string | null) => value?.toLowerCase() ?? null;
function quarantined(policy: PlanPolicy, input: CompletionEvaluation): boolean {
  const subject = lower(input.subject), wallet = lower(input.wallet);
  if (subject && policy.quarantine.subjects.includes(subject)) return true;
  if (wallet && policy.quarantine.wallets.includes(wallet)) return true;
  if (input.connection.network && policy.quarantine.networks.includes(input.connection.network)) return true;
  if (input.connection.asn !== null && policy.quarantine.networks.includes(`asn:${input.connection.asn}`)) return true;
  return false;
}
function emailChallengeDue(policy: PlanPolicy, input: CompletionEvaluation): boolean {
  if (policy.emailChallenge === "off" || input.facts.email === undefined || input.emailChallengePassed === true) return false;
  return policy.emailChallenge === "all" || input.flagged === true;
}
/** The checks both seams share, in their fixed order. `detail` carries only public placeholders. */
function common(set: PlanPolicySet, input: CompletionEvaluation, options: EvaluationOptions): {policy: PlanPolicy; refused: Refusal | undefined} {
  const policy = planPolicyFor(set, input.provider, input.plan);
  const detail = {provider: input.provider, plan: input.plan};
  // Quarantine and pause are judged by the plan's own document and by the defaults' lists alike: a quarantine entered
  // on the defaults covers every plan of the provider.
  const defaults = planPolicyFor(set, input.provider, null);
  if (quarantined(policy, input) || quarantined(defaults, input)) return {policy, refused: refusal("not_eligible", detail)};
  if (policy.paused) return {policy, refused: refusal("plan_paused", {...detail, ...(policy.reason ? {reason: policy.reason} : {})})};
  if (policy.minSchemaVersion > 0 && input.schemaVersion < policy.minSchemaVersion) return {policy, refused: refusal("reverification_required", {...detail, minSchemaVersion: policy.minSchemaVersion})};
  if (input.connection.country && policy.throttles.countryDeny.includes(input.connection.country)) return {policy, refused: refusal("rule_country", {...detail, country: input.connection.country})};
  if (input.connection.asn !== null && policy.throttles.asnDeny.includes(input.connection.asn)) return {policy, refused: refusal("rule_network", detail)};
  if (input.networkStarts !== undefined && policy.throttles.perNetworkRate !== null && input.networkStarts > policy.throttles.perNetworkRate) return {policy, refused: refusal("rule_network", detail)};
  if (missingProducedFacts(input.provider, input.schemaVersion, input.facts, options.factTables).length > 0) return {policy, refused: refusal("fact_unavailable", detail)};
  if (policy.rules.usage === "used" && input.facts.usageBucket === "none") return {policy, refused: refusal("rule_usage", detail)};
  if (input.facts.billingPlatform !== undefined && policy.rules.billingDeny.includes(input.facts.billingPlatform)) return {policy, refused: refusal("rule_billing", detail)};
  return {policy, refused: undefined};
}
/** At the verification result: the plan is now known; the connection is the admission's. */
export function evaluateAtCompletion(set: PlanPolicySet, input: CompletionEvaluation, options: EvaluationOptions = {}): Refusal | undefined {
  const {policy, refused} = common(set, input, options);
  if (refused) return refused;
  if (emailChallengeDue(policy, input)) return refusal("email_challenge_required", {provider: input.provider, plan: input.plan});
  return undefined;
}
/** The tenure fact a snapshot or age rule reads: the paid start where known, else the account's creation. */
export const tenureFactOf = (facts: ReceiptFacts): number | undefined => facts.tenureStartAt ?? facts.createdAt;
/** At the co-signature: the launch, chain time and the two counters are known; yesterday's verification meets today's rules. */
export function evaluateAtIssuance(set: PlanPolicySet, input: IssuanceEvaluation, options: EvaluationOptions = {}): Refusal | undefined {
  const {policy, refused} = common(set, input, options);
  if (refused) return refused;
  const detail = {provider: input.provider, plan: input.plan};
  const tenure = tenureFactOf(input.facts);
  if (tenure !== undefined && policy.rules.createdBefore !== "off") {
    const cutoff = policy.rules.createdBefore === "launch" ? input.launch.launchTs : policy.rules.createdBefore;
    if (tenure >= cutoff) return refusal("rule_created_after", {...detail, date: cutoff});
  }
  const minDays = minTenureDaysFor(set, policy, input.launch.claimContract);
  if (tenure !== undefined && minDays > 0 && input.now - tenure < minDays * 86_400) return refusal("rule_tenure", {...detail, days: minDays});
  if (policy.subjectClaimBudget.count > 0 && input.subjectClaimsInWindow >= policy.subjectClaimBudget.count) return refusal("subject_budget_exhausted", {...detail, days: policy.subjectClaimBudget.count});
  if (input.launchClaimsLastHour >= launchClaimsPerHour(policy, input.launch.maxClaims)) return refusal("launch_rate", detail);
  if (emailChallengeDue(policy, input)) return refusal("email_challenge_required", detail);
  return undefined;
}
/** The launch's hourly allowance: `maxClaims × bps / 10,000`, never below one claim an hour. */
export const launchClaimsPerHour = (policy: PlanPolicy, maxClaims: number) => Math.max(1, Math.floor(maxClaims * policy.launchClaimRate.perHourBpsOfCap / 10_000));
