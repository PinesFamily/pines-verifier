/**
 * The sybil-policy refusal codes: one module the identity, the app and the extension import, so a refusal is
 * explained with the same words everywhere (provider-fact specification §2.2, §2.5; identity policy specification §3).
 *
 * A code is a stable wire identifier, snake_case, carried as `{error, code}` by the identity and as an attempt's
 * `error_code` at completion. The copy here is the English default; the key (`sybil.refusal.<code>`) is what a
 * translation table is indexed by. Copy never carries a wallet, an address, a subject or an e-mail: the placeholders
 * are the provider's display name, the plan's label, the user's own connection country, a date and a day count.
 */
export const REFUSAL_CODES = Object.freeze([
  "plan_paused", "reverification_required", "rule_created_after", "rule_tenure", "rule_usage", "rule_billing",
  "rule_country", "rule_network", "subject_budget_exhausted", "launch_rate", "email_challenge_required", "not_eligible",
  // Track B (multi-exchange protocol §1.6): a fact the provider's schema produces is missing from the receipt and the
  // provider fails closed on it. Raised between the connection throttles and the fact rules it guards.
  "fact_unavailable",
] as const);
export type RefusalCode = typeof REFUSAL_CODES[number];
export const isRefusalCode = (value: unknown): value is RefusalCode => typeof value === "string" && (REFUSAL_CODES as readonly string[]).includes(value);

/** Where a code can be raised. `completion` is the verification result; `issuance` is the claim co-signature. */
export type RefusalSeam = "completion" | "issuance";
export type RefusalCopy = Readonly<{
  key: `sybil.refusal.${RefusalCode}`;
  /** What happened, in the title's register of `apps/web-next/src/lib/verify-failure.ts`. */
  title: string;
  /** What to do. */
  line: string;
  /** Whether verifying again can help now. */
  retry: boolean;
  /** The HTTP status the identity answers with. 403 is a policy refusal; 429 is a rate the caller can wait out. */
  status: 403 | 429;
  seams: readonly RefusalSeam[];
  /** `generic` copy deliberately says nothing about the cause (quarantine, identity defense specification §3.2 P6). */
  disclosure: "specific" | "generic";
}>;
const copy = (code: RefusalCode, title: string, line: string, retry: boolean, status: 403 | 429, seams: readonly RefusalSeam[], disclosure: RefusalCopy["disclosure"] = "specific"): RefusalCopy =>
  Object.freeze({key: `sybil.refusal.${code}` as const, title, line, retry, status, seams, disclosure});

/**
 * Placeholders: `{provider}` display name, `{plan}` label, `{country}` ISO 3166-1 alpha-2 of the user's own connection,
 * `{date}` the launch's creation date, `{days}` a day count, `{reason}` the operator's published pause reason.
 */
export const REFUSAL_COPY: Readonly<Record<RefusalCode, RefusalCopy>> = Object.freeze({
  plan_paused: copy("plan_paused", "{provider} {plan} verifications are paused", "{reason} Try again later.", false, 403, ["completion", "issuance"]),
  reverification_required: copy("reverification_required", "Your {provider} {plan} verification needs to be redone", "Verify again under the updated checks.", true, 403, ["issuance"]),
  rule_created_after: copy("rule_created_after", "This account is newer than the launch", "Only accounts created before {date} can claim this drop.", false, 403, ["issuance"]),
  rule_tenure: copy("rule_tenure", "This account is too new", "Accounts need {days} days with {provider} to claim this drop.", false, 403, ["issuance"]),
  rule_usage: copy("rule_usage", "This account hasn’t been used", "Use {provider} with this account, then verify again.", true, 403, ["completion", "issuance"]),
  rule_billing: copy("rule_billing", "This plan’s billing isn’t accepted here", "Claims on this plan aren’t available for accounts billed this way at the moment.", false, 403, ["completion", "issuance"]),
  rule_country: copy("rule_country", "Not available from {country} right now", "Claims on this plan aren’t available from your country at the moment.", false, 403, ["completion", "issuance"]),
  rule_network: copy("rule_network", "Not available from this network right now", "Claims on this plan aren’t available from your network at the moment.", false, 403, ["completion", "issuance"]),
  subject_budget_exhausted: copy("subject_budget_exhausted", "This account has reached its claim limit", "An account can claim {days} drops per 30 days. Try again later.", false, 429, ["issuance"]),
  launch_rate: copy("launch_rate", "This drop is busy", "Claims are being paced. Try again in a few minutes.", true, 429, ["issuance"]),
  email_challenge_required: copy("email_challenge_required", "Confirm it’s you", "Enter the code we sent to the e-mail on your {provider} account.", true, 403, ["completion", "issuance"]),
  not_eligible: copy("not_eligible", "Not eligible", "This account can’t claim here.", false, 403, ["completion", "issuance"], "generic"),
  fact_unavailable: copy("fact_unavailable", "A required {provider} account detail couldn’t be read", "Verify again later; share the error code if it repeats.", true, 403, ["completion", "issuance"]),
});

/** A refusal as the seams return it: the code, the status and the public placeholders, never a secret. */
export type Refusal = Readonly<{
  code: RefusalCode; status: 403 | 429;
  detail: Readonly<{provider: string; plan: string | null; reason?: string; date?: number; days?: number; country?: string; minSchemaVersion?: number}>;
}>;
export const refusal = (code: RefusalCode, detail: Refusal["detail"]): Refusal => Object.freeze({code, status: REFUSAL_COPY[code].status, detail: Object.freeze({...detail})});

/** Fill the copy's placeholders. Unknown placeholders stay literal so a missing value is visible, not silent. */
export function renderRefusal(value: Pick<Refusal, "code" | "detail">, names: {provider?: string; plan?: string} = {}): {title: string; line: string; retry: boolean; key: RefusalCopy["key"]} {
  const entry = REFUSAL_COPY[value.code];
  const fill = (text: string) => text
    .replace(/\{provider\}/g, names.provider ?? value.detail.provider)
    .replace(/\{plan\}/g, names.plan ?? value.detail.plan ?? "")
    .replace(/\{country\}/g, value.detail.country ?? "your country")
    .replace(/\{date\}/g, value.detail.date === undefined ? "the launch" : new Date(value.detail.date * 1000).toISOString().slice(0, 10))
    .replace(/\{days\}/g, value.detail.days === undefined ? "" : String(value.detail.days))
    .replace(/\{reason\}/g, value.detail.reason ? value.detail.reason.trim().replace(/[.!]?$/, ".") : "Verifications for this plan are paused.")
    .replace(/\s{2,}/g, " ").trim();
  return {key: entry.key, title: fill(entry.title), line: fill(entry.line), retry: entry.retry};
}
