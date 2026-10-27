import { requireThat, reject } from "./errors.ts";
import { canonicalJson, parseJson, selectJson } from "./json.ts";
import { headerValue, parseHttp, utf8 } from "./http.ts";
import type { HttpMessage } from "./http.ts";
import { acceptEncoding, connectionHeader, exchangeViews, matchRequestTarget, requestBody, type ExchangeView } from "./schema.ts";
import { messageBoundaries } from "./http.ts";
import { validateHeader } from "./capture.ts";
import { inspectDisclosedRequest, type RedactedHeader } from "./redacted-request.ts";
import { inspectDisclosedResponse } from "./redacted-response.ts";
import type { EvidenceFacts, FieldTransform, Json, ResponseDisclosureMode, VerificationSchema, VerifiedBytes, VerifiedExchange } from "./types.ts";

/** Returns the authenticated path parameters, `{}` for a schema that declares none. */
export function validateRequest(schema: VerificationSchema, request: HttpMessage, final = true): Readonly<Record<string, string>> {
  const match = /^([A-Z]+) (\S+) HTTP\/1\.1$/.exec(request.startLine);
  requireThat(match && match[1] === schema.request.method, "SCOPE_MISMATCH");
  const pathParams = matchRequestTarget(schema, match![2]!);
  const fixed = { ...schema.replay.headers, host: new URL(schema.request.origin).host, "accept-encoding": acceptEncoding(schema), connection: connectionHeader(final) };
  for (const [name, value] of Object.entries(fixed)) requireThat(headerValue(request, name) === value, "SCOPE_MISMATCH");
  const allowed = new Set([...Object.keys(fixed), "content-length", ...schema.capture.headers.map(rule => rule.name)]);
  if (schema.capture.cookies.length) allowed.add("cookie");
  for (const header of request.headers) {
    requireThat(allowed.has(header.name), "SCOPE_MISMATCH");
    headerValue(request, header.name); // No duplicate request headers, including credentials.
  }
  for (const rule of schema.capture.headers) {
    const value = headerValue(request, rule.name);
    requireThat(value !== undefined ? validateHeader(value, rule.validation) : !rule.required, "SCOPE_MISMATCH");
  }
  const cookie = headerValue(request, "cookie");
  if (cookie !== undefined) {
    const names = new Set<string>();
    for (const part of cookie.split(";")) {
      const match = /^([a-zA-Z\d_.-]+)=([\x21-\x7e]+)$/.exec(part.trim());
      requireThat(match && (schema.capture.cookies.includes(match[1]!) || schema.capture.optionalCookies?.includes(match[1]!)) && !names.has(match[1]!), "SCOPE_MISMATCH");
      names.add(match[1]!);
    }
    if (schema.capture.optionalCookies) requireThat(schema.capture.cookies.every(name => names.has(name)), "SCOPE_MISMATCH");
  }
  if (schema.capture.optionalCookies) requireThat(cookie !== undefined, "SCOPE_MISMATCH");
  if (schema.request.body.kind === "empty") requireThat(request.body.length === 0, "SCOPE_MISMATCH");
  else requireThat(canonicalJson(parseJson(utf8(request.body), schema.limits.maxJsonDepth)) === requestBody(schema), "SCOPE_MISMATCH");
  return pathParams;
}

export function deriveSubjectKey(schema: VerificationSchema, value: Json, recipient: string): string {
  requireThat(typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value)), "INVALID_FIELD");
  if (schema.identity.kind === "legacy-plan-wallet") {
    requireThat(typeof value === "string" && /^[a-z][a-z\d_-]{0,63}$/i.test(value), "INVALID_FIELD");
    requireThat(/^0x[a-f\d]{40}$/i.test(recipient) && recipient.startsWith("0x"), "INVALID_RECIPIENT");
    return `${value}:${recipient.toLowerCase()}`;
  }
  requireThat(String(value).length > 0, "INVALID_FIELD");
  return String(value);
}

// Claude's `/api/organizations` lists every organization the account belongs to: the personal chat
// org, any API org, any Team org. Exactly one element may qualify, or nothing does — two paid personal
// orgs, or a paid marker without a matching tier, is ambiguity, and ambiguity fails closed.
//
const CLAUDE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLAUDE_TIER = /^default_claude_(max|pro)(?:_[a-z0-9]+){0,4}$/;
// Claude serves Pro on Free's tier: a real Pro org (2026-10-11) answered `["chat","claude_pro"]` with
// `default_claude_ai`. So for Pro the capability is the paid signal and the tier may be that shared
// one; Max keeps its own tier (`default_claude_max_20x`, observed 2026-09-26). Free stays out because
// it carries no paid capability, which every Claude selector requires.
const CLAUDE_SHARED_TIER = "default_claude_ai";
function claudePaidMarker(value: Json): "max" | "pro" | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) return null;
  if (!value.every(entry => typeof entry === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(entry))) return null;
  if (new Set(value).size !== value.length || !value.includes("chat") || value.includes("raven")) return null;
  const max = value.includes("claude_max"), pro = value.includes("claude_pro");
  return max === pro ? null : max ? "max" : "pro";
}
function claudeTier(value: Json): "max" | "pro" | "shared" | null {
  if (typeof value !== "string" || value.length > 64) return null;
  if (value === CLAUDE_SHARED_TIER) return "shared";
  const match = CLAUDE_TIER.exec(value);
  return match ? match[1] as "max" | "pro" : null;
}
/** The paid plan an org's `capabilities` and `rate_limit_tier` agree on, or null. Reads only those
 *  two keys, so it takes an organization object or the schema's extracted values alike. */
export function claudePaidPlan(value: Json): "max" | "pro" | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const marker = claudePaidMarker(value.capabilities ?? null), tier = claudeTier(value.rate_limit_tier ?? null);
  return marker !== null && (tier === marker || (marker === "pro" && tier === "shared")) ? marker : null;
}
export function isClaudePaidPersonalOrg(value: Json): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  // Personal orgs only: no Team (`raven`) type and no parent organization.
  return claudePaidPlan(value) !== null && value.raven_type === null && value.parent_organization_uuid === null;
}
// The same predicate the single-object selector applies, exported so a client that has
// to choose among several qualifying personal organizations cannot disagree with the
// enclave's judgement. Highest tier first (max before pro), then the provider's own
// order within a tier. This is a convenience for a caller: the enclave never ranks.
export function rankClaudePersonalOrgs(document: Json): readonly Readonly<{ uuid: string; tier: "max" | "pro" }>[] {
  if (!Array.isArray(document) || document.length > 64) return Object.freeze([]);
  const ranked: Readonly<{ uuid: string; tier: "max" | "pro" }>[] = [];
  for (const tier of ["max", "pro"] as const) {
    for (const entry of document) {
      if (!isClaudePaidPersonalOrg(entry)) continue;
      const value = entry as Record<string, Json>;
      if (claudePaidMarker(value.capabilities ?? null) !== tier) continue;
      if (typeof value.uuid === "string" && CLAUDE_UUID.test(value.uuid)) ranked.push(Object.freeze({ uuid: value.uuid, tier }));
    }
  }
  return Object.freeze(ranked);
}

// Grok's `/rest/subscriptions` lists the signed-in xAI user's subscriptions: X-billed (Basic, Premium,
// Premium+) and xAI-billed (SuperGrok Lite, SuperGrok, Plus, Pro) side by side. The tier names and their
// order are grok.com's own client code (`getSubscriptionLevel`, read 2026-09-27): it keeps ACTIVE items and
// takes the highest tier, and so does this. Paid means Premium+ or any SuperGrok; X Basic and X Premium are
// X plans with limited Grok and are not a Grok subscription ("SuperGrok · Premium+").
// Every item must name the same xAI user: a list that mixes accounts is ambiguity, and fails closed.
//
const GROK_UUID = CLAUDE_UUID;
const GROK_PAID_TIERS: readonly string[] = Object.freeze([
  "SUBSCRIPTION_TIER_X_PREMIUM_PLUS", "SUBSCRIPTION_TIER_SUPER_GROK_LITE", "SUBSCRIPTION_TIER_GROK_PRO",
  "SUBSCRIPTION_TIER_SUPER_GROK_PLUS", "SUBSCRIPTION_TIER_SUPER_GROK_PRO",
]);
const grokPaidRank = (value: Json) => typeof value === "string" ? GROK_PAID_TIERS.indexOf(value) : -1;
function selectGrokSubscription(document: Json, maxItems: number): Json {
  requireThat(document !== null && typeof document === "object" && !Array.isArray(document), "INVALID_JSON");
  const items = document.subscriptions;
  // The filtered route answers only ACTIVE items, so a tight cap is both the cost
  // bound and the fail-closed behaviour if the provider ever ignores `?status`.
  requireThat(Array.isArray(items) && items.length <= maxItems, "INVALID_JSON");
  let selected: Json | undefined, rank = -1;
  for (const item of items) {
    requireThat(item !== null && typeof item === "object" && !Array.isArray(item), "INVALID_JSON");
    requireThat(typeof item.xaiUserId === "string" && item.xaiUserId === (items[0] as { xaiUserId?: Json }).xaiUserId, "CHECK_FAILED");
    const itemRank = item.status === "SUBSCRIPTION_STATUS_ACTIVE" ? grokPaidRank(item.tier ?? null) : -1;
    if (itemRank > rank) { selected = item; rank = itemRank; }
  }
  requireThat(selected !== undefined, "CHECK_FAILED");
  return selected;
}
// The billing object present on the selected subscription names the platform (capture record §3: a `stripe` object
// beside `billingSystem` LEGACY). Exactly one known object names it; none or several is `unknown`.
const GROK_BILLING_OBJECTS: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), { stripe: "stripe", apple: "apple", google: "google", x: "x" }));
function grokBillingPlatform(item: Json): string {
  if (item === null || typeof item !== "object" || Array.isArray(item)) return "unknown";
  const present = Object.keys(GROK_BILLING_OBJECTS).filter(key => item[key] !== null && typeof item[key] === "object" && !Array.isArray(item[key]));
  return present.length === 1 ? GROK_BILLING_OBJECTS[present[0]!]! : "unknown";
}
// ChatGPT's plan-limit history (capture record §1): `periods[]` are plan segments of varying length ordered by
// descending start, overlapping at a plan change; `days` is the depth and coverage is always 30 days; a foreign
// account id answers an empty list. The facts: the earliest accepted-plan segment's start, else `data_as_of` (no paid
// period in the window: tenure of at most zero days, which the tenure rule refuses and the proof does not); the usage
// bucket from `used_basis_points` on `accounting_complete` segments, `unknown` when none carries a figure.
const CHATGPT_HISTORY_PLANS: readonly string[] = Object.freeze(["plus", "pro", "prolite", "promax"]);
const CHATGPT_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
function selectChatgptHistory(document: Json): Json {
  requireThat(document !== null && typeof document === "object" && !Array.isArray(document), "INVALID_JSON");
  const asOf = document.data_as_of, periods = document.periods;
  requireThat(typeof asOf === "string" && CHATGPT_ISO.test(asOf) && Array.isArray(periods) && periods.length <= 64, "INVALID_FIELD");
  let earliest: string | undefined, used = -1;
  for (const period of periods) {
    requireThat(period !== null && typeof period === "object" && !Array.isArray(period), "INVALID_JSON");
    const plan = period.plan_type, start = period.starts_at;
    requireThat(typeof plan === "string" && typeof start === "string" && CHATGPT_ISO.test(start), "INVALID_FIELD");
    // Usage is the account's, whichever plan the segment was on; tenure counts accepted plans only.
    const figure = period.used_basis_points;
    if (period.accounting_complete === true && typeof figure === "number" && Number.isSafeInteger(figure) && figure >= 0) used = Math.max(used, figure);
    if (!CHATGPT_HISTORY_PLANS.includes(plan)) continue;
    if (earliest === undefined || Date.parse(start) < Date.parse(earliest)) earliest = start;
  }
  const bucket = used < 0 ? "unknown" : used === 0 ? "none" : used < 1000 ? "low" : used < 5000 ? "medium" : "high";
  return { tenure_start_at: earliest ?? asOf, usage_bucket: bucket, periods: periods.length, coverage_complete: document.coverage_complete === true };
}
function selectDocument(schema: VerificationSchema, document: Json): Json {
  if (!schema.selector) return document;
  switch (schema.selector.kind) {
    case "claude-paid-personal-org-v1": {
      requireThat(Array.isArray(document) && document.length <= 64, "INVALID_JSON");
      const selected = document.filter(isClaudePaidPersonalOrg);
      requireThat(selected.length === 1, "CHECK_FAILED");
      return selected[0]!;
    }
    // The per-organization route answers exactly one organization, so there is no
    // list to disambiguate; the same predicate judges that one object.
    case "claude-paid-personal-org-single-v1": {
      requireThat(isClaudePaidPersonalOrg(document), "SELECTED_SUBJECT_INELIGIBLE");
      return document;
    }
    case "grok-paid-subscription-v1": return selectGrokSubscription(document, schema.selector.maxItems ?? 64);
    case "grok-paid-subscription-v2": {
      const item = selectGrokSubscription(document, schema.selector.maxItems ?? 64) as { [key: string]: Json };
      return { ...item, pines_billing_platform_source: grokBillingPlatform(item) };
    }
    case "chatgpt-plan-limit-history-v1": return selectChatgptHistory(document);
    default: return reject("INVALID_SCHEMA");
  }
}

// The closed field transforms (identity policy specification §4). A billing vocabulary the map does not
// know becomes `unknown`, which the policy can still deny, rather than refusing the whole proof;
// a date that does not parse is refused, because a fact that is present must be a fact.
// Only the recorded vocabulary: `BILLING_SYSTEM_LEGACY` (Grok qualification specification). The xAI-billed
// value is not captured by us and maps to `unknown` until the owner's capture names it.
const GROK_BILLING: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), { BILLING_SYSTEM_LEGACY: "x" }));
const CLAUDE_BILLING: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), { stripe_subscription: "stripe", apple_subscription: "apple" }));
const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
export function transformValue(transform: FieldTransform, value: Json): Json {
  requireThat(typeof value === "string" && value.length <= 64, "CHECK_FAILED");
  switch (transform) {
    case "iso-8601-seconds-v1": {
      requireThat(ISO_8601.test(value), "CHECK_FAILED");
      const ms = Date.parse(value);
      requireThat(Number.isFinite(ms) && ms > 0, "CHECK_FAILED");
      return Math.floor(ms / 1000);
    }
    case "grok-billing-system-v1": return GROK_BILLING[value] ?? "unknown";
    case "claude-billing-type-v1": return CLAUDE_BILLING[value] ?? "unknown";
    default: return reject("INVALID_SCHEMA");
  }
}

type Bound = Readonly<{ pointer: string; expected: Json; member?: string }> | undefined;
/** One exchange's disclosed values: the selected document's fields, judged by its checks, then transformed. */
function exchangeValues(schema: VerificationSchema, response: Json, pathParams: Readonly<Record<string, string>>, bound: Bound): Readonly<{ values: Readonly<Record<string, Json>>; document: Json }> {
  const document = selectDocument(schema, response);
  requireThat(document !== null && typeof document === "object" && !Array.isArray(document), "INVALID_JSON");
  // A proven request path parameter must equal the field it declares in the SELECTED
  // document, so a prover cannot pair one subject's request with another's response.
  for (const [name, declared] of Object.entries(schema.request.pathParams ?? {})) {
    requireThat(selectJson(document, declared.bindsTo) === pathParams[name], "PATH_PARAM_MISMATCH");
  }
  // A later exchange bound by a response field must name the first exchange's subject; bound by a member, one
  // element of the array at the pointer must.
  if (bound && bound.member === undefined) requireThat(selectJson(document, bound.pointer) === bound.expected, "EXCHANGE_BINDING_MISMATCH");
  if (bound && bound.member !== undefined) {
    const members = selectJson(document, bound.pointer);
    requireThat(Array.isArray(members) && members.length <= 64, "EXCHANGE_BINDING_MISMATCH");
    requireThat(members.some(member => member !== null && typeof member === "object" && !Array.isArray(member) && selectJson(member, bound.member!) === bound.expected), "EXCHANGE_BINDING_MISMATCH");
  }
  const raw: Record<string, Json> = Object.create(null), values: Record<string, Json> = Object.create(null);
  for (const field of schema.fields) {
    const value = selectJson(document, field.pointer);
    requireThat(field.type === "array" ? Array.isArray(value) : field.type === "safe-integer" ? typeof value === "number" && Number.isSafeInteger(value) : typeof value === field.type, "INVALID_FIELD");
    raw[field.id] = value;
    values[field.id] = field.transform ? transformValue(field.transform, value) : value;
  }
  for (const check of schema.checks) {
    const value = raw[check.field]!;
    let passes: boolean;
    switch (check.op) {
      case "eq": passes = value === check.value; break;
      case "in": passes = check.values.some(expected => value === expected); break;
      case "gte": passes = typeof value === "number" && value >= check.value; break;
      case "lte": passes = typeof value === "number" && value <= check.value; break;
      case "array-length-gte": passes = Array.isArray(value) && value.length >= check.value; break;
      case "custom":
        switch (check.handler) {
          case "chatgpt-plan-v1": passes = typeof value === "string" && /^[a-z][a-z\d_-]{0,63}$/i.test(value); break;
          // Provider IDs are opaque and case-sensitive. Never trim, case-fold or
          // substitute a wallet/email/workspace when the authenticated ID is absent.
          case "chatgpt-user-id-v1": passes = typeof value === "string" && value.length === 29 && /^user-[A-Za-z0-9]{24}$/.test(value); break;
          case "non-empty-string-v1": passes = typeof value === "string" && value.length > 0; break;
          // Lowercase exactly as Claude serves it: never case-fold an identity into a second nullifier.
          case "claude-org-uuid-v1": passes = typeof value === "string" && CLAUDE_UUID.test(value); break;
          // Alone, the tier may be Free's shared one: the selector has already required a paid capability
          // that agrees with it, and `claudePaidPlan` is what names the plan.
          case "claude-paid-tier-v1": passes = claudeTier(value) !== null; break;
          case "claude-paid-capabilities-v1": passes = claudePaidMarker(value) !== null; break;
          // Lowercase exactly as grok.com serves it (observed 2026-09-27), for the same reason.
          case "grok-user-uuid-v1": passes = typeof value === "string" && GROK_UUID.test(value); break;
          case "grok-paid-tier-v1": passes = grokPaidRank(value) >= 0; break;
          default: return reject("INVALID_SCHEMA");
        }
        break;
      default: return reject("INVALID_SCHEMA");
    }
    requireThat(passes, "CHECK_FAILED");
  }
  return Object.freeze({ values: Object.freeze(values), document });
}

/** The per-exchange evidence the session evaluator joins: the view, its parsed response, the
 *  proven path parameters and a comparable key for the credential that sent it (the
 *  plaintext values where the evaluator saw them, the hidden slots' names and sizes where it did not). */
type ExchangeInput = Readonly<{ view: ExchangeView; response: HttpMessage; pathParams: Readonly<Record<string, string>>; credentialKey: string; header: (name: string) => string | undefined }>;

function responseDocument(schema: VerificationSchema, response: HttpMessage): Json {
  requireThat(/^HTTP\/1\.1 200 [\x20-\x7e]*$/.test(response.startLine), "SCOPE_MISMATCH");
  const type = headerValue(response, "content-type");
  requireThat(type !== undefined && /^application\/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?$/i.test(type), "SCOPE_MISMATCH");
  // `parseHttp` has already decoded an admitted coding; this is the independent
  // restatement of what the schema admits, on the same bytes the facts come from.
  const encoding = headerValue(response, "content-encoding")?.toLowerCase();
  if (!schema.response.privacy) requireThat(encoding === undefined || encoding === "identity", "SCOPE_MISMATCH");
  else requireThat((schema.response.privacy.encodings as readonly string[]).includes(encoding ?? "identity"), "RESPONSE_ENCODING_UNSUPPORTED");
  return parseJson(utf8(response.body), schema.limits.maxJsonDepth);
}

/**
 * One receipt's facts from every exchange of the session, in order. The first exchange names the
 * subject; each later one is bound to it as its schema declares, and its values join the same
 * `values` object (field ids are unique across the schema).
 */
function sessionFacts(schema: VerificationSchema, recipient: string, inputs: readonly ExchangeInput[]): EvidenceFacts {
  const primary = inputs[0]!;
  const values: Record<string, Json> = Object.create(null);
  const first = exchangeValues(primary.view.schema, responseDocument(primary.view.schema, primary.response), primary.pathParams, undefined);
  Object.assign(values, first.values);
  const identity = values[schema.identity.field]!;
  for (const input of inputs.slice(1)) {
    const binding = input.view.binding!;
    // Every exchange of a session is sent with the same captured credential: the shared secret slots must agree
    // whatever else the binding checks (structural in the enclave; exact in the browser).
    requireThat(input.credentialKey === primary.credentialKey, "EXCHANGE_BINDING_MISMATCH");
    if (binding.kind === "request-header") {
      const value = input.header(binding.header);
      requireThat(value !== undefined && value === selectJson(first.document, binding.pointer), "EXCHANGE_BINDING_MISMATCH");
    }
    const bound: Bound = binding.kind === "response-field" ? { pointer: binding.pointer, expected: identity }
      : binding.kind === "response-member" ? { pointer: binding.pointer, expected: identity, member: binding.field } : undefined;
    Object.assign(values, exchangeValues(input.view.schema, responseDocument(input.view.schema, input.response), input.pathParams, bound).values);
  }
  return Object.freeze({ providerId: schema.providerId, domain: schema.claims.domain, identityVersion: schema.identity.version, subjectKey: deriveSubjectKey(schema, identity, recipient), values: Object.freeze(values), claimable: false });
}

/** The credential every exchange shares: the schema's own secret headers and its cookie jar. An
 *  exchange-only header is that exchange's selector, not the session's credential. */
const sharedCredentialNames = (schema: VerificationSchema): readonly string[] =>
  [...schema.capture.headers.filter(rule => rule.secret).map(rule => rule.name), ...(schema.capture.cookies.length ? ["cookie"] : [])];
/** The plaintext credential of a request, as one comparable key. */
function plaintextCredentialKey(schema: VerificationSchema, request: HttpMessage): string {
  return canonicalJson(sharedCredentialNames(schema).map(name => [name, headerValue(request, name) ?? null]));
}
/** A slice of a verified transcript as its own verified bytes: ranges clipped and re-based. */
function sliceVerified(verified: VerifiedBytes, start: number, end: number): VerifiedBytes {
  const authenticated = [];
  for (const range of verified.authenticated) {
    const from = Math.max(range.start, start), to = Math.min(range.end, end);
    if (from < to) authenticated.push({ start: from - start, end: to - start });
  }
  return { bytes: verified.bytes.subarray(start, end), originalLength: end - start, authenticated };
}
const hiddenRequest = (schema: VerificationSchema) => schema.capture.cookies.length > 0 || schema.capture.headers.some(header => header.secret);

// Browser-only precheck on its own full transcript. Successful parsing is not
// evidence of TLS authenticity and must not be submitted to the API as proof.
export function previewExchange(schema: VerificationSchema, sent: Uint8Array, recv: Uint8Array, recipient: string): EvidenceFacts {
  const views = exchangeViews(schema);
  if (views.length === 1) {
    const request = parseHttp(sent, schema, "sent");
    const pathParams = validateRequest(schema, request);
    return sessionFacts(schema, recipient, [{ view: views[0]!, response: parseHttp(recv, schema, "recv"), pathParams, credentialKey: "", header: name => headerValue(request, name) }]);
  }
  requireThat(sent.length <= schema.limits.maxSentBytes && recv.length <= schema.limits.maxRecvBytes, "LIMIT_EXCEEDED");
  const sentRanges = messageBoundaries(sent, schema, "sent", views.length), recvRanges = messageBoundaries(recv, schema, "recv", views.length);
  requireThat(sentRanges.length === views.length && recvRanges.length === views.length, "SCOPE_MISMATCH");
  return sessionFacts(schema, recipient, views.map((view, index) => {
    const request = parseHttp(sent.subarray(sentRanges[index]!.start, sentRanges[index]!.end), view.schema, "sent");
    const pathParams = validateRequest(view.schema, request, view.final);
    const response = parseHttp(recv.subarray(recvRanges[index]!.start, recvRanges[index]!.end), view.schema, "recv");
    return { view, response, pathParams, credentialKey: plaintextCredentialKey(schema, request), header: name => headerValue(request, name) };
  }));
}

/** Every request of a session through the redacted-request inspector, one per exchange, in order: the
 *  enclave's independent restatement of the request structure. For a single-exchange schema this is the one inspection. */
export function inspectDisclosedRequests(schema: VerificationSchema, sent: VerifiedBytes): readonly (readonly RedactedHeader[])[] {
  const views = exchangeViews(schema);
  if (views.length === 1) return Object.freeze([inspectDisclosedRequest(schema, sent)]);
  requireThat(sent.bytes instanceof Uint8Array && sent.originalLength === sent.bytes.length && sent.bytes.length <= schema.limits.maxSentBytes, "PARTIAL_TRANSCRIPT");
  const ranges = messageBoundaries(sent.bytes, schema, "sent", views.length);
  requireThat(ranges.length === views.length, "SCOPE_MISMATCH");
  return Object.freeze(views.map((view, index) => inspectDisclosedRequest(view.schema, sliceVerified(sent, ranges[index]!.start, ranges[index]!.end), view.final)));
}
/** Every response message of a session, parsed: one per exchange, in order. The enclave's
 *  inventory inspection runs on each. For a single-exchange schema this is the one message. */
export function inspectDisclosedResponses(schema: VerificationSchema, recv: VerifiedBytes, responseDisclosure: ResponseDisclosureMode = "selective"): readonly HttpMessage[] {
  const views = exchangeViews(schema);
  if (views.length === 1) return Object.freeze([inspectDisclosedResponse(schema, recv, responseDisclosure)]);
  requireThat(recv.bytes instanceof Uint8Array && recv.originalLength === recv.bytes.length && recv.bytes.length <= schema.limits.maxRecvBytes, "PARTIAL_TRANSCRIPT");
  const ranges = messageBoundaries(recv.bytes, schema, "recv", views.length);
  requireThat(ranges.length === views.length, "SCOPE_MISMATCH");
  return Object.freeze(views.map((view, index) => inspectDisclosedResponse(view.schema, sliceVerified(recv, ranges[index]!.start, ranges[index]!.end), responseDisclosure)));
}
export function requireCompleteCoverage(transcript: VerifiedBytes, limit: number): void {
  requireThat(transcript.bytes instanceof Uint8Array && Number.isSafeInteger(transcript.originalLength) && transcript.originalLength > 0 && transcript.originalLength === transcript.bytes.length, "PARTIAL_TRANSCRIPT");
  requireThat(transcript.originalLength <= limit && Array.isArray(transcript.authenticated) && transcript.authenticated.length <= 4096, "LIMIT_EXCEEDED");
  let end = 0;
  for (const range of transcript.authenticated) {
    requireThat(Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end) && range.start === end && range.end > range.start && range.end <= transcript.originalLength, "PARTIAL_TRANSCRIPT");
    end = range.end;
  }
  requireThat(end === transcript.originalLength, "PARTIAL_TRANSCRIPT");
}

/** The public request start line, read back from bytes a request inspector has already
 *  proven are authenticated and well formed. It is never parsed before that proof. */
function provenStartLine(bytes: Uint8Array): string {
  const end = bytes.findIndex((byte, index) => byte === 13 && bytes[index + 1] === 10);
  requireThat(end > 0 && end <= 2048, "SCOPE_MISMATCH");
  const line = bytes.subarray(0, end);
  requireThat(line.every(byte => byte >= 32 && byte <= 126), "SCOPE_MISMATCH");
  return new TextDecoder().decode(line);
}

// Only call after the exact-byte event has been authenticated to our verifier and
// bound to the server-owned attempt/schema. No labels or client metadata are used.
export function evaluateVerifiedExchange(schema: VerificationSchema, exchange: VerifiedExchange, recipient: string, responseDisclosure: ResponseDisclosureMode = "selective"): EvidenceFacts {
  requireThat(exchange.mode === "Proxy" && exchange.serverName === new URL(schema.request.origin).hostname, "SCOPE_MISMATCH");
  const views = exchangeViews(schema);
  const judgeRequest = (view: ExchangeView, sent: VerifiedBytes): Readonly<{ pathParams: Readonly<Record<string, string>>; credentialKey: string; header: (name: string) => string | undefined }> => {
    // A cookie is always a credential, so a cookie schema always takes the redacted path.
    if (hiddenRequest(view.schema)) {
      const publicHeaders = new Map<string, string>();
      const slots = inspectDisclosedRequest(view.schema, sent, view.final, publicHeaders);
      // The inspector proved the start line is public and matches the declared template;
      // this reads the parameter values back out of it through that same matcher.
      const match = /^([A-Z]+) (\S+) HTTP\/1\.1$/.exec(provenStartLine(sent.bytes));
      requireThat(match && match[1] === view.schema.request.method, "SCOPE_MISMATCH");
      // Hidden bytes are opaque here, so the credential is compared by its slots: names and sizes.
      const shared = sharedCredentialNames(schema);
      return { pathParams: matchRequestTarget(view.schema, match![2]!), credentialKey: canonicalJson(slots.filter(slot => shared.includes(slot.name)).map(slot => [slot.name, slot.end - slot.start])), header: name => publicHeaders.get(name) };
    }
    requireCompleteCoverage(sent, view.schema.limits.maxSentBytes);
    const request = parseHttp(sent.bytes, view.schema, "sent");
    return { pathParams: validateRequest(view.schema, request, view.final), credentialKey: plaintextCredentialKey(schema, request), header: name => headerValue(request, name) };
  };
  if (views.length === 1) {
    const judged = judgeRequest(views[0]!, exchange.sent);
    return sessionFacts(schema, recipient, [{ view: views[0]!, response: inspectDisclosedResponse(schema, exchange.recv, responseDisclosure), ...judged }]);
  }
  for (const side of [exchange.sent, exchange.recv]) requireThat(side.bytes instanceof Uint8Array && Number.isSafeInteger(side.originalLength) && side.originalLength === side.bytes.length && side.originalLength > 0, "PARTIAL_TRANSCRIPT");
  requireThat(exchange.sent.bytes.length <= schema.limits.maxSentBytes && exchange.recv.bytes.length <= schema.limits.maxRecvBytes, "LIMIT_EXCEEDED");
  const sentRanges = messageBoundaries(exchange.sent.bytes, schema, "sent", views.length);
  requireThat(sentRanges.length === views.length, "SCOPE_MISMATCH");
  const responses = inspectDisclosedResponses(schema, exchange.recv, responseDisclosure);
  return sessionFacts(schema, recipient, views.map((view, index) => ({ view, response: responses[index]!, ...judgeRequest(view, sliceVerified(exchange.sent, sentRanges[index]!.start, sentRanges[index]!.end)) })));
}
