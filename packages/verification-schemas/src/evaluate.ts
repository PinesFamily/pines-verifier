import { requireThat, reject } from "./errors.ts";
import { canonicalJson, parseJson, selectJson } from "./json.ts";
import { headerValue, parseHttp, utf8 } from "./http.ts";
import type { HttpMessage } from "./http.ts";
import { acceptEncoding, matchRequestTarget, requestBody } from "./schema.ts";
import { validateHeader } from "./capture.ts";
import { inspectDisclosedRequest } from "./redacted-request.ts";
import { inspectDisclosedResponse } from "./redacted-response.ts";
import type { EvidenceFacts, Json, ResponseDisclosureMode, VerificationSchema, VerifiedBytes, VerifiedExchange } from "./types.ts";

/** Returns the authenticated path parameters, `{}` for a schema that declares none. */
export function validateRequest(schema: VerificationSchema, request: HttpMessage): Readonly<Record<string, string>> {
  const match = /^([A-Z]+) (\S+) HTTP\/1\.1$/.exec(request.startLine);
  requireThat(match && match[1] === schema.request.method, "SCOPE_MISMATCH");
  const pathParams = matchRequestTarget(schema, match![2]!);
  const fixed = { ...schema.replay.headers, host: new URL(schema.request.origin).host, "accept-encoding": acceptEncoding(schema), connection: "close" };
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
      requireThat(match && schema.capture.cookies.includes(match[1]!) && !names.has(match[1]!), "SCOPE_MISMATCH");
      names.add(match[1]!);
    }
  }
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
function claudePaidMarker(value: Json): "max" | "pro" | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) return null;
  if (!value.every(entry => typeof entry === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(entry))) return null;
  if (new Set(value).size !== value.length || !value.includes("chat") || value.includes("raven")) return null;
  const max = value.includes("claude_max"), pro = value.includes("claude_pro");
  return max === pro ? null : max ? "max" : "pro";
}
function claudePaidTier(value: Json): "max" | "pro" | null {
  if (typeof value !== "string" || value.length > 64) return null;
  const match = CLAUDE_TIER.exec(value);
  return match ? match[1] as "max" | "pro" : null;
}
export function isClaudePaidPersonalOrg(value: Json): boolean {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const marker = claudePaidMarker(value.capabilities ?? null);
  // Personal orgs only: no Team (`raven`) type and no parent organization.
  return marker !== null && marker === claudePaidTier(value.rate_limit_tier ?? null)
    && value.raven_type === null && value.parent_organization_uuid === null;
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
    default: return reject("INVALID_SCHEMA");
  }
}

function facts(schema: VerificationSchema, response: Json, recipient: string, pathParams: Readonly<Record<string, string>>): EvidenceFacts {
  const document = selectDocument(schema, response);
  requireThat(document !== null && typeof document === "object" && !Array.isArray(document), "INVALID_JSON");
  // A proven request path parameter must equal the field it declares in the SELECTED
  // document, so a prover cannot pair one subject's request with another's response.
  for (const [name, declared] of Object.entries(schema.request.pathParams ?? {})) {
    requireThat(selectJson(document, declared.bindsTo) === pathParams[name], "PATH_PARAM_MISMATCH");
  }
  const values: Record<string, Json> = Object.create(null);
  for (const field of schema.fields) {
    const value = selectJson(document, field.pointer);
    requireThat(field.type === "array" ? Array.isArray(value) : field.type === "safe-integer" ? typeof value === "number" && Number.isSafeInteger(value) : typeof value === field.type, "INVALID_FIELD");
    values[field.id] = value;
  }
  for (const check of schema.checks) {
    const value = values[check.field]!;
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
          case "claude-paid-tier-v1": passes = claudePaidTier(value) !== null; break;
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
  return Object.freeze({ providerId: schema.providerId, domain: schema.claims.domain, identityVersion: schema.identity.version, subjectKey: deriveSubjectKey(schema, values[schema.identity.field]!, recipient), values: Object.freeze(values), claimable: false });
}

// Browser-only precheck on its own full transcript. Successful parsing is not
// evidence of TLS authenticity and must not be submitted to the API as proof.
export function previewExchange(schema: VerificationSchema, sent: Uint8Array, recv: Uint8Array, recipient: string): EvidenceFacts {
  const request = parseHttp(sent, schema, "sent");
  const pathParams = validateRequest(schema, request);
  return factsFromResponse(schema, parseHttp(recv, schema, "recv"), recipient, pathParams);
}

function factsFromResponse(schema: VerificationSchema, response: HttpMessage, recipient: string, pathParams: Readonly<Record<string, string>>): EvidenceFacts {
  requireThat(/^HTTP\/1\.1 200 [\x20-\x7e]*$/.test(response.startLine), "SCOPE_MISMATCH");
  const type = headerValue(response, "content-type");
  requireThat(type !== undefined && /^application\/json(?:\s*;\s*charset=(?:utf-8|"utf-8"))?$/i.test(type), "SCOPE_MISMATCH");
  // `parseHttp` has already decoded an admitted coding; this is the independent
  // restatement of what the schema admits, on the same bytes the facts come from.
  const encoding = headerValue(response, "content-encoding")?.toLowerCase();
  if (!schema.response.privacy) requireThat(encoding === undefined || encoding === "identity", "SCOPE_MISMATCH");
  else requireThat((schema.response.privacy.encodings as readonly string[]).includes(encoding ?? "identity"), "RESPONSE_ENCODING_UNSUPPORTED");
  return facts(schema, parseJson(utf8(response.body), schema.limits.maxJsonDepth), recipient, pathParams);
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
  let pathParams: Readonly<Record<string, string>>;
  // A cookie is always a credential, so a cookie schema always takes the redacted path.
  if (schema.capture.cookies.length > 0 || schema.capture.headers.some(header => header.secret)) {
    inspectDisclosedRequest(schema, exchange.sent);
    // The inspector proved the start line is public and matches the declared template;
    // this reads the parameter values back out of it through that same matcher.
    const match = /^([A-Z]+) (\S+) HTTP\/1\.1$/.exec(provenStartLine(exchange.sent.bytes));
    requireThat(match && match[1] === schema.request.method, "SCOPE_MISMATCH");
    pathParams = matchRequestTarget(schema, match![2]!);
  } else {
    requireCompleteCoverage(exchange.sent, schema.limits.maxSentBytes);
    pathParams = validateRequest(schema, parseHttp(exchange.sent.bytes, schema, "sent"));
  }
  return factsFromResponse(schema, inspectDisclosedResponse(schema, exchange.recv, responseDisclosure), recipient, pathParams);
}
