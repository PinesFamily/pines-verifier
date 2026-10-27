import { canonicalJson, pointerTokens } from "./json.ts";
import { requireThat } from "./errors.ts";
import type { ExchangeBinding, VerificationSchema } from "./types.ts";

type ObjectValue = Record<string, unknown>;
function object(value: unknown, keys?: readonly string[]): ObjectValue {
  requireThat(value !== null && typeof value === "object" && !Array.isArray(value), "INVALID_SCHEMA");
  if (keys) requireThat(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)), "INVALID_SCHEMA");
  return value as ObjectValue;
}
function string(value: unknown, pattern?: RegExp): asserts value is string {
  requireThat(typeof value === "string" && value.length > 0 && value.length <= 2048, "INVALID_SCHEMA");
  if (pattern) requireThat(pattern.test(value), "INVALID_SCHEMA");
}
function list(value: unknown): unknown[] {
  requireThat(Array.isArray(value) && value.length <= 128, "INVALID_SCHEMA");
  return value;
}
function integer(value: unknown, max = 1_048_576): asserts value is number {
  requireThat(typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value <= max, "INVALID_SCHEMA");
}
function uniqueStrings(value: unknown, pattern?: RegExp): string[] {
  const result = list(value);
  for (const entry of result) string(entry, pattern);
  requireThat(new Set(result).size === result.length, "INVALID_SCHEMA");
  return result as string[];
}
export function httpsOrigin(value: unknown): string {
  string(value);
  let url: URL;
  try { url = new URL(value); } catch { requireThat(false, "INVALID_SCHEMA"); }
  requireThat(url.protocol === "https:" && url.port === "" && url.username === "" && url.password === "", "INVALID_SCHEMA");
  requireThat(/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*$/.test(url.hostname), "INVALID_SCHEMA");
  requireThat(value === `https://${url.hostname}`, "INVALID_SCHEMA");
  return value;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// Every custom handler, and the one field type it can be applied to.
const HANDLER_TYPES: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), {
  "chatgpt-plan-v1": "string", "chatgpt-user-id-v1": "string", "non-empty-string-v1": "string",
  "claude-org-uuid-v1": "string", "claude-paid-tier-v1": "string", "claude-paid-capabilities-v1": "array",
  "grok-user-uuid-v1": "string", "grok-paid-tier-v1": "string",
}));
// Each selector is written for one provider's response shape; it is never reusable elsewhere.
const SELECTOR_ORIGINS: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), {
  "claude-paid-personal-org-v1": "https://claude.ai", "claude-paid-personal-org-single-v1": "https://claude.ai",
  "grok-paid-subscription-v1": "https://grok.com", "grok-paid-subscription-v2": "https://grok.com",
  "chatgpt-plan-limit-history-v1": "https://chatgpt.com",
}));
// Only a selector that reads a bounded list can be given an item cap.
const SELECTOR_MAX_ITEMS: Readonly<Record<string, number>> = Object.freeze(Object.assign(Object.create(null), {
  "grok-paid-subscription-v1": 64, "grok-paid-subscription-v2": 64,
}));

// Each field transform reads one provider's value vocabulary, so it is bound to that
// provider's origin exactly as a selector is; the generic one is origin-free.
const TRANSFORM_TYPES: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), {
  "iso-8601-seconds-v1": "string", "grok-billing-system-v1": "string", "claude-billing-type-v1": "string",
}));
const TRANSFORM_ORIGINS: Readonly<Record<string, string>> = Object.freeze(Object.assign(Object.create(null), {
  "grok-billing-system-v1": "https://grok.com", "claude-billing-type-v1": "https://claude.ai",
}));
// At most this many request/response pairs in one TLS session (the first plus `exchanges`).
export const MAX_EXCHANGES = 4;

// Declared request path parameters. Each kind is a fixed-length, anchored pattern, so a
// concrete target splits into literal text and parameter values with no ambiguity.
const PATH_PARAM_NAME = /^[a-z][a-z0-9_]{0,31}$/;
const PARAM_KINDS: Readonly<Record<string, Readonly<{ pattern: RegExp; length: number; specimen: string }>>> =
  Object.freeze(Object.assign(Object.create(null), {
    "lowercase-uuid-v1": Object.freeze({
      pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, length: 36,
      specimen: "00000000-0000-4000-8000-000000000000",
    }),
  }));
// The framing values a private-headers response keeps public. Every other header value
// is one complete hidden range, so this list is the whole public-header budget.
export const VISIBLE_RESPONSE_HEADERS: readonly string[] =
  Object.freeze(["content-type", "content-length", "transfer-encoding", "content-encoding"]);
// Request exactly gzip or exactly identity; never br or zstd (claude.ai's brotli is
// larger than its gzip). `["gzip"]` alone is the one-constant tightening.
const ENCODING_SETS: readonly (readonly string[])[] =
  Object.freeze([Object.freeze(["gzip", "identity"]), Object.freeze(["identity"]), Object.freeze(["gzip"])]);
const PRIVACY_LIMITS: readonly string[] =
  Object.freeze(["maxDecodedBodyBytes", "maxChunks", "maxRevealedRecvBytes", "maxRevealedSentBytes"]);

export function parseSchema(input: unknown): VerificationSchema {
  // Copy data, reject unsupported values/accessors, and detach it from caller mutation.
  const encoded = canonicalJson(input);
  requireThat(encoded.length <= 65_536, "INVALID_SCHEMA");
  const parsed = JSON.parse(encoded) as unknown;
  // `selector` is optional so every schema pinned before it existed keeps its exact digest.
  const optional = parsed !== null && typeof parsed === "object" && Object.hasOwn(parsed, "selector") ? ["selector"] : [];
  // `exchanges` is optional for the same reason: a single-exchange schema's bytes are untouched.
  const hasExchanges = parsed !== null && typeof parsed === "object" && Object.hasOwn(parsed, "exchanges");
  const value = object(parsed, ["format", "schemaId", "version", "providerId", "lifecycle", "request", "capture", "replay", "limits", "response", ...optional, "fields", "checks", "identity", "claims", ...(hasExchanges ? ["exchanges"] : [])]);
  requireThat(value.format === "pines-verification-schema-v1", "INVALID_SCHEMA");
  string(value.schemaId, /^[a-z][a-z0-9.-]{0,95}$/);
  integer(value.version);
  string(value.providerId, /^[A-Z][A-Z0-9-]{0,95}$/);
  requireThat(["fixture", "candidate", "qualified"].includes(String(value.lifecycle)), "INVALID_SCHEMA");
  const hasPathParams = Object.hasOwn(Object(value.request), "pathParams");
  const request = object(value.request, ["origin", "method", "path", "query", "body", ...(hasPathParams ? ["pathParams"] : [])]);
  const origin = httpsOrigin(request.origin);
  requireThat(request.method === "GET" || request.method === "POST", "INVALID_SCHEMA");
  string(request.path, /^\/[\x21-\x7e]*$/);
  requireThat(!/[?#]/.test(request.path), "INVALID_SCHEMA");
  // Without declared parameters the path is one literal, which must survive a URL
  // pathname round trip; `{` would not, which is why a template declares itself.
  if (!hasPathParams) requireThat(!/[{}]/.test(request.path) && new URL(request.origin + request.path).pathname === request.path, "INVALID_SCHEMA");
  else {
    const params = object(request.pathParams);
    const names = Object.keys(params);
    requireThat(names.length >= 1 && names.length <= 4, "INVALID_SCHEMA");
    let instantiated: string = request.path;
    for (const [name, entry] of Object.entries(params)) {
      string(name, PATH_PARAM_NAME);
      const spec = object(entry, ["kind", "bindsTo"]);
      const kind = PARAM_KINDS[String(spec.kind)];
      requireThat(kind !== undefined, "INVALID_SCHEMA");
      // The proven value must equal a field of the SELECTED response document. A
      // pointer can only name response JSON, never a prover-controlled cookie such
      // as claude.ai's `lastActiveOrg`, which is a hint and never an authority.
      string(spec.bindsTo); pointerTokens(spec.bindsTo);
      requireThat(spec.bindsTo !== "", "INVALID_SCHEMA");
      const placeholder = `{${name}}`;
      requireThat(request.path.split(placeholder).length === 2, "INVALID_SCHEMA");
      instantiated = instantiated.split(placeholder).join(kind!.specimen);
    }
    requireThat(!/[{}]/.test(instantiated) && new URL(request.origin + instantiated).pathname === instantiated, "INVALID_SCHEMA");
  }
  const query = object(request.query);
  for (const [key, entry] of Object.entries(query)) { string(key); requireThat(typeof entry === "string", "INVALID_SCHEMA"); }
  const body = object(request.body);
  if (body.kind === "empty") object(body, ["kind"]);
  else { requireThat(body.kind === "json" && request.method === "POST", "INVALID_SCHEMA"); object(body, ["kind", "value"]); }

  const capture = object(value.capture, ["navigationUrl", "authOrigins", "headers", "cookies", ...(Object.hasOwn(Object(value.capture), "trigger") ? ["trigger"] : []), ...(Object.hasOwn(Object(value.capture), "optionalCookies") ? ["optionalCookies"] : [])]);
  const origins = uniqueStrings(capture.authOrigins).map(httpsOrigin);
  requireThat(origins.includes(origin), "INVALID_SCHEMA");
  string(capture.navigationUrl);
  let navigation: URL;
  try { navigation = new URL(capture.navigationUrl); } catch { requireThat(false, "INVALID_SCHEMA"); }
  requireThat(origins.includes(navigation.origin) && !navigation.username && !navigation.password, "INVALID_SCHEMA");
  const names = new Set<string>();
  parseCaptureHeaders(capture.headers, names);
  const cookies = uniqueStrings(capture.cookies, /^[a-zA-Z0-9_.-]+$/);
  if (Object.hasOwn(capture, "optionalCookies")) {
    const optional = uniqueStrings(capture.optionalCookies, /^[a-zA-Z0-9_.-]+$/);
    requireThat(cookies.length > 0 && optional.length > 0 && optional.length <= 4
      && optional.every(name => !cookies.includes(name)), "INVALID_SCHEMA");
  }
  if (Object.hasOwn(capture, "trigger")) {
    // A trigger only makes sense for an origin-wide credential: a cookie jar and no Authorization,
    // which is request-scoped and would have to come from the proven request itself.
    const trigger = object(capture.trigger, ["pathPrefix"]);
    string(trigger.pathPrefix, /^\/(?:[a-z0-9_-]+\/)*$/);
    requireThat(cookies.length > 0 && !names.has("authorization") && request.method === "GET" && body.kind === "empty", "INVALID_SCHEMA");
  }
  const replay = object(value.replay, ["transform", "headers"]);
  requireThat(replay.transform === "fixed-request-v1", "INVALID_SCHEMA");
  for (const [name, entry] of Object.entries(object(replay.headers))) {
    requireThat(/^[a-z][a-z0-9-]*$/.test(name) && !names.has(name), "INVALID_SCHEMA");
    requireThat(!/^(?:host|connection|content-length|transfer-encoding|accept-encoding|authorization|cookie|proxy-.*)$/.test(name), "INVALID_SCHEMA");
    string(entry, /^[\x20-\x7e]+$/);
  }
  // The four privacy limits exist only together with `response.privacy`, so no schema
  // can be half-configured and every schema pinned before them keeps its exact digest.
  const hasPrivacy = Object.hasOwn(Object(value.response), "privacy");
  const privacyLimits = PRIVACY_LIMITS.filter(key => Object.hasOwn(Object(value.limits), key));
  requireThat(privacyLimits.length === (hasPrivacy ? PRIVACY_LIMITS.length : 0), "INVALID_SCHEMA");
  const limits = object(value.limits, ["maxSentBytes", "maxRecvBytes", "maxHeaderBytes", "maxBodyBytes", "maxJsonDepth", "sessionTimeoutMs", "maxRecvRecords", "concurrency", ...privacyLimits]);
  for (const entry of Object.values(limits)) integer(entry);
  requireThat(Number(limits.maxJsonDepth) <= 64 && Number(limits.sessionTimeoutMs) <= 120_000 && Number(limits.concurrency) <= 16, "INVALID_SCHEMA");
  requireThat(Number(limits.maxHeaderBytes) <= Number(limits.maxSentBytes) && Number(limits.maxHeaderBytes) <= Number(limits.maxRecvBytes) && Number(limits.maxBodyBytes) <= Number(limits.maxRecvBytes), "INVALID_SCHEMA");
  if (hasPrivacy) {
    // maxBodyBytes keeps its meaning: the de-chunked wire body, i.e. the encoded one.
    requireThat(Number(limits.maxDecodedBodyBytes) >= Number(limits.maxBodyBytes) && Number(limits.maxDecodedBodyBytes) <= 65_536, "INVALID_SCHEMA");
    requireThat(Number(limits.maxChunks) <= 4096, "INVALID_SCHEMA");
    requireThat(Number(limits.maxRevealedRecvBytes) <= Number(limits.maxRecvBytes), "INVALID_SCHEMA");
    requireThat(Number(limits.maxRevealedSentBytes) <= Number(limits.maxSentBytes), "INVALID_SCHEMA");
  }
  const response = object(value.response, ["status", "contentType", "disclosure",
    ...(Object.hasOwn(Object(value.response), "secretHeaders") ? ["secretHeaders"] : []), ...(hasPrivacy ? ["privacy"] : [])]);
  requireThat(response.status === 200 && response.contentType === "application/json" && response.disclosure === "full-json-body", "INVALID_SCHEMA");
  if (Object.hasOwn(response, "secretHeaders")) {
    const secretHeaders = uniqueStrings(response.secretHeaders);
    requireThat(request.origin === "https://chatgpt.com" && secretHeaders.length === 1
      && secretHeaders[0] === "x-oai-is-update", "INVALID_SCHEMA");
  }
  if (hasPrivacy) {
    // Hiding is not a judgement about which header is sensitive: everything except
    // the framing is hidden, so `secretHeaders` has nothing left to name.
    requireThat(!Object.hasOwn(response, "secretHeaders"), "INVALID_SCHEMA");
    const privacy = object(response.privacy, ["mode", "visibleHeaders", "encodings"]);
    requireThat(privacy.mode === "private-headers-v1", "INVALID_SCHEMA");
    const visible = uniqueStrings(privacy.visibleHeaders, /^[a-z][a-z0-9-]*$/);
    requireThat(visible.length === VISIBLE_RESPONSE_HEADERS.length
      && visible.every((name, index) => name === VISIBLE_RESPONSE_HEADERS[index]), "INVALID_SCHEMA");
    const encodings = uniqueStrings(privacy.encodings, /^[a-z]+$/);
    requireThat(ENCODING_SETS.some(set => set.length === encodings.length && set.every((name, index) => name === encodings[index])), "INVALID_SCHEMA");
  }
  if (optional.length) parseSelector(value.selector, origin);
  // Field ids are unique across the first exchange and every later one: all of them land
  // in one `values` object on one receipt.
  const allFields = new Set<string>();
  const fields = parseFieldsAndChecks(value.fields, value.checks, origin, allFields);
  const identity = object(value.identity, ["version", "kind", "field"]);
  string(identity.version, /^[a-z][a-z0-9-]{0,95}$/); string(identity.field);
  requireThat(["string", "safe-integer"].includes(String(fields.get(identity.field)?.type)), "INVALID_SCHEMA");
  // The subject is the provider's own identifier, never a transformed value.
  requireThat(!Object.hasOwn(fields.get(identity.field)!, "transform"), "INVALID_SCHEMA");
  requireThat(identity.kind === "field" || identity.kind === "legacy-plan-wallet", "INVALID_SCHEMA");
  if (identity.kind === "legacy-plan-wallet") {
    requireThat(value.providerId === "CHATGPT-SUBSCRIPTION" && identity.version === "legacy-plan-wallet-v1" && fields.get(identity.field)?.pointer === "/plan_type", "INVALID_SCHEMA");
  }
  const claims = object(value.claims, ["enabled", "domain", "templateIds"]);
  requireThat(typeof claims.enabled === "boolean" && claims.enabled === (value.lifecycle === "qualified"), "INVALID_SCHEMA");
  string(claims.domain, /^[a-z0-9.-]+$/); uniqueStrings(claims.templateIds, /^[A-Z][A-Z0-9-]*$/);
  if (value.lifecycle === "fixture") requireThat((claims.templateIds as unknown[]).length === 0, "INVALID_SCHEMA");
  if (claims.enabled) requireThat((claims.templateIds as unknown[]).length > 0, "INVALID_SCHEMA");
  if (identity.kind === "legacy-plan-wallet") requireThat(claims.domain === "chatgpt.com" && request.origin === "https://chatgpt.com", "INVALID_SCHEMA");
  if (hasExchanges) {
    // Later exchanges ride the same TLS session as the first: same origin and method, no
    // body, the same captured credential. Each has its own path, query, fields and checks.
    const exchanges = list(value.exchanges);
    requireThat(exchanges.length >= 1 && exchanges.length + 1 <= MAX_EXCHANGES, "INVALID_SCHEMA");
    // The first request may be a template (Claude's per-org route); later paths are literals.
    requireThat(request.method === "GET" && body.kind === "empty", "INVALID_SCHEMA");
    const replayHeaders = object(replay.headers);
    for (const entry of exchanges) {
      const hasSelector = Object.hasOwn(Object(entry), "selector");
      const exchange = object(entry, ["request", ...(hasSelector ? ["selector"] : []), "fields", "checks", "binding"]);
      const later = object(exchange.request, ["path", "query", "headers"]);
      string(later.path, /^\/[\x21-\x7e]*$/);
      requireThat(!/[?#{}]/.test(later.path) && new URL(origin + later.path).pathname === later.path, "INVALID_SCHEMA");
      const laterQuery = object(later.query);
      for (const [key, v] of Object.entries(laterQuery)) { string(key); requireThat(typeof v === "string", "INVALID_SCHEMA"); }
      // Exchange-only headers (a provider's per-route selector header, say) join the
      // capture's for that exchange alone; the names stay distinct from the shared ones.
      const laterNames = new Set(names);
      parseCaptureHeaders(later.headers, laterNames);
      for (const name of laterNames) requireThat(!Object.hasOwn(replayHeaders, name), "INVALID_SCHEMA");
      if (hasSelector) parseSelector(exchange.selector, origin);
      parseFieldsAndChecks(exchange.fields, exchange.checks, origin, allFields);
      const binding = object(exchange.binding);
      if (binding.kind === "credential") {
        object(binding, ["kind"]);
        // There must be a credential to bind: a hidden header or the cookie jar.
        requireThat(cookies.length > 0 || (capture.headers as { secret: boolean }[]).some(h => h.secret), "INVALID_SCHEMA");
      } else if (binding.kind === "request-header") {
        object(binding, ["kind", "header", "pointer"]);
        // A public header of the later request (declared, never secret) against a field of the first document.
        string(binding.header, /^[a-z][a-z0-9-]*$/);
        const rule = [...(capture.headers as { name: string; secret: boolean }[]), ...(later.headers as { name: string; secret: boolean }[])].find(h => h.name === binding.header);
        requireThat(rule !== undefined && rule.secret === false, "INVALID_SCHEMA");
        string(binding.pointer); pointerTokens(binding.pointer);
        requireThat(binding.pointer !== "", "INVALID_SCHEMA");
      } else if (binding.kind === "response-member") {
        object(binding, ["kind", "pointer", "field"]);
        requireThat(identity.kind === "field", "INVALID_SCHEMA");
        string(binding.pointer); pointerTokens(binding.pointer); string(binding.field); pointerTokens(binding.field);
        requireThat(binding.pointer !== "" && binding.field !== "", "INVALID_SCHEMA");
      } else {
        object(binding, ["kind", "pointer"]);
        requireThat(binding.kind === "response-field" && identity.kind === "field", "INVALID_SCHEMA");
        string(binding.pointer); pointerTokens(binding.pointer);
        requireThat(binding.pointer !== "", "INVALID_SCHEMA");
      }
    }
  }
  return freeze(value) as VerificationSchema;
}

function parseCaptureHeaders(value: unknown, names: Set<string>): void {
  for (const entry of list(value)) {
    const header = object(entry, ["name", "required", "secret", "validation"]);
    string(header.name, /^[a-z][a-z0-9-]*$/);
    requireThat(!/^(?:host|connection|content-length|content-type|transfer-encoding|accept-encoding|cookie|proxy-.*)$/.test(header.name), "INVALID_SCHEMA");
    requireThat(!names.has(header.name), "INVALID_SCHEMA"); names.add(header.name);
    requireThat(typeof header.required === "boolean" && typeof header.secret === "boolean", "INVALID_SCHEMA");
    requireThat(header.validation === "bearer" || header.validation === "visible-ascii", "INVALID_SCHEMA");
    if (header.name === "authorization") requireThat(header.secret === true && header.required === true && header.validation === "bearer", "INVALID_SCHEMA");
  }
}
function parseSelector(value: unknown, origin: string): void {
  // `maxItems` is optional for the same reason the selector itself is.
  const hasMaxItems = Object.hasOwn(Object(value), "maxItems");
  const selector = object(value, ["kind", ...(hasMaxItems ? ["maxItems"] : [])]);
  requireThat(SELECTOR_ORIGINS[String(selector.kind)] !== undefined && SELECTOR_ORIGINS[String(selector.kind)] === origin, "INVALID_SCHEMA");
  if (hasMaxItems) {
    const ceiling = SELECTOR_MAX_ITEMS[String(selector.kind)];
    requireThat(ceiling !== undefined, "INVALID_SCHEMA");
    integer(selector.maxItems);
    requireThat(Number(selector.maxItems) <= ceiling!, "INVALID_SCHEMA");
  }
}
function parseFieldsAndChecks(fieldsValue: unknown, checksValue: unknown, origin: string, allFields: Set<string>): Map<string, ObjectValue> {
  const fields = new Map<string, ObjectValue>();
  for (const entry of list(fieldsValue)) {
    // `transform` is optional so every schema pinned before it existed keeps its exact digest.
    const hasTransform = Object.hasOwn(Object(entry), "transform");
    const field = object(entry, ["id", "pointer", "type", ...(hasTransform ? ["transform"] : [])]);
    string(field.id, /^[a-z][a-zA-Z0-9_]{0,63}$/);
    string(field.pointer); pointerTokens(field.pointer);
    requireThat(["string", "safe-integer", "boolean", "array"].includes(String(field.type)), "INVALID_SCHEMA");
    if (hasTransform) {
      const sourceType = TRANSFORM_TYPES[String(field.transform)];
      requireThat(sourceType !== undefined && field.type === sourceType, "INVALID_SCHEMA");
      const bound = TRANSFORM_ORIGINS[String(field.transform)];
      requireThat(bound === undefined || bound === origin, "INVALID_SCHEMA");
    }
    requireThat(!fields.has(field.id) && !allFields.has(field.id), "INVALID_SCHEMA"); fields.set(field.id, field); allFields.add(field.id);
  }
  requireThat(fields.size > 0, "INVALID_SCHEMA");
  for (const entry of list(checksValue)) {
    const check = object(entry);
    string(check.field); const field = fields.get(check.field);
    requireThat(field, "INVALID_SCHEMA");
    if (check.op === "custom") {
      object(check, ["op", "field", "handler"]);
      const handlerType = HANDLER_TYPES[String(check.handler)];
      requireThat(handlerType !== undefined && field.type === handlerType, "INVALID_SCHEMA");
    } else if (check.op === "in" || check.op === "eq") {
      object(check, ["op", "field", check.op === "in" ? "values" : "value"]);
      const entries = check.op === "in" ? list(check.values) : [check.value];
      requireThat(entries.length > 0 && field.type !== "array", "INVALID_SCHEMA");
      for (const expected of entries) {
        requireThat(field.type === "safe-integer" ? Number.isSafeInteger(expected) : typeof expected === field.type, "INVALID_SCHEMA");
      }
    } else {
      object(check, ["op", "field", "value"]);
      requireThat(check.op === "gte" || check.op === "lte" || check.op === "array-length-gte", "INVALID_SCHEMA");
      requireThat(Number.isSafeInteger(check.value), "INVALID_SCHEMA");
      requireThat(check.op === "array-length-gte" ? field.type === "array" && Number(check.value) >= 0 : field.type === "safe-integer", "INVALID_SCHEMA");
    }
  }
  return fields;
}

/**
 * The ordered exchanges of a schema as views: index 0 is the schema itself; a later one is
 * the same schema with that exchange's request, headers, selector, fields and checks in
 * place, and no `exchanges`. Every matcher, validator and inspector written for one
 * exchange works unchanged on a view, so a later exchange is judged by exactly the code
 * that judges the first. `final` is whether the request closes the TLS session.
 */
export type ExchangeView = Readonly<{ schema: VerificationSchema; index: number; final: boolean; binding?: ExchangeBinding }>;
export function exchangeViews(schema: VerificationSchema): readonly ExchangeView[] {
  const later = schema.exchanges ?? [];
  const views: ExchangeView[] = [Object.freeze({ schema, index: 0, final: later.length === 0 })];
  later.forEach((exchange, offset) => {
    const { exchanges: _exchanges, selector: _selector, ...rest } = schema;
    const view: VerificationSchema = freeze({
      ...rest,
      request: { origin: schema.request.origin, method: schema.request.method, path: exchange.request.path, query: exchange.request.query, body: schema.request.body },
      capture: { ...schema.capture, headers: [...schema.capture.headers, ...exchange.request.headers] },
      ...(exchange.selector ? { selector: exchange.selector } : {}),
      fields: exchange.fields,
      checks: exchange.checks,
    });
    views.push(Object.freeze({ schema: view, index: offset + 1, final: offset === later.length - 1, binding: exchange.binding }));
  });
  return Object.freeze(views);
}
/** The header-name allowlist a capture keeps for every exchange, so a later exchange's own header survives the capture. */
export function captureHeaderNames(schema: VerificationSchema): readonly string[] {
  return Object.freeze([...new Set([...schema.capture.headers, ...(schema.exchanges ?? []).flatMap(exchange => exchange.request.headers)].map(rule => rule.name))]);
}

function querySuffix(schema: VerificationSchema): string {
  const query = new URLSearchParams(Object.entries(schema.request.query).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)).toString();
  return query ? `?${query}` : "";
}

/** Instantiate the declared path template. A schema without one ignores no value: a
 *  parameter offered to a schema that declares none is a mismatch, not a courtesy. */
export function instantiatePath(schema: VerificationSchema, pathParams?: Readonly<Record<string, string>>): string {
  const declared = schema.request.pathParams;
  if (!declared) {
    requireThat(pathParams === undefined || Object.keys(pathParams).length === 0, "PATH_PARAM_MISMATCH");
    return schema.request.path;
  }
  const given = pathParams ?? {};
  const names = Object.keys(declared);
  requireThat(Object.keys(given).length === names.length, "PATH_PARAM_MISMATCH");
  let path = schema.request.path;
  for (const name of names) {
    const value = given[name];
    requireThat(typeof value === "string" && PARAM_KINDS[declared[name]!.kind]!.pattern.test(value), "PATH_PARAM_MISMATCH");
    path = path.split(`{${name}}`).join(value);
  }
  return path;
}

/** The exact inverse: read the parameter values back out of a concrete request target.
 *  Both request paths (full and redacted) use this one matcher, so they cannot differ. */
export function matchRequestTarget(schema: VerificationSchema, target: string): Readonly<Record<string, string>> {
  requireThat(typeof target === "string" && target.length > 0 && target.length <= 2048, "SCOPE_MISMATCH");
  const suffix = querySuffix(schema);
  const declared = schema.request.pathParams;
  if (!declared) {
    requireThat(target === schema.request.path + suffix, "SCOPE_MISMATCH");
    return Object.freeze(Object.create(null) as Record<string, string>);
  }
  requireThat(target.endsWith(suffix) && target.length > suffix.length, "SCOPE_MISMATCH");
  const path = suffix ? target.slice(0, -suffix.length) : target;
  const template = schema.request.path;
  const values: Record<string, string> = Object.create(null);
  let cursor = 0, index = 0;
  while (index < template.length) {
    if (template[index] === "{") {
      const close = template.indexOf("}", index);
      requireThat(close > index, "INVALID_SCHEMA");
      const name = template.slice(index + 1, close);
      const kind = PARAM_KINDS[declared[name]?.kind ?? ""];
      requireThat(kind !== undefined, "INVALID_SCHEMA");
      // Every kind is fixed-length, so the value's extent never depends on a search
      // through attacker-chosen text.
      const value = path.slice(cursor, cursor + kind!.length);
      requireThat(kind!.pattern.test(value), "PATH_PARAM_MISMATCH");
      values[name] = value;
      cursor += kind!.length;
      index = close + 1;
    } else {
      requireThat(path[cursor] === template[index], "SCOPE_MISMATCH");
      cursor++; index++;
    }
  }
  requireThat(cursor === path.length, "SCOPE_MISMATCH");
  requireThat(Object.keys(values).length === Object.keys(declared).length, "PATH_PARAM_MISMATCH");
  return Object.freeze(values);
}

/** The request's content coding, derived from the response privacy block: one source
 *  of truth for the capture, the replay and the two request validators. */
export function acceptEncoding(schema: VerificationSchema): "gzip" | "identity" {
  return schema.response.privacy?.encodings.includes("gzip") ? "gzip" : "identity";
}

/** The one request header that differs between exchanges of a session: only the last closes it. */
export const connectionHeader = (final: boolean): "close" | "keep-alive" => final ? "close" : "keep-alive";

export function requestTarget(schema: VerificationSchema, pathParams?: Readonly<Record<string, string>>): string {
  return instantiatePath(schema, pathParams) + querySuffix(schema);
}
export function requestUrl(schema: VerificationSchema, pathParams?: Readonly<Record<string, string>>): string {
  return schema.request.origin + requestTarget(schema, pathParams);
}
export function requestBody(schema: VerificationSchema): string {
  return schema.request.body.kind === "empty" ? "" : canonicalJson(schema.request.body.value);
}
export async function schemaDigest(schema: VerificationSchema): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(schema));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return "sha256:" + Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}
