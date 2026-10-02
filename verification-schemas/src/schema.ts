import { canonicalJson, pointerTokens } from "./json.ts";
import { requireThat } from "./errors.ts";
import type { VerificationSchema } from "./types.ts";

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
  "claude-paid-personal-org-v1": "https://claude.ai", "grok-paid-subscription-v1": "https://grok.com",
}));

export function parseSchema(input: unknown): VerificationSchema {
  // Copy data, reject unsupported values/accessors, and detach it from caller mutation.
  const encoded = canonicalJson(input);
  requireThat(encoded.length <= 65_536, "INVALID_SCHEMA");
  const parsed = JSON.parse(encoded) as unknown;
  // `selector` is optional so every schema pinned before it existed keeps its exact digest.
  const optional = parsed !== null && typeof parsed === "object" && Object.hasOwn(parsed, "selector") ? ["selector"] : [];
  const value = object(parsed, ["format", "schemaId", "version", "providerId", "lifecycle", "request", "capture", "replay", "limits", "response", ...optional, "fields", "checks", "identity", "claims"]);
  requireThat(value.format === "pines-verification-schema-v1", "INVALID_SCHEMA");
  string(value.schemaId, /^[a-z][a-z0-9.-]{0,95}$/);
  integer(value.version);
  string(value.providerId, /^[A-Z][A-Z0-9-]{0,95}$/);
  requireThat(["fixture", "candidate", "qualified"].includes(String(value.lifecycle)), "INVALID_SCHEMA");
  const request = object(value.request, ["origin", "method", "path", "query", "body"]);
  const origin = httpsOrigin(request.origin);
  requireThat(request.method === "GET" || request.method === "POST", "INVALID_SCHEMA");
  string(request.path, /^\/[\x21-\x7e]*$/);
  requireThat(!/[?#]/.test(request.path) && new URL(request.origin + request.path).pathname === request.path, "INVALID_SCHEMA");
  const query = object(request.query);
  for (const [key, entry] of Object.entries(query)) { string(key); requireThat(typeof entry === "string", "INVALID_SCHEMA"); }
  const body = object(request.body);
  if (body.kind === "empty") object(body, ["kind"]);
  else { requireThat(body.kind === "json" && request.method === "POST", "INVALID_SCHEMA"); object(body, ["kind", "value"]); }

  const capture = object(value.capture, ["navigationUrl", "authOrigins", "headers", "cookies", ...(Object.hasOwn(Object(value.capture), "trigger") ? ["trigger"] : [])]);
  const origins = uniqueStrings(capture.authOrigins).map(httpsOrigin);
  requireThat(origins.includes(origin), "INVALID_SCHEMA");
  string(capture.navigationUrl);
  let navigation: URL;
  try { navigation = new URL(capture.navigationUrl); } catch { requireThat(false, "INVALID_SCHEMA"); }
  requireThat(origins.includes(navigation.origin) && !navigation.username && !navigation.password, "INVALID_SCHEMA");
  const names = new Set<string>();
  for (const entry of list(capture.headers)) {
    const header = object(entry, ["name", "required", "secret", "validation"]);
    string(header.name, /^[a-z][a-z0-9-]*$/);
    requireThat(!/^(?:host|connection|content-length|content-type|transfer-encoding|accept-encoding|cookie|proxy-.*)$/.test(header.name), "INVALID_SCHEMA");
    requireThat(!names.has(header.name), "INVALID_SCHEMA"); names.add(header.name);
    requireThat(typeof header.required === "boolean" && typeof header.secret === "boolean", "INVALID_SCHEMA");
    requireThat(header.validation === "bearer" || header.validation === "visible-ascii", "INVALID_SCHEMA");
    if (header.name === "authorization") requireThat(header.secret === true && header.required === true && header.validation === "bearer", "INVALID_SCHEMA");
  }
  const cookies = uniqueStrings(capture.cookies, /^[a-zA-Z0-9_.-]+$/);
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
  const limits = object(value.limits, ["maxSentBytes", "maxRecvBytes", "maxHeaderBytes", "maxBodyBytes", "maxJsonDepth", "sessionTimeoutMs", "maxRecvRecords", "concurrency"]);
  for (const entry of Object.values(limits)) integer(entry);
  requireThat(Number(limits.maxJsonDepth) <= 64 && Number(limits.sessionTimeoutMs) <= 120_000 && Number(limits.concurrency) <= 16, "INVALID_SCHEMA");
  requireThat(Number(limits.maxHeaderBytes) <= Number(limits.maxSentBytes) && Number(limits.maxHeaderBytes) <= Number(limits.maxRecvBytes) && Number(limits.maxBodyBytes) <= Number(limits.maxRecvBytes), "INVALID_SCHEMA");
  const response = object(value.response, ["status", "contentType", "disclosure"]);
  requireThat(response.status === 200 && response.contentType === "application/json" && response.disclosure === "full-json-body", "INVALID_SCHEMA");
  if (optional.length) {
    const selector = object(value.selector, ["kind"]);
    requireThat(SELECTOR_ORIGINS[String(selector.kind)] !== undefined && SELECTOR_ORIGINS[String(selector.kind)] === request.origin, "INVALID_SCHEMA");
  }
  const fields = new Map<string, ObjectValue>();
  for (const entry of list(value.fields)) {
    const field = object(entry, ["id", "pointer", "type"]);
    string(field.id, /^[a-z][a-zA-Z0-9_]{0,63}$/);
    string(field.pointer); pointerTokens(field.pointer);
    requireThat(["string", "safe-integer", "boolean", "array"].includes(String(field.type)), "INVALID_SCHEMA");
    requireThat(!fields.has(field.id), "INVALID_SCHEMA"); fields.set(field.id, field);
  }
  requireThat(fields.size > 0, "INVALID_SCHEMA");
  for (const entry of list(value.checks)) {
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
  const identity = object(value.identity, ["version", "kind", "field"]);
  string(identity.version, /^[a-z][a-z0-9-]{0,95}$/); string(identity.field);
  requireThat(["string", "safe-integer"].includes(String(fields.get(identity.field)?.type)), "INVALID_SCHEMA");
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
  return freeze(value) as VerificationSchema;
}

export function requestTarget(schema: VerificationSchema): string {
  const query = new URLSearchParams(Object.entries(schema.request.query).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)).toString();
  return schema.request.path + (query ? `?${query}` : "");
}
export function requestUrl(schema: VerificationSchema): string { return schema.request.origin + requestTarget(schema); }
export function requestBody(schema: VerificationSchema): string {
  return schema.request.body.kind === "empty" ? "" : canonicalJson(schema.request.body.value);
}
export async function schemaDigest(schema: VerificationSchema): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(schema));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return "sha256:" + Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}
