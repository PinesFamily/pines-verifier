import { requireThat } from "./errors.ts";
import { canonicalJson, parseJson } from "./json.ts";
import { acceptEncoding, connectionHeader, exchangeViews, requestBody, requestTarget, requestUrl } from "./schema.ts";
import { encoder } from "./http.ts";
import type { CapturedRequest, ReplayRequest, VerificationSchema } from "./types.ts";

export function validateHeader(value: string, rule: "bearer" | "visible-ascii"): boolean {
  return rule === "bearer" ? /^Bearer [A-Za-z\d._~+/-]+=*$/i.test(value) : /^[\x20-\x7e]+$/.test(value);
}

// The request credentials may be taken from: the proven request itself, or — for an origin-wide cookie
// credential — any same-origin request under the schema's trigger prefix. Never another origin.
export function capturedFrom(schema: VerificationSchema, url: string, pathParams?: Readonly<Record<string, string>>): boolean {
  if (!schema.capture.trigger) {
    try { return url === requestUrl(schema, pathParams); } catch { return false; }
  }
  let parsed: URL;
  try { parsed = new URL(url); } catch { return false; }
  return parsed.origin === schema.request.origin && !parsed.username && !parsed.password && !parsed.hash
    && parsed.pathname.startsWith(schema.capture.trigger.pathPrefix);
}

export type ReplayOptions = Readonly<{ pathParams?: Readonly<Record<string, string>> }>;

export function prepareReplay(schema: VerificationSchema, captured: CapturedRequest, options: ReplayOptions = {}): ReplayRequest {
  return buildReplay(schema, captured, options, true, true);
}
/**
 * The ordered replays of a multi-exchange session, every one built from the ONE captured
 * request: the credential captured for the first exchange sends them all, each exchange's
 * own headers are taken from the same capture, and only the last request closes the
 * session. A single-exchange schema yields exactly `[prepareReplay(...)]`.
 */
export function prepareReplays(schema: VerificationSchema, captured: CapturedRequest, options: ReplayOptions = {}): readonly ReplayRequest[] {
  // A declared path parameter belongs to the first request alone; later paths are literals.
  return Object.freeze(exchangeViews(schema).map(view => buildReplay(view.schema, captured, view.index === 0 ? options : {}, view.final, view.index === 0)));
}
function buildReplay(schema: VerificationSchema, captured: CapturedRequest, options: ReplayOptions, final: boolean, matchUrl: boolean): ReplayRequest {
  // A declared template is instantiated before anything else, so a missing or
  // malformed parameter refuses here rather than producing a request to nowhere.
  const target = requestTarget(schema, options.pathParams);
  requireThat(captured.method === schema.request.method && (!matchUrl || capturedFrom(schema, captured.url, options.pathParams)), "INVALID_CAPTURE");
  requireThat(Array.isArray(captured.headers) && captured.headers.length <= 128, "INVALID_CAPTURE");
  const original = new Map<string, string>();
  for (const header of captured.headers) {
    requireThat(typeof header.name === "string" && /^[a-z\d-]+$/i.test(header.name) && typeof header.value === "string", "INVALID_CAPTURE");
    const name = header.name.toLowerCase();
    requireThat(!original.has(name) && !/[\r\n\0]/.test(header.value), "INVALID_CAPTURE");
    original.set(name, header.value);
  }
  const headers: Record<string, string> = { ...schema.replay.headers };
  for (const rule of schema.capture.headers) {
    const value = original.get(rule.name);
    if (value === undefined) { requireThat(!rule.required, "INVALID_CAPTURE"); continue; }
    requireThat(validateHeader(value, rule.validation), "INVALID_CAPTURE");
    headers[rule.name] = value;
  }
  if (schema.capture.cookies.length) {
    const cookies = new Map<string, string>();
    for (const part of (original.get("cookie") ?? "").split(";")) {
      const separator = part.indexOf("=");
      if (separator < 1) continue;
      const name = part.slice(0, separator).trim();
      if (!schema.capture.cookies.includes(name) && !schema.capture.optionalCookies?.includes(name)) continue;
      const value = part.slice(separator + 1).trim();
      requireThat(!cookies.has(name) && /^[\x21-\x7e]+$/.test(value), "INVALID_CAPTURE");
      cookies.set(name, value);
    }
    // Triggered capture exists only to carry the jar, so a jar missing any named cookie is no capture.
    if (schema.capture.trigger) requireThat(schema.capture.cookies.every(name => cookies.has(name)), "INVALID_CAPTURE");
    if (cookies.size) headers.cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }
  const body = requestBody(schema);
  const capturedBody = captured.body ?? "";
  requireThat(typeof capturedBody === "string" && encoder.encode(capturedBody).length <= schema.limits.maxSentBytes, "INVALID_CAPTURE");
  requireThat(schema.request.body.kind === "empty" ? capturedBody === "" : canonicalJson(parseJson(capturedBody, schema.limits.maxJsonDepth)) === body, "INVALID_CAPTURE");
  headers.host = new URL(schema.request.origin).host;
  // One derivation, shared with both request validators: gzip only when the schema's
  // privacy block lists it, identity otherwise. `replay.headers` still refuses to name it.
  headers["accept-encoding"] = acceptEncoding(schema);
  headers.connection = connectionHeader(final);
  if (schema.request.method === "POST") headers["content-length"] = String(encoder.encode(body).length);
  const wire = `${schema.request.method} ${target} HTTP/1.1\r\n` + Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join("") + "\r\n" + body;
  requireThat(encoder.encode(wire).length <= schema.limits.maxSentBytes, "LIMIT_EXCEEDED");
  return Object.freeze({ url: schema.request.origin + target, method: schema.request.method, headers: Object.freeze(headers), body });
}
