import { requireThat } from "./errors.ts";
import { requestTarget } from "./schema.ts";
import { validateHeader } from "./capture.ts";
import type { Range, VerificationSchema, VerifiedBytes } from "./types.ts";

export type RedactedHeader = Readonly<{ name: string; start: number; end: number }>;

// Inspect only authenticated public bytes surrounding native TLSN redactions.
// Hidden contents remain opaque: this does not prove their syntax or semantics.
export function inspectDisclosedRequest(
  schema: VerificationSchema,
  sent: VerifiedBytes,
): readonly RedactedHeader[] {
  requireThat(schema.request.body.kind === "empty", "PRIVATE_REQUEST_UNSUPPORTED");
  // A cookie jar is one required, entirely opaque header — the schema's cookie names are not
  // checkable once hidden, exactly as a hidden Authorization's Bearer syntax is not.
  const cookieRule = schema.capture.cookies.length > 0
    ? [{ name: "cookie", required: true, secret: true, validation: "visible-ascii" as const }] : [];
  const privateRules = [...schema.capture.headers, ...cookieRule].filter(rule => rule.secret);
  requireThat(privateRules.length > 0, "PRIVATE_REQUEST_UNSUPPORTED");
  requireThat(sent.bytes instanceof Uint8Array && Number.isSafeInteger(sent.originalLength)
    && sent.originalLength > 0 && sent.originalLength === sent.bytes.length, "PARTIAL_TRANSCRIPT");
  const bytes = sent.bytes, length = bytes.length;
  requireThat(length <= schema.limits.maxSentBytes && length <= schema.limits.maxHeaderBytes, "LIMIT_EXCEEDED");
  requireThat(Array.isArray(sent.authenticated) && sent.authenticated.length <= 4096, "LIMIT_EXCEEDED");
  const coverage = new Uint8Array(length);
  let end = 0;
  for (const range of sent.authenticated) {
    requireThat(range && Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end)
      && range.start >= end && range.end > range.start && range.end <= length, "PARTIAL_TRANSCRIPT");
    coverage.fill(1, range.start, range.end);
    end = range.end;
  }
  const hidden = new Map<number, Range>();
  for (let i = 0; i < length;) {
    if (coverage[i] === 1) { i++; continue; }
    const start = i;
    while (i < length && coverage[i] === 0) {
      requireThat(bytes[i] === 0, "PARTIAL_TRANSCRIPT");
      i++;
    }
    hidden.set(start, {start, end: i});
  }

  let cursor = 0;
  const publicByte = () => {
    requireThat(cursor < length && coverage[cursor] === 1, "PARTIAL_TRANSCRIPT");
    return bytes[cursor++]!;
  };
  const crlf = () => { requireThat(publicByte() === 13 && publicByte() === 10, "INVALID_HTTP"); };
  const publicLine = (allowTab: boolean) => {
    const value: number[] = [];
    for (;;) {
      const byte = publicByte();
      if (byte === 13) { requireThat(publicByte() === 10, "INVALID_HTTP"); break; }
      requireThat((byte >= 32 && byte <= 126) || (allowTab && byte === 9), "INVALID_HTTP");
      value.push(byte);
    }
    return new TextDecoder().decode(new Uint8Array(value));
  };
  requireThat(publicLine(false) === `${schema.request.method} ${requestTarget(schema)} HTTP/1.1`, "SCOPE_MISMATCH");
  const fixed = { ...schema.replay.headers, host: new URL(schema.request.origin).host, "accept-encoding": "identity", connection: "close" };
  const rules = new Map([...schema.capture.headers, ...cookieRule].map(rule => [rule.name, rule]));
  const allowed = new Set([...Object.keys(fixed), "content-length", ...rules.keys()]);
  const seen = new Set<string>(), publicHeaders = new Map<string, string>();
  const slots: RedactedHeader[] = [];
  for (;;) {
    requireThat(cursor < length && coverage[cursor] === 1, "PARTIAL_TRANSCRIPT");
    if (bytes[cursor] === 13) { crlf(); break; }
    requireThat(seen.size < 128, "LIMIT_EXCEEDED");
    let name = "";
    for (;;) {
      const byte = publicByte();
      if (byte === 58) break;
      const char = String.fromCharCode(byte);
      requireThat(/^[!#$%&'*+.^_`|~\da-z-]$/i.test(char), "INVALID_HTTP");
      name += char;
    }
    name = name.toLowerCase();
    requireThat(name.length > 0 && allowed.has(name) && !seen.has(name), "SCOPE_MISMATCH");
    seen.add(name);
    const rule = rules.get(name);
    if (rule?.secret) {
      // Canonical private wire form: public name + ": " + one entire opaque
      // value + public CRLF. Mixed public/private values and extra OWS are refused.
      requireThat(publicByte() === 32, "INVALID_HTTP");
      const range = hidden.get(cursor);
      requireThat(range !== undefined, "PRIVATE_REQUEST_UNSUPPORTED");
      slots.push(Object.freeze({ name, start: range.start, end: range.end }));
      cursor = range.end;
      crlf();
    } else {
      publicHeaders.set(name, publicLine(true).trim());
    }
  }
  requireThat(cursor === length && slots.length === hidden.size, "SCOPE_MISMATCH");
  for (const [name, value] of Object.entries(fixed)) requireThat(publicHeaders.get(name) === value, "SCOPE_MISMATCH");
  for (const rule of [...schema.capture.headers, ...cookieRule]) {
    requireThat(seen.has(rule.name) || !rule.required, "SCOPE_MISMATCH");
    if (!rule.secret && seen.has(rule.name)) requireThat(validateHeader(publicHeaders.get(rule.name)!, rule.validation), "SCOPE_MISMATCH");
  }
  requireThat(!seen.has("content-length") || publicHeaders.get("content-length") === "0", "INVALID_HTTP");
  return Object.freeze(slots);
}
