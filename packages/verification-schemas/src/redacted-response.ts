import { requireThat } from "./errors.ts";
import { parseHttp, type HttpMessage } from "./http.ts";
import type { ResponseDisclosureMode, VerificationSchema, VerifiedBytes } from "./types.ts";

type Coverage = Readonly<{ bytes: Uint8Array; length: number; coverage: Uint8Array; revealed: number }>;

// Authenticated coverage, plus the revealed-byte total this disclosure actually costs.
// Every revealed byte is authenticated in zero knowledge once any response byte is
// hidden, so the total — not the response size — is the budget that matters.
function cover(schema: VerificationSchema, recv: VerifiedBytes): Coverage {
  requireThat(recv.bytes instanceof Uint8Array && Number.isSafeInteger(recv.originalLength)
    && recv.originalLength > 0 && recv.originalLength === recv.bytes.length, "PARTIAL_TRANSCRIPT");
  const bytes = recv.bytes, length = bytes.length;
  requireThat(length <= schema.limits.maxRecvBytes && Array.isArray(recv.authenticated)
    && recv.authenticated.length <= 4096, "LIMIT_EXCEEDED");
  const coverage = new Uint8Array(length);
  let end = 0, revealed = 0;
  for (const range of recv.authenticated) {
    requireThat(range && Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end)
      && range.start >= end && range.end > range.start && range.end <= length, "PARTIAL_TRANSCRIPT");
    coverage.fill(1, range.start, range.end); end = range.end;
    revealed += range.end - range.start;
  }
  return { bytes, length, coverage, revealed };
}

// Read authenticated HTTP structure, permitting only complete opaque values of
// Set-Cookie and the schema's reviewed secret headers. Native disclosure does
// not certify the grammar of hidden bytes. Never interpret a hidden value.
export function inspectDisclosedResponse(schema: VerificationSchema, recv: VerifiedBytes, responseDisclosure: ResponseDisclosureMode = "selective"): HttpMessage {
  requireThat(responseDisclosure === "selective" || responseDisclosure === "complete" || responseDisclosure === "private-headers", "PRIVATE_REQUEST_UNSUPPORTED");
  // A privacy block and the private-headers mode are refused apart: a schema whose
  // header-hiding contract is undeclared must never be disclosed under it, and a
  // schema that declares one must never be disclosed under the older contracts.
  requireThat((responseDisclosure === "private-headers") === (schema.response.privacy !== undefined), "PRIVATE_REQUEST_UNSUPPORTED");
  const { bytes, length, coverage, revealed } = cover(schema, recv);
  if (responseDisclosure === "complete") {
    requireThat(coverage.every(byte => byte === 1), "PARTIAL_TRANSCRIPT");
    return parseHttp(bytes, schema, "recv");
  }
  if (schema.limits.maxRevealedRecvBytes !== undefined) requireThat(revealed <= schema.limits.maxRevealedRecvBytes, "REVEALED_LIMIT_EXCEEDED");
  const privateHeaders = responseDisclosure === "private-headers";
  const visible: readonly string[] = schema.response.privacy?.visibleHeaders ?? [];
  let cursor = 0;
  const publicByte = () => {
    requireThat(cursor < length && coverage[cursor] === 1, "PARTIAL_TRANSCRIPT");
    requireThat(cursor < schema.limits.maxHeaderBytes, "LIMIT_EXCEEDED");
    return bytes[cursor++]!;
  };
  const crlf = () => {requireThat(publicByte() === 13 && publicByte() === 10, "INVALID_HTTP");};
  const line = (allowTab: boolean) => {
    const chars: number[] = [];
    for (;;) {
      const byte = publicByte();
      if (byte === 13) {requireThat(publicByte() === 10, "INVALID_HTTP"); break;}
      requireThat((byte >= 32 && byte <= 126) || (allowTab && byte === 9), "INVALID_HTTP");
      chars.push(byte);
    }
    return new TextDecoder().decode(new Uint8Array(chars));
  };
  const lines = [line(false)];
  const responseSecrets = new Set(["set-cookie", ...(schema.response.secretHeaders ?? [])]);
  let headers = 0;
  for (;;) {
    requireThat(cursor < length && coverage[cursor] === 1, "PARTIAL_TRANSCRIPT");
    if (bytes[cursor] === 13) {crlf(); break;}
    requireThat(++headers <= 128, "LIMIT_EXCEEDED");
    let name = "";
    for (;;) {
      const byte = publicByte();
      if (byte === 58) break;
      const char = String.fromCharCode(byte);
      requireThat(/^[!#$%&'*+.^_`|~\da-z-]$/i.test(char), "INVALID_HTTP");
      name += char;
    }
    requireThat(name.length > 0, "INVALID_HTTP");
    // In private-headers mode the rule is not a list of sensitive names: every value
    // except the framing is hidden, so hiding carries no judgement about any header.
    const hidden = privateHeaders ? !visible.includes(name.toLowerCase()) : responseSecrets.has(name.toLowerCase());
    if (hidden) {
      requireThat(publicByte() === 32, "INVALID_HTTP");
      const start = cursor;
      while (cursor < length && coverage[cursor] === 0) {
        requireThat(bytes[cursor] === 0, "PARTIAL_TRANSCRIPT"); cursor++;
      }
      // One complete value per range: nothing public before or after it on the line,
      // so a partly hidden value can never be read as a whole one.
      requireThat(cursor > start, "PRIVATE_REQUEST_UNSUPPORTED");
      crlf();
      // The NAME stays public and stays subject to the measured inventory's allowlist,
      // so an unknown header still refuses. An empty value carries no bytes to read.
      if (privateHeaders) lines.push(name + ":");
    } else {
      // A framing header must be public and a non-framing one must not be: a public
      // value where the contract promises a hidden one is a disclosure, not a detail.
      if (privateHeaders) {
        requireThat(visible.includes(name.toLowerCase()), "PRIVATE_REQUEST_UNSUPPORTED");
        // And the converse: a framing value that arrives hidden is refused by name
        // rather than through whatever the framing parser would make of nothing.
        for (let scan = cursor; scan < length && bytes[scan] !== 13; scan++) {
          requireThat(coverage[scan] === 1, "PRIVATE_REQUEST_UNSUPPORTED");
        }
      }
      lines.push(name + ":" + line(true));
    }
  }
  // JSON and all its framing bytes (including chunk lengths) must be public.
  // Quote/colon boundaries alone cannot certify hidden string interiors.
  requireThat(coverage.subarray(cursor).every(byte => byte === 1), "PARTIAL_TRANSCRIPT");
  // Omit the opaque, non-semantic secret headers. Everything parsed below is
  // authenticated public data, never placeholder plaintext for a hidden value.
  const head = new TextEncoder().encode(lines.join("\r\n") + "\r\n\r\n");
  const message = new Uint8Array(head.length + length - cursor);
  message.set(head); message.set(bytes.subarray(cursor), head.length);
  return parseHttp(message, schema, "recv");
}
