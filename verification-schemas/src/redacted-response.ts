import { requireThat } from "./errors.ts";
import { parseHttp, type HttpMessage } from "./http.ts";
import type { VerificationSchema, VerifiedBytes } from "./types.ts";

// Read authenticated HTTP structure, permitting only entire opaque Set-Cookie
// values. This checks the visible structure; native selective disclosure does
// not certify the grammar of hidden bytes. Never interpret a hidden value.
export function inspectDisclosedResponse(schema: VerificationSchema, recv: VerifiedBytes): HttpMessage {
  requireThat(recv.bytes instanceof Uint8Array && Number.isSafeInteger(recv.originalLength)
    && recv.originalLength > 0 && recv.originalLength === recv.bytes.length, "PARTIAL_TRANSCRIPT");
  const bytes = recv.bytes, length = bytes.length;
  requireThat(length <= schema.limits.maxRecvBytes && Array.isArray(recv.authenticated)
    && recv.authenticated.length <= 4096, "LIMIT_EXCEEDED");
  const coverage = new Uint8Array(length);
  let end = 0;
  for (const range of recv.authenticated) {
    requireThat(range && Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end)
      && range.start >= end && range.end > range.start && range.end <= length, "PARTIAL_TRANSCRIPT");
    coverage.fill(1, range.start, range.end); end = range.end;
  }
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
    if (name.toLowerCase() === "set-cookie") {
      requireThat(publicByte() === 32, "INVALID_HTTP");
      const start = cursor;
      while (cursor < length && coverage[cursor] === 0) {
        requireThat(bytes[cursor] === 0, "PARTIAL_TRANSCRIPT"); cursor++;
      }
      requireThat(cursor > start, "PRIVATE_REQUEST_UNSUPPORTED");
      crlf();
    } else lines.push(name + ":" + line(true));
  }
  // JSON and all its framing bytes (including chunk lengths) must be public.
  // Quote/colon boundaries alone cannot certify hidden string interiors
  // (see test/selective-disclosure-soundness.test.ts).
  requireThat(coverage.subarray(cursor).every(byte => byte === 1), "PARTIAL_TRANSCRIPT");
  // Omit the opaque, non-semantic cookie headers. Everything parsed below is
  // authenticated public data, never placeholder plaintext for a hidden value.
  const head = new TextEncoder().encode(lines.join("\r\n") + "\r\n\r\n");
  const message = new Uint8Array(head.length + length - cursor);
  message.set(head); message.set(bytes.subarray(cursor), head.length);
  return parseHttp(message, schema, "recv");
}
