import { requireThat, reject } from "./errors.ts";
import type { VerificationSchema } from "./types.ts";

export type Header = Readonly<{ name: string; value: string; valueStart: number; valueEnd: number }>;
export type HttpMessage = Readonly<{ startLine: string; headers: readonly Header[]; body: Uint8Array }>;
export const encoder = new TextEncoder();
export function utf8(bytes: Uint8Array): string {
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { return reject("INVALID_JSON"); }
}
export function headerValue(message: HttpMessage, name: string): string | undefined {
  const values = message.headers.filter(header => header.name === name);
  requireThat(values.length <= 1, "INVALID_HTTP");
  return values[0]?.value;
}
function indexOf(bytes: Uint8Array, pattern: readonly number[], from = 0): number {
  outer: for (let i = from; i <= bytes.length - pattern.length; i++) {
    for (let j = 0; j < pattern.length; j++) if (bytes[i + j] !== pattern[j]) continue outer;
    return i;
  }
  return -1;
}
function chunkedBody(bytes: Uint8Array, limit: number): Uint8Array {
  let offset = 0;
  let size = 0;
  const chunks: Uint8Array[] = [];
  for (;;) {
    const lineEnd = indexOf(bytes, [13, 10], offset);
    requireThat(lineEnd >= offset && lineEnd - offset <= 8, "INVALID_HTTP");
    const line = String.fromCharCode(...bytes.subarray(offset, lineEnd));
    requireThat(/^[a-f\d]{1,8}$/i.test(line), "INVALID_HTTP");
    const length = Number.parseInt(line, 16);
    offset = lineEnd + 2;
    if (length === 0) {
      // v1 deliberately rejects trailers and chunk extensions.
      requireThat(offset + 2 === bytes.length && bytes[offset] === 13 && bytes[offset + 1] === 10, "INVALID_HTTP");
      break;
    }
    requireThat(size + length <= limit && chunks.length < 4096, "LIMIT_EXCEEDED");
    requireThat(offset + length + 2 <= bytes.length && bytes[offset + length] === 13 && bytes[offset + length + 1] === 10, "INVALID_HTTP");
    chunks.push(bytes.subarray(offset, offset + length));
    size += length; offset += length + 2;
  }
  const result = new Uint8Array(size);
  let cursor = 0;
  for (const chunk of chunks) { result.set(chunk, cursor); cursor += chunk.length; }
  return result;
}

// Full bytes only. A redacted credential could hide CRLF; parsing a replacement
// character as a header value cannot authenticate the actual request grammar.
export function parseHttp(bytes: Uint8Array, schema: VerificationSchema, direction: "sent" | "recv"): HttpMessage {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0, "INVALID_HTTP");
  requireThat(bytes.length <= (direction === "sent" ? schema.limits.maxSentBytes : schema.limits.maxRecvBytes), "LIMIT_EXCEEDED");
  const headerEnd = indexOf(bytes.subarray(0, schema.limits.maxHeaderBytes), [13, 10, 13, 10]);
  requireThat(headerEnd >= 0, "INVALID_HTTP");
  const head = bytes.subarray(0, headerEnd);
  requireThat(head.every(byte => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)), "INVALID_HTTP");
  const lines = new TextDecoder().decode(head).split("\r\n");
  const startLine = lines.shift()!;
  requireThat(/^[\x20-\x7e]+$/.test(startLine), "INVALID_HTTP");
  const headers: Header[] = [];
  let offset = startLine.length + 2;
  for (const line of lines) {
    requireThat(headers.length < 128 && !/^[ \t]/.test(line), "INVALID_HTTP");
    const match = /^([!#$%&'*+.^_`|~\da-z-]+):([\t\x20-\x7e]*)$/i.exec(line);
    requireThat(match, "INVALID_HTTP");
    const prefix = match[1]!.length + 1;
    const leading = /^[ \t]*/.exec(match[2]!)![0].length;
    const trailing = /[ \t]*$/.exec(match[2]!)![0].length;
    const value = match[2]!.trim();
    headers.push({ name: match[1]!.toLowerCase(), value, valueStart: offset + prefix + leading, valueEnd: offset + line.length - (value ? trailing : 0) });
    offset += line.length + 2;
  }
  const message = { startLine, headers, body: bytes.subarray(headerEnd + 4) };
  for (const key of ["host", "content-length", "transfer-encoding", "content-encoding", "content-type"]) headerValue(message, key);
  const length = headerValue(message, "content-length");
  const coding = headerValue(message, "transfer-encoding");
  requireThat(!(length !== undefined && coding !== undefined), "INVALID_HTTP");
  if (coding !== undefined) {
    requireThat(direction === "recv" && coding.toLowerCase() === "chunked", "INVALID_HTTP");
    message.body = chunkedBody(message.body, schema.limits.maxBodyBytes);
  } else if (length !== undefined) {
    requireThat(/^(?:0|[1-9]\d*)$/.test(length) && Number.isSafeInteger(Number(length)) && Number(length) === message.body.length, "INVALID_HTTP");
  } else requireThat(direction === "sent" && message.body.length === 0, "INVALID_HTTP");
  requireThat(message.body.length <= schema.limits.maxBodyBytes, "LIMIT_EXCEEDED");
  return message;
}
