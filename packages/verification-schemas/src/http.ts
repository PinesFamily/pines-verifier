import { requireThat, reject } from "./errors.ts";
import { gunzip } from "./gzip.ts";
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
function chunkedBody(bytes: Uint8Array, limit: number, maxChunks: number): Uint8Array {
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
    requireThat(size + length <= limit && chunks.length < maxChunks, "LIMIT_EXCEEDED");
    requireThat(offset + length + 2 <= bytes.length && bytes[offset + length] === 13 && bytes[offset + length + 1] === 10, "INVALID_HTTP");
    chunks.push(bytes.subarray(offset, offset + length));
    size += length; offset += length + 2;
  }
  const result = new Uint8Array(size);
  let cursor = 0;
  for (const chunk of chunks) { result.set(chunk, cursor); cursor += chunk.length; }
  return result;
}

/**
 * Where each HTTP/1.1 message of a multi-exchange session starts and ends, read from the
 * public framing alone: the start line, header names, and the values of the framing
 * headers (`content-length`, `transfer-encoding`), which every disclosure mode keeps public.
 * A hidden (zeroed) header value is skipped without being read. The slices are then parsed
 * and judged by exactly the single-message code, so this scanner decides nothing but where
 * one message ends and the next begins. A request without a body ends at its header block.
 */
export function messageBoundaries(bytes: Uint8Array, schema: VerificationSchema, direction: "sent" | "recv", maxMessages: number): readonly Readonly<{ start: number; end: number }>[] {
  requireThat(bytes instanceof Uint8Array && bytes.length > 0, "INVALID_HTTP");
  const result: { start: number; end: number }[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    requireThat(result.length < maxMessages, "SCOPE_MISMATCH");
    const headerEnd = indexOf(bytes.subarray(offset, offset + schema.limits.maxHeaderBytes), [13, 10, 13, 10]);
    requireThat(headerEnd >= 0, "INVALID_HTTP");
    let length: number | undefined, chunked = false;
    const head = bytes.subarray(offset, offset + headerEnd);
    let lineStart = 0;
    for (;;) {
      const lineEnd = indexOf(head, [13, 10], lineStart);
      const line = head.subarray(lineStart, lineEnd < 0 ? head.length : lineEnd);
      if (lineStart > 0) {
        const colon = line.indexOf(58);
        requireThat(colon > 0, "INVALID_HTTP");
        const name = String.fromCharCode(...line.subarray(0, colon)).toLowerCase();
        if (name === "content-length" || name === "transfer-encoding") {
          requireThat(line.subarray(colon + 1).every(byte => byte >= 32 && byte <= 126 || byte === 9), "INVALID_HTTP");
          const value = String.fromCharCode(...line.subarray(colon + 1)).trim();
          if (name === "content-length") { requireThat(length === undefined && /^(?:0|[1-9]\d*)$/.test(value), "INVALID_HTTP"); length = Number(value); }
          else { requireThat(!chunked && value.toLowerCase() === "chunked", "INVALID_HTTP"); chunked = true; }
        }
      }
      if (lineEnd < 0) break;
      lineStart = lineEnd + 2;
    }
    requireThat(!(length !== undefined && chunked), "INVALID_HTTP");
    let end = offset + headerEnd + 4;
    if (chunked) {
      requireThat(direction === "recv", "INVALID_HTTP");
      for (;;) {
        const lineEnd = indexOf(bytes, [13, 10], end);
        requireThat(lineEnd >= end && lineEnd - end <= 8, "INVALID_HTTP");
        const size = String.fromCharCode(...bytes.subarray(end, lineEnd));
        requireThat(/^[a-f\d]{1,8}$/i.test(size), "INVALID_HTTP");
        const chunk = Number.parseInt(size, 16);
        end = lineEnd + 2 + chunk + 2;
        requireThat(end <= bytes.length && bytes[end - 2] === 13 && bytes[end - 1] === 10, "INVALID_HTTP");
        if (chunk === 0) break;
      }
    } else if (length !== undefined) {
      requireThat(Number.isSafeInteger(length) && end + length <= bytes.length, "INVALID_HTTP");
      end += length;
    } else requireThat(direction === "sent", "INVALID_HTTP");
    result.push({ start: offset, end });
    offset = end;
  }
  return Object.freeze(result.map(range => Object.freeze(range)));
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
    message.body = chunkedBody(message.body, schema.limits.maxBodyBytes, schema.limits.maxChunks ?? 4096);
  } else if (length !== undefined) {
    requireThat(/^(?:0|[1-9]\d*)$/.test(length) && Number.isSafeInteger(Number(length)) && Number(length) === message.body.length, "INVALID_HTTP");
  } else requireThat(direction === "sent" && message.body.length === 0, "INVALID_HTTP");
  // maxBodyBytes bounds the de-chunked WIRE body, so it bounds the encoded one.
  requireThat(message.body.length <= schema.limits.maxBodyBytes, "LIMIT_EXCEEDED");
  // The single decode point. Every caller — the browser's previewExchange and
  // planDisclosure, the enclave's inspectDisclosedResponse and inspectProviderShape —
  // reaches the body through parseHttp, so the body is decoded exactly once per parse
  // and no caller can forget to do it. The encoded bytes are already bounded above.
  message.body = decodedBody(message, schema, direction);
  return message;
}

function decodedBody(message: HttpMessage, schema: VerificationSchema, direction: "sent" | "recv"): Uint8Array {
  const privacy = schema.response.privacy;
  // A schema without a privacy block decodes nothing and is left exactly as it was:
  // the response validator still refuses every coding but identity, with its own code.
  // The request direction carries accept-encoding, never a content coding.
  if (!privacy || direction !== "recv") return message.body;
  // An absent content-encoding is identity, and must still be one the schema admits:
  // a gzip-only schema refuses an identity reply here rather than after parsing.
  const coding = headerValue(message, "content-encoding")?.toLowerCase() ?? "identity";
  requireThat((privacy.encodings as readonly string[]).includes(coding), "RESPONSE_ENCODING_UNSUPPORTED");
  // Never br or zstd: claude.ai's brotli is larger than its gzip, and an unmeasured
  // coding has no bounded decoder here.
  if (coding === "identity") return message.body;
  requireThat(coding === "gzip", "RESPONSE_ENCODING_UNSUPPORTED");
  return gunzip(message.body, schema.limits.maxDecodedBodyBytes!);
}
