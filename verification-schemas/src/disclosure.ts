import { parseHttp } from "./http.ts";
import { previewExchange } from "./evaluate.ts";
import { requireThat } from "./errors.ts";
import type { Range, VerificationSchema } from "./types.ts";

function complement(length: number, hidden: Range[]): Range[] {
  const result: Range[] = [];
  let cursor = 0;
  for (const range of hidden.sort((a, b) => a.start - b.start)) {
    requireThat(range.start >= cursor && range.end >= range.start && range.end <= length, "INVALID_HTTP");
    if (range.start > cursor) result.push({ start: cursor, end: range.start });
    cursor = range.end;
  }
  if (cursor < length) result.push({ start: cursor, end: length });
  return result;
}

// Native TLSN disclosure ranges. The local precheck sees the full transcript;
// the verifier receives only disclosed bytes and treats hidden contents as opaque.
export function planDisclosure(schema: VerificationSchema, sent: Uint8Array, recv: Uint8Array, recipient: string) {
  const preview = previewExchange(schema, sent, recv, recipient);
  const request = parseHttp(sent, schema, "sent");
  const response = parseHttp(recv, schema, "recv");
  const secrets = new Set(schema.capture.headers.filter(rule => rule.secret).map(rule => rule.name));
  secrets.add("cookie");
  const hiddenSent = request.headers.filter(header => secrets.has(header.name) && header.value.length > 0).map(header => ({ start: header.valueStart, end: header.valueEnd }));
  const hiddenRecv = response.headers.filter(header => header.name === "set-cookie" && header.value.length > 0).map(header => ({ start: header.valueStart, end: header.valueEnd }));
  return {
    sent: complement(sent.length, hiddenSent),
    recv: complement(recv.length, hiddenRecv),
    server_identity: true,
    preview,
    disclosure: "full-json-body" as const,
    requiresUserConsent: true,
  };
}
