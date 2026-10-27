import { parseHttp, type Header } from "./http.ts";
import { previewExchange } from "./evaluate.ts";
import { requireThat } from "./errors.ts";
import type { Range, ResponseDisclosureMode, VerificationSchema } from "./types.ts";

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

function hiddenHeaderRanges(bytes: Uint8Array, headers: readonly Header[], hide: (name: string) => boolean): Range[] {
  return headers.filter(header => hide(header.name)).map(header => {
    // Match the independent disclosed-request/response inspectors before reveal.
    // parseHttp trims OWS, but the private wire contract requires an exact public
    // ": " prefix and CRLF suffix around one nonempty opaque value. Do not widen
    // that contract or expose whitespace/credential contents to make it pass.
    requireThat(header.value.length > 0 && bytes[header.valueStart - 2] === 58
      && bytes[header.valueStart - 1] === 32 && bytes[header.valueEnd] === 13
      && bytes[header.valueEnd + 1] === 10, "PRIVATE_REQUEST_UNSUPPORTED");
    return { start: header.valueStart, end: header.valueEnd };
  });
}

const revealed = (ranges: readonly Range[]) => ranges.reduce((total, range) => total + range.end - range.start, 0);

// Native TLSN disclosure ranges. The local precheck sees the full transcript;
// the verifier receives only disclosed bytes and treats hidden contents as opaque.
export function planDisclosure(schema: VerificationSchema, sent: Uint8Array, recv: Uint8Array, recipient: string, responseDisclosure: ResponseDisclosureMode = "selective") {
  requireThat(responseDisclosure === "selective" || responseDisclosure === "complete" || responseDisclosure === "private-headers", "PRIVATE_REQUEST_UNSUPPORTED");
  // The schema's declared header-privacy contract and the selected disclosure mode are
  // refused apart, exactly as the inspector refuses them apart.
  requireThat((responseDisclosure === "private-headers") === (schema.response.privacy !== undefined), "PRIVATE_REQUEST_UNSUPPORTED");
  const preview = previewExchange(schema, sent, recv, recipient);
  const request = parseHttp(sent, schema, "sent");
  const response = parseHttp(recv, schema, "recv");
  const secrets = new Set(schema.capture.headers.filter(rule => rule.secret).map(rule => rule.name));
  secrets.add("cookie");
  const hiddenSent = hiddenHeaderRanges(sent, request.headers, name => secrets.has(name));
  const responseSecrets = new Set(["set-cookie", ...(schema.response.secretHeaders ?? [])]);
  const visible: readonly string[] = schema.response.privacy?.visibleHeaders ?? [];
  // Hide the value of EVERY response header except the framing. A value shorter than
  // one AES block saves nothing by staying public, so there is no reason to keep any.
  const hiddenRecv = responseDisclosure === "complete" ? []
    : hiddenHeaderRanges(recv, response.headers, responseDisclosure === "private-headers"
      ? name => !visible.includes(name) : name => responseSecrets.has(name));
  const plan = { sent: complement(sent.length, hiddenSent), recv: complement(recv.length, hiddenRecv) };
  // The same revealed-byte budget the inspectors enforce, refused here so a browser
  // never offers a proposal the enclave would reject after the proof was paid for.
  if (schema.limits.maxRevealedSentBytes !== undefined) requireThat(revealed(plan.sent) <= schema.limits.maxRevealedSentBytes, "REVEALED_LIMIT_EXCEEDED");
  if (schema.limits.maxRevealedRecvBytes !== undefined) requireThat(revealed(plan.recv) <= schema.limits.maxRevealedRecvBytes, "REVEALED_LIMIT_EXCEEDED");
  return {
    ...plan,
    server_identity: true,
    preview,
    disclosure: "full-json-body" as const,
    requiresUserConsent: true,
  };
}
