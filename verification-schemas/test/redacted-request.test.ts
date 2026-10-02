import assert from "node:assert/strict";
import test from "node:test";
import { inspectDisclosedRequest, evaluateVerifiedExchange, SchemaError } from "../src/index.ts";
import type { Range, VerifiedBytes } from "../src/index.ts";
import { chatgpt, encode, recipient, response } from "./helpers.ts";

const authorization = "Bearer synthetic-private-token";
const userAgent = "Pines synthetic browser";
const request = `GET /backend-api/wham/usage HTTP/1.1\r\nHost: chatgpt.com\r\nAuthorization: ${authorization}\r\nUser-Agent: ${userAgent}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n`;
function masked(text = request, slots?: Range[]) {
  const original = encode(text), bytes = original.slice();
  const ranges = slots ?? [authorization, userAgent].map(value => ({ start: text.indexOf(value), end: text.indexOf(value) + value.length }));
  const authenticated: Range[] = [];
  let cursor = 0;
  for (const { start, end } of [...ranges].sort((a, b) => a.start - b.start)) {
    assert(start >= cursor && end > start && end <= bytes.length);
    if (start > cursor) authenticated.push({ start: cursor, end: start });
    bytes.fill(0, start, end); cursor = end;
  }
  if (cursor < bytes.length) authenticated.push({ start: cursor, end: bytes.length });
  return { sent: { bytes, originalLength: bytes.length, authenticated } satisfies VerifiedBytes, ranges };
}
const inspect = (data = masked()) => inspectDisclosedRequest(chatgpt, data.sent);

test("native redaction identifies only the opaque header intervals", () => {
  const data = masked(), slots = inspect(data);
  assert.deepEqual(slots.map(slot => slot.name), ["authorization", "user-agent"]);
  assert.deepEqual(slots.map(({start, end}) => ({start, end})), data.ranges);
  assert(Object.isFrozen(slots) && Object.isFrozen(slots[0]));
  assert(!JSON.stringify(slots).includes(authorization));
});

test("hidden contents are opaque, including control characters", () => {
  const data = masked();
  const start = request.indexOf(authorization), end = start + authorization.length;
  const opaque = "x\r\nX-Injected: a".padEnd(authorization.length, "a");
  const other = masked(request.slice(0, start) + opaque + request.slice(end), data.ranges);
  assert.deepEqual(data.sent, other.sent);
  assert.deepEqual(inspect(data), inspect(other));
});

test("malformed coverage and nonzero hidden bytes fail", () => {
  const attacks: ((data: any) => void)[] = [
    d => { d.sent.bytes[d.ranges[0].start] = 65; },
    d => { d.sent.originalLength -= 1; }, d => { d.sent.authenticated[0].end -= 1; },
    d => { d.sent.authenticated.reverse(); }, d => { d.sent.authenticated[1].start = 0; },
    d => { d.sent.authenticated.push(d.sent.authenticated[0]); },
    d => { d.sent.authenticated[0].end = Infinity; }, d => { d.sent.authenticated[0].end = 1.5; },
  ];
  for (const attack of attacks) { const data = masked(); attack(data); assert.throws(() => inspect(data), SchemaError); }
});

test("hidden values cannot absorb header names, delimiters, request lines or public headers", () => {
  const auth = request.indexOf(authorization), ua = request.indexOf(userAgent);
  const original = [{ start: auth, end: auth + authorization.length }, { start: ua, end: ua + userAgent.length }];
  for (const range of [
    { start: 0, end: request.indexOf("\r\n") },
    { start: request.indexOf("Authorization:"), end: auth + authorization.length },
    { start: auth - 2, end: auth + authorization.length },
    { start: auth, end: auth + authorization.length + 2 },
    { start: request.indexOf("chatgpt.com"), end: request.indexOf("chatgpt.com") + "chatgpt.com".length },
  ]) assert.throws(() => inspect(masked(request, [range, original[1]!])), SchemaError);
  assert.throws(() => inspect(masked(request, [{ start: auth + 7, end: original[0]!.end }, original[1]!])), SchemaError);
});

test("request scope remains exact and public framing/body ambiguities fail", () => {
  const add = (header: string) => request.replace("\r\n\r\n", `\r\n${header}\r\n\r\n`);
  for (const text of [
    request.replace("GET /backend-api/wham/usage", "GET /backend-api/wham/usage?other=1"),
    request.replace("GET ", "POST "), request.replace("Host: chatgpt.com", "Host: other.example"),
    request.replace("Accept-Encoding: identity", "Accept-Encoding: gzip"),
    request.replace("Authorization: ", "Authorization:\t"),
    request.replace(`${authorization}\r\n`, `${authorization} \r\n`),
    request.replace("Host:", "Host :"), request.replace("User-Agent:", " user-agent:"),
    add("Host: chatgpt.com"), add(`Authorization: ${authorization}`), add("Cookie: a=b"),
    add("X-Extra: value"), add("Transfer-Encoding: chunked"), add("Content-Length: 1"),
    add("Content-Length: 00"), request + "x", request + "GET / HTTP/1.1\r\n\r\n",
    request.slice(0, -2), request.replace("Connection: close", "Connection: keep-alive"),
  ]) assert.throws(() => inspect(masked(text)), SchemaError);
  assert.equal(inspect(masked(add("Content-Length: 0"))).length, 2);
});

test("credentials must remain hidden instead of falling back to full disclosure", () => {
  const sent = encode(request);
  const full = { bytes: sent, originalLength: sent.length, authenticated: [{ start: 0, end: sent.length }] };
  assert.throws(() => inspectDisclosedRequest(chatgpt, full), { code: "PRIVATE_REQUEST_UNSUPPORTED" });
  const recv = response({ plan_type: "pro" });
  assert.throws(() => evaluateVerifiedExchange(chatgpt, { mode: "Proxy", serverName: "chatgpt.com", sent: full,
    recv: { bytes: recv, originalLength: recv.length, authenticated: [{ start: 0, end: recv.length }] },
  }, recipient), { code: "PRIVATE_REQUEST_UNSUPPORTED" });
});

test("required private headers cannot be omitted and unsupported private policies stay closed", () => {
  for (const [name, value, remaining] of [["Authorization", authorization, userAgent], ["User-Agent", userAgent, authorization]]) {
    const text = request.replace(`${name}: ${value}\r\n`, "");
    const start = text.indexOf(remaining!);
    assert.throws(() => inspect(masked(text, [{ start, end: start + remaining!.length }])), { code: "SCOPE_MISMATCH" });
  }
  const data = masked();
  assert.throws(() => inspectDisclosedRequest({ ...chatgpt, capture: { ...chatgpt.capture, headers: [] } }, data.sent), { code: "PRIVATE_REQUEST_UNSUPPORTED" });
  // A cookie policy makes the opaque jar a required private header, so a request without one is out of scope.
  assert.throws(() => inspectDisclosedRequest({ ...chatgpt, capture: { ...chatgpt.capture, cookies: ["session"] } }, data.sent), { code: "SCOPE_MISMATCH" });
  assert.throws(() => inspectDisclosedRequest({...chatgpt, limits: {...chatgpt.limits, maxSentBytes: 10}}, data.sent), {code: "LIMIT_EXCEEDED"});
});

test("native selective disclosure derives facts from an authenticated full response", () => {
  const data = masked(), recv = response({plan_type: "pro"});
  const facts = evaluateVerifiedExchange(chatgpt, {mode: "Proxy", serverName: "chatgpt.com", sent: data.sent,
    recv: {bytes: recv, originalLength: recv.length, authenticated: [{start: 0, end: recv.length}]},
  }, recipient);
  assert.equal(facts.subjectKey, `pro:${recipient.toLowerCase()}`);
  assert.equal(facts.claimable, false);
});
